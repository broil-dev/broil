// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"io"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const maxHistoryItems = 4096
const syntheticHistory = `{"comment":"broil.input.history.v1","created_by":"Broil synthetic history: original history unavailable","empty_layer":false}`

// The private map identifies the actual implementation, including its bounds.
//
//go:embed history.go
var historySource string

type historyAddition struct {
	HistoryOrdinal int             `json:"history_ordinal"`
	LayerOrdinal   int             `json:"layer_ordinal"`
	Layer          json.RawMessage `json:"layer"`
	DiffID         digest.Digest   `json:"diff_id"`
	Entry          digest.Digest   `json:"entry_sha256"`
}

type historyCompletion struct {
	Version          int               `json:"protocol_version"`
	Source           digest.Digest     `json:"source_sha256"`
	Convention       string            `json:"convention"`
	OriginalConfig   json.RawMessage   `json:"original_config"`
	OriginalForm     string            `json:"original_form"`
	OriginalEntries  int               `json:"original_entries"`
	OriginalNonempty int               `json:"original_nonempty"`
	LayerCount       int               `json:"layer_count"`
	MissingHistory   string            `json:"missing_history,omitempty"`
	Added            []historyAddition `json:"added"`
}

// Every array is counted before allocating the next element. The caller has
// already checked the enclosing encoded size, duplicate keys and JSON depth.
func boundedArray(raw json.RawMessage) ([]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('[') {
		return nil, errInput
	}
	items := []json.RawMessage{}
	for d.More() {
		if len(items) == maxHistoryItems {
			return nil, errUnsupported
		}
		var item json.RawMessage
		if d.Decode(&item) != nil {
			return nil, errInput
		}
		items = append(items, item)
	}
	if token, err = d.Token(); err != nil || token != json.Delim(']') {
		return nil, errInput
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errInput
	}
	return items, nil
}

func completeHistory(image map[string]json.RawMessage, manifestBytes []byte, complete bool) (*historyCompletion, bool, error) {
	var manifest, rootfs map[string]json.RawMessage
	if json.Unmarshal(manifestBytes, &manifest) != nil || json.Unmarshal(image["rootfs"], &rootfs) != nil || rootfs == nil {
		return nil, false, errInput
	}
	var kind string
	if json.Unmarshal(rootfs["type"], &kind) != nil || kind != "layers" {
		return nil, false, errInput
	}
	layers, err := boundedArray(manifest["layers"])
	if err != nil {
		return nil, false, err
	}
	diffIDs, err := boundedArray(rootfs["diff_ids"])
	if err != nil || len(layers) != len(diffIDs) {
		return nil, false, errInput
	}
	for i, raw := range layers {
		var layer ocispec.Descriptor
		var diffID digest.Digest
		if json.Unmarshal(raw, &layer) != nil || layer.Digest.Validate() != nil || layer.Digest.Algorithm() != digest.SHA256 || layer.Size < 0 || layer.MediaType == "" || json.Unmarshal(diffIDs[i], &diffID) != nil || diffID.Validate() != nil || diffID.Algorithm() != digest.SHA256 {
			return nil, false, errInput
		}
	}
	info := &historyCompletion{Version: 1, Source: digest.FromString(historySource), Convention: "buildkit-v0.24.0-tail-completion", OriginalConfig: manifest["config"], OriginalForm: "absent", LayerCount: len(layers), Added: []historyAddition{}}
	entries := []json.RawMessage{}
	if raw, exists := image["history"]; exists {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			info.OriginalForm = "null"
		} else {
			entries, err = boundedArray(raw)
			if err != nil {
				return nil, false, err
			}
			info.OriginalForm = "empty"
			if len(entries) > 0 {
				info.OriginalForm = "non-empty"
			}
		}
	}
	info.OriginalEntries = len(entries)
	for _, raw := range entries {
		var fields map[string]json.RawMessage
		var entry ocispec.History
		if json.Unmarshal(raw, &fields) != nil || fields == nil || json.Unmarshal(raw, &entry) != nil {
			return nil, false, errInput
		}
		if !entry.EmptyLayer {
			info.OriginalNonempty++
		}
	}
	if info.OriginalNonempty > len(layers) {
		return nil, false, errInput
	}
	missing := len(layers) - info.OriginalNonempty
	if missing == 0 || !complete {
		return info, false, nil
	}
	if len(entries)+missing > maxHistoryItems || len(image["history"])+missing*(len(syntheticHistory)+1)+2 > 1<<20 {
		return nil, false, errUnsupported
	}
	info.MissingHistory = "unavailable"
	for ordinal := info.OriginalNonempty; ordinal < len(layers); ordinal++ {
		var diffID digest.Digest
		_ = json.Unmarshal(diffIDs[ordinal], &diffID)
		info.Added = append(info.Added, historyAddition{HistoryOrdinal: len(entries), LayerOrdinal: ordinal, Layer: layers[ordinal], DiffID: diffID, Entry: digest.FromString(syntheticHistory)})
		entries = append(entries, json.RawMessage(syntheticHistory))
	}
	// Raw entries preserve authored and unknown fields, nulls and empty flags.
	image["history"], err = json.Marshal(entries)
	return info, true, err
}
