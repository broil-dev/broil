// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"

	"github.com/distribution/reference"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type identity struct {
	Version    uint64 `json:"protocol_version"`
	Operation  string `json:"operation_id"`
	Analysis   uint64 `json:"analysis_id"`
	Resolution string `json:"resolution_id"`
}

type sourceRange struct {
	Start       int  `json:"start_line"`
	End         int  `json:"end_line"`
	StartColumn *int `json:"start_column"`
	EndColumn   *int `json:"end_column"`
}

type location struct {
	Kind      string        `json:"kind"`
	Ranges    []sourceRange `json:"ranges,omitempty"`
	Parent    string        `json:"parent_reference,omitempty"`
	Root      digest.Digest `json:"parent_root,omitempty"`
	Platform  string        `json:"parent_platform,omitempty"`
	Trigger   *int          `json:"trigger_index,omitempty"`
	Consuming []sourceRange `json:"consuming_from,omitempty"`
}

type publicUse struct {
	Role        string   `json:"role"`
	Instruction string   `json:"instruction"`
	TagOrigin   string   `json:"tag_origin"`
	Location    location `json:"location"`
}

type publicSource struct {
	Reference string         `json:"reference"`
	Platform  string         `json:"platform"`
	Root      *digest.Digest `json:"root"`
	Uses      []publicUse    `json:"uses"`
}

type diagnostic struct {
	Reason   string   `json:"reason"`
	Location location `json:"location"`
}

type locatedError struct {
	err      error
	location location
}

func (e *locatedError) Error() string { return "invalid source" }
func (e *locatedError) Unwrap() error { return e.err }

func atRanges(err error, ranges []parser.Range, text string) error {
	if projected, failure := originalRanges(ranges, text); failure == nil {
		return &locatedError{err: err, location: location{Kind: "dockerfile", Ranges: projected}}
	}
	return err
}

func atUse(err error, use sourceUse, text string) error {
	if projected, failure := useProjection(use, text); failure == nil {
		return &locatedError{err: err, location: projected.Location}
	}
	return err
}

// Source rewriting preserves lines but not columns. Do not invent precise
// original columns from the generated text's upstream source map.
func originalRanges(ranges []parser.Range, text string) ([]sourceRange, error) {
	if len(ranges) == 0 || len(ranges) > 1024 {
		return nil, errInput
	}
	// A terminating newline ends the last line instead of starting another.
	lines := strings.Count(text, "\n")
	if text != "" && !strings.HasSuffix(text, "\n") {
		lines++
	}
	result := make([]sourceRange, 0, len(ranges))
	for _, r := range ranges {
		if r.Start.Line < 1 || r.End.Line < r.Start.Line || r.End.Line > lines {
			return nil, errInput
		}
		result = append(result, sourceRange{Start: r.Start.Line, End: r.End.Line})
	}
	return result, nil
}

func useProjection(use sourceUse, text string) (publicUse, error) {
	p := publicUse{Role: use.Role, Instruction: use.Instruction, TagOrigin: use.TagOrigin}
	if use.Parent != "" {
		r, err := originalRanges(use.ConsumingFrom, text)
		if err != nil || use.Trigger == nil || *use.Trigger < 0 || *use.Trigger >= 256 {
			return p, errInput
		}
		p.Location = location{Kind: "inherited", Parent: use.Parent, Root: use.ParentRoot, Platform: use.ParentPlatform, Trigger: use.Trigger, Consuming: r}
	} else {
		r, err := originalRanges(use.Locations, text)
		if err != nil {
			return p, err
		}
		p.Location = location{Kind: "dockerfile", Ranges: r}
	}
	return p, nil
}

func errorLocation(err error, text string) location {
	var located *locatedError
	if errors.As(err, &located) {
		return located.location
	}
	var source *parser.LocationError
	if errors.As(err, &source) {
		for _, ranges := range source.Locations {
			if r, e := originalRanges(ranges, text); e == nil {
				return location{Kind: "dockerfile", Ranges: r}
			}
		}
	}
	return location{Kind: "unavailable"}
}

func refuse(out result, status, reason string, err error, text string) (result, []byte) {
	out.Status = status
	out.Operations = []operation{}
	out.Diagnostics = []diagnostic{{Reason: reason, Location: errorLocation(err, text)}}
	return out, nil
}

func tagOrigin(name string) string {
	n, err := reference.ParseNormalizedNamed(name)
	if err != nil {
		return ""
	}
	if _, ok := n.(reference.Tagged); ok {
		return "declared"
	}
	if _, ok := n.(reference.Digested); ok {
		return "absent"
	}
	return "default"
}

func exact(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil || len(values) != len(keys) {
		return nil, errInput
	}
	for _, key := range keys {
		v, ok := values[key]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return nil, errInput
		}
	}
	return values, nil
}

func decodeRequest(input []byte) (request, error) {
	var req request
	d := json.NewDecoder(bytes.NewReader(input))
	d.UseNumber()
	if unique(d, 1) != nil {
		return req, errInput
	}
	if _, err := d.Token(); err != io.EOF {
		return req, errInput
	}
	values, err := exact(input, "protocol_version", "operation_id", "analysis_id", "resolution_id", "dockerfile", "path", "stage", "args", "build_platform", "platform", "contexts", "frontend", "analyzer_identity", "metadata")
	if err != nil {
		return req, err
	}
	if requestBounds(values) != nil {
		return req, errInput
	}
	items, err := boundedArray(values["metadata"])
	if err != nil || len(items) > 1024 {
		return req, errInput
	}
	for _, item := range items {
		if _, err := exact(item, "reference", "platform", "root", "config", "manifest", "indexes"); err != nil {
			return req, err
		}
	}
	d = json.NewDecoder(bytes.NewReader(input))
	d.DisallowUnknownFields()
	if d.Decode(&req) != nil || req.Version != 2 || req.Analysis == 0 || len(req.Operation) != 42 || !strings.HasPrefix(req.Operation, "operation-") || !lowerHex(req.Operation[10:]) || !sha256ID(req.Resolution) || !sha256ID(req.AnalyzerIdentity) {
		return req, errInput
	}
	for _, m := range req.Metadata {
		if m.Indexes == nil {
			return req, errInput
		}
	}
	return req, nil
}

func lowerHex(text string) bool {
	for _, c := range text {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func sha256ID(text string) bool {
	return len(text) == 71 && strings.HasPrefix(text, "sha256:") && lowerHex(text[7:])
}

// The digest binds encoded objects, not a JSON reserialization. The caller
// independently authenticates their original repository association.
func resolutionID(req request) (string, error) {
	h := digest.SHA256.Digester()
	w := h.Hash()
	w.Write([]byte("broil.image.analysis.v2\x00"))
	number := func(n uint64) { var b [8]byte; binary.BigEndian.PutUint64(b[:], n); w.Write(b[:]) }
	str := func(s string) { number(uint64(len(s))); w.Write([]byte(s)) }
	encoded := func(raw []byte) error {
		if len(raw) == 0 || len(raw) > 1<<20 {
			return errInput
		}
		var object struct {
			MediaType string `json:"mediaType"`
		}
		if json.Unmarshal(raw, &object) != nil {
			return errInput
		}
		str(digest.FromBytes(raw).String())
		number(uint64(len(raw)))
		str(object.MediaType)
		return nil
	}
	descriptor := func(d ocispec.Descriptor) { str(d.Digest.String()); number(uint64(d.Size)); str(d.MediaType) }
	str(req.Dockerfile)
	str(req.Path)
	str(req.Stage)
	keys := make([]string, 0, len(req.Args))
	for key := range req.Args {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	number(uint64(len(keys)))
	for _, key := range keys {
		str(key)
		str(req.Args[key])
	}
	str(req.BuildPlatform)
	str(req.Platform)
	contexts := append([]string{}, req.Contexts...)
	sort.Strings(contexts)
	number(uint64(len(contexts)))
	for _, name := range contexts {
		str(name)
	}
	str(req.Frontend)
	str(req.AnalyzerIdentity)
	items := append([]metadata{}, req.Metadata...)
	sort.Slice(items, func(i, j int) bool {
		if items[i].Reference == items[j].Reference {
			return items[i].Platform < items[j].Platform
		}
		return items[i].Reference < items[j].Reference
	})
	number(uint64(len(items)))
	for _, m := range items {
		str(m.Reference)
		str(m.Platform)
		root := m.Manifest
		if len(m.Indexes) > 0 {
			root = m.Indexes[0]
		}
		if err := encoded(root); err != nil {
			return "", err
		}
		number(uint64(len(m.Indexes)))
		for _, index := range m.Indexes {
			if err := encoded(index); err != nil {
				return "", err
			}
		}
		if err := encoded(m.Manifest); err != nil {
			return "", err
		}
		var manifest ocispec.Manifest
		if json.Unmarshal(m.Manifest, &manifest) != nil || manifest.Config.Size < 0 || manifest.Config.Digest != digest.FromBytes(m.Config) || manifest.Config.Size != int64(len(m.Config)) {
			return "", errInput
		}
		descriptor(manifest.Config)
	}
	return h.Digest().String(), nil
}
