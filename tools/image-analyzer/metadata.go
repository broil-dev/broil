// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"unicode/utf8"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func contentJSON(raw []byte) error {
	if len(raw) == 0 || len(raw) > 1<<20 || !utf8.Valid(raw) {
		return errInput
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if unique(d, 1) != nil {
		return errInput
	}
	if _, err := d.Token(); err != io.EOF {
		return errInput
	}
	return nil
}

func strictBytes(raw json.RawMessage) error {
	// Reject oversized encoded content before base64 decoding allocates it.
	var text string
	if len(raw) > (1<<20)*8 || json.Unmarshal(raw, &text) != nil || len(text) == 0 || len(text) > ((1<<20)+2)/3*4 {
		return errInput
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(decoded) > 1<<20 {
		return errInput
	}
	return nil
}

func requestBounds(values map[string]json.RawMessage) error {
	var args map[string]json.RawMessage
	if json.Unmarshal(values["args"], &args) != nil || args == nil || len(args) > 256 {
		return errInput
	}
	for _, v := range args {
		var s string
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) || json.Unmarshal(v, &s) != nil {
			return errInput
		}
	}
	contexts, err := boundedArray(values["contexts"])
	if err != nil || len(contexts) > 256 {
		return errInput
	}
	for _, v := range contexts {
		var s string
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) || json.Unmarshal(v, &s) != nil {
			return errInput
		}
	}
	items, err := boundedArray(values["metadata"])
	if err != nil || len(items) > 1024 {
		return errInput
	}
	for _, item := range items {
		m, err := exact(item, "reference", "platform", "root", "config", "manifest", "indexes")
		if err != nil {
			return err
		}
		if strictBytes(m["config"]) != nil || strictBytes(m["manifest"]) != nil {
			return errInput
		}
		indexes, err := boundedArray(m["indexes"])
		if err != nil || len(indexes) > 32 {
			return errInput
		}
		for _, index := range indexes {
			if strictBytes(index) != nil {
				return errInput
			}
		}
	}
	return nil
}

func metadataSchema(m metadata) error {
	var manifest map[string]json.RawMessage
	if json.Unmarshal(m.Manifest, &manifest) != nil || manifest == nil {
		return errInput
	}
	var media string
	var version uint64
	if json.Unmarshal(manifest["schemaVersion"], &version) != nil || version != 2 || json.Unmarshal(manifest["mediaType"], &media) != nil {
		return errInput
	}
	wantConfig := "application/vnd.oci.image.config.v1+json"
	if media == "application/vnd.docker.distribution.manifest.v2+json" {
		wantConfig = "application/vnd.docker.container.image.v1+json"
	} else if media != ocispec.MediaTypeImageManifest {
		return errInput
	}
	for key := range manifest {
		switch key {
		case "schemaVersion", "mediaType", "config", "layers", "annotations":
		default:
			return errInput
		}
	}
	var config ocispec.Descriptor
	if json.Unmarshal(manifest["config"], &config) != nil || config.MediaType != wantConfig || config.Size != int64(len(m.Config)) || config.Digest != digest.FromBytes(m.Config) {
		return errInput
	}
	layers, err := boundedArray(manifest["layers"])
	if err != nil {
		return err
	}
	for _, raw := range layers {
		var layer ocispec.Descriptor
		if json.Unmarshal(raw, &layer) != nil || layer.Digest.Validate() != nil || layer.Digest.Algorithm() != digest.SHA256 || layer.Size < 0 || layer.Size > 1<<30 {
			return errInput
		}
		if media == ocispec.MediaTypeImageManifest {
			switch layer.MediaType {
			case ocispec.MediaTypeImageLayer, ocispec.MediaTypeImageLayerGzip, ocispec.MediaTypeImageLayerZstd:
			default:
				return errInput
			}
		} else if layer.MediaType != "application/vnd.docker.image.rootfs.diff.tar.gzip" {
			return errInput
		}
	}
	var image map[string]json.RawMessage
	if json.Unmarshal(m.Config, &image) != nil || image == nil {
		return errInput
	}
	// The unchanged history implementation also verifies the layer/diff-ID and
	// history bounds for metadata not requested by the selected conversion.
	if _, _, err := completeHistory(image, m.Manifest, false); err != nil {
		return err
	}
	var cfg map[string]json.RawMessage
	if raw, ok := image["config"]; ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if json.Unmarshal(raw, &cfg) != nil {
			return errInput
		}
		if raw, ok := cfg["OnBuild"]; ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			triggers, err := boundedArray(raw)
			if err != nil || len(triggers) > 256 {
				return errInput
			}
			for _, trigger := range triggers {
				var text string
				if bytes.Equal(bytes.TrimSpace(trigger), []byte("null")) || json.Unmarshal(trigger, &text) != nil {
					return errInput
				}
			}
		}
	}
	return nil
}
