// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"

	"github.com/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// The caller has verified the complete original closure. This separately binds
// the selected immutable manifest/configuration to its original index root and
// requested platform. Private OCI inputs can address that selected manifest;
// the original repository pin still identifies the original root.
func validateSelection(m metadata, platform ocispec.Platform) error {
	root := m.Root
	for i, raw := range m.Indexes {
		if digest.FromBytes(raw) != root {
			return errInput
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			return errInput
		}
		var version int
		var media string
		if json.Unmarshal(object["schemaVersion"], &version) != nil || version != 2 || json.Unmarshal(object["mediaType"], &media) != nil || (media != ocispec.MediaTypeImageIndex && media != "application/vnd.docker.distribution.manifest.list.v2+json") {
			return errInput
		}
		entries, err := boundedArray(object["manifests"])
		if err != nil {
			return err
		}
		next := m.Manifest
		if i+1 < len(m.Indexes) {
			next = m.Indexes[i+1]
		}
		var nextObject struct {
			MediaType string `json:"mediaType"`
		}
		if json.Unmarshal(next, &nextObject) != nil {
			return errInput
		}
		selected, matching := 0, 0
		for _, entry := range entries {
			var desc ocispec.Descriptor
			if json.Unmarshal(entry, &desc) != nil || desc.Digest.Validate() != nil || desc.Size <= 0 {
				return errInput
			}
			matches := desc.Platform == nil || platforms.OnlyStrict(platform).Match(*desc.Platform)
			if matches {
				matching++
			}
			if desc.Digest == digest.FromBytes(next) {
				if !matches || desc.Size != int64(len(next)) || desc.MediaType != nextObject.MediaType {
					return errInput
				}
				selected++
			}
		}
		if selected != 1 || matching != 1 {
			return errUnsupported
		}
		root = digest.FromBytes(next)
	}
	if root != digest.FromBytes(m.Manifest) {
		return errInput
	}
	return nil
}
