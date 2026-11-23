// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"syscall"
)

const ociIndex = "application/vnd.oci.image.index.v1+json"
const ociManifest = "application/vnd.oci.image.manifest.v1+json"
const ociConfig = "application/vnd.oci.image.config.v1+json"
const dockerIndex = "application/vnd.docker.distribution.manifest.list.v2+json"
const dockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
const dockerConfig = "application/vnd.docker.container.image.v1+json"
const cacheConfig = "application/vnd.buildkit.cacheconfig.v0"
const manifestAccept = ociIndex + ", " + ociManifest + ", " + dockerIndex + ", " + dockerManifest

func isIndex(m string) bool    { return m == ociIndex || m == dockerIndex }
func isManifest(m string) bool { return isIndex(m) || m == ociManifest || m == dockerManifest }
func isConfig(m string) bool   { return m == ociConfig || m == dockerConfig || m == cacheConfig }
func isLayer(m string) bool {
	return m == "application/vnd.oci.image.layer.v1.tar" || m == "application/vnd.oci.image.layer.v1.tar+gzip" || m == "application/vnd.oci.image.layer.v1.tar+zstd" || m == "application/vnd.docker.image.rootfs.diff.tar.gzip"
}
func knownMedia(m string) bool { return isManifest(m) || isConfig(m) || isLayer(m) }

type platform struct {
	OS           string   `json:"os"`
	Architecture string   `json:"architecture"`
	Variant      string   `json:"variant"`
	Version      string   `json:"os.version"`
	Features     []string `json:"os.features"`
}
type wireDescriptor struct {
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Media       string            `json:"mediaType"`
	Platform    *platform         `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func (w wireDescriptor) descriptor() descriptor {
	d := descriptor{w.Digest, w.Size, w.Media}
	validDescriptor(d)
	return d
}

type manifest struct {
	Schema      int               `json:"schemaVersion"`
	Media       string            `json:"mediaType"`
	Manifests   []wireDescriptor  `json:"manifests,omitempty"`
	Config      *wireDescriptor   `json:"config,omitempty"`
	Layers      []wireDescriptor  `json:"layers,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}
type node struct {
	d         descriptor
	metadata  []byte
	children  []wireDescriptor
	platforms map[string]platform
	done      bool
}
type graph struct {
	p                                            *policy
	n                                            *network
	stage                                        *staging
	source                                       *os.File
	nodes                                        map[string]*node
	order                                        []*node
	edges, content, verifiedBytes, verifiedCount int64
}

func hash(data []byte) string   { h := sha256.Sum256(data); return "sha256:" + hex.EncodeToString(h[:]) }
func same(a, b descriptor) bool { return a == b }
func (g *graph) register(d descriptor) *node {
	validDescriptor(d)
	if previous, ok := g.nodes[d.Digest]; ok {
		require(same(previous.d, d), "integrity")
		return previous
	}
	require(int64(len(g.nodes)) < g.p.Limits["descriptors"] && d.Size <= g.p.Limits["content_bytes"]-g.content, "limit")
	g.content += d.Size
	v := &node{d: d}
	g.nodes[d.Digest] = v
	g.n.allowed[d.Digest] = d
	return v
}
func (g *graph) bytes(d descriptor) []byte {
	var input io.ReadCloser
	if g.source != nil {
		input = contentFile(g.source, d.Digest)
	} else {
		kind := "blobs"
		if isManifest(d.Media) {
			kind = "manifests"
		}
		r := g.n.request("GET", g.n.resource(kind, d.Digest), nil, 0, "")
		input = r.Body
		require(r.StatusCode == 200, "integrity")
		responseIdentity(r, d)
		if isManifest(d.Media) {
			require(singleHeader(r, "Content-Type") == d.Media, "integrity")
		}
	}
	defer input.Close()
	data := readBounded(input, g.p.Limits["metadata_bytes"])
	require(int64(len(data)) == d.Size && hash(data) == d.Digest, "integrity")
	return data
}
func (g *graph) save(d descriptor, data []byte) {
	if g.source != nil {
		return
	}
	f := g.stage.file(g.stage.blobs, d.Digest[7:])
	defer f.Close()
	g.stage.account(len(data))
	_, err := f.Write(data)
	checked(err, "storage")
	checked(f.Sync(), "storage")
}
func (g *graph) layer(d descriptor) {
	var input io.ReadCloser
	if g.source != nil {
		input = contentFile(g.source, d.Digest)
	} else {
		r := g.n.request("GET", g.n.resource("blobs", d.Digest), nil, 0, "")
		input = r.Body
		require(r.StatusCode == 200, "integrity")
		responseIdentity(r, d)
	}
	defer input.Close()
	var destination io.Writer = io.Discard
	account := func(int) {}
	if g.source == nil {
		f := g.stage.file(g.stage.blobs, d.Digest[7:])
		defer f.Close()
		destination = f
		account = g.stage.account
	}
	copyVerified(input, destination, d, g.p.Limits["blob_bytes"], account)
}
func platformMatch(actual platform, expected *platform) {
	if expected == nil {
		return
	}
	require(expected.OS != "" && expected.Architecture != "" && actual.OS == expected.OS && actual.Architecture == expected.Architecture, "integrity")
	require(expected.Variant == "" || actual.Variant == expected.Variant, "integrity")
	require(expected.Version == "" || actual.Version == expected.Version, "integrity")
	for _, feature := range expected.Features {
		found := false
		for _, have := range actual.Features {
			if have == feature {
				found = true
			}
		}
		require(found, "integrity")
	}
}
func configPlatform(data []byte, media string) platform {
	uniqueJSON(data, 128)
	var raw map[string]json.RawMessage
	decode(data, &raw)
	require(raw != nil, "integrity")
	if media == cacheConfig {
		require(raw["layers"] != nil, "integrity")
		return platform{}
	}
	var value platform
	for name, dst := range map[string]any{"os": &value.OS, "architecture": &value.Architecture, "variant": &value.Variant, "os.version": &value.Version, "os.features": &value.Features} {
		if data, ok := raw[name]; ok {
			nonnull(data)
			decode(data, dst)
		}
	}
	require(value.OS != "" && value.Architecture != "" && safeText(value.OS) && safeText(value.Architecture), "integrity")
	var rootfs struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	}
	decode(raw["rootfs"], &rootfs)
	require(rootfs.Type == "layers" && rootfs.DiffIDs != nil, "integrity")
	for _, digest := range rootfs.DiffIDs {
		require(digestRE.MatchString(digest), "integrity")
	}
	return value
}
func (g *graph) visit(d descriptor, depth int64, expected *platform) map[string]platform {
	require(depth <= g.p.Limits["graph_depth"], "limit")
	g.edges++
	require(g.edges <= g.p.Limits["descriptor_edges"], "limit")
	v, existed := g.nodes[d.Digest]
	if !existed {
		v = g.register(d)
	} else {
		require(same(v.d, d), "integrity")
	}
	if v.done {
		for _, p := range v.platforms {
			platformMatch(p, expected)
		}
		return v.platforms
	}
	// A node is in progress only during this DFS. Re-entering it is a cycle.
	require(v.children == nil, "integrity")
	v.children = []wireDescriptor{}
	if isLayer(d.Media) {
		if g.p.Action == "inspect" {
			v.done = true
			return nil
		}
		g.layer(d)
	} else {
		if v.metadata == nil {
			v.metadata = g.bytes(d)
		}
		require(d.Size <= g.p.Limits["metadata_bytes"], "limit")
		uniqueJSON(v.metadata, 128)
		if isConfig(d.Media) {
			v.platforms = map[string]platform{d.Digest: configPlatform(v.metadata, d.Media)}
		} else {
			var m manifest
			decode(v.metadata, &m)
			require(m.Schema == 2 && m.Media == d.Media, "integrity")
			if isIndex(d.Media) {
				v.platforms = map[string]platform{}
				require(g.p.Kind == "image" && len(m.Manifests) > 0 && m.Config == nil && m.Layers == nil, "integrity")
				for _, child := range m.Manifests {
					if d.Media == dockerIndex {
						require(child.Platform != nil, "integrity")
					}
					cd := child.descriptor()
					require(isManifest(cd.Media), "integrity")
					v.children = append(v.children, child)
					for config, platform := range g.visit(cd, depth+1, child.Platform) {
						v.platforms[config] = platform
					}
				}
			} else {
				require(m.Config != nil && m.Layers != nil && m.Manifests == nil, "integrity")
				cd := m.Config.descriptor()
				want := ociConfig
				if d.Media == dockerManifest {
					want = dockerConfig
				}
				if g.p.Kind == "cache" {
					want = cacheConfig
					require(d.Media == ociManifest, "integrity")
				}
				require(cd.Media == want && m.Config.Platform == nil, "integrity")
				v.children = append(v.children, *m.Config)
				v.platforms = g.visit(cd, depth+1, nil)
				for _, child := range m.Layers {
					ld := child.descriptor()
					require(isLayer(ld.Media) && child.Platform == nil, "integrity")
					require((d.Media == dockerManifest) == strings.HasPrefix(ld.Media, "application/vnd.docker."), "integrity")
					v.children = append(v.children, child)
					g.visit(ld, depth+1, nil)
				}
				if g.p.Kind == "image" {
					var configuration struct {
						Rootfs struct {
							DiffIDs []string `json:"diff_ids"`
						} `json:"rootfs"`
					}
					checked(json.Unmarshal(g.nodes[cd.Digest].metadata, &configuration), "integrity")
					require(len(configuration.Rootfs.DiffIDs) == len(m.Layers), "integrity")
				}
			}
		}
		g.save(d, v.metadata)
	}
	for _, p := range v.platforms {
		platformMatch(p, expected)
	}
	v.done = true
	g.order = append(g.order, v)
	g.verifiedCount++
	g.verifiedBytes += d.Size
	return v.platforms
}
func (g *graph) root() descriptor {
	if g.p.writing() {
		input := openPath(*g.p.Input, true, true)
		defer input.Close()
		layout := openAt(input, "oci-layout", syscall.O_RDONLY)
		checkFile(layout, false, true)
		data := readBounded(layout, g.p.Limits["metadata_bytes"])
		layout.Close()
		uniqueJSON(data, 128)
		var version struct {
			Version string `json:"imageLayoutVersion"`
		}
		decode(data, &version)
		require(version.Version == "1.0.0", "integrity")
		index := openAt(input, "index.json", syscall.O_RDONLY)
		checkFile(index, false, true)
		data = readBounded(index, g.p.Limits["metadata_bytes"])
		index.Close()
		uniqueJSON(data, 128)
		var wrapper manifest
		decode(data, &wrapper)
		require(wrapper.Schema == 2 && wrapper.Media == ociIndex && len(wrapper.Manifests) == 1 && wrapper.Config == nil && wrapper.Layers == nil, "integrity")
		require(same(wrapper.Manifests[0].descriptor(), *g.p.Root), "integrity")
		blobs := openAt(input, "blobs", syscall.O_RDONLY|syscall.O_DIRECTORY)
		defer blobs.Close()
		checkFile(blobs, true, true)
		g.source = openAt(blobs, "sha256", syscall.O_RDONLY|syscall.O_DIRECTORY)
		checkFile(g.source, true, true)
		return *g.p.Root
	}
	r := g.n.request("GET", g.n.resource("manifests", g.p.ref), nil, 0, "")
	defer r.Body.Close()
	if r.StatusCode == 404 && g.p.Purpose == "cache_read" && g.p.Action == "fetch" && g.p.Kind == "cache" {
		missingCacheRoot(readBounded(r.Body, min(int64(65536), g.p.Limits["metadata_bytes"])))
		require(g.n.ctx.Err() == nil, "timeout")
		panic(failure("cache-miss"))
	}
	require(r.StatusCode == 200, "integrity")
	data := readBounded(r.Body, g.p.Limits["metadata_bytes"])
	d := descriptor{hash(data), int64(len(data)), singleHeader(r, "Content-Type")}
	validDescriptor(d)
	require(isManifest(d.Media), "integrity")
	require(g.p.pin == "" || d.Digest == g.p.pin, "integrity")
	if g.p.Root != nil {
		require(same(d, *g.p.Root), "integrity")
	}
	responseIdentity(r, d)
	g.register(d).metadata = data
	return d
}

// Only the initial cache root response reaches this private parser. Neither
// diagnostic text nor a missing descendant establishes an optional cache miss.
func missingCacheRoot(data []byte) {
	uniqueJSON(data, 16)
	envelope := fields(data, "errors")
	var entries []json.RawMessage
	decode(envelope["errors"], &entries)
	require(len(entries) == 1, "protocol")
	var entry map[string]json.RawMessage
	decode(entries[0], &entry)
	require(entry["code"] != nil, "protocol")
	for key, value := range entry {
		switch key {
		case "code", "message":
			nonnull(value)
			var text string
			decode(value, &text)
			if key == "code" {
				require(text == "MANIFEST_UNKNOWN", "integrity")
			}
		case "detail":
			// Its size, UTF-8, duplicates and nesting were checked above.
		default:
			panic(failure("protocol"))
		}
	}
}

func (g *graph) upload(root descriptor) {
	// Authenticate and obtain repository-scoped write/verification authority via a
	// body-free immutable read before any write; an absent root is legitimate.
	r := g.n.request("HEAD", g.n.resource("manifests", root.Digest), nil, 0, "")
	r.Body.Close()
	require(r.StatusCode == 200 || r.StatusCode == 404, "authentication")
	for _, v := range g.order {
		d := v.d
		if !isManifest(d.Media) {
			r = g.n.request("HEAD", g.n.resource("blobs", d.Digest), nil, 0, "")
			r.Body.Close()
			if r.StatusCode == 200 {
				responseIdentity(r, d)
				continue
			}
			require(r.StatusCode == 404, "protocol")
			r = g.n.request("POST", g.n.resource("blobs", "uploads/"), nil, 0, "")
			r.Body.Close()
			require(r.StatusCode == 202, "indeterminate")
			location := g.n.uploadLocation(r, "")
			g.n.writePending = false
			f := contentFile(g.source, d.Digest)
			r = g.n.request("PATCH", location, f, d.Size, "application/octet-stream")
			f.Close()
			r.Body.Close()
			require(r.StatusCode == 202, "indeterminate")
			session := strings.Split(location, "?")[0]
			location = g.n.uploadLocation(r, session)
			g.n.writePending = false
			u := resolveLocation(g.p.origin, location)
			q := continuationQuery(u.RawQuery, false)
			q.Set("digest", d.Digest)
			u.RawQuery = q.Encode()
			r = g.n.request("PUT", u.RequestURI(), nil, 0, "application/octet-stream")
			r.Body.Close()
			require(r.StatusCode == 201, "indeterminate")
			final := resolveLocation(r.Request.URL, singleHeader(r, "Location"))
			g.n.authorize("GET", final, false)
			require(final.Path == g.n.resource("blobs", d.Digest), "policy")
			responseIdentity(r, d)
			g.n.writePending = false
		} else {
			r = g.n.request("PUT", g.n.resource("manifests", d.Digest), bytes.NewReader(v.metadata), d.Size, d.Media)
			r.Body.Close()
			require(r.StatusCode == 201, "indeterminate")
			responseIdentity(r, d)
			g.n.writePending = false
		}
	}
	if g.p.tag != "" {
		v := g.nodes[root.Digest]
		r = g.n.request("PUT", g.n.resource("manifests", g.p.tag), bytes.NewReader(v.metadata), root.Size, root.Media)
		r.Body.Close()
		require(r.StatusCode == 201, "indeterminate")
		responseIdentity(r, root)
		g.n.writePending = false
		r = g.n.request("GET", g.n.resource("manifests", g.p.tag), nil, 0, "")
		require(r.StatusCode == 200, "integrity")
		copyVerified(r.Body, io.Discard, root, g.p.Limits["metadata_bytes"], func(int) {})
		r.Body.Close()
		responseIdentity(r, root)
	}
	// Read every required byte independently of write responses and HEAD claims.
	for _, v := range g.order {
		kind := "blobs"
		if isManifest(v.d.Media) {
			kind = "manifests"
		}
		r = g.n.request("GET", g.n.resource(kind, v.d.Digest), nil, 0, "")
		require(r.StatusCode == 200, "integrity")
		responseIdentity(r, v.d)
		if isManifest(v.d.Media) {
			require(singleHeader(r, "Content-Type") == v.d.Media, "integrity")
		}
		copyVerified(r.Body, io.Discard, v.d, g.p.Limits["blob_bytes"], func(int) {})
		r.Body.Close()
	}
}
func (g *graph) finish(root descriptor) {
	if g.p.writing() {
		g.upload(root)
		return
	}
	if g.p.Action == "fetch" {
		g.stage.put("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`))
		wrapper := manifest{Schema: 2, Media: ociIndex, Manifests: []wireDescriptor{{Digest: root.Digest, Size: root.Size, Media: root.Media}}}
		data, err := json.Marshal(wrapper)
		checked(err, "protocol")
		g.stage.put("index.json", data)
	}
	// This exclusive final marker records transient transfer state only.
	data, err := json.Marshal(struct {
		Root     descriptor `json:"root"`
		Complete bool       `json:"closure_complete"`
	}{root, g.p.Action == "fetch"})
	checked(err, "protocol")
	g.stage.complete(data)
}
