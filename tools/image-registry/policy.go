// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type failure string

func (f failure) Error() string { return string(f) }
func require(ok bool, class failure) {
	if !ok {
		panic(class)
	}
}
func checked(err error, class failure) {
	if err == nil {
		return
	}
	if own, ok := err.(failure); ok {
		panic(own)
	}
	if timeout, ok := err.(interface{ Timeout() bool }); ok && timeout.Timeout() {
		panic(failure("timeout"))
	}
	panic(class)
}

var maxima = map[string]int64{
	"header_bytes": 65536, "result_bytes": 65536, "http_header_bytes": 65536, "stderr_bytes": 65536,
	"credential_bytes": 1048576, "token_response_bytes": 1048576, "metadata_bytes": 16777216,
	"blob_bytes": 1073741824, "content_bytes": 4294967296, "staging_bytes": 5368709120,
	"network_bytes": 17179869184, "descriptors": 4096, "descriptor_edges": 8192, "graph_depth": 32,
	"requests": 16384, "redirects": 3, "token_exchanges": 2, "operation_ms": 1800000,
	"frame_ms": 10000, "connect_ms": 20000, "request_ms": 300000, "idle_ms": 30000, "cleanup_ms": 5000,
}
var operationRE = regexp.MustCompile(`^operation-[0-9a-f]{32}$`)
var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var repositoryRE = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
var tagRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
var hostRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$`)
var realmRE = regexp.MustCompile(`^/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*$`)
var bearerRE = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)
var sessionRE = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)

type descriptor struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	Media  string `json:"media_type"`
}
type tokenService struct {
	Realm   string `json:"realm"`
	Service string `json:"service"`
}
type authentication struct {
	Kind         string        `json:"kind"`
	Username     string        `json:"username"`
	TokenService *tokenService `json:"token_service"`
}
type policy struct {
	Version             int              `json:"protocol_version"`
	ID                  string           `json:"operation_id"`
	Endpoint            string           `json:"endpoint"`
	HTTP                bool             `json:"development_http"`
	CA                  *string          `json:"ca"`
	Repository          string           `json:"repository"`
	Reference           string           `json:"reference"`
	Root                *descriptor      `json:"expected_root"`
	Purpose             string           `json:"purpose"`
	Action              string           `json:"action"`
	Kind                string           `json:"content_kind"`
	Auth                authentication   `json:"auth"`
	Staging             string           `json:"staging_dir"`
	Input               *string          `json:"input_dir"`
	Limits              map[string]int64 `json:"limits"`
	origin              *url.URL
	repo, ref, pin, tag string
}

func (p *policy) duration(key string) time.Duration {
	return time.Duration(p.Limits[key]) * time.Millisecond
}
func (p *policy) writing() bool { return p.Action == "upload" }

// Detect duplicates before typed decoding. All storage here belongs to the Go
// consumer; these routines never expose raw JSON or decoder errors.
func uniqueJSON(data []byte, depth int) {
	require(utf8.Valid(data), "protocol")
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var walk func(int)
	walk = func(level int) {
		require(level <= depth, "limit")
		t, err := d.Token()
		checked(err, "protocol")
		if delim, ok := t.(json.Delim); ok {
			require(delim == '{' || delim == '[', "protocol")
			seen := map[string]bool{}
			for d.More() {
				if delim == '{' {
					k, err := d.Token()
					checked(err, "protocol")
					s, ok := k.(string)
					require(ok && !seen[s], "protocol")
					seen[s] = true
				}
				walk(level + 1)
			}
			end, err := d.Token()
			checked(err, "protocol")
			require(end == json.Delim('}') && delim == '{' || end == json.Delim(']') && delim == '[', "protocol")
		}
	}
	walk(1)
	_, err := d.Token()
	require(err == io.EOF, "protocol")
}
func decode(data []byte, dst any) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	checked(d.Decode(dst), "protocol")
}
func fields(data []byte, names string) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	checked(json.Unmarshal(data, &m), "protocol")
	keys := strings.Fields(names)
	require(len(m) == len(keys), "protocol")
	for _, k := range keys {
		_, ok := m[k]
		require(ok, "protocol")
	}
	return m
}
func nonnull(raw json.RawMessage) {
	require(!bytes.Equal(bytes.TrimSpace(raw), []byte("null")), "protocol")
}
func safeText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func absolute(s string) bool {
	return strings.HasPrefix(s, "/") && path.Clean(s) == s && safeText(s) && !strings.Contains(s, "\\")
}
func endpoint(raw string, development bool) *url.URL {
	u, err := url.Parse(raw)
	checked(err, "policy")
	require(u.Scheme == "https" || u.Scheme == "http" && development, "policy")
	require(u.Host != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" && u.RawPath == "", "policy")
	require(safeText(raw) && !strings.ContainsAny(raw, "%\\#"), "policy")
	h := u.Hostname()
	if ip, err := netip.ParseAddr(h); err == nil {
		require(ip.String() == h && ip.Zone() == "", "policy")
	} else {
		require(len(h) <= 253 && hostRE.MatchString(h), "policy")
		for _, part := range strings.Split(h, ".") {
			require(len(part) <= 63, "policy")
		}
		last := h[strings.LastIndex(h, ".")+1:]
		_, numeric := strconv.ParseUint(last, 10, 64)
		require(numeric != nil && !strings.HasPrefix(h, "0x"), "policy")
	}
	if u.Port() != "" {
		n, err := strconv.Atoi(u.Port())
		require(err == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == u.Port(), "policy")
	}
	canonical := h
	if strings.Contains(h, ":") {
		canonical = "[" + h + "]"
	}
	if u.Port() != "" {
		canonical += ":" + u.Port()
	}
	require(u.Host == canonical, "policy")
	return u
}
func origin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return u.Scheme + "://" + net.JoinHostPort(u.Hostname(), port)
}
func validDescriptor(d descriptor) {
	require(digestRE.MatchString(d.Digest) && d.Size > 0 && knownMedia(d.Media), "integrity")
}
func parsePolicy(data []byte) *policy {
	uniqueJSON(data, 16)
	m := fields(data, "protocol_version operation_id endpoint development_http ca repository reference expected_root purpose action content_kind auth staging_dir input_dir limits")
	for k, v := range m {
		if k != "ca" && k != "input_dir" && k != "expected_root" {
			nonnull(v)
		}
	}
	var p policy
	decode(data, &p)
	require(p.Version == 1 && operationRE.MatchString(p.ID), "protocol")
	p.origin = endpoint(p.Endpoint, p.HTTP)
	require(p.origin.Path == "" || p.origin.Path == "/", "policy")
	p.origin.Path = ""
	p.Endpoint = p.origin.String()
	require(strings.HasPrefix(p.Repository, p.origin.Host+"/"), "policy")
	p.repo = strings.TrimPrefix(p.Repository, p.origin.Host+"/")
	require(len(p.Repository) <= 255 && repositoryRE.MatchString(p.repo), "policy")
	require(strings.HasPrefix(p.Reference, p.Repository), "policy")
	suffix := strings.TrimPrefix(p.Reference, p.Repository)
	parts := strings.Split(suffix, "@")
	require(len(parts) <= 2, "policy")
	if len(parts) == 2 {
		require(digestRE.MatchString(parts[1]), "policy")
		p.pin = parts[1]
	}
	if parts[0] != "" {
		require(strings.HasPrefix(parts[0], ":") && tagRE.MatchString(parts[0][1:]), "policy")
		p.ref = parts[0][1:]
		p.tag = p.ref
	}
	if p.pin != "" {
		p.ref = p.pin
	}
	if p.ref == "" {
		p.ref, p.tag = "latest", "latest"
	}
	allowed := map[string]string{"metadata": "inspect/image", "pull": "fetch/image", "cache_read": "fetch/cache", "push": "upload/image", "cache_write": "upload/cache"}
	require(allowed[p.Purpose] == p.Action+"/"+p.Kind, "policy")
	if p.Root != nil {
		fields(m["expected_root"], "digest size media_type")
		validDescriptor(*p.Root)
		require(isManifest(p.Root.Media), "integrity")
		require(p.pin == "" || p.Root.Digest == p.pin, "integrity")
	}
	require(absolute(p.Staging), "policy")
	if p.writing() {
		require(p.Input != nil && absolute(*p.Input) && p.Root != nil && *p.Input != p.Staging, "policy")
	} else {
		require(p.Input == nil, "policy")
	}
	if p.CA != nil {
		require(absolute(*p.CA), "policy")
	}
	switch p.Auth.Kind {
	case "none", "bearer":
		fields(m["auth"], "kind")
	case "password":
		a := fields(m["auth"], "kind username token_service")
		nonnull(a["username"])
		require(p.Auth.Username != "" && safeText(p.Auth.Username) && !strings.Contains(p.Auth.Username, ":"), "policy")
		if t := p.Auth.TokenService; t != nil {
			fields(a["token_service"], "realm service")
			realm := endpoint(t.Realm, p.HTTP)
			require(origin(realm) == origin(p.origin) && realmRE.MatchString(realm.Path), "policy")
			require(len(t.Service) > 0 && len(t.Service) <= 255, "policy")
			for _, c := range []byte(t.Service) {
				require(c > 32 && c < 127, "policy")
			}
		}
	default:
		panic(failure("policy"))
	}
	for k, v := range p.Limits {
		maximum, ok := maxima[k]
		require(ok && v > 0 && v <= maximum, "limit")
	}
	for k, v := range maxima {
		if _, ok := p.Limits[k]; !ok {
			p.Limits[k] = v
		}
	}
	require(int64(len(data)) <= p.Limits["header_bytes"], "limit")
	return &p
}
func readFrame(r io.Reader, accepted func(*policy)) (*policy, []byte) {
	part := func(max int64) []byte {
		var length uint32
		checked(binary.Read(r, binary.BigEndian, &length), "protocol")
		require(int64(length) <= max, "limit")
		data := make([]byte, int(length))
		_, err := io.ReadFull(r, data)
		checked(err, "protocol")
		return data
	}
	p := parsePolicy(part(maxima["header_bytes"]))
	accepted(p)
	if pipe, ok := r.(*boundedPipe); ok {
		pipe.frame = p.duration("frame_ms")
		pipe.idle = p.duration("idle_ms")
		if p.duration("operation_ms") < pipe.frame {
			pipe.frame = p.duration("operation_ms")
		}
	}
	credential := part(p.Limits["credential_bytes"])
	var trailing [1]byte
	n, err := r.Read(trailing[:])
	require(n == 0 && err == io.EOF, "protocol")
	require(utf8.Valid(credential) && !bytes.ContainsRune(credential, 0), "credential")
	if p.Auth.Kind == "none" {
		require(len(credential) == 0, "credential")
	} else {
		require(len(credential) > 0, "credential")
	}
	if p.Auth.Kind == "bearer" {
		require(bearerRE.Match(credential), "credential")
	}
	return p, credential
}
