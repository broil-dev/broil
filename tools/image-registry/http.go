// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type idleConnection struct {
	net.Conn
	idle time.Duration
}

func (c *idleConnection) Read(b []byte) (int, error) {
	c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(b)
}
func (c *idleConnection) Write(b []byte) (int, error) {
	c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(b)
}

type networkBody struct {
	io.ReadCloser
	n *network
}

func (b *networkBody) Read(data []byte) (int, error) {
	n, e := b.ReadCloser.Read(data)
	if !b.n.account(n) {
		return 0, failure("limit")
	}
	return n, e
}

type sentBody struct {
	io.Reader
	n *network
}

func (b *sentBody) Read(data []byte) (int, error) {
	n, e := b.Reader.Read(data)
	if !b.n.account(n) {
		return 0, failure("limit")
	}
	return n, e
}

type network struct {
	p                          *policy
	credential                 []byte
	client                     *http.Client
	ctx                        context.Context
	requests, bytes, exchanges int64
	token                      string
	expiry                     time.Time
	dispatch                   string
	writePending               bool
	allowed                    map[string]descriptor
	sessions                   map[string]bool
	budget                     sync.Mutex
}

func newNetwork(ctx context.Context, p *policy, credential []byte) *network {
	var roots *x509.CertPool
	if p.CA != nil {
		f := openPath(*p.CA, false, false)
		defer f.Close()
		roots = x509.NewCertPool()
		require(roots.AppendCertsFromPEM(readBounded(f, 1048576)), "trust")
	}
	dialer := &net.Dialer{Timeout: p.duration("connect_ms")}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &idleConnection{c, p.duration("idle_ms")}, nil
	}
	tlsPolicy := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		MaxResponseHeaderBytes: p.Limits["http_header_bytes"], TLSHandshakeTimeout: p.duration("connect_ms"),
		ResponseHeaderTimeout: p.duration("request_ms"), TLSClientConfig: tlsPolicy,
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
		DialContext:  dial,
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, p.duration("connect_ms"))
			defer cancel()
			raw, err := dial(ctx, network, address)
			if err != nil {
				return nil, err
			}
			config := tlsPolicy.Clone()
			config.ServerName, _, err = net.SplitHostPort(address)
			if err != nil {
				raw.Close()
				return nil, err
			}
			secure := tls.Client(raw, config)
			if err = secure.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return secure, nil
		},
	}
	return &network{p: p, credential: credential, ctx: ctx, dispatch: "none", allowed: map[string]descriptor{}, sessions: map[string]bool{},
		client: &http.Client{Transport: transport, Timeout: p.duration("request_ms"), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
}
func (n *network) account(count int) bool {
	n.budget.Lock()
	defer n.budget.Unlock()
	if int64(count) > n.p.Limits["network_bytes"]-n.bytes {
		return false
	}
	n.bytes += int64(count)
	return true
}
func (n *network) scope() string {
	actions := "pull"
	if n.p.writing() {
		actions = "pull,push"
	}
	return "repository:" + n.p.repo + ":" + actions
}
func (n *network) resource(kind, ref string) string {
	return "/v2/" + n.p.repo + "/" + kind + "/" + ref
}
func (n *network) authorize(method string, u *url.URL, token bool) {
	p := n.p
	require(origin(u) == origin(p.origin) && u.User == nil && u.Fragment == "" && u.RawPath == "" && u.Opaque == "" && !strings.ContainsAny(u.Path, "%\\"), "policy")
	if token {
		t := p.Auth.TokenService
		require(t != nil && method == "GET" && u.Scheme+"://"+u.Host+u.Path == t.Realm, "policy")
		q := url.Values{"service": {t.Service}, "scope": {n.scope()}}
		require(u.RawQuery == q.Encode(), "policy")
		return
	}
	read := method == "GET" || method == "HEAD"
	if u.Path == "/v2/" {
		require(method == "GET" && u.RawQuery == "" && !u.ForceQuery, "policy")
		return
	}
	if strings.HasPrefix(u.Path, n.resource("blobs", "uploads/")) {
		require(p.writing(), "policy")
		if method == "POST" {
			require(u.Path == n.resource("blobs", "uploads/") && u.RawQuery == "" && !u.ForceQuery, "policy")
			return
		}
		require((method == "PATCH" || method == "PUT") && n.sessions[u.Path], "policy")
		q := continuationQuery(u.RawQuery, method == "PUT")
		if method == "PUT" {
			d, ok := n.allowed[q.Get("digest")]
			require(ok && !isManifest(d.Media), "policy")
		}
		return
	}
	require(u.RawQuery == "" && !u.ForceQuery, "policy")
	for d, v := range n.allowed {
		kind := "blobs"
		if isManifest(v.Media) {
			kind = "manifests"
		}
		if u.Path == n.resource(kind, d) {
			require(read || method == "PUT" && p.writing() && kind == "manifests", "policy")
			return
		}
	}
	if u.Path == n.resource("manifests", p.ref) {
		require(read || method == "PUT" && p.writing(), "policy")
		return
	}
	if p.writing() && p.tag != "" && u.Path == n.resource("manifests", p.tag) {
		require(read || method == "PUT", "policy")
		return
	}
	panic(failure("policy"))
}
func (n *network) dispatchRequest(method string, u *url.URL, body io.Reader, size int64, media string, token bool) *http.Response {
	n.authorize(method, u, token)
	require(n.requests < n.p.Limits["requests"], "limit")
	var reader io.Reader
	if body != nil {
		reader = &sentBody{body, n}
	}
	req, err := http.NewRequestWithContext(n.ctx, method, u.String(), reader)
	checked(err, "protocol")
	req.ContentLength = size
	req.Header.Set("Accept", manifestAccept)
	if media != "" {
		req.Header.Set("Content-Type", media)
	}
	if u.Path != "/v2/" {
		switch {
		case token || n.p.Auth.Kind == "password" && n.p.Auth.TokenService == nil:
			req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(append(append([]byte(n.p.Auth.Username), ':'), n.credential...)))
		case n.p.Auth.Kind == "bearer":
			req.Header.Set("Authorization", "Bearer "+string(n.credential))
		case n.token != "":
			require(time.Now().Before(n.expiry), "authentication")
			req.Header.Set("Authorization", "Bearer "+n.token)
		}
	}
	headerBytes := len(method) + len(u.RequestURI()) + len(u.Host) + 256
	for k, values := range req.Header {
		for _, v := range values {
			headerBytes += len(k) + len(v) + 4
		}
	}
	require(int64(headerBytes) <= n.p.Limits["http_header_bytes"], "limit")
	n.requests++
	if method != "GET" && method != "HEAD" {
		n.dispatch = "write"
		n.writePending = true
	} else if n.dispatch == "none" {
		n.dispatch = "read"
	}
	r, err := n.client.Do(req)
	if err != nil {
		if n.ctx.Err() != nil {
			panic(failure("timeout"))
		}
		var authority x509.UnknownAuthorityError
		var hostname x509.HostnameError
		var invalid x509.CertificateInvalidError
		if errors.As(err, &authority) || errors.As(err, &hostname) || errors.As(err, &invalid) {
			panic(failure("trust"))
		}
		checked(err, "protocol")
	}
	r.Body = &networkBody{r.Body, n}
	return r
}

var challengePart = regexp.MustCompile(`^([a-z_]+)="([^"\\]*)"`)

func (n *network) challenge(r *http.Response) {
	values := r.Header.Values("WWW-Authenticate")
	require(len(values) == 1 && strings.HasPrefix(values[0], "Bearer "), "authentication")
	rest := strings.TrimPrefix(values[0], "Bearer ")
	parts := map[string]string{}
	for rest != "" {
		m := challengePart.FindStringSubmatch(rest)
		require(m != nil, "policy")
		_, duplicate := parts[m[1]]
		require(!duplicate && (m[1] == "realm" || m[1] == "service" || m[1] == "scope"), "policy")
		parts[m[1]] = m[2]
		rest = strings.TrimSpace(rest[len(m[0]):])
		if rest != "" {
			require(strings.HasPrefix(rest, ","), "policy")
			rest = strings.TrimSpace(rest[1:])
			require(rest != "", "policy")
		}
	}
	t := n.p.Auth.TokenService
	require(t != nil && parts["realm"] == t.Realm && parts["service"] == t.Service, "policy")
	if scope, ok := parts["scope"]; ok {
		prefix := "repository:" + n.p.repo + ":"
		require(strings.HasPrefix(scope, prefix), "policy")
		seen := map[string]bool{}
		for _, action := range strings.Split(strings.TrimPrefix(scope, prefix), ",") {
			require(!seen[action] && (action == "pull" || action == "push" && n.p.writing()), "policy")
			seen[action] = true
		}
	}
}
func (n *network) exchange() {
	require(n.p.Auth.Kind == "password" && n.p.Auth.TokenService != nil && n.exchanges < n.p.Limits["token_exchanges"], "authentication")
	n.exchanges++
	t := n.p.Auth.TokenService
	u, err := url.Parse(t.Realm)
	checked(err, "policy")
	u.RawQuery = url.Values{"service": {t.Service}, "scope": {n.scope()}}.Encode()
	r := n.dispatchRequest("GET", u, nil, 0, "", true)
	defer r.Body.Close()
	require(r.StatusCode == 200, "authentication")
	data := readBounded(r.Body, n.p.Limits["token_response_bytes"])
	uniqueJSON(data, 16)
	var raw map[string]json.RawMessage
	decode(data, &raw)
	require(raw != nil, "authentication")
	for k, v := range raw {
		require(k == "token" || k == "access_token" || k == "issued_at" || k == "expires_in", "authentication")
		nonnull(v)
	}
	var result struct {
		Token   string `json:"token"`
		Access  string `json:"access_token"`
		Issued  string `json:"issued_at"`
		Expires int64  `json:"expires_in"`
	}
	decode(data, &result)
	if result.Token == "" {
		result.Token = result.Access
	} else if result.Access != "" {
		require(result.Token == result.Access, "authentication")
	}
	require(bearerRE.MatchString(result.Token), "authentication")
	seconds := int64(60)
	if _, ok := raw["expires_in"]; ok {
		seconds = result.Expires
	}
	require(seconds > 0 && seconds <= int64((1<<63-1)/int64(time.Second)), "authentication")
	issued := time.Now()
	if _, ok := raw["issued_at"]; ok {
		issued, err = time.Parse(time.RFC3339, result.Issued)
		require(err == nil && strings.HasSuffix(result.Issued, "Z"), "authentication")
	}
	expires := issued.Add(time.Duration(seconds) * time.Second)
	require(expires.After(time.Now()) && !issued.After(time.Now().Add(time.Second)), "authentication")
	n.token = result.Token
	n.expiry = expires
}
func (n *network) request(method, resource string, body io.Reader, size int64, media string) *http.Response {
	u, err := url.Parse(n.p.Endpoint + resource)
	checked(err, "policy")
	read := method == "GET" || method == "HEAD"
	if n.token != "" && !time.Now().Before(n.expiry) {
		n.exchange()
	}
	for redirects := int64(0); ; {
		r := n.dispatchRequest(method, u, body, size, media, false)
		if r.StatusCode == 401 {
			// A write is never replayed, even when the server appears to reject it.
			if !read {
				r.Body.Close()
				panic(failure("indeterminate"))
			}
			n.challenge(r)
			r.Body.Close()
			n.exchange()
			continue
		}
		if r.StatusCode >= 300 && r.StatusCode < 400 {
			r.Body.Close()
			require(read && (r.StatusCode == 307 || r.StatusCode == 308) && redirects < n.p.Limits["redirects"], "policy")
			location := singleHeader(r, "Location")
			next := resolveLocation(u, location)
			n.authorize(method, next, false)
			require(next.Path == u.Path && next.RawQuery == "" && !next.ForceQuery, "policy")
			redirects++
			u = next
			continue
		}
		return r
	}
}
func singleHeader(r *http.Response, key string) string {
	values := r.Header.Values(key)
	require(len(values) == 1 && values[0] != "", "protocol")
	return values[0]
}
func resolveLocation(base *url.URL, raw string) *url.URL {
	require(safeText(raw) && !strings.ContainsAny(raw, "\\#"), "policy")
	u, err := url.Parse(raw)
	checked(err, "policy")
	require(u.RawPath == "" && !strings.Contains(u.Path, "%") && (u.Path == "" || pathCanonical(u.Path)), "policy")
	return base.ResolveReference(u)
}
func pathCanonical(s string) bool {
	for _, p := range strings.Split(strings.Trim(s, "/"), "/") {
		if p == "." || p == ".." || p == "" {
			return false
		}
	}
	return true
}
func continuationQuery(raw string, complete bool) url.Values {
	require(len(raw) <= 8192, "limit")
	q, err := url.ParseQuery(raw)
	checked(err, "policy")
	for key, values := range q {
		require((key == "_state" || key == "digest" && complete) && len(values) == 1 && values[0] != "" && safeText(values[0]), "policy")
		if key == "_state" {
			require(len(values[0]) <= 4096, "limit")
		}
	}
	if complete {
		require(digestRE.MatchString(q.Get("digest")), "policy")
	}
	return q
}
func (n *network) uploadLocation(r *http.Response, previous string) string {
	u := resolveLocation(r.Request.URL, singleHeader(r, "Location"))
	prefix := n.resource("blobs", "uploads/")
	require(origin(u) == origin(n.p.origin) && u.User == nil && u.Fragment == "" && strings.HasPrefix(u.Path, prefix), "policy")
	require(sessionRE.MatchString(strings.TrimPrefix(u.Path, prefix)) && (previous == "" || u.Path == previous), "policy")
	continuationQuery(u.RawQuery, false)
	n.sessions[u.Path] = true
	return u.RequestURI()
}
func responseIdentity(r *http.Response, d descriptor) {
	if raw := r.Header.Get("Docker-Content-Digest"); raw != "" {
		require(singleHeader(r, "Docker-Content-Digest") == d.Digest, "integrity")
	}
	if raw := r.Header.Get("Content-Length"); raw != "" && (r.Request.Method == "GET" || r.Request.Method == "HEAD") {
		size, err := strconv.ParseInt(raw, 10, 64)
		require(err == nil && size == d.Size, "integrity")
	}
}
