// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

// The analyzer is a credential-free external consumer of private image metadata.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	"github.com/moby/buildkit/frontend/dockerfile/dockerfile2llb"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/moby/buildkit/frontend/dockerui"
	"github.com/moby/buildkit/frontend/gateway/client"
	gwpb "github.com/moby/buildkit/frontend/gateway/pb"
	"github.com/moby/buildkit/solver/pb"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const maxFrame = 16 << 20

var errInput = errors.New("invalid input")
var errMetadata = errors.New("metadata required")
var errUnsupported = errors.New("unsupported semantics")

type metadata struct {
	Reference string        `json:"reference"`
	Platform  string        `json:"platform"`
	Root      digest.Digest `json:"root"`
	Config    []byte        `json:"config"`
	Manifest  []byte        `json:"manifest"`
	Indexes   [][]byte      `json:"indexes"`
}

type request struct {
	identity
	AnalyzerIdentity string            `json:"analyzer_identity"`
	Dockerfile       string            `json:"dockerfile"`
	Path             string            `json:"path"`
	Stage            string            `json:"stage"`
	Args             map[string]string `json:"args"`
	BuildPlatform    string            `json:"build_platform"`
	Platform         string            `json:"platform"`
	Contexts         []string          `json:"contexts"`
	Frontend         string            `json:"frontend"`
	Metadata         []metadata        `json:"metadata"`
}

type source struct {
	Reference string        `json:"reference"`
	Platform  string        `json:"platform"`
	Root      digest.Digest `json:"root,omitempty"`
}

type operation struct {
	ID        string     `json:"id"`
	Kind      string     `json:"kind"`
	Source    *int       `json:"source"`
	Context   *string    `json:"context"`
	Inputs    []string   `json:"inputs"`
	Locations []location `json:"locations"`
}

type result struct {
	identity
	Status      string         `json:"status"`
	Sources     []publicSource `json:"sources"`
	Diagnostics []diagnostic   `json:"diagnostics"`
	Operations  []operation    `json:"operations"`
}

// Check duplicate members and nesting before decoding into owned schema types.
func unique(dec *json.Decoder, depth int) error {
	if depth > 128 {
		return errInput
	}
	token, err := dec.Token()
	if err != nil {
		return errInput
	}
	if delimiter, ok := token.(json.Delim); ok {
		switch delimiter {
		case '{':
			keys := map[string]bool{}
			for dec.More() {
				if len(keys) >= 4096 {
					return errInput
				}
				key, err := dec.Token()
				name, ok := key.(string)
				if err != nil || !ok || keys[name] {
					return errInput
				}
				keys[name] = true
				if err := unique(dec, depth+1); err != nil {
					return err
				}
			}
		case '[':
			count := 0
			for dec.More() {
				if count >= 8192 {
					return errInput
				}
				count++
				if err := unique(dec, depth+1); err != nil {
					return err
				}
			}
		default:
			return errInput
		}
		_, err = dec.Token()
	}
	return err
}

func normalized(value string) (string, error) {
	n, err := reference.ParseNormalizedNamed(value)
	if err != nil {
		return "", errInput
	}
	named, err := reference.WithName(strings.ToLower(reference.Domain(n)) + "/" + reference.Path(n))
	if err != nil {
		return "", errInput
	}
	if tagged, ok := n.(reference.Tagged); ok {
		named, err = reference.WithTag(named, tagged.Tag())
		if err != nil {
			return "", errInput
		}
	}
	if pinned, ok := n.(reference.Digested); ok {
		named, err = reference.WithDigest(named, pinned.Digest())
		if err != nil {
			return "", errInput
		}
	}
	return reference.TagNameOnly(named).String(), nil
}

type recorder struct {
	mu           sync.Mutex
	metadata     map[string]metadata
	sources      map[string]publicSource
	dockerfile   string
	inputs       map[string]llb.State
	opts         client.BuildOpts
	plan         *bindingPlan
	bindings     map[string]binding
	bindingBytes map[string]int
	privateBytes int
}

func (r *recorder) BuildOpts() client.BuildOpts                          { return r.opts }
func (r *recorder) Inputs(context.Context) (map[string]llb.State, error) { return r.inputs, nil }
func (r *recorder) Solve(context.Context, client.SolveRequest) (*client.Result, error) {
	return nil, errUnsupported
}
func (r *recorder) NewContainer(context.Context, client.NewContainerRequest) (client.Container, error) {
	return nil, errUnsupported
}
func (r *recorder) Warn(context.Context, digest.Digest, string, client.WarnOpts) error { return nil }
func (r *recorder) ResolveSourceMetadata(ctx context.Context, op *pb.SourceOp, opt sourceresolver.Opt) (*sourceresolver.MetaResponse, error) {
	ref, ok := strings.CutPrefix(op.Identifier, "docker-image://")
	if !ok {
		return nil, errUnsupported
	}
	_, root, cfg, err := r.ResolveImageConfig(ctx, ref, opt)
	if err != nil {
		return nil, err
	}
	return &sourceresolver.MetaResponse{Op: op, Image: &sourceresolver.ResolveImageResponse{Digest: root, Config: cfg}}, nil
}
func (r *recorder) ResolveImageConfig(_ context.Context, ref string, opt sourceresolver.Opt) (string, digest.Digest, []byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if opt.Platform == nil || opt.OCILayoutOpt != nil {
		return "", "", nil, errUnsupported
	}
	name, err := normalized(ref)
	if err != nil {
		return "", "", nil, err
	}
	platform := platforms.FormatAll(platforms.Normalize(*opt.Platform))
	operand, known := r.plan.aliases[name]
	if !known {
		return "", "", nil, errUnsupported
	}
	key := operand.reference + "::" + platform
	if _, exists := r.sources[key]; !exists && len(r.sources) >= 1024 {
		return "", "", nil, errUnsupported
	}
	observed := r.sources[key]
	observed.Reference, observed.Platform = operand.reference, platform
	for _, use := range operand.uses {
		projected, err := useProjection(use, r.dockerfile)
		if err != nil {
			return "", "", nil, err
		}
		encoded, _ := json.Marshal(projected)
		found := false
		for _, previous := range observed.Uses {
			old, _ := json.Marshal(previous)
			if bytes.Equal(old, encoded) {
				found = true
				break
			}
		}
		if !found {
			if len(observed.Uses) >= 1024 {
				return "", "", nil, errUnsupported
			}
			observed.Uses = append(observed.Uses, projected)
		}
	}
	r.sources[key] = observed
	m, ok := r.metadata[key]
	if !ok {
		return "", "", nil, errMetadata
	}
	observed.Root = &m.Root
	r.sources[key] = observed
	projected, err := r.plan.project(name, platform, m)
	if err != nil {
		return "", "", nil, err
	}
	encoded, err := json.Marshal(projected)
	bindingKey := name + "::" + platform
	if err != nil || len(encoded) > maxFrame || r.privateBytes-r.bindingBytes[bindingKey] > maxFrame-len(encoded) {
		return "", "", nil, errUnsupported
	}
	r.privateBytes += len(encoded) - r.bindingBytes[bindingKey]
	r.bindingBytes[bindingKey] = len(encoded)
	r.bindings[bindingKey] = projected
	observed.Root = &m.Root
	r.sources[key] = observed
	return name, projected.Root, projected.Config, nil
}

func analyze(ctx context.Context, req request) (result, []byte) {
	out := result{identity: req.identity, Status: "invalid", Sources: []publicSource{}, Operations: []operation{}, Diagnostics: []diagnostic{}}
	if req.Version != 2 || len(req.Dockerfile) == 0 || len(req.Dockerfile) > 1<<20 || req.Path == "" || strings.ContainsRune(req.Path, 0) || len(req.Path) > 4096 || len(req.Metadata) > 1024 || len(req.Contexts) > 256 || len(req.Args) > 256 || req.Args == nil || req.Metadata == nil || req.Contexts == nil {
		return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
	}
	frontend, frontendErr := reference.ParseNormalizedNamed(req.Frontend)
	frontendPin, pinned := frontend.(reference.Digested)
	if frontendErr != nil || !pinned || frontendPin.Digest() != "sha256:6ce6616ec35021075551c55e604374e8b47a66d157bc55ec2f2d2326450a9ae1" {
		return refuse(out, "unsupported", "unsupported-frontend", nil, req.Dockerfile)
	}
	platform, err := platforms.Parse(req.Platform)
	if err != nil || platforms.FormatAll(platforms.Normalize(platform)) != req.Platform {
		return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
	}
	buildPlatform, err := platforms.Parse(req.BuildPlatform)
	if err != nil || platforms.FormatAll(platforms.Normalize(buildPlatform)) != req.BuildPlatform {
		return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
	}
	parsed, err := parser.Parse(strings.NewReader(req.Dockerfile))
	if err != nil {
		return refuse(out, "invalid", "invalid-dockerfile", err, req.Dockerfile)
	}
	stages, argCommands, err := instructions.Parse(parsed.AST, nil)
	if err != nil {
		return refuse(out, "invalid", "invalid-instruction", err, req.Dockerfile)
	}
	if len(stages) > 256 {
		return refuse(out, "unsupported", "limit", nil, req.Dockerfile)
	}
	if req.Stage != "" {
		found := false
		for _, s := range stages {
			if strings.EqualFold(s.Name, req.Stage) {
				found = true
			}
		}
		if !found {
			return refuse(out, "invalid", "missing-stage", nil, req.Dockerfile)
		}
	}
	if frontend, _, locations, ok := parser.DetectSyntax([]byte(req.Dockerfile)); ok && frontend != req.Frontend {
		return refuse(out, "unsupported", "unsupported-frontend", atRanges(errUnsupported, locations, req.Dockerfile), req.Dockerfile)
	}
	r := &recorder{metadata: map[string]metadata{}, sources: map[string]publicSource{}, dockerfile: req.Dockerfile, inputs: map[string]llb.State{"context": llb.Local("context")}, bindings: map[string]binding{}, bindingBytes: map[string]int{}}
	r.opts = client.BuildOpts{Opts: map[string]string{"platform": req.Platform}, LLBCaps: pb.Caps.CapSet(pb.Caps.All()), Caps: gwpb.Caps.CapSet(gwpb.Caps.All()), Workers: []client.WorkerInfo{{Platforms: []ocispec.Platform{buildPlatform}}}}
	for _, name := range req.Contexts {
		n, err := reference.ParseNormalizedNamed(name)
		if err != nil {
			return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
		}
		key := strings.TrimSuffix(reference.FamiliarString(n), ":latest")
		if _, exists := r.opts.Opts["context:"+key]; exists || key == "context" || key == "scratch" {
			return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
		}
		r.opts.Opts["context:"+key] = "input:" + name
		r.inputs[name] = llb.Local(name)
	}
	for _, m := range req.Metadata {
		n, err := normalized(m.Reference)
		if n != m.Reference {
			return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
		}
		if err != nil || m.Root.Validate() != nil || m.Root.Algorithm() != digest.SHA256 || len(m.Config) == 0 || len(m.Config) > 1<<20 || len(m.Manifest) == 0 || len(m.Manifest) > 1<<20 || len(m.Indexes) > 32 {
			return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
		}
		for _, encoded := range append([][]byte{m.Config, m.Manifest}, m.Indexes...) {
			if len(encoded) == 0 || len(encoded) > 1<<20 {
				return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
			}
			if contentJSON(encoded) != nil {
				return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
			}
		}
		if err := metadataSchema(m); errors.Is(err, errUnsupported) {
			return refuse(out, "unsupported", "limit", nil, req.Dockerfile)
		} else if err != nil {
			return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
		}
		var manifest ocispec.Manifest
		if json.Unmarshal(m.Manifest, &manifest) != nil || manifest.Config.Digest != digest.FromBytes(m.Config) || manifest.Config.Size != int64(len(m.Config)) {
			return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
		}
		p, err := platforms.Parse(m.Platform)
		if err != nil || platforms.FormatAll(platforms.Normalize(p)) != m.Platform {
			return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
		}
		if validateSelection(m, p) != nil {
			return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
		}
		// Do not let a typed image decode allocate unbounded history slices before
		// the role projection checks their per-array limits.
		var config struct{ ocispec.Platform }
		if json.Unmarshal(m.Config, &config) != nil || config.OS != p.OS || config.Architecture != p.Architecture || config.Variant != p.Variant {
			return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
		}
		if named, err := reference.ParseNormalizedNamed(n); err != nil {
			return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
		} else if pinned, ok := named.(reference.Digested); ok && pinned.Digest() != m.Root {
			return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
		}
		key := n + "::" + m.Platform
		if _, exists := r.metadata[key]; exists {
			return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
		}
		m.Reference = n
		r.metadata[key] = m
	}
	resolution, err := resolutionID(req)
	if err != nil || resolution != req.Resolution {
		return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
	}
	plan, generated, err := prepareBindings(req, parsed, stages, argCommands, buildPlatform, platform)
	if err != nil {
		if errors.Is(err, errUnsupported) {
			return refuse(out, "unsupported", "unsupported-semantics", err, req.Dockerfile)
		}
		return refuse(out, "invalid", "unresolved-source", err, req.Dockerfile)
	}
	r.plan = plan
	dc, err := dockerui.NewClient(r)
	if err != nil {
		return refuse(out, "unsupported", "unsupported-semantics", nil, req.Dockerfile)
	}
	opt := dockerfile2llb.ConvertOpt{Client: dc, MetaResolver: r, TargetPlatform: &platform, SourceMap: llb.NewSourceMap(nil, req.Path, "Dockerfile", []byte(req.Dockerfile)), Config: dockerui.Config{BuildArgs: req.Args, Target: req.Stage, BuildPlatforms: []ocispec.Platform{buildPlatform}, TargetPlatforms: []ocispec.Platform{platform}}}
	state, config, _, _, err := dockerfile2llb.Dockerfile2LLB(ctx, []byte(generated), opt)
	for _, s := range r.sources {
		out.Sources = append(out.Sources, s)
	}
	sort.Slice(out.Sources, func(i, j int) bool {
		return out.Sources[i].Reference+out.Sources[i].Platform < out.Sources[j].Reference+out.Sources[j].Platform
	})
	if err != nil {
		if errors.Is(err, errMetadata) {
			out.Status = "metadata-required"
			return out, nil
		}
		if errors.Is(err, errUnsupported) {
			return refuse(out, "unsupported", "unsupported-semantics", err, req.Dockerfile)
		}
		return refuse(out, "invalid", "invalid-instruction", err, req.Dockerfile)
	}
	definition, err := state.Marshal(ctx, llb.Platform(platform))
	if err != nil || len(definition.Def) > 8192 {
		return refuse(out, "unsupported", "unsupported-semantics", nil, req.Dockerfile)
	}
	for _, data := range definition.Def {
		var op pb.Op
		if op.UnmarshalVT(data) != nil {
			return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
		}
		item := operation{ID: digest.FromBytes(data).String(), Kind: "result", Inputs: []string{}, Locations: []location{}}
		for _, input := range op.Inputs {
			item.Inputs = append(item.Inputs, input.Digest)
		}
		if sourceOp := op.GetSource(); sourceOp != nil {
			item.Kind = "source"
			if ref, ok := strings.CutPrefix(sourceOp.Identifier, "docker-image://"); ok {
				alias, resolved, _ := strings.Cut(ref, "@")
				operand, found := r.plan.aliases[alias]
				// A portable deferred operand may itself carry an original digest.
				// The converter's source now carries its independently derived root.
				if !found {
					for _, binding := range r.bindings {
						name, _, _ := strings.Cut(binding.Alias, "@")
						if name == alias && binding.Root.String() == resolved {
							candidate := r.plan.aliases[binding.Alias]
							if found && operand.reference != candidate.reference {
								return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
							}
							operand, found = candidate, true
						}
					}
				}
				if !found {
					return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
				}
				for i, source := range out.Sources {
					if source.Reference == operand.reference && source.Root != nil {
						// Source platform is an upstream operation attribute.
						p := op.Platform
						if p != nil && source.Platform != platforms.FormatAll(platforms.Normalize(ocispec.Platform{OS: p.OS, Architecture: p.Architecture, Variant: p.Variant})) {
							continue
						}
						if item.Source != nil {
							return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
						}
						index := i
						item.Source = &index
					}
				}
				if item.Source == nil {
					return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
				}
			} else if name, ok := strings.CutPrefix(sourceOp.Identifier, "local://"); ok {
				for _, context := range req.Contexts {
					if context == name {
						value := context
						item.Context = &value
					}
				}
			}
		}
		if op.GetFile() != nil {
			item.Kind = "file"
		}
		if op.GetExec() != nil {
			item.Kind = "exec"
		}
		if op.GetMerge() != nil {
			item.Kind = "merge"
		}
		if op.GetDiff() != nil {
			item.Kind = "diff"
		}
		if definition.Source != nil {
			if locations := definition.Source.Locations[item.ID]; locations != nil {
				for _, mapped := range locations.Locations {
					if mapped.SourceIndex != 0 {
						item.Locations = append(item.Locations, location{Kind: "unavailable"})
						continue
					}
					ranges := []parser.Range{}
					for _, r := range mapped.Ranges {
						ranges = append(ranges, parser.Range{Start: parser.Position{Line: int(r.Start.Line)}, End: parser.Position{Line: int(r.End.Line)}})
					}
					if original, err := originalRanges(ranges, req.Dockerfile); err == nil {
						item.Locations = append(item.Locations, location{Kind: "dockerfile", Ranges: original})
					} else {
						item.Locations = append(item.Locations, location{Kind: "unavailable"})
					}
				}
			}
		}
		out.Operations = append(out.Operations, item)
	}
	if len(config.History) > 4096 || len(config.Config.OnBuild) > 256 {
		return refuse(out, "unsupported", "limit", nil, req.Dockerfile)
	}
	image, err := json.Marshal(config)
	if err != nil || len(image) > 1<<20 {
		return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
	}
	private, err := json.Marshal(privateResult{identity: req.identity, Image: image, Dockerfile: generated, Bindings: privateBindings(r)})
	if err != nil || len(private) > maxFrame {
		return refuse(out, "invalid", "integrity", nil, req.Dockerfile)
	}
	out.Status = "complete"
	return out, private
}

func run() int {
	if len(os.Args) != 1 {
		return 1
	}
	// Parent supervision supplies the separate cleanup deadline and uncertainty.
	timer := time.AfterFunc(30*time.Second, func() { os.Exit(1) })
	defer timer.Stop()
	// Standard streams are not guaranteed to support Go's poller deadlines.
	// Stage watchdogs bound blocked reads/writes even when Set*Deadline fails.
	frameTimer := time.AfterFunc(10*time.Second, func() { os.Exit(1) })
	defer frameTimer.Stop()
	_ = os.Stdin.SetReadDeadline(time.Now().Add(10 * time.Second))
	var length uint32
	if binary.Read(os.Stdin, binary.BigEndian, &length) != nil || length == 0 || length > maxFrame-4 {
		return 1
	}
	input := make([]byte, length)
	if _, err := io.ReadFull(os.Stdin, input); err != nil || !utf8.Valid(input) {
		return 1
	}
	var trailing [1]byte
	if n, err := os.Stdin.Read(trailing[:]); n != 0 || err != io.EOF {
		return 1
	}
	frameTimer.Stop()
	analysisTimer := time.AfterFunc(20*time.Second, func() { os.Exit(1) })
	defer analysisTimer.Stop()
	req, err := decodeRequest(input)
	if err != nil {
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	response, private := analyze(ctx, req)
	public, err := json.Marshal(response)
	if err != nil || len(public)+len(private)+8 > maxFrame {
		return 1
	}
	analysisTimer.Stop()
	writeTimer := time.AfterFunc(5*time.Second, func() { os.Exit(1) })
	defer writeTimer.Stop()
	_ = os.Stdout.SetWriteDeadline(time.Now().Add(5 * time.Second))
	for _, frame := range [][]byte{public, private} {
		if binary.Write(os.Stdout, binary.BigEndian, uint32(len(frame))) != nil {
			return 1
		}
		if _, err := os.Stdout.Write(frame); err != nil {
			return 1
		}
	}
	return 0
}

func main() { os.Exit(run()) }
