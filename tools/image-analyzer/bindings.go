// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type sourceUse struct {
	Reference      string         `json:"reference"`
	Role           string         `json:"role"`
	Instruction    string         `json:"instruction"`
	TagOrigin      string         `json:"tag_origin"`
	Stage          int            `json:"-"`
	Locations      []parser.Range `json:"locations"`
	Parent         string         `json:"parent,omitempty"`
	Trigger        *int           `json:"trigger,omitempty"`
	ParentRoot     digest.Digest  `json:"parent_root,omitempty"`
	ParentPlatform string         `json:"parent_platform,omitempty"`
	ConsumingFrom  []parser.Range `json:"consuming_from,omitempty"`
}

type binding struct {
	Alias    string             `json:"alias"`
	Context  string             `json:"context"`
	Source   source             `json:"source"`
	Role     string             `json:"role"`
	Root     digest.Digest      `json:"root"`
	Config   []byte             `json:"config"`
	Manifest []byte             `json:"manifest"`
	Uses     []publicUse        `json:"uses"`
	History  *historyCompletion `json:"history_completion"`
}

type privateResult struct {
	identity
	Image      json.RawMessage `json:"image"`
	Dockerfile string          `json:"dockerfile"`
	Bindings   []binding       `json:"bindings"`
}

type operandBinding struct {
	reference string
	role      string
	uses      []sourceUse
	portable  bool
}

type bindingPlan struct {
	aliases    map[string]*operandBinding
	stages     map[string]bool
	contexts   map[string]bool
	reserved   map[string]bool
	escape     rune
	dockerfile string
	stage      int
}

// The upstream parser selects operands. This scanner only finds their byte spans
// in the original instruction; it never infers dependencies or instruction kinds.
type wordSpan struct {
	start, end int
	value      string
}

func prefixWords(text string, count int, escape rune) ([]wordSpan, error) {
	words := []wordSpan{}
	i := 0
	for len(words) < count {
		for i < len(text) {
			if strings.ContainsRune(" \t\r\n", rune(text[i])) {
				i++
				continue
			}
			if rune(text[i]) == escape && i+1 < len(text) && (text[i+1] == '\n' || text[i+1] == '\r') {
				i += 2
				continue
			}
			if text[i] == '#' {
				for i < len(text) && text[i] != '\n' {
					i++
				}
				continue
			}
			break
		}
		if i == len(text) {
			return nil, errUnsupported
		}
		w := wordSpan{start: i}
		var value strings.Builder
		quote := byte(0)
		for i < len(text) {
			c := text[i]
			if quote == 0 && strings.ContainsRune(" \t\r\n", rune(c)) {
				break
			}
			i++
			if rune(c) == escape && i < len(text) {
				c = text[i]
				i++
				if c == '\r' && i < len(text) && text[i] == '\n' {
					i++
				}
				if c == '\n' || c == '\r' {
					continue
				}
			} else if c == quote {
				quote = 0
				continue
			} else if quote == 0 && (c == '\'' || c == '"') {
				quote = c
				continue
			}
			value.WriteByte(c)
		}
		if quote != 0 {
			return nil, errUnsupported
		}
		w.end, w.value = i, value.String()
		words = append(words, w)
	}
	return words, nil
}

func contextName(name string) string {
	if n, err := reference.ParseNormalizedNamed(name); err == nil {
		return strings.TrimSuffix(reference.FamiliarString(n), ":latest")
	}
	return name
}

func (p *bindingPlan) add(name, role string, use sourceUse, portable bool) (string, error) {
	ref, err := normalized(name)
	if err != nil {
		return "", err
	}
	use.Reference = ref
	use.TagOrigin = tagOrigin(name)
	alias := ref
	if !portable {
		for nonce := 0; ; nonce++ {
			origin, _ := json.Marshal(use)
			alias = "broil-bind.invalid/s" + digest.FromString(fmt.Sprintf("%s\x00%s\x00%s\x00%d", role, ref, origin, nonce)).Encoded() + ":latest"
			if !p.reserved[alias] {
				break
			}
			if nonce >= 1024 {
				return "", errUnsupported
			}
		}
	}
	if existing, ok := p.aliases[alias]; ok {
		if existing.reference != ref || existing.role != role {
			return "", errUnsupported
		}
		if len(existing.uses) >= 1024 {
			return "", errUnsupported
		}
		encoded, _ := json.Marshal(use)
		for _, previous := range existing.uses {
			other, _ := json.Marshal(previous)
			if bytes.Equal(encoded, other) {
				return alias, nil
			}
		}
		existing.uses = append(existing.uses, use)
	} else {
		if len(p.aliases) >= 1024 {
			return "", errUnsupported
		}
		p.aliases[alias] = &operandBinding{reference: ref, role: role, uses: []sourceUse{use}, portable: portable}
	}
	return alias, nil
}

func (p *bindingPlan) fileOperand(name string, numeric bool) bool {
	if name == "" || name == "scratch" || p.stages[strings.ToLower(name)] || p.contexts[contextName(name)] {
		return false
	}
	if numeric {
		if _, err := strconv.Atoi(name); err == nil {
			return false
		}
	}
	return true
}

// Only flags identified by an upstream parsed COPY/RUN command are candidates.
// Deferred ONBUILD stays byte-identical; its file role is registered for a later
// actual upstream resolver call, which establishes whether it is inherited.
func (p *bindingPlan) rewriteCommand(node *parser.Node, raw string, portable bool, inherited *sourceUse) (string, error) {
	command, err := instructions.ParseInstruction(node)
	if err != nil {
		return "", errInput
	}
	if _, ok := command.(instructions.Command); !ok {
		return "", errInput
	}
	if onbuild, ok := command.(*instructions.OnbuildCommand); ok {
		parsed, err := parser.Parse(strings.NewReader(onbuild.Expression))
		if err != nil || len(parsed.AST.Children) != 1 {
			return "", errInput
		}
		// Authored deferred operands belong to the authored ONBUILD range, not
		// line one of the separately parsed expression.
		parsed.AST.Children[0].StartLine, parsed.AST.Children[0].EndLine = node.StartLine, node.EndLine
		_, err = p.rewriteCommand(parsed.AST.Children[0], onbuild.Expression, true, inherited)
		return raw, err
	}
	copyCmd, isCopy := command.(*instructions.CopyCommand)
	runCmd, isRun := command.(*instructions.RunCommand)
	if !isCopy && !isRun {
		return raw, nil
	}
	words, err := prefixWords(raw, 1+len(node.Flags), p.escape)
	if err != nil {
		return "", err
	}
	for i, flag := range node.Flags {
		if words[i+1].value != flag {
			return "", errUnsupported
		}
	}
	type edit struct {
		start, end int
		value      string
	}
	edits := []edit{}
	for i, flag := range node.Flags {
		name, replacement := "", ""
		if isCopy && strings.HasPrefix(flag, "--from=") && p.fileOperand(copyCmd.From, true) {
			name = copyCmd.From
		} else if isRun && strings.HasPrefix(flag, "--mount=") {
			// The upstream mount parser has already rejected unsupported expansion.
			// Preserve all other bytes; a unique literal component must identify From.
			for _, mount := range instructions.GetMounts(runCmd) {
				if p.fileOperand(mount.From, false) && strings.Contains(","+strings.TrimPrefix(flag, "--mount=")+",", ",from="+mount.From+",") {
					if name != "" && name != mount.From {
						return "", errUnsupported
					}
					name = mount.From
				}
			}
		}
		if name == "" {
			continue
		}
		use := sourceUse{Reference: name, Role: "file-source", Locations: node.Location(), Stage: p.stage}
		instruction := "copy"
		if isRun {
			instruction = "run-mount"
		}
		if inherited != nil {
			use = *inherited
			use.Reference, use.Role = name, "file-source"
			// Original external trigger source lines are unavailable. The exact
			// parent/trigger and original consuming FROM ranges are separate facts.
			use.Locations = nil
		}
		use.Instruction = instruction
		alias, err := p.add(name, "file-source", use, portable)
		if err != nil {
			return "", err
		}
		if portable {
			continue
		}
		if isCopy {
			replacement = "--from=" + alias
		} else {
			needle := "from=" + name
			if strings.Count(flag, needle) != 1 {
				return "", errUnsupported
			}
			replacement = strings.Replace(flag, needle, "from="+alias, 1)
		}
		// Unquoted replacement flags are safe only when the remaining parsed bytes
		// need no quoting. Complex flags remain unsupported until a proved mapping.
		if strings.ContainsAny(replacement, " \t\r\n\"'\\`") {
			return "", errUnsupported
		}
		edits = append(edits, edit{words[i+1].start, words[i+1].end, replacement})
	}
	for i := len(edits) - 1; i >= 0; i-- {
		e := edits[i]
		raw = raw[:e.start] + e.value + raw[e.end:]
	}
	return raw, nil
}

func prepareBindings(req request, parsed *parser.Result, stages []instructions.Stage, args []instructions.ArgCommand, build, target ocispec.Platform) (*bindingPlan, string, error) {
	p := &bindingPlan{aliases: map[string]*operandBinding{}, stages: map[string]bool{}, contexts: map[string]bool{}, reserved: map[string]bool{}, escape: parsed.EscapeToken, dockerfile: req.Dockerfile}
	for _, s := range stages {
		if s.Name != "" {
			p.stages[strings.ToLower(s.Name)] = true
		}
	}
	for _, name := range req.Contexts {
		p.contexts[contextName(name)] = true
		if n, err := normalized(name); err == nil {
			p.reserved[n] = true
		}
	}
	for _, m := range req.Metadata {
		if n, err := normalized(m.Reference); err == nil {
			p.reserved[n] = true
		}
	}
	// Include every authored token and metadata trigger in collision prevention.
	for _, text := range append([]string{req.Dockerfile}, metadataTexts(req.Metadata)...) {
		for _, word := range strings.FieldsFunc(text, func(c rune) bool { return strings.ContainsRune(" \t\r\n=,\"'", c) }) {
			if n, err := normalized(word); err == nil {
				p.reserved[n] = true
			}
		}
	}
	stageName := req.Stage
	if stageName == "" && len(stages) > 0 {
		stageName = stages[len(stages)-1].Name
	}
	if stageName == "" {
		stageName = "default"
	}
	defaults := map[string]string{"BUILDPLATFORM": platforms.Format(build), "BUILDOS": build.OS, "BUILDOSVERSION": build.OSVersion, "BUILDARCH": build.Architecture, "BUILDVARIANT": build.Variant, "TARGETPLATFORM": platforms.FormatAll(target), "TARGETOS": target.OS, "TARGETOSVERSION": target.OSVersion, "TARGETARCH": target.Architecture, "TARGETVARIANT": target.Variant, "TARGETSTAGE": stageName}
	env := &llb.EnvList{}
	for key, value := range defaults {
		if v, ok := req.Args[key]; ok {
			value = v
		}
		env = env.AddOrReplace(key, value)
	}
	lex := shell.NewLex(parsed.EscapeToken)
	for _, arg := range args {
		for _, pair := range arg.Args {
			if value, ok := req.Args[pair.Key]; ok {
				env = env.AddOrReplace(pair.Key, value)
			} else if pair.Value != nil {
				value, err := lex.ProcessWordWithMatches(*pair.Value, env)
				if err != nil {
					return nil, "", errInput
				}
				env = env.AddOrReplace(pair.Key, value.Result)
			}
		}
	}
	lines := strings.SplitAfter(req.Dockerfile, "\n")
	live, err := inheritedLocalStages(req, stages, env, p.escape, p.contexts)
	if err != nil {
		return nil, "", err
	}
	previous := map[string]bool{}
	stageIndex := 0
	for _, node := range parsed.AST.Children {
		start, end := node.StartLine-1, node.EndLine
		if start < 0 || end > len(lines) {
			return nil, "", atRanges(errInput, node.Location(), req.Dockerfile)
		}
		raw := strings.Join(lines[start:end], "")
		if strings.EqualFold(node.Value, "from") {
			st := stages[stageIndex]
			p.stage = stageIndex
			stageIndex++
			value, err := lex.ProcessWordWithMatches(st.BaseName, env)
			if err != nil {
				return nil, "", atRanges(errInput, node.Location(), req.Dockerfile)
			}
			name := value.Result
			if name != "scratch" && !previous[strings.ToLower(name)] && !p.contexts[contextName(name)] {
				words, err := prefixWords(raw, 2+len(node.Flags), p.escape)
				if err != nil {
					return nil, "", atRanges(err, node.Location(), req.Dockerfile)
				}
				operand := words[len(words)-1]
				if operand.value != st.BaseName {
					return nil, "", atRanges(errUnsupported, node.Location(), req.Dockerfile)
				}
				alias, err := p.add(name, "inheritance", sourceUse{Reference: name, Role: "inheritance", Instruction: "from", Locations: node.Location()}, false)
				if err != nil {
					return nil, "", atRanges(err, node.Location(), req.Dockerfile)
				}
				raw = raw[:operand.start] + alias + raw[operand.end:]
			}
			if st.Name != "" {
				previous[strings.ToLower(st.Name)] = true
			}
		} else if !strings.EqualFold(node.Value, "arg") {
			var err error
			raw, err = p.rewriteCommand(node, raw, false, nil)
			if err != nil {
				return nil, "", atRanges(err, node.Location(), req.Dockerfile)
			}
		}
		// Keep each instruction's original line count, including continuation and
		// heredoc bodies, so upstream ranges still identify original source lines.
		if strings.Count(raw, "\n") != strings.Count(strings.Join(lines[start:end], ""), "\n") {
			return nil, "", atRanges(errUnsupported, node.Location(), req.Dockerfile)
		}
		lines[start] = raw
		for i := start + 1; i < end; i++ {
			lines[i] = ""
		}
	}
	generated := strings.Join(lines, "")
	for alias, operand := range p.aliases {
		if operand.portable {
			uses := []sourceUse{}
			for _, use := range operand.uses {
				if live[use.Stage] {
					uses = append(uses, use)
				}
			}
			operand.uses = uses
			if len(uses) == 0 {
				delete(p.aliases, alias)
			}
		}
	}
	if len(generated) > 2<<20 {
		return nil, "", errUnsupported
	}
	if _, err := parser.Parse(strings.NewReader(generated)); err != nil {
		return nil, "", errInput
	}
	return p, generated, nil
}

func metadataTexts(items []metadata) []string {
	texts := make([]string, 0, len(items))
	for _, m := range items {
		texts = append(texts, string(m.Config))
	}
	return texts
}

func (p *bindingPlan) project(alias, platform string, m metadata) (binding, error) {
	b := binding{Alias: alias, Context: contextName(alias) + "::" + platform, Source: source{Reference: m.Reference, Platform: platform, Root: m.Root}, Root: digest.FromBytes(m.Manifest), Config: m.Config, Manifest: m.Manifest}
	operand, ok := p.aliases[alias]
	if !ok {
		return b, errUnsupported
	}
	b.Role = operand.role
	b.Uses = []publicUse{}
	for _, use := range operand.uses {
		projected, err := useProjection(use, p.dockerfile)
		if err != nil {
			return b, err
		}
		b.Uses = append(b.Uses, projected)
	}
	var image map[string]json.RawMessage
	var config map[string]json.RawMessage
	if json.Unmarshal(m.Config, &image) != nil {
		return b, errInput
	}
	if raw, ok := image["config"]; ok && json.Unmarshal(raw, &config) != nil {
		return b, errInput
	}
	var triggers []string
	if raw, ok := config["OnBuild"]; ok && json.Unmarshal(raw, &triggers) != nil {
		return b, errInput
	}
	if len(triggers) > 256 {
		return b, errUnsupported
	}
	changed := false
	if b.Role == "file-source" {
		if len(triggers) > 0 {
			config["OnBuild"] = json.RawMessage("[]")
			changed = true
		}
	} else {
		for i, text := range triggers {
			index := i
			origin := sourceUse{Parent: m.Reference, ParentRoot: m.Root, ParentPlatform: platform, Trigger: &index}
			for _, use := range operand.uses {
				origin.ConsumingFrom = append(origin.ConsumingFrom, use.Locations...)
			}
			parsed, err := parser.Parse(strings.NewReader(text))
			if err != nil || len(parsed.AST.Children) != 1 {
				return b, atUse(errInput, origin, p.dockerfile)
			}
			rewritten, err := p.rewriteCommand(parsed.AST.Children[0], text, false, &origin)
			if err != nil {
				return b, atUse(err, origin, p.dockerfile)
			}
			if rewritten != text {
				changed = true
				triggers[i] = rewritten
			}
		}
		if changed {
			config["OnBuild"], _ = json.Marshal(triggers)
		}
	}
	if changed {
		image["config"], _ = json.Marshal(config)
	}
	history, historyChanged, err := completeHistory(image, m.Manifest, b.Role == "inheritance")
	if err != nil {
		return b, err
	}
	if b.Role == "inheritance" {
		b.History = history
	}
	changed = changed || historyChanged
	if !changed {
		return b, nil
	}
	b.Config, _ = json.Marshal(image)
	if len(b.Config) > 1<<20 {
		return b, errUnsupported
	}
	var manifest map[string]json.RawMessage
	var descriptor map[string]json.RawMessage
	if json.Unmarshal(m.Manifest, &manifest) != nil || json.Unmarshal(manifest["config"], &descriptor) != nil {
		return b, errInput
	}
	descriptor["digest"], _ = json.Marshal(digest.FromBytes(b.Config))
	descriptor["size"], _ = json.Marshal(len(b.Config))
	manifest["config"], _ = json.Marshal(descriptor)
	b.Manifest, _ = json.Marshal(manifest)
	b.Root = digest.FromBytes(b.Manifest)
	if len(b.Manifest) > 1<<20 || bytes.Equal(b.Config, m.Config) {
		return b, errInput
	}
	return b, nil
}

func privateBindings(r *recorder) []binding {
	keys := make([]string, 0, len(r.bindings))
	for key := range r.bindings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	items := make([]binding, 0, len(keys))
	for _, key := range keys {
		items = append(items, r.bindings[key])
	}
	return items
}
