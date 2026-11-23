// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/containerd/platforms"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
)

// Deferred operands keep their authored bytes, so their resolver alias can be
// shared by several original uses. Filter those uses with the already parsed
// local-stage model. The upstream conversion still requests actual sources and
// owns all instruction semantics; this is not a completed producer graph.
func inheritedLocalStages(req request, stages []instructions.Stage, env shell.EnvGetter, escape rune, contexts map[string]bool) (map[int]bool, error) {
	if len(stages) == 0 || len(stages) > 256 {
		return nil, errInput
	}
	lex := shell.NewLex(escape)
	names, previous := map[string]int{}, map[string]int{}
	bases, baseNames, stagePlatforms := make([]int, len(stages)), make([]string, len(stages)), make([]string, len(stages))
	for i, stage := range stages {
		bases[i] = -1
		base, err := lex.ProcessWordWithMatches(stage.BaseName, env)
		if err != nil {
			return nil, atRanges(errInput, stage.Location, req.Dockerfile)
		}
		baseNames[i] = base.Result
		if parent, ok := previous[strings.ToLower(base.Result)]; ok {
			bases[i] = parent
		}
		stagePlatforms[i] = req.Platform
		if stage.Platform != "" {
			value, err := lex.ProcessWordWithMatches(stage.Platform, env)
			if err != nil {
				return nil, atRanges(errInput, stage.Location, req.Dockerfile)
			}
			platform, err := platforms.Parse(value.Result)
			if err != nil {
				return nil, atRanges(errInput, stage.Location, req.Dockerfile)
			}
			stagePlatforms[i] = platforms.FormatAll(platforms.Normalize(platform))
		}
		if stage.Name != "" {
			names[strings.ToLower(stage.Name)], previous[strings.ToLower(stage.Name)] = i, i
		}
	}
	target := len(stages) - 1
	if req.Stage != "" {
		var ok bool
		target, ok = names[strings.ToLower(req.Stage)]
		if !ok {
			return nil, errInput
		}
	}
	live, visited := map[int]bool{}, map[int]bool{}
	var visit func(int) error
	var command func(instructions.Command) error
	edges := 0
	dependency := func(name string, numeric bool) error {
		if name == "" {
			return nil
		}
		if numeric {
			if number, err := strconv.Atoi(name); err == nil {
				if number < 0 || number >= len(stages) {
					return errInput
				}
				return visit(number)
			}
		}
		if number, ok := names[strings.ToLower(name)]; ok {
			return visit(number)
		}
		return nil
	}
	command = func(cmd instructions.Command) error {
		edges++
		if edges > 65536 {
			return errUnsupported
		}
		switch cmd := cmd.(type) {
		case *instructions.CopyCommand:
			return dependency(cmd.From, true)
		case *instructions.RunCommand:
			for _, mount := range instructions.GetMounts(cmd) {
				if err := dependency(mount.From, false); err != nil {
					return err
				}
			}
		}
		return nil
	}
	trigger := func(text string) error {
		parsed, err := parser.Parse(strings.NewReader(text))
		if err != nil || len(parsed.AST.Children) != 1 {
			return nil // The conversion reports the original trigger diagnostic.
		}
		cmd, err := instructions.ParseInstruction(parsed.AST.Children[0])
		if err != nil {
			return nil
		}
		if cmd, ok := cmd.(instructions.Command); ok {
			return command(cmd)
		}
		return nil
	}
	visit = func(index int) error {
		if visited[index] {
			return nil
		}
		visited[index] = true
		stage := stages[index]
		if stage.Name != "" && contexts[contextName(stage.Name)] {
			return nil
		}
		for _, cmd := range stage.Commands {
			if err := command(cmd); err != nil {
				return err
			}
		}
		if parent := bases[index]; parent >= 0 {
			if err := visit(parent); err != nil {
				return err
			}
			if !contexts[contextName(stages[parent].Name)] {
				live[parent] = true
				for _, cmd := range stages[parent].Commands {
					if onbuild, ok := cmd.(*instructions.OnbuildCommand); ok {
						if err := trigger(onbuild.Expression); err != nil {
							return err
						}
					}
				}
			}
		} else if !contexts[contextName(baseNames[index])] && baseNames[index] != "scratch" {
			name, err := normalized(baseNames[index])
			if err != nil {
				return err
			}
			for _, m := range req.Metadata {
				if m.Reference == name && m.Platform == stagePlatforms[index] {
					var image struct {
						Config struct {
							OnBuild []string `json:"OnBuild"`
						} `json:"config"`
					}
					if json.Unmarshal(m.Config, &image) != nil {
						return errInput
					}
					for _, text := range image.Config.OnBuild {
						if err := trigger(text); err != nil {
							return err
						}
					}
				}
			}
		}
		return nil
	}
	if err := visit(target); err != nil {
		return nil, err
	}
	return live, nil
}
