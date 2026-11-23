// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

var launched = time.Now()

type result struct {
	Version             int         `json:"protocol_version"`
	ID                  *string     `json:"operation_id"`
	Status              string      `json:"status"`
	Failure             string      `json:"failure_class"`
	Dispatch            string      `json:"dispatch"`
	CompletionUncertain bool        `json:"completion_uncertain"`
	CleanupUncertain    bool        `json:"cleanup_uncertain"`
	Root                *descriptor `json:"root"`
	Complete            bool        `json:"closure_complete"`
	Count               int64       `json:"verified_descriptors"`
	Bytes               int64       `json:"verified_bytes"`
	Peak                int64       `json:"peak_staging_bytes"`
}
type boundedPipe struct{ frame, idle time.Duration }

func (p *boundedPipe) Read(b []byte) (int, error) {
	deadline := launched.Add(p.frame)
	if idle := time.Now().Add(p.idle); idle.Before(deadline) {
		deadline = idle
	}
	// Stdin must be a pollable private pipe; unsupported deadline semantics fail.
	if err := os.Stdin.SetReadDeadline(deadline); err != nil {
		return 0, failure("protocol")
	}
	return os.Stdin.Read(b)
}
func run() (exit int) {
	exit = 1
	r := result{Version: 1, Status: "failed", Failure: "protocol", Dispatch: "none"}
	var p *policy
	var n *network
	var s *staging
	var g *graph
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The parent also supervises and bounds termination: an uninterruptible OS
	// operation can defeat process-local cleanup, never establish known success.
	watchdog := time.AfterFunc(time.Duration(maxima["frame_ms"]+maxima["cleanup_ms"])*time.Millisecond, func() { os.Exit(124) })
	var cleanupMillis atomic.Int64
	cleanupMillis.Store(maxima["cleanup_ms"])
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			watchdog.Reset(time.Duration(cleanupMillis.Load()) * time.Millisecond)
			os.Stdin.SetReadDeadline(time.Now())
		case <-finished:
		}
	}()
	defer watchdog.Stop()
	defer func() {
		grace := time.Duration(maxima["cleanup_ms"]) * time.Millisecond
		if p != nil {
			grace = p.duration("cleanup_ms")
		}
		watchdog.Reset(grace)
		if recovered := recover(); recovered != nil {
			if class, ok := recovered.(failure); ok {
				r.Failure = string(class)
			}
			r.Status = "failed"
			r.Root = nil
			r.Complete = false
		}
		if p != nil {
			r.ID = &p.ID
		}
		if n != nil {
			r.Dispatch = n.dispatch
		}
		if ctx.Err() != nil {
			r.Status = "cancelled"
			r.Failure = "cancellation"
			r.Root = nil
			r.Complete = false
		}
		if n != nil && n.writePending {
			r.Status = "unknown"
			r.Failure = "indeterminate"
			r.CompletionUncertain = true
			r.Root = nil
			r.Complete = false
		}
		if s != nil {
			r.Peak = s.peak
			if r.Status != "succeeded" || p.writing() {
				r.CleanupUncertain = s.cleanup()
			} else {
				s.close()
			}
		}
		if g != nil && g.source != nil {
			g.source.Close()
		}
		if r.CleanupUncertain && (r.Status == "succeeded" || r.Failure == "cache-miss") {
			r.Status = "failed"
			r.Failure = "storage"
			r.Root = nil
			r.Complete = false
		}
		data, err := json.Marshal(r)
		if err != nil {
			return
		}
		limit := maxima["result_bytes"]
		idle := time.Second
		if p != nil {
			limit = p.Limits["result_bytes"]
			idle = p.duration("idle_ms")
		}
		if int64(len(data)) > limit {
			return
		}
		if os.Stdout.SetWriteDeadline(time.Now().Add(idle)) != nil {
			return
		}
		if binary.Write(os.Stdout, binary.BigEndian, uint32(len(data))) != nil {
			return
		}
		if _, err = os.Stdout.Write(data); err == nil && r.Status == "succeeded" {
			exit = 0
		}
	}()
	require(len(os.Args) == 1, "protocol")
	pipe := &boundedPipe{time.Duration(maxima["frame_ms"]) * time.Millisecond, time.Duration(maxima["idle_ms"]) * time.Millisecond}
	var credential []byte
	p, credential = readFrame(pipe, func(value *policy) { p = value; cleanupMillis.Store(p.Limits["cleanup_ms"]) })
	cleanupMillis.Store(p.Limits["cleanup_ms"])
	deadline := launched.Add(p.duration("operation_ms"))
	require(time.Now().Before(deadline), "timeout")
	watchdog.Reset(time.Until(deadline) + p.duration("cleanup_ms"))
	operation, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	n = newNetwork(operation, p, credential)
	s = newStaging(p)
	s.create()
	g = &graph{p: p, n: n, stage: s, nodes: map[string]*node{}}
	root := g.root()
	g.visit(root, 1, nil)
	g.finish(root)
	require(operation.Err() == nil, "timeout")
	r.Status = "succeeded"
	r.Failure = "none"
	r.Root = &root
	r.Complete = p.Action != "inspect"
	r.Count = g.verifiedCount
	r.Bytes = g.verifiedBytes
	return
}
func privatePipe(file *os.File) (*os.File, error) {
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return nil, failure("protocol")
	}
	fd, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(fd)
	if err = syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "private-pipe"), nil
}

func main() {
	os.Clearenv()
	input, err := privatePipe(os.Stdin)
	if err != nil {
		os.Exit(1)
	}
	output, err := privatePipe(os.Stdout)
	if err != nil {
		os.Exit(1)
	}
	os.Stdin, os.Stdout = input, output
	os.Exit(run())
}
