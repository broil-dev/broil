// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"syscall"
)

// Open every component relative to the previous pinned directory descriptor.
// NONBLOCK prevents a hostile FIFO from blocking before its type is checked.
func openAt(parent *os.File, name string, flags int) *os.File {
	require(name != "" && name != "." && name != ".." && !strings.Contains(name, "/"), "storage")
	fd, err := syscall.Openat(int(parent.Fd()), name, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0600)
	checked(err, "storage")
	return os.NewFile(uintptr(fd), name)
}
func openPath(name string, directory bool, private bool) *os.File {
	require(absolute(name), "storage")
	f, err := os.Open("/")
	checked(err, "storage")
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	parts := strings.Split(strings.TrimPrefix(name, "/"), "/")
	for i, part := range parts {
		flags := syscall.O_RDONLY
		if i < len(parts)-1 || directory {
			flags |= syscall.O_DIRECTORY
		}
		next := openAt(f, part, flags)
		f.Close()
		f = next
	}
	checkFile(f, directory, private)
	result := f
	f = nil
	return result
}
func checkFile(f *os.File, directory, private bool) os.FileInfo {
	s, err := f.Stat()
	checked(err, "storage")
	require(s.IsDir() == directory && (directory || s.Mode().IsRegular()), "storage")
	if private {
		st, ok := s.Sys().(*syscall.Stat_t)
		require(ok && st.Uid == uint32(os.Geteuid()), "storage")
		permission := os.FileMode(0600)
		if directory {
			permission = 0700
		}
		require(s.Mode().Perm() == permission, "storage")
		if !directory {
			require(st.Nlink == 1, "storage")
		}
	}
	return s
}

type createdFile struct {
	parent    *os.File
	name      string
	identity  os.FileInfo
	directory bool
}
type staging struct {
	root, blobs *os.File
	opened      []*os.File
	created     []createdFile
	p           *policy
	live, peak  int64
}

func newStaging(p *policy) *staging {
	s := &staging{p: p}
	return s
}
func (s *staging) directory(parent *os.File, name string) *os.File {
	checked(syscall.Mkdirat(int(parent.Fd()), name, 0700), "storage")
	f := openAt(parent, name, syscall.O_RDONLY|syscall.O_DIRECTORY)
	info := checkFile(f, true, true)
	s.opened = append(s.opened, f)
	s.created = append(s.created, createdFile{parent, name, info, true})
	return f
}
func (s *staging) create() {
	parent := openPath(path.Dir(s.p.Staging), true, true)
	s.opened = append(s.opened, parent)
	s.root = s.directory(parent, path.Base(s.p.Staging))
	blobs := s.directory(s.root, "blobs")
	s.blobs = s.directory(blobs, "sha256")
}
func (s *staging) file(parent *os.File, name string) *os.File {
	f := openAt(parent, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL)
	s.created = append(s.created, createdFile{parent, name, checkFile(f, false, true), false})
	return f
}
func (s *staging) account(n int) {
	require(int64(n) <= s.p.Limits["staging_bytes"]-s.live, "limit")
	s.live += int64(n)
	if s.live > s.peak {
		s.peak = s.live
	}
}
func (s *staging) put(name string, data []byte) {
	f := s.file(s.root, name)
	defer f.Close()
	s.account(len(data))
	_, err := f.Write(data)
	checked(err, "storage")
	checked(f.Sync(), "storage")
}

func (s *staging) complete(data []byte) {
	s.put("verified.json.tmp", data)
	entry := s.created[len(s.created)-1]
	source := fmt.Sprintf("/proc/self/fd/%d/verified.json.tmp", s.root.Fd())
	destination := fmt.Sprintf("/proc/self/fd/%d/verified.json", s.root.Fd())
	info, err := os.Lstat(source)
	checked(err, "storage")
	require(os.SameFile(info, entry.identity), "storage")
	checked(os.Link(source, destination), "storage")
	s.created = append(s.created, createdFile{s.root, "verified.json", entry.identity, false})
	checked(syscall.Unlinkat(int(s.root.Fd()), "verified.json.tmp"), "storage")
	s.created = append(s.created[:len(s.created)-2], s.created[len(s.created)-1])
	checked(s.root.Sync(), "storage")
}
func (s *staging) cleanup() (uncertain bool) {
	// Cleanup errors stay private. Identity mismatches leave data for the caller.
	defer func() {
		if recover() != nil {
			uncertain = true
		}
		for i := len(s.opened) - 1; i >= 0; i-- {
			s.opened[i].Close()
		}
	}()
	for i := len(s.created) - 1; i >= 0; i-- {
		entry := s.created[i]
		name := fmt.Sprintf("/proc/self/fd/%d/%s", entry.parent.Fd(), entry.name)
		info, err := os.Lstat(name)
		if err != nil || !os.SameFile(info, entry.identity) {
			uncertain = true
			continue
		}
		if entry.directory {
			err = syscall.Rmdir(name)
		} else {
			err = syscall.Unlinkat(int(entry.parent.Fd()), entry.name)
		}
		if err != nil {
			uncertain = true
		}
	}
	return uncertain
}
func (s *staging) close() {
	for i := len(s.opened) - 1; i >= 0; i-- {
		s.opened[i].Close()
	}
}
func contentFile(dir *os.File, digest string) *os.File {
	require(digestRE.MatchString(digest), "integrity")
	f := openAt(dir, digest[7:], syscall.O_RDONLY)
	checkFile(f, false, true)
	return f
}
func copyVerified(src io.Reader, dst io.Writer, d descriptor, limit int64, account func(int)) {
	require(d.Size <= limit, "limit")
	h := sha256.New()
	buffer := make([]byte, 32768)
	var total int64
	for {
		n, err := src.Read(buffer)
		if n > 0 {
			require(int64(n) <= d.Size-total, "integrity")
			total += int64(n)
			account(n)
			h.Write(buffer[:n])
			_, writeErr := dst.Write(buffer[:n])
			checked(writeErr, "storage")
		}
		if err == io.EOF {
			break
		}
		checked(err, "integrity")
	}
	require(total == d.Size && hex.EncodeToString(h.Sum(nil)) == d.Digest[7:], "integrity")
}
func readBounded(r io.Reader, limit int64) []byte {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	checked(err, "protocol")
	require(int64(len(data)) <= limit, "limit")
	return data
}
