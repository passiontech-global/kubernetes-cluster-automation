// Package pagecache drops bulk file I/O back out of the kernel page
// cache (POSIX_FADV_DONTNEED) after the caller is done with it.
//
// Why this exists — cgroup memory accounting: every page the agent
// faults into the page cache is charged to ITS cgroup, hostPath or
// not. The agent writes/verifies ~130 MB of staged host binaries
// (self-stage + nebula/coredns/etcdctl/haproxy via untarInstall,
// downloadFile) at pod start and re-hashes ~60 MB of them every
// converge cycle (selfStageBinary, hubsync's sha256File every 10m).
// Those pages stay active_file forever — the next cycle touches them
// again before reclaim — so container_memory_working_set_bytes pins
// at ~200 Mi against a 256 Mi limit while the process itself uses
// ~15 Mi anon (cicd observation 2026-11-04). The limit holds only
// because the kernel reclaims clean file pages under pressure; the
// charge is pure overhead that also starves headroom for real anon
// growth.
//
// Dropping is safe at each call site by construction: for writes the
// pages belong to a tmp file only this process just wrote (no other
// reader's working set is harmed), and the drop runs AFTER fsync so
// only clean pages are evicted (FADV_DONTNEED on dirty pages merely
// schedules writeback). For verify reads the pages were pulled in
// solely for the hash — re-faulting them on the rare mismatch costs
// one disk read.
package pagecache

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// Drop evicts f's clean page-cache pages (whole file). Best-effort:
// fadvise is an advisory hint — errors (non-Linux, unsupported fs)
// are ignored. Call after fsync for files just written.
func Drop(f *os.File) {
	dontNeed(f)
}

// ReadFile is os.ReadFile that drops the file's pages afterwards —
// for reads done once per cycle purely to hash/compare/stage, where
// keeping the bytes cached only inflates the cgroup charge.
func ReadFile(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer func() { dontNeed(f); _ = f.Close() }()
	return io.ReadAll(f)
}

// Sha256File streams p's sha256 without holding it in memory and
// drops its pages afterwards — the every-cycle binary-verify path
// (~30 MiB agent binary) would otherwise keep the whole file in the
// pod's charged page cache permanently.
func Sha256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer func() { dontNeed(f); _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
