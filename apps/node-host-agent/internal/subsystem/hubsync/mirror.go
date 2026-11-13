// mirror.go — the local→remote file mirrors: syncDir (sha256-gated
// per-file puts over one batched hash session + stale-file pruning),
// putIfChanged for single-file pushes, the artifact/key-material
// classifiers and the pagecache-aware local binary hash.
package hubsync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/pagecache"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

// isKeyMaterial flags private-key-looking filenames — mirrored
// config lands under a shared 0644 mode, so staged key material
// would be world-readable on the target without the 0600 override.
func isKeyMaterial(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, ".key") ||
		strings.HasSuffix(n, "key.pem") ||
		strings.Contains(n, "private")
}

// syncDir mirrors every regular file of localDir into remoteDir —
// sha256-gated, atomic tmp+chmod+mv writes; the remote sums hash in
// ONE batched session (remoteSHA256All) instead of one SSH
// round-trip per file. ConfigMap
// volumes expose keys as symlinks, so "regular" means non-dir,
// non-hidden entries; ReadFile resolves the ..data links. A non-nil
// keep filter further restricts which filenames are mirrored. Key
// material is chmod'd 0600 regardless of mode. Finally, remote files
// absent from the local set are removed — remoteDir is a dedicated
// managed dir, and a locally-deleted file would otherwise linger on
// every target forever.
func (s *Syncer) syncDir(ctx context.Context, c Conn, localDir, remoteDir, mode string, keep func(string) bool) error {
	entries, err := os.ReadDir(localDir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if keep != nil && !keep(e.Name()) {
			continue
		}
		names = append(names, e.Name())
	}
	slices.Sort(names)
	rpaths := make([]string, len(names))
	for i := range names {
		rpaths[i] = path.Join(remoteDir, names[i])
	}
	sums, err := remoteSHA256All(ctx, c, rpaths)
	if err != nil {
		return err
	}
	for _, name := range names {
		data, err := os.ReadFile(path.Join(localDir, name))
		if err != nil {
			return err
		}
		m := mode
		if isKeyMaterial(name) {
			m = "0600"
		}
		sum := sha256.Sum256(data)
		rp := path.Join(remoteDir, name)
		if sums[rp] == hex.EncodeToString(sum[:]) {
			continue
		}
		if err := putAtomic(ctx, c, rp, bytes.NewReader(data), m); err != nil {
			return err
		}
	}
	return s.pruneRemoteDir(ctx, c, remoteDir, names)
}

// pruneRemoteDir removes files inside remoteDir that are not in
// names — the remote-side half of the mirror. `ls -1pA` returns
// basenames (dotfiles included, no ./..) and marks directories with
// a trailing '/', so stray subdirs are skipped rather than failing
// `rm -f` forever; deletions are scoped to remoteDir by
// construction (basename joined back onto it). An EMPTY kept-set
// refuses outright: mirror semantics would rm every remote file,
// but a locally-empty dir means the SOURCE is broken (empty
// ConfigMap / failed mount), not that the target should be wiped.
//
// Dotfiles are ALL left to sweepTmpOrphans: the `.<name>.tmp` /
// `.<name>.tmp.<nonce>` staging scheme is only deleted past the
// 15-minute in-flight window — a younger tmp may belong to a
// CONCURRENT converge (the per-dial nonce makes names unique but
// the pattern shared), and the old keep-set check could neither
// see nonce-suffixed tmps nor age-gate them, so orphans accumulated
// forever. Real (non-tmp) stale files still delete immediately.
func (s *Syncer) pruneRemoteDir(ctx context.Context, c Conn, remoteDir string, names []string) error {
	if len(names) == 0 {
		return fmt.Errorf("prune %s: refusing to empty remote dir — local kept-set empty",
			remoteDir)
	}
	out, err := c.Run(ctx, "ls -1pA "+fsx.ShellQuote(remoteDir))
	if err != nil {
		return fmt.Errorf("ls %s: %w", remoteDir, err)
	}
	local := make(map[string]bool, len(names))
	for _, n := range names {
		local[n] = true
	}
	for rname := range strings.SplitSeq(out, "\n") {
		rname = strings.TrimSpace(rname)
		if rname == "" || local[rname] || strings.HasSuffix(rname, "/") ||
			strings.HasPrefix(rname, ".") {
			continue
		}
		if _, err := c.Run(ctx, "rm -f "+fsx.ShellQuote(path.Join(remoteDir, rname))); err != nil {
			return fmt.Errorf("rm stale %s/%s: %w", remoteDir, rname, err)
		}
		s.cfg.Log.Info("hubsync: removed stale remote file",
			"path", path.Join(remoteDir, rname))
	}
	return s.sweepTmpOrphans(ctx, c, remoteDir)
}

// tmpOrphanMinAge is the in-flight window sweepTmpOrphans honors:
// a staging file younger than this may belong to a live upload
// (the put streams for seconds, WAN included); older than it the
// writer is gone — crash, cancel or a pre-trap build — and the
// file is an orphan.
const tmpOrphanMinAge = 15

// sweepTmpOrphans deletes `.<name>.tmp[.<nonce>]` staging leftovers
// older than tmpOrphanMinAge inside dir — one `find` listing plus
// one `rm -f` per actual orphan (zero extra execs in the common
// all-clean case). Best-effort by contract: a missing find(1) or a
// failed rm logs and returns nil — orphan tmps are cosmetic (the
// next put's trap or a later sweep collects them), never a reason
// to fail the mirror.
func (s *Syncer) sweepTmpOrphans(ctx context.Context, c Conn, dir string) error {
	out, err := c.Run(ctx, "find "+fsx.ShellQuote(dir)+
		" -maxdepth 1 -type f -name '.*.tmp*' -mmin +"+
		strconv.Itoa(tmpOrphanMinAge)+" -printf '%f\\n'")
	if err != nil {
		s.cfg.Log.Debug("hubsync: tmp-orphan sweep skipped",
			"dir", dir, "error", err)
		return nil
	}
	for name := range strings.SplitSeq(out, "\n") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, err := c.Run(ctx, "rm -f "+
			fsx.ShellQuote(path.Join(dir, name))); err != nil {
			s.cfg.Log.Warn("hubsync: tmp-orphan rm failed",
				"path", path.Join(dir, name), "error", err)
			continue
		}
		s.cfg.Log.Info("hubsync: removed orphan staging file",
			"path", path.Join(dir, name))
	}
	return nil
}

// putIfChanged writes data to remotePath only when the remote sha256
// differs — the ansible copy-module checksum gating.
func (s *Syncer) putIfChanged(ctx context.Context, c Conn, remotePath string, data []byte, mode string) error {
	sum := sha256.Sum256(data)
	remote, err := remoteSHA256(ctx, c, remotePath)
	if err != nil {
		return err
	}
	if remote == hex.EncodeToString(sum[:]) {
		return nil
	}
	return putAtomic(ctx, c, remotePath, bytes.NewReader(data), mode)
}

// sha256File hashes a local file without loading it whole — the
// agent binary is ~15 MiB and cycles run every few minutes — and
// drops its page-cache pages afterwards so the recurring hash does
// not pin the file in the pod's charged cache (pagecache pkg doc).
func sha256File(p string) (string, error) {
	return pagecache.Sha256File(p)
}
