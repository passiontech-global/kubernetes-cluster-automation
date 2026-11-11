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
	"sort"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/pagecache"
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
	sort.Strings(names)
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
// `.<name>.tmp` staging leftovers from an interrupted put are
// pruned too — but only for names absent from the kept set (a tmp
// whose file is still mirrored may be an in-flight upload).
func (s *Syncer) pruneRemoteDir(ctx context.Context, c Conn, remoteDir string, names []string) error {
	if len(names) == 0 {
		return fmt.Errorf("prune %s: refusing to empty remote dir — local kept-set empty",
			remoteDir)
	}
	out, err := c.Run(ctx, "ls -1pA "+hostutil.ShellQuote(remoteDir))
	if err != nil {
		return fmt.Errorf("ls %s: %w", remoteDir, err)
	}
	local := make(map[string]bool, len(names))
	for _, n := range names {
		local[n] = true
	}
	for _, rname := range strings.Split(out, "\n") {
		rname = strings.TrimSpace(rname)
		if rname == "" || local[rname] || strings.HasSuffix(rname, "/") {
			continue
		}
		if strings.HasPrefix(rname, ".") {
			// Dotfiles are bounded to the staging scheme — other
			// hidden files in the managed dir are not ours to
			// touch. A `.<name>.tmp` whose <name> is still kept may
			// be an in-flight upload: leave it.
			stem := strings.TrimPrefix(rname, ".")
			if !strings.HasSuffix(stem, ".tmp") ||
				local[strings.TrimSuffix(stem, ".tmp")] {
				continue
			}
		}
		if _, err := c.Run(ctx, "rm -f "+hostutil.ShellQuote(path.Join(remoteDir, rname))); err != nil {
			return fmt.Errorf("rm stale %s/%s: %w", remoteDir, rname, err)
		}
		s.cfg.Log.Info("hubsync: removed stale remote file",
			"path", path.Join(remoteDir, rname))
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
