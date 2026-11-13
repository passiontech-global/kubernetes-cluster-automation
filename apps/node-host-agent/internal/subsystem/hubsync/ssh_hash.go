// ssh_hash.go — remote content hashing for hubsync: the
// batched remoteSHA256{,All,Many} queries, sha256sum chunking,
// output parsing and directory detection. Split out of ssh.go
// — ssh.go keeps dialing, staging, putAtomic and session exec.

package hubsync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path"
	"strings"
	"sync"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/sshclient"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

// remoteSHA256 returns the hex sha256 of a remote file. Exit 1
// drift — while other non-zero exits (126/127 missing tool or
// denied exec, sudo/shell failures) and transport errors propagate:
// treating them as "absent" would re-upload on every cycle.
// A DIRECTORY at remotePath is surfaced first: sha256sum exits 1
// for a dir exactly like a missing file, and the follow-up
// `mv tmp remotePath` would then silently NEST the staging file
// inside the directory instead of replacing a file.
func remoteSHA256(ctx context.Context, c Conn, remotePath string) (string, error) {
	if _, err := c.Run(ctx, "test -d "+fsx.ShellQuote(remotePath)); err == nil {
		return "", fmt.Errorf("%s is a directory", remotePath)
	}
	out, err := c.Run(ctx, "sha256sum "+fsx.ShellQuote(remotePath))
	if err != nil {
		var ee ExitError
		if errors.As(err, &ee) && ee.ExitStatus() == 1 {
			return "", nil
		}
		return "", err
	}
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return "", nil
	}
	return fields[0], nil
}

// sha256sumCmdChunk bounds one sha256sum invocation's command line —
// 32KiB keeps every target's ARG_MAX (Linux ~2MiB) and any
// shell/sudo argv length limit comfortably clear even for the
// largest mirrors.
const sha256sumCmdChunk = 32 * 1024

// remoteSHA256All hashes many remote files in ONE SSH session per
// chunk — a single `sha256sum p1 p2 …` invocation (paths quoted,
// command line chunked at sha256sumCmdChunk) instead of one session
// per file, which over WAN round-trips dominated the sync. The
// per-file semantics remoteSHA256 documents are preserved exactly:
// an absent file produces no hash line (the coreutils "No such file
// or directory" note rides stderr through the combined output) and
// maps to "" — drift; a DIRECTORY is surfaced as an error naming
// the path (sha256sum reports "Is a directory" and exits 1 exactly
// like a missing file, and the follow-up `mv tmp path` would
// silently NEST the staging file inside the directory); any other
// non-zero exit (126/127 missing tool or denied exec, sudo/shell
// failures) and transport errors propagate — treating them as
// "absent" would re-upload on every cycle. Exit 1 from a chunk
// (absent and/or directory paths) still parses the hash lines the
// invocation did produce, so one stale path never blanks its
// siblings' results.
func remoteSHA256All(ctx context.Context, c Conn,
	paths []string) (map[string]string, error) {
	sums := make(map[string]string, len(paths))
	for _, chunk := range sha256sumChunks(paths) {
		out, err := c.Run(ctx, "sha256sum "+chunk)
		if err != nil {
			var ee ExitError
			if errors.As(err, &ee) && ee.ExitStatus() == 1 {
				if dir, isDir := directoryReport(out); isDir {
					return nil, fmt.Errorf("%s is a directory", dir)
				}
				parseSHA256Lines(out, sums)
				continue
			}
			return nil, err
		}
		parseSHA256Lines(out, sums)
	}
	return sums, nil
}

// sha256sumChunks splits the quoted-path command tail so no single
// invocation exceeds sha256sumCmdChunk; one oversized path gets its
// own chunk rather than being dropped.
func sha256sumChunks(paths []string) []string {
	var chunks []string
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			chunks = append(chunks, b.String())
			b.Reset()
		}
	}
	for _, p := range paths {
		q := fsx.ShellQuote(p)
		if b.Len() > 0 && b.Len()+1+len(q) > sha256sumCmdChunk {
			flush()
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(q)
	}
	flush()
	return chunks
}

// parseSHA256Lines reads coreutils `sha256sum` output lines —
// `<64 hex>  <path>` in text mode, `<64 hex> *<path>` in binary
// mode — into sums. Anything else in the combined output (the
// per-file error notes for absent paths, warnings) carries no hash
// shape and is skipped.
func parseSHA256Lines(out string, sums map[string]string) {
	for ln := range strings.SplitSeq(out, "\n") {
		ln = strings.TrimSpace(ln)
		if len(ln) < 66 || ln[64] != ' ' || !isHexHash(ln[:64]) {
			continue
		}
		p := strings.TrimLeft(ln[65:], " *")
		if p != "" {
			sums[p] = ln[:64]
		}
	}
}

// isHexHash checks the 64-char sha256 hex prefix.
func isHexHash(s string) bool {
	for i := range len(s) {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// directoryReport scans sha256sum's combined output for its per-file
// "Is a directory" note and returns the offending path.
func directoryReport(out string) (string, bool) {
	for ln := range strings.SplitSeq(out, "\n") {
		ln = strings.TrimSpace(ln)
		if rest, ok := strings.CutPrefix(ln, "sha256sum: "); ok {
			if p, ok := strings.CutSuffix(rest, ": Is a directory"); ok && p != "" {
				return p, true
			}
		}
	}
	return "", false
}

// atomicPutter is the single-session fast path — the real sshConn
// implements it (one session runs install→cat→chmod→sync→mv under
// a trap cleanup). Test fakes keep the Conn-only contract and take
// the fallback below, which preserves the exact per-op sequence
// the tests assert.
type atomicPutter interface {
	PutAtomic(ctx context.Context, remotePath string, r io.Reader, mode string) error
}

// putAtomic streams r into <path>'s staging file, chmods it and
// atomically renames it over the destination — the order ansible's
// copy module + mv produced, and the ordering the tests assert.
// Conns that implement atomicPutter pay ONE session; the fallback
// keeps the original install/chmod/sync/mv op sequence.
func putAtomic(ctx context.Context, c Conn, remotePath string, r io.Reader, mode string) error {
	if pa, ok := c.(atomicPutter); ok {
		return pa.PutAtomic(ctx, remotePath, r, mode)
	}
	tmp := tmpPath(remotePath, c.StageSuffix())
	// Secret material (0600 mode: tokens, .key files) must never
	// sit world-readable on the target — `cat >`/`tee` creates the
	// tmp file under the remote umask (~0644), so pre-create it at
	// 0600 BEFORE the upload: install(1) also fixes the mode of a
	// stale tmp left by an interrupted run, and the subsequent
	// `cat >`/`tee` only truncates — the inode keeps 0600.
	if mode == "0600" || isKeyMaterial(path.Base(remotePath)) {
		if _, err := c.Run(ctx, "install -m 600 /dev/null "+fsx.ShellQuote(tmp)); err != nil {
			return fmt.Errorf("install %s: %w", tmp, err)
		}
	}
	if err := c.Write(ctx, tmp, r); err != nil {
		return fmt.Errorf("upload %s: %w", tmp, err)
	}
	if _, err := c.Run(ctx, "chmod "+mode+" "+fsx.ShellQuote(tmp)); err != nil {
		return fmt.Errorf("chmod %s: %w", tmp, err)
	}
	// fsync the staged file before the mv — the SSH upload is plain
	// buffered writes; a crash after mv must not expose truncated
	// bytes at the target (the local writers' f.Sync() parity).
	if _, err := c.Run(ctx, "sync "+fsx.ShellQuote(tmp)); err != nil {
		return fmt.Errorf("sync %s: %w", tmp, err)
	}
	if _, err := c.Run(ctx, "mv "+fsx.ShellQuote(tmp)+" "+fsx.ShellQuote(remotePath)); err != nil {
		return fmt.Errorf("mv %s: %w", remotePath, err)
	}
	return nil
}

// --- real SSH implementation ---
//
// The dial mechanics (signer loading, client config, TCP dial +
// bounded handshake, the ssh_proxyjump hop, per-op conn bounds) now
// live in platform/sshclient — shared with the nebulasign host.pub
// fetch that used to carry a second private copy. What stays here
// is hubsync's own contract: the Conn/Dialer seams, the sudo
// wrapping, streaming Write and ExitError.

// sshDialer is the real Dialer — a thin Config→sshclient splice.
// The signer is loaded inside Dial (sshclient.Config.LoadSigner
// runs per dial) so Syncer.New succeeds while the optional:true
// secret is not mounted yet, and a rotated key is picked up on the
// next dial without a pod restart.
type sshDialer struct {
	cfg sshclient.Config
	// policy resolves host-key trust per dialed hostname — pin
	// spec (single or host=fp map), operator known_hosts, and the
	// persistent TOFU store (hostkeys.go). nil only in hand-built
	// test dialers, which keep the bare Config behavior.
	policy *hostKeyPolicy
	log    *slog.Logger
	// jumps caches one open Bastion per ssh_proxyjump spec — the
	// converge loop dials targets SEQUENTIALLY, so the shared
	// conn's SetDeadline bounding never overlaps ops; one jump
	// handshake per cycle replaces one per target. Entries live
	// for the dialer's lifetime (the agent process).
	mu    sync.Mutex
	jumps map[string]*sshclient.Bastion
}
