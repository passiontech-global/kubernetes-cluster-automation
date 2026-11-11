// files.go — content-level primitives: ansible lineinfile parity,
// sha256 verification, bounded downloads, and tar-member installs.
// All staging (tmp/.dl/.candidate) is swept on every failure path.
package converge

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/pagecache"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

// maxArtifactBytes bounds the bytes ONE DownloadFile download (and
// one UntarInstall member) may produce — a compromised mirror or a
// misrouted URL must not be able to fill the node's disk through the
// converge path. Var, not const: the tests shrink it instead of
// serving 256MiB fixtures.
var maxArtifactBytes = int64(256) << 20

// maxErrorBodyDrain bounds the non-200 body read — draining a
// bounded slice of the error body lets the keep-alive connection be
// reused for the next artifact; beyond the cap the connection is
// forfeited rather than read forever.
const maxErrorBodyDrain = 64 << 10

// LineInFile is ansible lineinfile parity: replace the LAST line
// matching re with line; when absent insert after the last line
// matching insAfter (or append at EOF).
func LineInFile(content, re, line, insAfter string) string {
	rex := regexp.MustCompile(re)
	if loc := findLastMatch(rex, content); loc != nil {
		nl := strings.IndexByte(content[loc[0]:], '\n')
		end := len(content)
		if nl >= 0 {
			end = loc[0] + nl + 1
		}
		if !strings.HasSuffix(line, "\n") {
			line += "\n"
		}
		return content[:loc[0]] + line + content[end:]
	}
	if insAfter != "" {
		ia := regexp.MustCompile(insAfter)
		if loc := findLastMatch(ia, content); loc != nil {
			nl := strings.IndexByte(content[loc[0]:], '\n')
			end := loc[0] + nl + 1
			if nl < 0 {
				end = len(content)
				return content[:end] + "\n" + line + "\n"
			}
			return content[:end] + line + "\n" + content[end:]
		}
	}
	return content + line + "\n"
}

func findLastMatch(re *regexp.Regexp, s string) []int {
	var last []int
	for _, loc := range re.FindAllStringIndex(s, -1) {
		last = loc
	}
	return last
}

// Sha256FileOK verifies a staged/downloaded artifact against its pin.
// An empty wantHex disables verification (vars may leave a pin
// blank; the caller decides whether that's allowed).
func Sha256FileOK(path, wantHex string) bool {
	if wantHex == "" {
		return true
	}
	sum, err := pagecache.Sha256File(path)
	if err != nil {
		return false
	}
	return strings.EqualFold(sum, wantHex)
}

// DownloadFile streams url to dst under the timeout client deadline,
// atomically: tmp file + sha256 verify + fsync + rename + dir fsync,
// partial tmp swept on every failure path. The response is capped at
// maxArtifactBytes — a body that crosses the cap fails the download
// and is never staged to disk beyond the one probing byte.
func DownloadFile(ctx context.Context, url, dst, wantSHA256 string, timeout time.Duration) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		// Drain (a bounded slice of) the error body so the
		// keep-alive connection survives for the next artifact;
		// oversize error pages forfeit reuse instead of blocking
		// the drain.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBodyDrain))
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".dl"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	h := sha256.New()
	// One byte past the cap: n > max means the artifact is over the
	// budget (the extra byte is discarded with the swept tmp, never
	// renamed into place).
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxArtifactBytes+1))
	if err == nil && n > maxArtifactBytes {
		err = fmt.Errorf("download %s: artifact exceeds the %d MiB cap",
			url, maxArtifactBytes>>20)
	}
	if err == nil && wantSHA256 != "" &&
		!strings.EqualFold(wantSHA256, hex.EncodeToString(h.Sum(nil))) {
		err = fmt.Errorf("download %s: sha256 mismatch", url)
	}
	if err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	// fsx.Promote carries the durability contract the bespoke tail
	// used to hand-roll: fsync before rename — the staged artifact
	// must be durable; Close's error counts too (NFS/delayed-write
	// failures only surface there); the just-written pages are
	// dropped after Sync — archives are staged for
	// UntarInstall/Sha256FileOK, not for serving, and their cache
	// would pin the pod's cgroup charge; the archive mode is pinned
	// before the rename (os.Create's 0666 rides the umask, so a
	// 077-umask host would stage the shared artifact tree at 0600
	// and break the non-root consumers); and the dir fsync after the
	// rename makes the directory entry itself durable (a crash
	// between rename and sync can lose the installed file).
	return fsx.Promote(f, dst, fsx.Opts{
		Mode:      0o644,
		DirSync:   true,
		AfterSync: pagecache.Drop,
	})
}

// UntarInstall extracts member name from a .tar.gz and atomically
// installs to dst. The member stream is capped at maxArtifactBytes —
// a hostile archive can't balloon one member past the artifact
// budget.
func UntarInstall(tgz, member, dst string, mode os.FileMode) error {
	f, err := os.Open(tgz)
	if err != nil {
		return err
	}
	// Drop the archive's read-behind pages on the way out — the tgz
	// is only scanned once per install.
	defer func() { pagecache.Drop(f); _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hd, err := tr.Next()
		if err != nil {
			return fmt.Errorf("%s not found in %s", member, tgz)
		}
		if filepath.Base(hd.Name) == member {
			return installMember(tr, dst, mode)
		}
	}
}

// installMember stages one tar member to dst atomically: CreateTemp
// staging under the target dir (hostutil StageTempPattern parity — a
// unique "base.tmp-*" name, so a crashed install's stage can never
// collide with the next attempt's), payload fsync + rename + dir
// fsync, the stage swept on EVERY failure path. The member stream is
// capped at maxArtifactBytes.
func installMember(r io.Reader, dst string, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".tmp-*")
	if err != nil {
		return err
	}
	// One byte past the cap: n > max means the member is over the
	// budget. Copy failure (and the cap) sweep the stage before
	// fsx.Promote takes over its failure paths.
	if n, cerr := io.Copy(tmp, io.LimitReader(r, maxArtifactBytes+1)); cerr != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return cerr
	} else if n > maxArtifactBytes {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("%s: member exceeds the %d MiB extract cap",
			dst, maxArtifactBytes>>20)
	}
	// fsx.Promote carries the durability contract the bespoke tail
	// used to hand-roll: fsync before rename (WriteManaged parity) —
	// a crash after rename must never expose a zeroed binary at the
	// install path; the staged pages are dropped after Sync (a
	// freshly installed binary's cache charge belongs to whoever
	// execs it, not to this pod's working set); CreateTemp's 0600 is
	// overridden with the caller's mode before the rename; and the
	// dir fsync after the rename makes the directory entry durable.
	return fsx.Promote(tmp, dst, fsx.Opts{
		Mode:      mode,
		DirSync:   true,
		AfterSync: pagecache.Drop,
	})
}
