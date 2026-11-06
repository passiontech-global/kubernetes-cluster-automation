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
)

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
// atomically: tmp file + sha256 verify + fsync + rename, partial tmp
// swept on every failure path.
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
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	if err == nil {
		// fsync before rename — the staged artifact must be durable;
		// Close's error counts too (NFS/delayed-write failures only
		// surface there). Drop the just-written pages after Sync —
		// archives are staged for UntarInstall/Sha256FileOK, not for
		// serving, and their cache would pin the pod's cgroup charge.
		if err = f.Sync(); err == nil {
			pagecache.Drop(f)
		}
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if wantSHA256 != "" && !strings.EqualFold(wantSHA256, hex.EncodeToString(h.Sum(nil))) {
		_ = os.Remove(tmp)
		return fmt.Errorf("download %s: sha256 mismatch", url)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// UntarInstall extracts member name from a .tar.gz and atomically
// installs to dst.
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
			tmp := dst + ".tmp"
			out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			_, err = io.Copy(out, tr)
			if err == nil {
				// fsync before rename (WriteManaged parity) — a
				// crash after rename must never expose a zeroed
				// binary at the install path. Then drop the staged
				// pages: a freshly installed binary's cache charge
				// belongs to whoever execs it, not to this pod's
				// working set.
				if err = out.Sync(); err == nil {
					pagecache.Drop(out)
				}
			}
			// Close's error counts too — delayed-write failures only
			// surface there.
			if cerr := out.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				// sweep the partial tmp — a truncated member must not
				// linger next to the live binary.
				_ = os.Remove(tmp)
				return err
			}
			if err := os.Rename(tmp, dst); err != nil {
				_ = os.Remove(tmp)
				return err
			}
			return nil
		}
	}
}
