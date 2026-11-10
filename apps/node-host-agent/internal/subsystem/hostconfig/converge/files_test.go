// files_test.go — the content-level primitives: ansible lineinfile
// parity, sha256 pin verification, httptest-served downloads, and
// in-test tar.gz member installs.
package converge

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func TestLineInFile(t *testing.T) {
	for _, tc := range []struct {
		name              string
		content, re, line string
		insAfter          string
		want              string
	}{
		{
			name:    "replace last matching line",
			content: "keep\nold 1\nold 2\ntail\n",
			re:      `(?m)^old `,
			line:    "new",
			want:    "keep\nold 1\nnew\ntail\n",
		},
		{
			name:    "newline-terminated line is not doubled",
			content: "a\nold\nb\n",
			re:      `(?m)^old$`,
			line:    "new\n",
			want:    "a\nnew\nb\n",
		},
		{
			name:    "match at EOF without trailing newline",
			content: "a\nold",
			re:      `(?m)^old$`,
			line:    "new",
			want:    "a\nnew\n",
		},
		{
			// Go regexp semantics: `^` without (?m) anchors to the
			// START OF TEXT, not line start — call sites spell the
			// line anchor as (?m)^ (see hostconfig's kubelet group).
			name:    "caret anchors text-start without (?m)",
			content: "old\na\nold\n",
			re:      `^old`,
			line:    "new",
			want:    "new\na\nold\n",
		},
		{
			name:     "insert after matching pattern",
			content:  "header\nfooter\n",
			re:       `^zzz`,
			line:     "inserted",
			insAfter: `(?m)^header`,
			want:     "header\ninserted\nfooter\n",
		},
		{
			name:     "insert after LAST matching pattern",
			content:  "marker\na\nmarker\nb\n",
			re:       `^zzz`,
			line:     "inserted",
			insAfter: `(?m)^marker`,
			want:     "marker\na\nmarker\ninserted\nb\n",
		},
		{
			name:     "insert-after match at EOF without newline",
			content:  "a\nmarker",
			re:       `^zzz`,
			line:     "x",
			insAfter: `marker$`,
			want:     "a\nmarker\nx\n",
		},
		{
			name:     "no match anywhere appends",
			content:  "a\nb\n",
			re:       `^zzz`,
			line:     "x",
			insAfter: `(?m)^yyy`,
			want:     "a\nb\nx\n",
		},
		{
			name:    "empty insertAfter appends",
			content: "a\n",
			re:      `^zzz`,
			line:    "x",
			want:    "a\nx\n",
		},
		{
			name:    "empty content",
			content: "",
			re:      `^zzz`,
			line:    "x",
			want:    "x\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := LineInFile(tc.content, tc.re, tc.line, tc.insAfter); got != tc.want {
				t.Fatalf("LineInFile = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSha256FileOK(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "artifact")
	content := "payload-bytes"
	testutil.WriteFile(t, p, content)
	sum := sha256.Sum256([]byte(content))
	good := hex.EncodeToString(sum[:])

	// Empty pin disables verification — even for a missing path,
	// since the short-circuit runs before the file is opened.
	if !Sha256FileOK(filepath.Join(dir, "missing"), "") {
		t.Error("empty wantHex must pass without touching the fs")
	}
	if Sha256FileOK(filepath.Join(dir, "missing"), good) {
		t.Error("missing file with a pin must fail")
	}
	if !Sha256FileOK(p, good) {
		t.Error("matching pin rejected")
	}
	if !Sha256FileOK(p, strings.ToUpper(good)) {
		t.Error("uppercase pin must compare equal-fold")
	}
	if Sha256FileOK(p, strings.Repeat("0", 64)) {
		t.Error("wrong pin accepted")
	}
}

func TestDownloadFile(t *testing.T) {
	ctx := context.Background()
	payload := "the artifact bytes"
	sum := sha256.Sum256([]byte(payload))
	good := hex.EncodeToString(sum[:])

	newServer := func(t *testing.T, status int, body string) *httptest.Server {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return srv
	}

	t.Run("downloads and creates parent dirs", func(t *testing.T) {
		srv := newServer(t, http.StatusOK, payload)
		dst := filepath.Join(t.TempDir(), "sub", "dir", "f.bin")
		if err := DownloadFile(ctx, srv.URL, dst, "", 10*time.Second); err != nil {
			t.Fatal(err)
		}
		if got := testutil.ReadFile(t, dst); got != payload {
			t.Fatalf("content = %q", got)
		}
	})

	t.Run("sha256 pin verified", func(t *testing.T) {
		srv := newServer(t, http.StatusOK, payload)
		dst := filepath.Join(t.TempDir(), "f.bin")
		if err := DownloadFile(ctx, srv.URL, dst, strings.ToUpper(good), 10*time.Second); err != nil {
			t.Fatalf("correct pin rejected: %v", err)
		}
	})

	t.Run("sha256 mismatch errors and sweeps", func(t *testing.T) {
		srv := newServer(t, http.StatusOK, payload)
		dir := t.TempDir()
		dst := filepath.Join(dir, "f.bin")
		err := DownloadFile(ctx, srv.URL, dst, strings.Repeat("0", 64), 10*time.Second)
		if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
			t.Fatalf("err = %v, want sha256 mismatch", err)
		}
		if _, serr := os.Stat(dst); !os.IsNotExist(serr) {
			t.Error("dst must not exist after a failed pin")
		}
		if _, serr := os.Stat(dst + ".dl"); !os.IsNotExist(serr) {
			t.Error("staged .dl must be swept after a failed pin")
		}
	})

	t.Run("non-200 status errors", func(t *testing.T) {
		srv := newServer(t, http.StatusInternalServerError, "")
		dst := filepath.Join(t.TempDir(), "f.bin")
		err := DownloadFile(ctx, srv.URL, dst, "", 10*time.Second)
		if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
			t.Fatalf("err = %v, want HTTP 500", err)
		}
		if _, serr := os.Stat(dst); !os.IsNotExist(serr) {
			t.Error("dst must not exist after an HTTP failure")
		}
	})

	t.Run("unreachable URL errors", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close() // listener gone → connection refused
		dst := filepath.Join(t.TempDir(), "f.bin")
		if err := DownloadFile(ctx, url, dst, "", 5*time.Second); err == nil {
			t.Fatal("expected a transport error")
		}
	})
}

// writeTarGz builds a fixture archive with the named file members.
func writeTarGz(t *testing.T, path string, members map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, body := range members {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o755, Size: int64(len(body)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUntarInstall(t *testing.T) {
	dir := t.TempDir()
	tgz := filepath.Join(dir, "bundle.tar.gz")
	writeTarGz(t, tgz, map[string]string{
		"bin/tool":   "tool-bytes",
		"share/doc":  "doc-bytes",
		"bin/helper": "helper-bytes",
	})

	t.Run("extracts member by basename with mode", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "installed")
		if err := UntarInstall(tgz, "tool", dst, 0o755); err != nil {
			t.Fatal(err)
		}
		if got := testutil.ReadFile(t, dst); got != "tool-bytes" {
			t.Fatalf("content = %q", got)
		}
		st, err := os.Stat(dst)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o755 {
			t.Fatalf("mode = %o, want 755", st.Mode().Perm())
		}
		// The CreateTemp stage (installed.tmp-*) must be renamed
		// away, not left behind next to the live binary.
		leftovers, err := filepath.Glob(dst + ".tmp-*")
		if err != nil {
			t.Fatal(err)
		}
		if len(leftovers) != 0 {
			t.Errorf("staged tmp left behind: %v", leftovers)
		}
		if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
			t.Error("fixed .tmp stage name must be gone too")
		}
	})

	t.Run("member not found errors", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "installed")
		err := UntarInstall(tgz, "ghost", dst, 0o755)
		if err == nil || !strings.Contains(err.Error(), "ghost not found") {
			t.Fatalf("err = %v, want 'ghost not found'", err)
		}
		if _, serr := os.Stat(dst); !os.IsNotExist(serr) {
			t.Error("dst must not exist when the member is absent")
		}
	})

	t.Run("member must be a basename", func(t *testing.T) {
		// Match is filepath.Base(hd.Name) == member — a slashed
		// member like "bin/tool" never matches ("tool" != "bin/tool").
		dst := filepath.Join(t.TempDir(), "installed")
		if err := UntarInstall(tgz, "bin/tool", dst, 0o755); err == nil {
			t.Fatal("a slashed member path must not match")
		}
	})

	t.Run("missing archive errors", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "installed")
		if err := UntarInstall(filepath.Join(dir, "gone.tgz"), "tool", dst, 0o755); err == nil {
			t.Fatal("expected an open error")
		}
	})

	t.Run("not-gzip errors", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.tgz")
		testutil.WriteFile(t, bad, "definitely not gzip")
		dst := filepath.Join(t.TempDir(), "installed")
		if err := UntarInstall(bad, "tool", dst, 0o755); err == nil {
			t.Fatal("expected a gzip header error")
		}
	})

	t.Run("dst parent dir must already exist", func(t *testing.T) {
		// Unlike DownloadFile, UntarInstall does not MkdirAll — the
		// staged .tmp open fails outright on a missing parent.
		dst := filepath.Join(t.TempDir(), "missing", "installed")
		if err := UntarInstall(tgz, "tool", dst, 0o755); err == nil {
			t.Fatal("expected an error installing into a missing dir")
		}
	})

	t.Run("member exactly at the cap installs", func(t *testing.T) {
		defer func(orig int64) { maxArtifactBytes = orig }(maxArtifactBytes)
		maxArtifactBytes = int64(len("tool-bytes"))
		dst := filepath.Join(t.TempDir(), "installed")
		if err := UntarInstall(tgz, "tool", dst, 0o755); err != nil {
			t.Fatal(err)
		}
		if got := testutil.ReadFile(t, dst); got != "tool-bytes" {
			t.Fatalf("content = %q", got)
		}
	})
}

func TestUntarInstallExtractCap(t *testing.T) {
	defer func(orig int64) { maxArtifactBytes = orig }(maxArtifactBytes)
	maxArtifactBytes = 1024

	dir := t.TempDir()
	tgz := filepath.Join(dir, "bundle.tar.gz")
	writeTarGz(t, tgz, map[string]string{"bin/tool": strings.Repeat("A", 2000)})

	dst := filepath.Join(t.TempDir(), "installed")
	err := UntarInstall(tgz, "tool", dst, 0o755)
	if err == nil || !strings.Contains(err.Error(), "extract cap") {
		t.Fatalf("err = %v, want the extract-cap failure", err)
	}
	if _, serr := os.Stat(dst); !os.IsNotExist(serr) {
		t.Error("dst must not exist when the member breaches the cap")
	}
	// The partial stage must be swept from the dst dir.
	leftovers, gerr := filepath.Glob(dst + ".tmp-*")
	if gerr != nil {
		t.Fatal(gerr)
	}
	if len(leftovers) != 0 {
		t.Errorf("oversize member stage left behind: %v", leftovers)
	}
}

func TestDownloadFileArtifactCap(t *testing.T) {
	defer func(orig int64) { maxArtifactBytes = orig }(maxArtifactBytes)
	maxArtifactBytes = 1024

	overCap := strings.Repeat("B", 2000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(overCap))
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	dst := filepath.Join(dir, "f.bin")
	err := DownloadFile(context.Background(), srv.URL, dst, "", 10*time.Second)
	if err == nil || !strings.Contains(err.Error(), "exceeds the") {
		t.Fatalf("err = %v, want the artifact-cap failure", err)
	}
	if _, serr := os.Stat(dst); !os.IsNotExist(serr) {
		t.Error("dst must not exist when the artifact breaches the cap")
	}
	if _, serr := os.Stat(dst + ".dl"); !os.IsNotExist(serr) {
		t.Error("staged .dl must be swept after a cap failure")
	}

	// Boundary: exactly the cap downloads fine.
	exact := strings.Repeat("B", 1024)
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(exact))
	}))
	t.Cleanup(srv2.Close)
	dst2 := filepath.Join(dir, "exact.bin")
	if err := DownloadFile(context.Background(), srv2.URL, dst2, "", 10*time.Second); err != nil {
		t.Fatalf("artifact at exactly the cap rejected: %v", err)
	}
	if got := testutil.ReadFile(t, dst2); got != exact {
		t.Fatalf("content = %d bytes, want the full capped artifact", len(got))
	}
}

// DownloadFile's remaining failure paths: unbuildable request, a
// parent component that is not a dir, a squatter at the .dl staging
// name, and a rename target that is a directory.
func TestDownloadFileFailures(t *testing.T) {
	ctx := context.Background()
	payload := "x"

	t.Run("bad URL", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "f")
		if err := DownloadFile(ctx, "http://bad url", dst, "", 5*time.Second); err == nil {
			t.Fatal("expected request-build error")
		}
	})

	t.Run("mkdir under a file fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(payload))
		}))
		defer srv.Close()
		dir := t.TempDir()
		testutil.WriteFile(t, filepath.Join(dir, "blocker"), "x")
		if err := DownloadFile(ctx, srv.URL, filepath.Join(dir, "blocker", "f"), "", 5*time.Second); err == nil {
			t.Fatal("expected mkdir error")
		}
	})

	t.Run(".dl squatter fails the stage", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(payload))
		}))
		defer srv.Close()
		dir := t.TempDir()
		dst := filepath.Join(dir, "f")
		if err := os.Mkdir(dst+".dl", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := DownloadFile(ctx, srv.URL, dst, "", 5*time.Second); err == nil {
			t.Fatal("expected stage-create error")
		}
	})

	t.Run("rename over a dir fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(payload))
		}))
		defer srv.Close()
		dir := t.TempDir()
		dst := filepath.Join(dir, "f")
		if err := os.Mkdir(dst, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := DownloadFile(ctx, srv.URL, dst, "", 5*time.Second); err == nil {
			t.Fatal("expected rename error onto a directory")
		}
		if _, serr := os.Stat(dst + ".dl"); !os.IsNotExist(serr) {
			t.Fatal("staged .dl not swept after rename failure")
		}
	})
}

// installMember's rename refuses a directory dst the same way —
// surfaced through UntarInstall.
func TestUntarInstallDstIsDir(t *testing.T) {
	dir := t.TempDir()
	tgz := filepath.Join(dir, "bundle.tar.gz")
	writeTarGz(t, tgz, map[string]string{"bin/tool": "tool-bytes"})
	dst := filepath.Join(dir, "tool")
	if err := os.Mkdir(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := UntarInstall(tgz, "tool", dst, 0o755); err == nil {
		t.Fatal("expected rename error onto a directory")
	}
}
