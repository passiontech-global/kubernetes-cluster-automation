// probes_test.go — the production defaults behind the newer probe
// seams (in-package: they are unexported): the deleted-fd stat over
// /proc/self/fd magic links, the TCP :53 DNS probe (probee.
// DNSQueryTCP — the DNSProbeTCP seam default) against a loopback
// fake, and the bearer-authenticated kubelet /metrics GET against
// an httptest server.
package wdeps

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/probee"
)

// TestDeletedFDStatRegularFile — a live regular file stats with its
// real dev/ino/size.
func TestDeletedFDStatRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "live.log")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	dev, ino, size, ok := deletedFDStat(path)
	if !ok || size != 5 || ino == 0 {
		t.Fatalf("dev=%d ino=%d size=%d ok=%v", dev, ino, size, ok)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if ino != st.Ino || dev != st.Dev {
		t.Fatalf("dev/ino mismatch: got %d/%d want %d/%d", dev, ino, st.Dev, st.Ino)
	}
}

// TestDeletedFDStatDeletedButOpen — the guard's premise: the magic
// /proc/<pid>/fd link still resolves to the pinned inode after the
// path is gone, and a non-regular fd (pipe) never qualifies.
func TestDeletedFDStatDeletedButOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gone.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString("payload"); err != nil {
		t.Fatal(err)
	}
	link := fmt.Sprintf("/proc/self/fd/%d", int(f.Fd()))

	dev, ino, size, ok := deletedFDStat(link)
	if !ok || size != int64(len("payload")) || ino == 0 {
		t.Fatalf("open fd: dev=%d ino=%d size=%d ok=%v", dev, ino, size, ok)
	}
	// Unlink the path — the fd still pins the inode.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	_, inoAfter, sizeAfter, okAfter := deletedFDStat(link)
	if !okAfter || inoAfter != ino || sizeAfter != size {
		t.Fatalf("deleted-but-open: ok=%v ino=%d size=%d (was ino=%d size=%d)",
			okAfter, inoAfter, sizeAfter, ino, size)
	}

	// A pipe fd is not a regular file — ok=false.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	if _, _, _, ok := deletedFDStat(fmt.Sprintf("/proc/self/fd/%d", int(r.Fd()))); ok {
		t.Fatal("pipe fd must not qualify")
	}

	// A vanished fd and a non-/proc path both read false.
	if _, _, _, ok := deletedFDStat(filepath.Join(t.TempDir(), "absent")); ok {
		t.Fatal("absent path must not qualify")
	}
}

// dnsTCPServer is a minimal RFC 1035 over-TCP responder: it echoes
// the query id, sets the QR bit when replyQR, and replies with the
// configured length prefix when replyLen >= 0 (a negative replyLen
// answers nothing).
func dnsTCPServer(t *testing.T, replyQR bool, replyLen int, delay time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		var hdr [2]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		q := make([]byte, n)
		if _, err := io.ReadFull(conn, q); err != nil {
			return
		}
		if delay > 0 {
			time.Sleep(delay) // the client deadline expires first
			return
		}
		if replyLen < 0 {
			return // silence — the wedged-listener shape
		}
		body := make([]byte, 4)
		body[0], body[1] = q[0], q[1] // ID echo
		if replyQR {
			body[2] |= 0x80
		}
		// The advertised length is whatever the case wants — a
		// truncated reply (3) exercises the client's rlen<4 guard.
		plen := replyLen
		if plen > len(body) {
			plen = len(body)
		}
		resp := make([]byte, 2+plen)
		binary.BigEndian.PutUint16(resp, uint16(plen))
		copy(resp[2:], body[:plen])
		_, _ = conn.Write(resp)
	}()
	return ln.Addr().String()
}

// TestTcpDNSQuery — the ID echo + QR bit are the liveness verdict:
// NXDOMAIN-class replies still count, wrong ids, missing QR, short
// replies and silence all read wedged.
func TestTcpDNSQuery(t *testing.T) {
	name := "kubernetes.default.svc.cluster.local."
	addr := dnsTCPServer(t, true, 4, 0)
	if !probee.DNSQueryTCP(context.Background(), addr, name, 2*time.Second) {
		t.Fatal("well-formed reply read as wedged")
	}

	// QR bit clear — a request echo is not an answer.
	if probee.DNSQueryTCP(context.Background(), dnsTCPServer(t, false, 4, 0), name, 2*time.Second) {
		t.Fatal("QR-clear reply counted as alive")
	}
	// Short reply (rlen < 4) — unreadable, not alive.
	if probee.DNSQueryTCP(context.Background(), dnsTCPServer(t, true, 3, 0), name, 2*time.Second) {
		t.Fatal("3-byte reply counted as alive")
	}
	// Silence past the deadline — the wedged TCP listener.
	if probee.DNSQueryTCP(context.Background(), dnsTCPServer(t, true, -1, time.Second), name, 100*time.Millisecond) {
		t.Fatal("silent listener counted as alive")
	}
	// Connection refused — nothing listens.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	if err := dead.Close(); err != nil {
		t.Fatal(err)
	}
	if probee.DNSQueryTCP(context.Background(), deadAddr, name, 2*time.Second) {
		t.Fatal("closed port counted as alive")
	}
}

// TestKubeletMetricsGet — the :10250 scrape: the SA bearer rides the
// Authorization header, a 200 body is returned, a non-200 is an
// error (unreadable, not zero) and request/timeout failures surface.
func TestKubeletMetricsGet(t *testing.T) {
	ctx := context.Background()
	var authMu sync.Mutex
	gotAuth := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authMu.Lock()
		gotAuth = r.Header.Get("Authorization")
		authMu.Unlock()
		if r.URL.Query().Get("fail") == "1" {
			http.Error(w, "boom", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Query().Get("slow") == "1" {
			time.Sleep(300 * time.Millisecond)
		}
		_, _ = io.WriteString(w, "# HELP kubelet metrics\n"+
			"kubelet_pleg_last_seen_seconds 1.7\nkubelet_running_pods 7\n")
	}))
	defer srv.Close()

	body, err := kubeletMetricsGet(ctx, srv.URL, "sa-token", 2*time.Second)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if !strings.Contains(body, "kubelet_pleg_last_seen_seconds 1.7") {
		t.Fatalf("body=%q", body)
	}
	// The scan keeps only the parsed families — a multi-MiB scrape
	// collapses to the PLEG/storage lines before it becomes a string.
	if strings.Contains(body, "kubelet_running_pods 7") {
		t.Fatalf("unparsed family leaked through the scan: %q", body)
	}
	authMu.Lock()
	auth := gotAuth
	authMu.Unlock()
	if auth != "Bearer sa-token" {
		t.Fatalf("authorization=%q", auth)
	}

	if _, err := kubeletMetricsGet(ctx, srv.URL+"?fail=1", "", 2*time.Second); err == nil ||
		!strings.Contains(err.Error(), "status 503") {
		t.Fatalf("503 error=%v", err)
	}
	if _, err := kubeletMetricsGet(ctx, srv.URL+"?slow=1", "", 50*time.Millisecond); err == nil {
		t.Fatal("deadline must error")
	}
	if _, err := kubeletMetricsGet(ctx, srv.URL, "", 2*time.Second); err != nil {
		t.Fatalf("empty bearer must still scrape: %v", err)
	}
	if _, err := kubeletMetricsGet(ctx, "://bad", "", time.Second); err == nil {
		t.Fatal("bad URL must error")
	}
	if _, err := kubeletMetricsGet(ctx, "http://127.0.0.1:1/metrics", "", 2*time.Second); err == nil {
		t.Fatal("unreachable URL must error")
	}
}
