// seams_test.go — the Seams applyDefaults pass: every nil seam gets
// its production implementation, the exec closure captures the
// Config's systemd client, the sd_notify sender dials a real
// unixgram socket, and the etcdctl default builds the cert argv and
// execs container-side with a separate stderr stream.
package cdeps

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
)

func TestSeamsApplyDefaults(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "") // deterministic: no notify socket
	var c Config
	c.ApplyDefaults()

	if c.Clock == nil {
		t.Fatal("clock cell not armed")
	}
	if c.SleepFn == nil {
		t.Fatal("SleepFn default missing")
	}
	c.SleepFn(0) // callable without sleeping
	if c.KillFn == nil {
		t.Fatal("KillFn default missing")
	}
	if c.ProbeFn == nil || c.PgWireFn == nil || c.CPHealthFn == nil ||
		c.KCMMetricsFn == nil || c.TLSCertFn == nil {
		t.Fatal("probe seam defaults missing")
	}
	if c.EvpurgeRunFn == nil || c.EtcdRescueFn == nil {
		t.Fatal("etcd remediation seam defaults missing")
	}
	if c.NotifyFn != nil {
		t.Fatal("NotifyFn armed without a notify socket")
	}
}

func TestSeamsHostExecFnDefaultNilClient(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	var c Config
	c.ApplyDefaults()
	_, err := c.HostExecFn(context.Background(), false, 0, "systemctl")
	if err == nil || !strings.Contains(err.Error(), "no systemd client wired") {
		t.Fatalf("nil client err=%v", err)
	}
}

func TestSeamsNotifyFnDefault(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "notify.sock")
	addr := &net.UnixAddr{Name: sock, Net: "unixgram"}
	srv, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	c := Config{Feeder: FeederConfig{NotifySocket: sock}}
	c.ApplyDefaults()
	if c.NotifyFn == nil {
		t.Fatal("NotifyFn default not armed with Feeder.NotifySocket set")
	}
	if err := c.NotifyFn("WATCHDOG=1"); err != nil {
		t.Fatalf("NotifyFn err=%v", err)
	}
	buf := make([]byte, 64)
	n, _, rerr := srv.ReadFromUnix(buf)
	if rerr != nil {
		t.Fatalf("datagram read err=%v", rerr)
	}
	if string(buf[:n]) != "WATCHDOG=1" {
		t.Fatalf("datagram=%q", buf[:n])
	}
}

// fakeEtcdctl installs a shell script as the etcdctl binary and
// returns what the script printed.
func fakeEtcdctl(t *testing.T, k0sDir, script string) string {
	t.Helper()
	bin := filepath.Join(k0sDir, "bin", "etcdctl")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestSeamsEtcdctlFnDefault(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	k0sDir := t.TempDir()
	c := Config{K0sDir: k0sDir}
	c.ApplyDefaults()

	// Success: stdout-only capture must keep the payload clean, and
	// the cert triple + endpoint + command-timeout prefix the args.
	fakeEtcdctl(t, k0sDir, `printf 'ARGS:%s\n' "$*"; exit 0`)
	out, err := c.EtcdctlFn(context.Background(), "member", "list")
	if err != nil {
		t.Fatalf("etcdctl err=%v", err)
	}
	if !strings.Contains(string(out), "ARGS:--cacert="+filepath.Join(k0sDir, "pki", "etcd", "ca.crt")) ||
		!strings.Contains(string(out), "--cert="+filepath.Join(k0sDir, "pki", "apiserver-etcd-client.crt")) ||
		!strings.Contains(string(out), "--key="+filepath.Join(k0sDir, "pki", "apiserver-etcd-client.key")) ||
		!strings.Contains(string(out), "--endpoints=https://127.0.0.1:2379") ||
		!strings.Contains(string(out), "--command-timeout=30s") ||
		!strings.Contains(string(out), "member list") {
		t.Fatalf("etcdctl argv wrong: %s", out)
	}

	// Failure: stderr folds into the error, partial stdout survives.
	fakeEtcdctl(t, k0sDir, `echo '{"partial":1}'; echo boom >&2; exit 1`)
	out, err = c.EtcdctlFn(context.Background())
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("stderr not folded into the error: err=%v out=%s", err, out)
	}
	if !strings.Contains(string(out), "partial") {
		t.Fatalf("partial stdout lost: %s", out)
	}
}

func TestSeamsExecClosureCapturesClient(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	var runArgv, combArgv []string
	sd := systemd.New(hostexec.Config{
		HostRoot: "/", // unwrapped — the scrub prefix must be visible
		RunCmd: func(_ context.Context, argv []string) (string, error) {
			runArgv = argv
			return "stdout\n", nil
		},
		RunCmdCombined: func(_ context.Context, argv []string) (string, error) {
			combArgv = argv
			return "combined\n", nil
		},
	})
	c := Config{Base: subframe.Base{Systemd: sd}}
	c.ApplyDefaults()

	out, err := c.HostExecFn(context.Background(), false, time.Second,
		"systemctl", "is-active", "u")
	if err != nil || out != "stdout\n" {
		t.Fatalf("HostExecFn out=%q err=%v", out, err)
	}
	want := []string{"systemctl", "is-active", "u"}
	if !reflect.DeepEqual(runArgv, want) {
		t.Fatalf("argv=%v want %v", runArgv, want)
	}
	out, err = c.HostExecFn(context.Background(), true, 0, "journalctl", "-n", "1")
	if err != nil || out != "combined\n" {
		t.Fatalf("HostExecFn combined out=%q err=%v", out, err)
	}
	if !reflect.DeepEqual(combArgv, []string{"journalctl", "-n", "1"}) {
		t.Fatalf("combined argv=%v", combArgv)
	}
}

// TestStatfsFreeBytes — the StatFSFn production default: real
// syscall.Statfs on the path's filesystem, sane byte counts, and
// an error for a path that does not exist.
func TestStatfsFreeBytes(t *testing.T) {
	free, total, err := statfsFreeBytes(t.TempDir())
	if err != nil {
		t.Fatalf("statfsFreeBytes: %v", err)
	}
	if total <= 0 || free <= 0 || free > total {
		t.Fatalf("free=%d total=%d — implausible statfs counts", free, total)
	}
	if _, _, err := statfsFreeBytes(
		filepath.Join(t.TempDir(), "no-such-path")); err == nil {
		t.Fatal("statfsFreeBytes on missing path returned nil error")
	}
}

func TestKeepKCMetricsLine(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"leader_election_master_status{name=\"kube-controller-manager\"} 1", true},
		{"  \tkonnectivity_network_proxy_server_ready_backend_connections 3", true},
		{"# HELP apiserver_storage_objects ...", false},
		{"go_goroutines 100", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := keepKCMetricsLine([]byte(tc.line)); got != tc.want {
			t.Errorf("keepKCMetricsLine(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}
