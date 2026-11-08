// seams_test.go — the Ctr/Cilium derived reads and the shared
// parser they compose: the ctr argv builders over the one Exec seam,
// the lease-table parser, and the wg/cilium-API derived reads
// (systemd exec + unix GET stubs, parsers exercised for real).
package wdeps_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// peerRow renders one 8-column `wg dump` peer row.
func peerRow(pub, allowedIPs string, handshake, rx, tx int64) string {
	return fmt.Sprintf("%s\tpsk\t12.0.0.9:51820\t%s\t%d\t%d\t%d\t25\n",
		pub, allowedIPs, handshake, rx, tx)
}

// --- Ctr named methods over the one Exec/ExecOut seam ---

// TestCtrMethodsBuildArgv — every rm/prune method builds its exact
// argv over the Ctr.Exec seam and propagates its error; Leases goes
// over ExecOut and parses the table.
func TestCtrMethodsBuildArgv(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()

	var argv []string
	e.D.Cfg.Seams.Ctr.Exec = func(_ context.Context, a ...string) error {
		argv = a
		return nil
	}
	cases := []struct {
		name string
		run  func() error
		want []string
	}{
		{"RmImage", func() error { return e.D.Cfg.Seams.Ctr.RmImage(ctx, "img:tag") },
			[]string{"k0s", "ctr", "--namespace", "k8s.io", "images", "rm", "--sync", "img:tag"}},
		{"RmIngest", func() error { return e.D.Cfg.Seams.Ctr.RmIngest(ctx, "sha256:abc") },
			[]string{"k0s", "ctr", "-n", "k8s.io", "content", "ingest", "rm", "sha256:abc"}},
		{"PruneContent", func() error { return e.D.Cfg.Seams.Ctr.PruneContent(ctx) },
			[]string{"k0s", "ctr", "-n", "k8s.io", "content", "prune"}},
		{"RmLease", func() error { return e.D.Cfg.Seams.Ctr.RmLease(ctx, "lease-1") },
			[]string{"k0s", "ctr", "-n", "k8s.io", "leases", "rm", "lease-1"}},
	}
	for _, tc := range cases {
		if err := tc.run(); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if strings.Join(argv, " ") != strings.Join(tc.want, " ") {
			t.Fatalf("%s argv=%v want %v", tc.name, argv, tc.want)
		}
	}

	// Error propagation — the exec failure IS the method's failure.
	wantErr := errors.New("exec failed")
	e.D.Cfg.Seams.Ctr.Exec = func(context.Context, ...string) error { return wantErr }
	if err := e.D.Cfg.Seams.Ctr.RmImage(ctx, "img:tag"); !errors.Is(err, wantErr) {
		t.Fatalf("RmImage error=%v want %v", err, wantErr)
	}

	// Leases reads over ExecOut and parses the table output.
	table := "ID                                                              CREATED                     \n" +
		"lease-1                                                         2026-01-02 15:04:05.123 +0000 UTC\n" +
		"lease-2                                                         2026-03-04 05:06:07 +0000 UTC    containerd.io/gc.expire=lease-2\n"
	e.D.Cfg.Seams.Ctr.ExecOut = func(_ context.Context, a ...string) (string, error) {
		if strings.Join(a, " ") != "k0s ctr -n k8s.io leases ls" {
			t.Fatalf("Leases argv=%v", a)
		}
		return table, nil
	}
	leases, err := e.D.Cfg.Seams.Ctr.Leases(ctx)
	if err != nil {
		t.Fatalf("Leases: %v", err)
	}
	if len(leases) != 2 || leases[0].ID != "lease-1" || leases[1].ID != "lease-2" || !leases[1].HasGCExp {
		t.Fatalf("Leases=%+v", leases)
	}
	// An exec error aborts the read.
	e.D.Cfg.Seams.Ctr.ExecOut = func(context.Context, ...string) (string, error) {
		return "", wantErr
	}
	if _, err := e.D.Cfg.Seams.Ctr.Leases(ctx); !errors.Is(err, wantErr) {
		t.Fatalf("Leases error=%v want %v", err, wantErr)
	}
}

// TestParseCtrLeases — table output: header and blank lines skipped,
// stamps parsed from the Go time.String form (fractional seconds and
// zone are optional noise), gc.expire labels detected, garbled rows
// never invent lease evidence.
func TestParseCtrLeases(t *testing.T) {
	out := strings.Join([]string{
		"ID                                          CREATED",
		"",
		"aaa 2026-01-02 15:04:05.999999999 +0000 UTC",
		"bbb 2026-03-04 05:06:07 +0000 UTC    containerd.io/gc.expire=bbb",
		"ccc 2026-05-06 07:08:09 +0200 CEST",
		"ddd extra-field 2026-07-08 09:10:11 +0000 UTC",
		"onlyid",
		"garbage no-date-here",
	}, "\n")
	leases := wdeps.ParseCtrLeases(out)
	// The bare "onlyid" row is dropped (no stamp field to parse).
	if len(leases) != 5 {
		t.Fatalf("leases=%d want 5: %+v", len(leases), leases)
	}
	if leases[0].ID != "aaa" || leases[0].HasGCExp {
		t.Fatalf("aaa=%+v", leases[0])
	}
	// The fractional-second suffix is optional parsing noise.
	if want := time.Date(2026, 1, 2, 15, 4, 5, 999999999, time.UTC); !leases[0].Created.Equal(want) {
		t.Fatalf("aaa created=%v want %v", leases[0].Created, want)
	}
	if !leases[1].HasGCExp {
		t.Fatalf("bbb hasGCExp=false")
	}
	if want := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC); !leases[1].Created.Equal(want) {
		t.Fatalf("bbb created=%v want %v", leases[1].Created, want)
	}
	// The +zone suffix is stripped before parsing, so the wall clock
	// lands as UTC.
	if want := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC); !leases[2].Created.Equal(want) {
		t.Fatalf("ccc created=%v want %v", leases[2].Created, want)
	}
	// A non-date field between id and stamp is skipped while the
	// search keeps looking.
	if want := time.Date(2026, 7, 8, 9, 10, 11, 0, time.UTC); !leases[3].Created.Equal(want) {
		t.Fatalf("ddd created=%v want %v", leases[3].Created, want)
	}
	if leases[4].ID != "garbage" || !leases[4].Created.IsZero() || leases[4].HasGCExp {
		t.Fatalf("row 4=%+v want bare garbage", leases[4])
	}
	if got := wdeps.ParseCtrLeases(""); got != nil {
		t.Fatalf("empty input=%+v want nil", got)
	}
}

// --- Cilium derived reads ---

// TestWGAllowedIPs — the `wg show cilium_wg0 allowed-ips` exec rides
// the systemd client; peers at "(none)" don't count. A nil systemd
// client errors instead of degrading to 0.
func TestWGAllowedIPs(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	e.SDReply["wg show cilium_wg0 allowed-ips"] =
		"pubA\t10.0.0.2/32 10.0.0.3/32\npubB\t(none)\n"
	n, err := e.D.Cfg.Seams.Cilium.WGAllowedIPs(ctx, e.D.Cfg.Systemd)
	if err != nil {
		t.Fatalf("WGAllowedIPs: %v", err)
	}
	if n != 1 {
		t.Fatalf("allowed-ips peers=%d want 1", n)
	}
	if !e.SDRan("wg show cilium_wg0 allowed-ips") {
		t.Fatal("wg allowed-ips not execed through the systemd client")
	}

	// The exec failing surfaces its error, not a zero count.
	e.SDReply = map[string]string{}
	if _, err := e.D.Cfg.Seams.Cilium.WGAllowedIPs(ctx, e.D.Cfg.Systemd); err == nil {
		t.Fatal("unconfigured wg exec must error")
	}

	e.D.Cfg.Systemd = nil
	if _, err := e.D.Cfg.Seams.Cilium.WGAllowedIPs(ctx, nil); err == nil ||
		!strings.Contains(err.Error(), "no systemd client wired") {
		t.Fatalf("nil client error=%v", err)
	}
}

// TestWGDumpPeers — the dump stub answers the TSV; the interface row
// is not a peer and garbled rows are skipped. Errors propagate.
func TestWGDumpPeers(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	e.D.Cfg.Seams.Cilium.WGDump = func(_ context.Context, _ *systemd.Client) (string, error) {
		return "iface\tpsk\t12.0.0.9:51820\t(none)\n" +
			peerRow("pubA", "10.0.0.2/32", 1700000000, 100, 200) +
			"too-few-columns\n", nil
	}
	peers, err := e.D.Cfg.Seams.Cilium.WGDumpPeers(ctx, e.D.Cfg.Systemd)
	if err != nil {
		t.Fatalf("WGDumpPeers: %v", err)
	}
	if len(peers) != 1 || peers[0].Pub != "pubA" ||
		peers[0].AllowedIPs != "10.0.0.2/32" ||
		peers[0].Handshake != 1700000000 || peers[0].RX != 100 || peers[0].TX != 200 {
		t.Fatalf("peers=%+v", peers)
	}

	wantErr := errors.New("dump failed")
	e.D.Cfg.Seams.Cilium.WGDump = func(context.Context, *systemd.Client) (string, error) {
		return "", wantErr
	}
	if _, err := e.D.Cfg.Seams.Cilium.WGDumpPeers(ctx, e.D.Cfg.Systemd); !errors.Is(err, wantErr) {
		t.Fatalf("dump error=%v want %v", err, wantErr)
	}
}

// TestEncryptPeers — /v1/healthz over the unix seam: the
// cluster.nodes[] member count is the expected peer count; a body
// without the section and a transport error both error (the caller
// falls back to ReadyNodes-1).
func TestEncryptPeers(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()

	e.UnixBody = []byte(`{"cluster":{"nodes":[{},{},{}]}}`)
	n, err := e.D.Cfg.Seams.Cilium.EncryptPeers(ctx, "/run/cilium/cilium.sock")
	if err != nil {
		t.Fatalf("EncryptPeers: %v", err)
	}
	if n != 3 {
		t.Fatalf("peers=%d want 3", n)
	}

	e.UnixBody = []byte(`{"cluster":{"nodes":[]}}`)
	if _, err := e.D.Cfg.Seams.Cilium.EncryptPeers(ctx, "sock"); err == nil ||
		!strings.Contains(err.Error(), "no cluster.nodes") {
		t.Fatalf("empty nodes error=%v", err)
	}

	e.UnixErr = errors.New("socket gone")
	if _, err := e.D.Cfg.Seams.Cilium.EncryptPeers(ctx, "sock"); !errors.Is(err, e.UnixErr) {
		t.Fatalf("transport error=%v want %v", err, e.UnixErr)
	}
}

// TestServiceBackends — the /v1/service stub renders SvcBackends
// through the real wire shape; SvcErr makes the read fail.
func TestServiceBackends(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()

	e.SvcBackends = map[string]int{"kube-system/kube-dns": 2}
	backends, err := e.D.Cfg.Seams.Cilium.ServiceBackends(ctx, "sock")
	if err != nil {
		t.Fatalf("ServiceBackends: %v", err)
	}
	if backends["kube-system/kube-dns"] != 2 || len(backends) != 1 {
		t.Fatalf("backends=%v", backends)
	}

	e.SvcErr = errors.New("map unreadable")
	if _, err := e.D.Cfg.Seams.Cilium.ServiceBackends(ctx, "sock"); !errors.Is(err, e.SvcErr) {
		t.Fatalf("SvcErr error=%v want %v", err, e.SvcErr)
	}
}
