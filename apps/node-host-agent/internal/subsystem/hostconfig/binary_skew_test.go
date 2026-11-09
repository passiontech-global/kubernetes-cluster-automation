// binary_skew_test.go — binaryNewerThanService: the mtime-vs-
// active-since probe behind the nebula/coredns restart-on-skew
// decision.
package hostconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBinaryNewerThanService(t *testing.T) {
	btime, err := procBootEpoch()
	if err != nil {
		t.Skipf("/proc/stat btime unavailable: %v", err)
	}
	vars := writeVarsDir(t, "")
	hr := t.TempDir()
	binPath := filepath.Join(hr, "usr/local/bin/fakebin")
	if err := os.MkdirAll(filepath.Dir(binPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	mkCyc := func(res map[string]string, errs map[string]bool) *cyc {
		t.Helper()
		sr := newScripted(res, errs)
		r, err := New(Config{NodeName: "node-b", HostRoot: hr,
			VarsDir: vars, Runner: sr}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return &cyc{r: r, ctx: context.Background()}
	}

	// Fresh binary vs a daemon active since ~boot → stale.
	if c := mkCyc(map[string]string{
		"ActiveEnterTimestampMonotonic": "1000000\n",
	}, nil); !c.binaryNewerThanService("/usr/local/bin/fakebin", "fake.service") {
		t.Fatal("binary newer than active-since not detected")
	}

	// Binary older than the daemon's active-since → not stale. The
	// 2020 mtime loses to ANY plausible active-since (btime is this
	// boot, always after 2020); the daemon side is placed 1h ago on
	// the monotonic clock.
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(binPath, past, past); err != nil {
		t.Fatal(err)
	}
	activeSinceSec := time.Now().Add(-time.Hour).Unix() - btime
	if activeSinceSec < 1 {
		t.Skip("host uptime < 1h — cannot place active-since in the past")
	}
	if c := mkCyc(map[string]string{
		"ActiveEnterTimestampMonotonic": fmt.Sprintf("%d\n", activeSinceSec*1_000_000),
	}, nil); c.binaryNewerThanService("/usr/local/bin/fakebin", "fake.service") {
		t.Fatal("old binary flagged stale against a newer daemon")
	}
	if err := os.Chtimes(binPath, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}

	// Every probe failure answers false — "can't tell" must not
	// flap the unit.
	for name, c := range map[string]*cyc{
		"never active": mkCyc(map[string]string{"ActiveEnterTimestampMonotonic": "0\n"}, nil),
		"garbage":      mkCyc(map[string]string{"ActiveEnterTimestampMonotonic": "n/a\n"}, nil),
		"show failed":  mkCyc(nil, map[string]bool{"ActiveEnterTimestampMonotonic": true}),
	} {
		if c.binaryNewerThanService("/usr/local/bin/fakebin", "fake.service") {
			t.Fatalf("%s: probe failure flagged stale", name)
		}
	}
	if c := mkCyc(nil, nil); c.binaryNewerThanService("/usr/local/bin/missing", "fake.service") {
		t.Fatal("missing binary flagged stale")
	}
}
