// binary_skew_test.go — binaryNewerThanService: the mtime-vs-
// active-since probe behind the nebula/coredns restart-on-skew
// decision.
package hostconfig

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

func TestBinaryNewerThanService(t *testing.T) {
	nowMono, err := defaultMonoNow()
	if err != nil {
		t.Skipf("CLOCK_MONOTONIC unavailable: %v", err)
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

	// Binary older than the daemon's active-since → not stale.
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(binPath, past, past); err != nil {
		t.Fatal(err)
	}
	activeSinceSec := int64((nowMono - time.Hour) / time.Second)
	if activeSinceSec < 1 {
		t.Skip("host monotonic uptime < 1h — cannot place active-since 1h ago")
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

// TestBinaryNewerThanServiceSuspendDrift verifies CLOCK_MONOTONIC alignment:
// after a 2h VM suspend, CLOCK_BOOTTIME (btime) diverges from CLOCK_MONOTONIC,
// but ActiveEnterTimestampMonotonic compared against CLOCK_MONOTONIC + Clock.Now()
// accurately knows the daemon started 5m ago vs a binary written 6m ago (not stale).
func TestBinaryNewerThanServiceSuspendDrift(t *testing.T) {
	vars := writeVarsDir(t, "")
	hr := t.TempDir()
	binPath := filepath.Join(hr, "usr/local/bin/fakebin")
	if err := os.MkdirAll(filepath.Dir(binPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}

	nowWall := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	// Binary written 6m before resume.
	binMtime := nowWall.Add(-6 * time.Minute)
	if err := os.Chtimes(binPath, binMtime, binMtime); err != nil {
		t.Fatal(err)
	}

	// Host ran 1h monotonic before suspend; daemon started at mono=55m (5m ago
	// on CLOCK_MONOTONIC, so 5m before nowWall even though VM suspended for 2h).
	nowMono := 60 * time.Minute
	daemonStartMono := 55 * time.Minute

	mk := func(monoVal time.Duration, monoErr error, enterUS int64) *cyc {
		t.Helper()
		sr := newScripted(map[string]string{
			"ActiveEnterTimestampMonotonic": fmt.Sprintf("%d\n", enterUS),
		}, nil)
		r, err := New(Config{
			NodeName: "node-b",
			VarsDir:  vars,
			Runner:   sr,
			Base: subframe.Base{
				HostRoot: hr,
				Clock:    timex.NewCell(func() time.Time { return nowWall }),
			},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return &cyc{
			r:       r,
			ctx:     context.Background(),
			monoNow: func() (time.Duration, error) { return monoVal, monoErr },
		}
	}

	if c := mk(nowMono, nil, daemonStartMono.Microseconds()); c.binaryNewerThanService("/usr/local/bin/fakebin", "fake.service") {
		t.Fatal("false stale detected across suspend drift (binary older than daemon)")
	}

	// Binary written 2m ago (newer than daemon started 5m ago) → stale.
	newMtime := nowWall.Add(-2 * time.Minute)
	if err := os.Chtimes(binPath, newMtime, newMtime); err != nil {
		t.Fatal(err)
	}
	if c := mk(nowMono, nil, daemonStartMono.Microseconds()); !c.binaryNewerThanService("/usr/local/bin/fakebin", "fake.service") {
		t.Fatal("newer binary not detected as stale")
	}

	// monoDur > nowMono (inconsistent kernel clock) → fail-safe false.
	if c := mk(nowMono, nil, (nowMono + time.Minute).Microseconds()); c.binaryNewerThanService("/usr/local/bin/fakebin", "fake.service") {
		t.Fatal("monoDur > nowMono flagged stale")
	}

	// monoNow error → fail-safe false.
	if c := mk(0, errors.New("clock error"), daemonStartMono.Microseconds()); c.binaryNewerThanService("/usr/local/bin/fakebin", "fake.service") {
		t.Fatal("monoNow error flagged stale")
	}
}
