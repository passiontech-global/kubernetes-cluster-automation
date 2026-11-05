package hostmetrics

import (
	"os"
	"path/filepath"
	"testing"
)

// --- W5.7 parsers ---

func TestPSIAvg60Full(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "memory")
	_ = os.WriteFile(f, []byte(
		"some avg10=1.25 avg60=2.50 avg300=0.10 total=99\n"+
			"full avg10=0.50 avg60=0.75 avg300=0.05 total=42\n"), 0o644)
	some, full, someOK, fullOK := psiAvg60Full(f)
	if !someOK || !fullOK || some != 2.50 || full != 0.75 {
		t.Fatalf("psiAvg60Full = (%v,%v,%v,%v), want (2.5,0.75,true,true)",
			some, full, someOK, fullOK)
	}
	if _, _, s, f := psiAvg60Full(filepath.Join(dir, "missing")); s || f {
		t.Fatal("missing file must report unparsed")
	}
}

func TestVMStatCounters(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "vmstat")
	_ = os.WriteFile(f, []byte(
		"nr_free_pages 100\npswpin 1234\npswpout 5678\nother junk\n"), 0o644)
	got := vmstatCounters(f, "pswpin", "pswpout")
	if got["pswpin"] != 1234 || got["pswpout"] != 5678 {
		t.Fatalf("vmstatCounters = %v", got)
	}
	if len(vmstatCounters(filepath.Join(dir, "missing"), "pswpin")) != 0 {
		t.Fatal("missing file must yield empty map")
	}
}

// --- W5.3 latch ---

func TestFSReadonlyLatch(t *testing.T) {
	dir := t.TempDir()
	c := New(Config{NodeName: "n1", WatchdogStateDir: dir})
	latch := filepath.Join(dir, "state-filesystem-readonly")
	c.updateFSReadonlyLatch(true, true)
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("RO mount did not latch state-filesystem-readonly")
	}
	c.updateFSReadonlyLatch(false, false) // inconclusive — latch stays
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("inconclusive scrape must not clear the latch")
	}
	c.updateFSReadonlyLatch(false, true) // all rw — clears
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("all-rw scrape did not clear the latch")
	}
}
