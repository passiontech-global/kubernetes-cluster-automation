// dns_fallback_test.go — dns-fallback host pinning, hosts-block rendering, and last-known-good recovery.

package nethealth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// --- dns-fallback (20) ---

func TestDNSFallbackPinAndRecover(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{
		DNSFallback: []watchdogconf.DNSEntry{
			{Name: "api.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.1", "10.0.0.2"}},
		},
	})
	writeFile(t, e.resv, "nameserver 10.1.1.1\n")
	latch := "dns-fallback"

	// All NS fail → counter, no pin yet (need 2 cycles).
	e.n.Cycle(context.Background())
	if strings.Contains(readFileT(t, e.hosts), "node-watchdog-dns") {
		t.Fatal("pinned before ConsecNeeded")
	}
	// Cycle 2: still failing → pin last-good/candidates that TCP-answer.
	e.tcpOK["10.0.0.2:6443"] = true
	e.n.Cycle(context.Background())
	hosts := readFileT(t, e.hosts)
	if !strings.Contains(hosts, "10.0.0.2 api.test.internal") {
		t.Fatalf("no pin written:\n%s", hosts)
	}
	if !stateExists(e, latch) {
		t.Fatal("dns-fallback latch missing")
	}
	// DNS recovers → block + pin + latch removed.
	e.dnsOK["10.1.1.1|api.test.internal"] = "10.0.0.1"
	e.n.Cycle(context.Background())
	hosts = readFileT(t, e.hosts)
	if strings.Contains(hosts, "node-watchdog-dns") {
		t.Fatalf("block not removed after recovery:\n%s", hosts)
	}
	if stateExists(e, latch) {
		t.Fatal("latch kept after recovery")
	}
	if files := e.n.pinFiles(); len(files) != 0 {
		t.Fatalf("pin files kept after recovery: %v", files)
	}
	// last-known-good cache kept the resolved IP.
	if got := hostutil.ReadTrimmed(filepath.Join(e.state, "dnsfb-lg-api.test.internal")); got != "10.0.0.1" {
		t.Fatalf("last-good=%q want 10.0.0.1", got)
	}
}

func TestDNSFallbackKeepsDeadPinWithoutReplacement(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{
		DNSFallback: []watchdogconf.DNSEntry{
			{Name: "api.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.1"}},
		},
	})
	writeFile(t, e.resv, "nameserver 10.1.1.1\n")
	// Pre-existing pin; DNS fails; candidate unreachable → keep pin.
	writeFile(t, filepath.Join(e.state, "dnsfb-pin-api.test.internal"),
		"10.0.0.1 api.test.internal\n")
	writeFile(t, e.hosts, "127.0.0.1 localhost\n# BEGIN node-watchdog-dns\n"+
		"10.0.0.1 api.test.internal\n# END node-watchdog-dns\n")
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	if !strings.Contains(readFileT(t, e.hosts), "10.0.0.1 api.test.internal") {
		t.Fatal("dead pin removed — a dead IP beats NXDOMAIN")
	}
	if !stateExists(e, "dns-fallback") {
		t.Fatal("latch missing with active pin")
	}
}

// A `# BEGIN` without `# END` (truncated/corrupted hosts file) must
// not silently eat the lines after the marker: they are kept as
// ordinary content and the rewritten file is well-formed again.
func TestRenderHostsBlockUnterminatedBegin(t *testing.T) {
	e := fixture(t, nil)
	writeFile(t, e.hosts, "127.0.0.1 localhost\n"+
		hostsBlockBegin+"\n10.0.0.1 stranded.example\n")

	if !e.n.renderHostsBlock("10.0.0.2 api.y\n") {
		t.Fatal("unterminated block not rewritten")
	}
	hosts := readFileT(t, e.hosts)
	if !strings.Contains(hosts, "10.0.0.1 stranded.example") {
		t.Fatalf("tail after unterminated BEGIN dropped:\n%s", hosts)
	}
	if !strings.Contains(hosts, hostsBlockEnd) ||
		!strings.Contains(hosts, "10.0.0.2 api.y") {
		t.Fatalf("new block not written well-formed:\n%s", hosts)
	}
	// The rewrite is convergent: the next render sees a clean file.
	if e.n.renderHostsBlock("10.0.0.2 api.y\n") {
		t.Fatalf("rewrite not idempotent:\n%s", readFileT(t, e.hosts))
	}

	// Removing the block keeps the tail too.
	writeFile(t, e.hosts, "127.0.0.1 localhost\n"+
		hostsBlockBegin+"\n10.0.0.1 stranded.example\n")
	if !e.n.renderHostsBlock("") {
		t.Fatal("unterminated block removal not rewritten")
	}
	hosts = readFileT(t, e.hosts)
	if !strings.Contains(hosts, "10.0.0.1 stranded.example") {
		t.Fatalf("tail dropped on block removal:\n%s", hosts)
	}
	if strings.Contains(hosts, hostsBlockBegin) {
		t.Fatalf("stray BEGIN kept:\n%s", hosts)
	}
}

// A tail line pinning a MANAGED fallback name is residue of an
// earlier managed block — keeping it above the new block would let a
// dead pin shadow the fresh one (first match wins). Foreign names
// still get the rescue.
func TestRenderHostsBlockTailDropsStaleManagedPins(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{
		DNSFallback: []watchdogconf.DNSEntry{
			{Name: "api.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.2"}},
		},
	})
	writeFile(t, e.hosts, "127.0.0.1 localhost\n"+
		hostsBlockBegin+"\n"+
		"10.0.0.9 api.test.internal\n"+ // stale pin on a managed name
		"10.0.0.7 stranded.example\n") // foreign entry — rescued

	if !e.n.renderHostsBlock("10.0.0.2 api.test.internal\n") {
		t.Fatal("unterminated block not rewritten")
	}
	hosts := readFileT(t, e.hosts)
	if !strings.Contains(hosts, "10.0.0.7 stranded.example") {
		t.Fatalf("foreign tail entry dropped:\n%s", hosts)
	}
	if strings.Contains(hosts, "10.0.0.9 api.test.internal") {
		t.Fatalf("stale managed pin kept in tail — shadows fresh pin:\n%s", hosts)
	}
	if !strings.Contains(hosts,
		hostsBlockBegin+"\n10.0.0.2 api.test.internal\n"+hostsBlockEnd) {
		t.Fatalf("fresh block not written well-formed:\n%s", hosts)
	}
}

// A file-level bind mount (the DaemonSet's /host/etc/hosts mount)
// makes rename(2) return EBUSY — hostutil.WriteFileAtomic must fall
// back to a direct fsync'd write instead of never landing the pin.
func TestWriteFileAtomicBusyFallback(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "hosts")
	writeFile(t, target, "127.0.0.1 localhost\n")

	old := hostutil.RenameFile
	defer func() { hostutil.RenameFile = old }()
	hostutil.RenameFile = func(_, _ string) error { return unix.EBUSY }

	if err := hostutil.WriteFileAtomic(target, "1.2.3.4 pinned.example\n"); err != nil {
		t.Fatalf("WriteFileAtomic EBUSY fallback failed: %v", err)
	}
	if got := readFileT(t, target); got != "1.2.3.4 pinned.example\n" {
		t.Fatalf("content after fallback=%q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, ".tmp-hosts")); !os.IsNotExist(err) {
		t.Fatal("tmp file left behind after fallback")
	}

	// A non-fallback rename error propagates and never touches the
	// target — the fallback is EBUSY/EXDEV only.
	hostutil.RenameFile = func(_, _ string) error { return unix.EPERM }
	if err := hostutil.WriteFileAtomic(target, "9.9.9.9 evil\n"); !errors.Is(err, unix.EPERM) {
		t.Fatalf("WriteFileAtomic err=%v want EPERM", err)
	}
	if got := readFileT(t, target); got != "1.2.3.4 pinned.example\n" {
		t.Fatalf("target overwritten on non-fallback rename error:\n%s", got)
	}
}

func TestDNSFallbackEmptyMapCleans(t *testing.T) {
	e := fixture(t, nil) // empty conf
	writeFile(t, e.resv, "nameserver 10.1.1.1\n")
	writeFile(t, e.hosts, "127.0.0.1 localhost\n# BEGIN node-watchdog-dns\n"+
		"10.0.0.1 api.x\n# END node-watchdog-dns\n")
	writeFile(t, filepath.Join(e.state, "dnsfb-pin-api.x"), "10.0.0.1 api.x\n")
	writeFile(t, filepath.Join(e.state, "state-dns-fallback"), "1\n")
	e.n.Cycle(context.Background())
	if strings.Contains(readFileT(t, e.hosts), "node-watchdog-dns") {
		t.Fatal("block kept with empty map")
	}
	if stateExists(e, "dns-fallback") {
		t.Fatal("latch kept with empty map")
	}
	if files := e.n.pinFiles(); len(files) != 0 {
		t.Fatalf("pins kept with empty map: %v", files)
	}
}

// TestDNSFallbackPrunesFailCounters: a name dropped from
// DNS_FALLBACK_MAP loses its in-memory fail counter alongside the
// pin/counter files — otherwise dnsfails grows with every map edit.
func TestDNSFallbackPrunesFailCounters(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{
		DNSFallback: []watchdogconf.DNSEntry{
			{Name: "api.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.1"}},
			{Name: "gone.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.1"}},
		},
	})
	writeFile(t, e.resv, "nameserver 10.1.1.1\n")
	// All lookups fail → both names accumulate fail counters.
	e.n.Cycle(context.Background())
	if len(e.n.dnsfails) != 2 {
		t.Fatalf("dnsfails = %v, want 2 entries", e.n.dnsfails)
	}

	// Drop the second name from the map → its counter is pruned.
	e.n.cfg.Watchdog = &watchdogconf.Config{
		DNSFallback: []watchdogconf.DNSEntry{
			{Name: "api.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.1"}},
		},
	}
	e.n.Cycle(context.Background())
	if _, ok := e.n.dnsfails["gone.test.internal"]; ok {
		t.Fatal("dnsfails kept a name removed from DNS_FALLBACK_MAP")
	}
	if _, ok := e.n.dnsfails["api.test.internal"]; !ok {
		t.Fatal("dnsfails lost the still-mapped name")
	}
}

func TestDNSFallbackEmptyMapRemovesAllDNSFBFiles(t *testing.T) {
	e := fixture(t, nil)
	writeFile(t, e.resv, "nameserver 10.1.1.1\n")
	for _, f := range []string{"dnsfb-pin-api.x", "dnsfb-lg-api.x", "dnsfb-ctr-api.x"} {
		writeFile(t, filepath.Join(e.state, f), "x\n")
	}
	e.n.Cycle(context.Background())
	for _, f := range []string{"dnsfb-pin-api.x", "dnsfb-lg-api.x", "dnsfb-ctr-api.x"} {
		if _, err := os.Stat(filepath.Join(e.state, f)); !os.IsNotExist(err) {
			t.Fatalf("%s kept with empty map", f)
		}
	}
}
