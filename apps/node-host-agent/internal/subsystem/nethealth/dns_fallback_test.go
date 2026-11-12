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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

// --- dns-fallback (20) ---

func TestDNSFallbackPinAndRecover(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{
		DNSFallback: []watchdogconf.DNSEntry{
			{Name: "api.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.1", "10.0.0.2"}},
		},
	})
	testutil.WriteFile(t, e.resv, "nameserver 10.1.1.1\n")
	latch := "dns-fallback"

	// All NS fail → counter, no pin yet (need 2 cycles).
	e.n.Cycle(context.Background())
	if strings.Contains(testutil.ReadFile(t, e.hosts), "node-watchdog-dns") {
		t.Fatal("pinned before ConsecNeeded")
	}
	// Cycle 2: still failing → pin last-good/candidates that TCP-answer.
	e.tcpOK["10.0.0.2:6443"] = true
	e.n.Cycle(context.Background())
	hosts := testutil.ReadFile(t, e.hosts)
	if !strings.Contains(hosts, "10.0.0.2 api.test.internal") {
		t.Fatalf("no pin written:\n%s", hosts)
	}
	if !stateExists(e, latch) {
		t.Fatal("dns-fallback latch missing")
	}
	// DNS recovers → the pin survives the FIRST success (unpin is
	// hysteretic like the pin-on streak) and the second consecutive
	// success removes block + pin + latch.
	e.dnsOK["10.1.1.1|api.test.internal"] = "10.0.0.1"
	e.n.Cycle(context.Background())
	if !strings.Contains(testutil.ReadFile(t, e.hosts), "10.0.0.2 api.test.internal") {
		t.Fatalf("a single success tore the pin out:\n%s", testutil.ReadFile(t, e.hosts))
	}
	e.n.Cycle(context.Background())
	hosts = testutil.ReadFile(t, e.hosts)
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
	if got := fsx.ReadTrimmed(filepath.Join(e.state, "dnsfb-lg-api.test.internal")); got != "10.0.0.1" {
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
	testutil.WriteFile(t, e.resv, "nameserver 10.1.1.1\n")
	// Pre-existing pin; DNS fails; candidate unreachable → keep pin.
	testutil.WriteFile(t, filepath.Join(e.state, "dnsfb-pin-api.test.internal"),
		"10.0.0.1 api.test.internal\n")
	testutil.WriteFile(t, e.hosts, "127.0.0.1 localhost\n# BEGIN node-watchdog-dns\n"+
		"10.0.0.1 api.test.internal\n# END node-watchdog-dns\n")
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	if !strings.Contains(testutil.ReadFile(t, e.hosts), "10.0.0.1 api.test.internal") {
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
	testutil.WriteFile(t, e.hosts, "127.0.0.1 localhost\n"+
		hostsBlockBegin+"\n10.0.0.1 stranded.example\n")

	if _, err := e.n.renderHostsBlock("10.0.0.2 api.y\n"); err != nil {
		t.Fatal("unterminated block not rewritten")
	}
	hosts := testutil.ReadFile(t, e.hosts)
	if !strings.Contains(hosts, "10.0.0.1 stranded.example") {
		t.Fatalf("tail after unterminated BEGIN dropped:\n%s", hosts)
	}
	if !strings.Contains(hosts, hostsBlockEnd) ||
		!strings.Contains(hosts, "10.0.0.2 api.y") {
		t.Fatalf("new block not written well-formed:\n%s", hosts)
	}
	// The rewrite is convergent: the next render sees a clean file.
	if changed, _ := e.n.renderHostsBlock("10.0.0.2 api.y\n"); changed {
		t.Fatalf("rewrite not idempotent:\n%s", testutil.ReadFile(t, e.hosts))
	}

	// Removing the block keeps the tail too.
	testutil.WriteFile(t, e.hosts, "127.0.0.1 localhost\n"+
		hostsBlockBegin+"\n10.0.0.1 stranded.example\n")
	if _, err := e.n.renderHostsBlock(""); err != nil {
		t.Fatal("unterminated block removal not rewritten")
	}
	hosts = testutil.ReadFile(t, e.hosts)
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
	testutil.WriteFile(t, e.hosts, "127.0.0.1 localhost\n"+
		hostsBlockBegin+"\n"+
		"10.0.0.9 api.test.internal\n"+ // stale pin on a managed name
		"10.0.0.7 stranded.example\n") // foreign entry — rescued

	if _, err := e.n.renderHostsBlock("10.0.0.2 api.test.internal\n"); err != nil {
		t.Fatal("unterminated block not rewritten")
	}
	hosts := testutil.ReadFile(t, e.hosts)
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
// makes rename(2) return EBUSY — fsx.WriteFileAtomic must fall
// back to a direct fsync'd write instead of never landing the pin.
func TestWriteFileAtomicBusyFallback(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "hosts")
	testutil.WriteFile(t, target, "127.0.0.1 localhost\n")

	old := fsx.RenameFile
	defer func() { fsx.RenameFile = old }()
	fsx.RenameFile = func(_, _ string) error { return unix.EBUSY }

	if err := fsx.WriteFileAtomic(target, "1.2.3.4 pinned.example\n"); err != nil {
		t.Fatalf("WriteFileAtomic EBUSY fallback failed: %v", err)
	}
	if got := testutil.ReadFile(t, target); got != "1.2.3.4 pinned.example\n" {
		t.Fatalf("content after fallback=%q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, ".tmp-hosts")); !os.IsNotExist(err) {
		t.Fatal("tmp file left behind after fallback")
	}

	// A non-fallback rename error propagates and never touches the
	// target — the fallback is EBUSY/EXDEV only.
	fsx.RenameFile = func(_, _ string) error { return unix.EPERM }
	if err := fsx.WriteFileAtomic(target, "9.9.9.9 evil\n"); !errors.Is(err, unix.EPERM) {
		t.Fatalf("WriteFileAtomic err=%v want EPERM", err)
	}
	if got := testutil.ReadFile(t, target); got != "1.2.3.4 pinned.example\n" {
		t.Fatalf("target overwritten on non-fallback rename error:\n%s", got)
	}
}

func TestDNSFallbackEmptyMapCleans(t *testing.T) {
	e := fixture(t, nil) // empty conf
	testutil.WriteFile(t, e.resv, "nameserver 10.1.1.1\n")
	testutil.WriteFile(t, e.hosts, "127.0.0.1 localhost\n# BEGIN node-watchdog-dns\n"+
		"10.0.0.1 api.x\n# END node-watchdog-dns\n")
	testutil.WriteFile(t, filepath.Join(e.state, "dnsfb-pin-api.x"), "10.0.0.1 api.x\n")
	testutil.WriteFile(t, filepath.Join(e.state, "state-dns-fallback"), "1\n")
	e.n.Cycle(context.Background())
	if strings.Contains(testutil.ReadFile(t, e.hosts), "node-watchdog-dns") {
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
	testutil.WriteFile(t, e.resv, "nameserver 10.1.1.1\n")
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
	testutil.WriteFile(t, e.resv, "nameserver 10.1.1.1\n")
	for _, f := range []string{"dnsfb-pin-api.x", "dnsfb-lg-api.x", "dnsfb-ctr-api.x"} {
		testutil.WriteFile(t, filepath.Join(e.state, f), "x\n")
	}
	e.n.Cycle(context.Background())
	for _, f := range []string{"dnsfb-pin-api.x", "dnsfb-lg-api.x", "dnsfb-ctr-api.x"} {
		if _, err := os.Stat(filepath.Join(e.state, f)); !os.IsNotExist(err) {
			t.Fatalf("%s kept with empty map", f)
		}
	}
}

// nameservers parses up to max entries and tolerates a missing file
// (no nameservers → DNS probes idle).
func TestNameserversParsing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	testutil.WriteFile(t, path,
		"# comment\nnameserver 10.0.0.1\nsearch x\nnameserver 10.0.0.2\nnameserver 10.0.0.3\nnameserver 10.0.0.4\n")
	got := nameservers(path, 3)
	if len(got) != 3 || got[0] != "10.0.0.1" || got[2] != "10.0.0.3" {
		t.Fatalf("nameservers=%v want first 3", got)
	}
	if got := nameservers(filepath.Join(t.TempDir(), "absent"), 3); got != nil {
		t.Fatalf("missing file nameservers=%v want nil", got)
	}
}

// An unreadable hosts file must not be rewritten — renderHostsBlock
// refuses and reports no change AND an error (the caller must be
// able to tell "unchanged" from "not applied").
func TestRenderHostsBlockUnreadableFile(t *testing.T) {
	e := fixture(t, nil)
	e.n.cfg.HostsFile = filepath.Join(t.TempDir(), "absent-hosts")
	if changed, err := e.n.renderHostsBlock("10.0.0.1 api\n"); changed || err == nil {
		t.Fatalf("changed=%v err=%v — rendered into an unreadable hosts file", changed, err)
	}
}

// A hosts file that cannot be atomically rewritten (read-only
// directory — the read-only /etc bind mount case) reports no change
// AND an error instead of crashing the cycle.
func TestRenderHostsBlockWriteFailure(t *testing.T) {
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts")
	testutil.WriteFile(t, hosts, "127.0.0.1 localhost\n")
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	e := fixture(t, nil)
	e.n.cfg.HostsFile = hosts
	if changed, err := e.n.renderHostsBlock("10.0.0.1 api\n"); changed || err == nil {
		t.Fatalf("changed=%v err=%v — claimed success on a failed write", changed, err)
	}
	if got := testutil.ReadFile(t, hosts); got != "127.0.0.1 localhost\n" {
		t.Fatalf("hosts mutated despite write failure: %q", got)
	}
}

// A dnsfb-pin-<name> file that cannot be overwritten (a directory
// squatting the path) must not abort the cycle — the pin action is
// logged, the write failure logged, the cycle moves on.
func TestDNSFallbackPinWriteFailureLogged(t *testing.T) {
	wd := &watchdogconf.Config{DNSFallback: []watchdogconf.DNSEntry{
		{Name: "api.test.internal", Port: "6443",
			Candidates: []string{"10.0.0.1"}},
	}}
	e := fixture(t, wd)
	testutil.WriteFile(t, e.resv, "nameserver 10.1.1.1\n")
	e.tcpOK["10.0.0.1:6443"] = true
	if err := os.MkdirAll(filepath.Join(e.state, "dnsfb-pin-api.test.internal"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	if !strings.Contains(logLines(t, e), "pin file write failed for api.test.internal") {
		t.Fatalf("missing pin-write failure log:\n%s", logLines(t, e))
	}
}

// An unwritable last-known-good file (directory squatting the path)
// logs the warning; resolution otherwise proceeds and the fail
// counter still resets.
func TestDNSFallbackLastGoodWriteFailureLogged(t *testing.T) {
	wd := &watchdogconf.Config{DNSFallback: []watchdogconf.DNSEntry{
		{Name: "api.test.internal", Port: "6443"},
	}}
	e := fixture(t, wd)
	testutil.WriteFile(t, e.resv, "nameserver 10.1.1.1\n")
	e.dnsOK["10.1.1.1|api.test.internal"] = "10.0.0.9"
	if err := os.MkdirAll(filepath.Join(e.state, "dnsfb-lg-api.test.internal"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.n.Cycle(context.Background())
	// The warning goes to the structured log (slog), the observable
	// on-disk contract is: the squatting directory is untouched, the
	// cycle completed cleanly — DNS answered, so no latch armed and
	// the stale pin (none) was cleared as usual.
	if _, err := os.Stat(filepath.Join(e.state, "dnsfb-pin-api.test.internal")); !os.IsNotExist(err) {
		t.Fatal("pin file resurrected on a DNS-ok cycle")
	}
	if stateExists(e, "dns-fallback") {
		t.Fatal("latch armed while DNS answered")
	}
}

// A pin left for a name dropped from the map loses its pin AND its
// dnsfb-ctr counter file; a counter file for a still-mapped name is
// not touched by the prune (the counter dir file is legacy shell
// residue — the Go port keeps the counter in memory).
func TestDNSFallbackPruneRemovesCtrFile(t *testing.T) {
	wd := &watchdogconf.Config{DNSFallback: []watchdogconf.DNSEntry{
		{Name: "api.test.internal", Port: "6443"},
	}}
	e := fixture(t, wd)
	pinGone := filepath.Join(e.state, "dnsfb-pin-old.test.internal")
	ctrGone := filepath.Join(e.state, "dnsfb-ctr-old.test.internal")
	testutil.WriteFile(t, pinGone, "10.9.9.9 old.test.internal\n")
	testutil.WriteFile(t, ctrGone, "3\n")
	e.n.Cycle(context.Background())
	for _, f := range []string{pinGone, ctrGone} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Fatalf("prune kept %s", f)
		}
	}
}

// TestDNSFallbackUnpinNeedsConsecSuccesses: the unpin is hysteretic
// like the pin — one successful probe must NOT tear the pin (and the
// managed block) out, and a failure between successes resets the
// streak. The pin drops only after ConsecNeeded CONSECUTIVE
// successes; on flapping DNS a single lucky resolution must not
// toggle the block (and its conntrack flush) every other cycle.
func TestDNSFallbackUnpinNeedsConsecSuccesses(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{
		DNSFallback: []watchdogconf.DNSEntry{
			{Name: "api.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.2"}},
		},
	})
	testutil.WriteFile(t, e.resv, "nameserver 10.1.1.1\n")
	e.tcpOK["10.0.0.2:6443"] = true

	// Two failing cycles → pin 10.0.0.2.
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	if !strings.Contains(testutil.ReadFile(t, e.hosts), "10.0.0.2 api.test.internal") {
		t.Fatalf("no pin written:\n%s", testutil.ReadFile(t, e.hosts))
	}

	// One successful resolution → pin kept.
	e.dnsOK["10.1.1.1|api.test.internal"] = "10.0.0.1"
	e.n.Cycle(context.Background())
	if !strings.Contains(testutil.ReadFile(t, e.hosts), "10.0.0.2 api.test.internal") {
		t.Fatal("a single success tore the pin out")
	}

	// A failed probe between successes resets the streak.
	delete(e.dnsOK, "10.1.1.1|api.test.internal")
	e.n.Cycle(context.Background())
	e.dnsOK["10.1.1.1|api.test.internal"] = "10.0.0.1"
	e.n.Cycle(context.Background())
	if !strings.Contains(testutil.ReadFile(t, e.hosts), "10.0.0.2 api.test.internal") {
		t.Fatal("pin dropped although a failure interrupted the success streak")
	}

	// Second consecutive success → unpin: block + pin + latch gone.
	e.n.Cycle(context.Background())
	if strings.Contains(testutil.ReadFile(t, e.hosts), "10.0.0.2 api.test.internal") {
		t.Fatalf("pin kept after ConsecNeeded consecutive successes:\n%s",
			testutil.ReadFile(t, e.hosts))
	}
	if stateExists(e, "dns-fallback") {
		t.Fatal("latch kept after unpin")
	}
}

// A failed hosts render must not lie to the condition: with a pin to
// apply but an unwritable hosts file, the dns-fallback latch stays
// UNENTERED — the block never landed, kubelet still resolves against
// dead DNS, and claiming engagement would misreport the node
// condition. The failure is logged distinctly.
func TestDNSFallbackWriteFailureDoesNotEnterLatch(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{
		DNSFallback: []watchdogconf.DNSEntry{
			{Name: "api.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.1"}},
		},
	})
	testutil.WriteFile(t, e.resv, "nameserver 10.1.1.1\n")
	e.tcpOK["10.0.0.1:6443"] = true
	ro := t.TempDir()
	hosts := filepath.Join(ro, "hosts")
	testutil.WriteFile(t, hosts, "127.0.0.1 localhost\n")
	if err := os.Chmod(ro, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o755) })
	e.n.cfg.HostsFile = hosts

	for range 2 { // ConsecNeeded cycles → pin file written
		e.n.Cycle(context.Background())
	}
	if pins := e.n.pinFiles(); len(pins) == 0 {
		t.Fatal("pin file not written — test setup broken")
	}
	if stateExists(e, "dns-fallback") {
		t.Fatal("dns-fallback latch entered although the hosts block never landed")
	}
	if !strings.Contains(logLines(t, e), "block not applied") {
		t.Fatalf("render failure not logged distinctly:\n%s", logLines(t, e))
	}
}

// Symmetric honesty on the exit side: a map-empty cleanup whose
// hosts render fails must KEEP the latch — the block may still sit
// in the hosts file, so exiting would claim the remediation ended
// while the pins are still live.
func TestDNSFallbackEmptyMapWriteFailureKeepsLatch(t *testing.T) {
	e := fixture(t, nil) // empty map → the cleanup path
	ro := t.TempDir()
	hosts := filepath.Join(ro, "hosts")
	testutil.WriteFile(t, hosts, "127.0.0.1 localhost\n"+
		"# BEGIN node-watchdog-dns\n10.0.0.1 api.x\n# END node-watchdog-dns\n")
	if err := os.Chmod(ro, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o755) })
	e.n.cfg.HostsFile = hosts
	testutil.WriteFile(t, filepath.Join(e.state, "state-dns-fallback"), "1\n")

	e.n.Cycle(context.Background())
	if !stateExists(e, "dns-fallback") {
		t.Fatal("latch exited although the hosts render failed and the block is still live")
	}
	if got := testutil.ReadFile(t, hosts); !strings.Contains(got, "10.0.0.1 api.x") {
		t.Fatalf("hosts mutated despite write failure: %q", got)
	}
}
