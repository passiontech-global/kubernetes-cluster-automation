// group_thp_test.go — unit tests for Wave-4 #9 THP convergence and rp_filter integration.
package hostconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
)

func TestParseTHPActive(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "madvise", raw: "always [madvise] never\n", want: "madvise"},
		{name: "always", raw: "[always] madvise never\n", want: "always"},
		{name: "defer_plus_madvise", raw: "always defer [defer+madvise] madvise never\n", want: "defer+madvise"},
		{name: "single_bare", raw: "madvise\n", want: "madvise"},
		{name: "empty", raw: "", want: ""},
		{name: "whitespace", raw: "   \n", want: ""},
		{name: "ambiguous_unbracketed", raw: "always madvise never", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseTHPActive(tc.raw); got != tc.want {
				t.Fatalf("parseTHPActive(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestConvergeTHPDefaultsAndIdempotency(t *testing.T) {
	r, sr, c := baseFixture(t, "")
	hostWrite(t, r, thpEnabledPath, "[always] madvise never\n")
	hostWrite(t, r, thpDefragPath, "[always] defer defer+madvise madvise never\n")

	// Cycle 1: persists tmpfiles.d, invokes systemd-tmpfiles --create, writes both sysfs knobs.
	c.convergeTHP()
	if c.errs != 0 {
		t.Fatalf("cycle 1 errs = %d, want 0", c.errs)
	}
	tf := hostRead(t, r, thpTmpfilesPath)
	for _, want := range []string{
		"w /sys/kernel/mm/transparent_hugepage/enabled - - - - madvise",
		"w /sys/kernel/mm/transparent_hugepage/defrag - - - - defer+madvise",
	} {
		if !strings.Contains(tf, want) {
			t.Fatalf("tmpfiles missing %q:\n%s", want, tf)
		}
	}
	if len(sr.CallsMatching("systemd-tmpfiles --create "+thpTmpfilesPath)) != 1 {
		t.Fatalf("expected 1 systemd-tmpfiles call, got %v", sr.Calls())
	}
	if len(sr.CallsMatching("printf '%s\\n' 'madvise' > "+thpEnabledPath)) != 1 {
		t.Fatalf("expected enabled sysfs write call, got %v", sr.Calls())
	}
	if len(sr.CallsMatching("printf '%s\\n' 'defer+madvise' > "+thpDefragPath)) != 1 {
		t.Fatalf("expected defrag sysfs write call, got %v", sr.Calls())
	}
	if got := promtestutil.ToFloat64(r.actions.WithLabelValues("thp:enabled")); got != 1 {
		t.Fatalf("actions{thp:enabled} = %v, want 1", got)
	}
	if got := promtestutil.ToFloat64(r.actions.WithLabelValues("thp:defrag")); got != 1 {
		t.Fatalf("actions{thp:defrag} = %v, want 1", got)
	}

	// Cycle 2: sysfs already converged -> zero tmpfiles or sh -c sysfs writes.
	hostWrite(t, r, thpEnabledPath, "always [madvise] never\n")
	hostWrite(t, r, thpDefragPath, "always defer [defer+madvise] madvise never\n")
	sr.ClearLog()
	c.convergeTHP()
	if c.errs != 0 {
		t.Fatalf("cycle 2 errs = %d, want 0", c.errs)
	}
	if len(sr.Calls()) != 0 {
		t.Fatalf("expected zero runner calls on converged cycle, got %v", sr.Calls())
	}

	// Cycle 3: runtime drift on enabled only while tmpfiles.d unchanged -> converges enabled only.
	hostWrite(t, r, thpEnabledPath, "[always] madvise never\n")
	sr.ClearLog()
	c.convergeTHP()
	if c.errs != 0 {
		t.Fatalf("cycle 3 errs = %d, want 0", c.errs)
	}
	if len(sr.CallsMatching("systemd-tmpfiles")) != 0 {
		t.Fatalf("unexpected systemd-tmpfiles on unchanged tmpfiles.d: %v", sr.Calls())
	}
	if len(sr.CallsMatching(thpEnabledPath)) != 1 || len(sr.CallsMatching(thpDefragPath)) != 0 {
		t.Fatalf("expected enabled-only converge, got %v", sr.Calls())
	}
}

func TestConvergeTHPOverridePrecedence(t *testing.T) {
	// Vars override defaults.
	r, sr, c := baseFixture(t, "host_thp_enabled: never\nhost_thp_defrag: madvise\n")
	hostWrite(t, r, thpEnabledPath, "always [madvise] never\n")
	hostWrite(t, r, thpDefragPath, "always defer [defer+madvise] madvise never\n")
	c.convergeTHP()
	if c.errs != 0 {
		t.Fatalf("vars override errs = %d, want 0", c.errs)
	}
	tf := hostRead(t, r, thpTmpfilesPath)
	if !strings.Contains(tf, "w "+thpEnabledPath+" - - - - never") ||
		!strings.Contains(tf, "w "+thpDefragPath+" - - - - madvise") {
		t.Fatalf("vars override tmpfiles wrong:\n%s", tf)
	}
	if len(sr.CallsMatching("printf '%s\\n' 'never' > "+thpEnabledPath)) != 1 ||
		len(sr.CallsMatching("printf '%s\\n' 'madvise' > "+thpDefragPath)) != 1 {
		t.Fatalf("vars override sysfs writes wrong: %v", sr.Calls())
	}

	// Config / env overrides vars.
	vars := writeVarsDir(t, "host_thp_enabled: never\nhost_thp_defrag: madvise\n")
	sr2 := newScripted(nil, nil)
	r2, err := New(Config{
		NodeName:           "node-b",
		HostRoot:           t.TempDir(),
		VarsDir:            vars,
		NebulaCertsDir:     t.TempDir(),
		WatchdogScriptsDir: t.TempDir(),
		Runner:             sr2,
		THPEnabled:         "always",
		THPDefrag:          "never",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r2, thpEnabledPath, "always [madvise] never\n")
	hostWrite(t, r2, thpDefragPath, "always defer [defer+madvise] madvise never\n")
	c2 := loadCyc(t, r2, vars, "node-b")
	c2.convergeTHP()
	if c2.errs != 0 {
		t.Fatalf("config override errs = %d, want 0", c2.errs)
	}
	tf2 := hostRead(t, r2, thpTmpfilesPath)
	if !strings.Contains(tf2, "w "+thpEnabledPath+" - - - - always") ||
		!strings.Contains(tf2, "w "+thpDefragPath+" - - - - never") {
		t.Fatalf("config override tmpfiles wrong:\n%s", tf2)
	}
	if len(sr2.CallsMatching("printf '%s\\n' 'always' > "+thpEnabledPath)) != 1 ||
		len(sr2.CallsMatching("printf '%s\\n' 'never' > "+thpDefragPath)) != 1 {
		t.Fatalf("config override sysfs writes wrong: %v", sr2.Calls())
	}
}

func TestConvergeTHPUnsafeValueRefused(t *testing.T) {
	// Unsafe var injection refused before writing tmpfiles.d or invoking sh -c.
	r, sr, c := baseFixture(t, "host_thp_enabled: \"madvise\\nw /etc/passwd - - - - pwn\"\n")
	hostWrite(t, r, thpEnabledPath, "[always] madvise never\n")
	c.convergeTHP()
	if c.errs == 0 {
		t.Fatal("expected unsafe var to increment c.errs")
	}
	if hostExists(r, thpTmpfilesPath) {
		t.Fatal("tmpfiles written despite unsafe var")
	}
	if len(sr.Calls()) != 0 {
		t.Fatalf("runner invoked despite unsafe var: %v", sr.Calls())
	}

	// Unsafe Config/env override refused too.
	r2, sr2, c2 := baseFixture(t, "")
	r2.cfg.THPDefrag = "madvise; rm -rf /"
	hostWrite(t, r2, thpDefragPath, "[always] defer defer+madvise madvise never\n")
	c2.convergeTHP()
	if c2.errs == 0 {
		t.Fatal("expected unsafe Config.THPDefrag to increment c.errs")
	}
	if hostExists(r2, thpTmpfilesPath) {
		t.Fatal("tmpfiles written despite unsafe Config.THPDefrag")
	}
	if len(sr2.Calls()) != 0 {
		t.Fatalf("runner invoked despite unsafe Config.THPDefrag: %v", sr2.Calls())
	}
}

func TestConvergeTHPReadOnlyHostSysAndMissingSysfs(t *testing.T) {
	// Missing sysfs: tmpfiles written, live write skipped with 0 errors.
	rMissing, srMissing, cMissing := baseFixture(t, "")
	cMissing.convergeTHP()
	if cMissing.errs != 0 {
		t.Fatalf("missing sysfs errs = %d, want 0", cMissing.errs)
	}
	if !hostExists(rMissing, thpTmpfilesPath) {
		t.Fatal("tmpfiles not written when sysfs absent")
	}
	if len(srMissing.CallsMatching("sh -c")) != 0 {
		t.Fatalf("unexpected sh -c when sysfs absent: %v", srMissing.Calls())
	}

	// Read-only /host/sys files (0444): read succeeds, live write routes through Runner cleanly.
	r, sr, c := baseFixture(t, "")
	hostWrite(t, r, thpEnabledPath, "[always] madvise never\n")
	hostWrite(t, r, thpDefragPath, "[always] defer defer+madvise madvise never\n")
	for _, p := range []string{thpEnabledPath, thpDefragPath} {
		hp := filepath.Join(r.cfg.HostRoot, p)
		if err := os.Chmod(hp, 0o444); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(hp, 0o644) })
	}
	c.convergeTHP()
	if c.errs != 0 {
		t.Fatalf("read-only /host/sys errs = %d, want 0 (must use Runner, never os.WriteFile)", c.errs)
	}
	if len(sr.CallsMatching("sh -c")) != 2 {
		t.Fatalf("expected 2 Runner sh -c calls for read-only /host/sys, got %v", sr.Calls())
	}
}

func TestConvergeTHPRunnerFailureCountsError(t *testing.T) {
	// Sysfs write failure counts an error and skips action metric; systemd-tmpfiles failure is warn-only.
	r, sr, c := baseFixture(t, "")
	hostWrite(t, r, thpEnabledPath, "[always] madvise never\n")
	hostWrite(t, r, thpDefragPath, "[always] defer defer+madvise madvise never\n")
	sr.FailOn("systemd-tmpfiles", nil)
	sr.FailOn("transparent_hugepage/enabled", nil)
	c.convergeTHP()
	if c.errs != 1 {
		t.Fatalf("errs = %d, want 1 (enabled write failure only; systemd-tmpfiles is warn-only)", c.errs)
	}
	if got := promtestutil.ToFloat64(r.actions.WithLabelValues("thp:enabled")); got != 0 {
		t.Fatalf("actions{thp:enabled} = %v, want 0 on failure", got)
	}
	if got := promtestutil.ToFloat64(r.actions.WithLabelValues("thp:defrag")); got != 1 {
		t.Fatalf("actions{thp:defrag} = %v, want 1 on defrag success", got)
	}
}

func TestGroupBaseConvergesRPFilterAndTHP(t *testing.T) {
	r, sr, c := baseFixture(t, "")
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	hostWrite(t, r, thpEnabledPath, "[always] madvise never\n")
	hostWrite(t, r, thpDefragPath, "[always] defer defer+madvise madvise never\n")

	c.groupBase()
	if c.errs != 0 {
		t.Fatalf("groupBase errs = %d, want 0", c.errs)
	}
	sysctlConf := hostRead(t, r, "/etc/sysctl.d/99-k8s-network-tuning.conf")
	for _, want := range []string{
		"net.ipv4.conf.all.rp_filter = 0",
		"net.ipv4.conf.default.rp_filter = 0",
	} {
		if !strings.Contains(sysctlConf, want) {
			t.Fatalf("99-k8s-network-tuning.conf missing %q:\n%s", want, sysctlConf)
		}
	}
	tf := hostRead(t, r, thpTmpfilesPath)
	if !strings.Contains(tf, "w "+thpEnabledPath+" - - - - madvise") {
		t.Fatalf("tmpfiles missing madvise:\n%s", tf)
	}
	if len(sr.CallsMatching("transparent_hugepage/enabled")) != 1 ||
		len(sr.CallsMatching("transparent_hugepage/defrag")) != 1 {
		t.Fatalf("expected THP live writes in groupBase, got %v", sr.Calls())
	}
}
