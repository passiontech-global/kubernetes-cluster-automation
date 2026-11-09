// group_sysctl_test.go — sysctlPairs/sysctlVal: var-driven
// /etc/sysctl.d pair extraction — degenerate entries skipped before
// the gates, charset-refused pairs counted as cycle errors.
package hostconfig

import (
	"slices"
	"testing"
)

func TestSysctlPairs(t *testing.T) {
	vars := writeVarsDir(t, `test_sysctl_pairs:
  - name: net.ipv4.ip_forward
    value: "1"
  - name: "bad key"
    value: "x"
  - name: net.ipv4.tcp_keepalive_time
    value: "1\n2"
  - name: ""
    value: "y"
  - value: "no-name"
  - name: kernel.pid_max
    value: "4194304"
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")

	want := [][2]string{
		{"net.ipv4.ip_forward", "1"},
		{"kernel.pid_max", "4194304"},
	}
	if got := c.sysctlPairs("test_sysctl_pairs"); !slices.Equal(got, want) {
		t.Fatalf("sysctlPairs=%v want %v", got, want)
	}
	// One cycle error per gate refusal: "bad key" fails the key
	// charset, "1\n2" fails the value charset; the empty/missing
	// name entries skip BEFORE the gates and count nothing.
	if c.errs != 2 {
		t.Fatalf("errs=%d want 2 (bad key + newline value refused)", c.errs)
	}

	// sysctlVal indexes into the same filtered pair list — each call
	// re-runs sysctlPairs, so the refusals count again.
	if v := c.sysctlVal("test_sysctl_pairs", 1); v != "4194304" {
		t.Fatalf("sysctlVal(1)=%q want 4194304", v)
	}
	if v := c.sysctlVal("test_sysctl_pairs", 9); v != "" {
		t.Fatalf("sysctlVal out of range=%q want empty", v)
	}
	if p := c.sysctlPairs("no_such_var"); len(p) != 0 {
		t.Fatalf("unset var sysctlPairs=%v want empty", p)
	}
}
