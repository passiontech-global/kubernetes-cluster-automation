// group_gomemlimit_test.go — gomemlimit-sum GOMEMLIMIT sum guard: the
// 52-go-memlimit-sumguard.conf drop-in clamps only when the
// configured cap leaves < 2GiB sibling headroom under MemoryMax.
package hostconfig

import (
	"strings"
	"testing"
)

const guardPath = "/etc/systemd/system/k0scontroller.service.d/52-go-memlimit-sumguard.conf"

// gomemlimitEnv builds a controller-host cyc with the two per-host
// OMaps set for node-b.
func gomemlimitEnv(t *testing.T, memMax, gomemlimit string) (*cyc, *Reconciler) {
	t.Helper()
	vars := writeVarsDir(t, "k0scontroller_memory_max_by_host:\n"+
		"  node-b: "+memMax+"\n"+
		"k0scontroller_go_memlimit_by_host:\n"+
		"  node-b: "+gomemlimit+"\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The controller() gate checks the unit file under HostRoot.
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service",
		"[Unit]\nDescription=k0s controller\n")
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	return loadCyc(t, r, vars, "node-b"), r
}

func TestGoMemlimitGuardSafeConfigNoDropIn(t *testing.T) {
	// Documented anchors: 2900MiB vs 7G and 5G both fit under
	// MemoryMax-2GiB — the guard drop-in must stay absent.
	for _, pair := range [][2]string{
		{"7G", "2900MiB"},
		{"5G", "2900MiB"},
		{"7G", "4500MiB"}, // kine-split sizing
	} {
		c, r := gomemlimitEnv(t, pair[0], pair[1])
		c.k0scontrollerGoMemlimitSumGuard()
		if hostExists(r, guardPath) {
			t.Fatalf("guard drop-in written for safe %s/%s", pair[0], pair[1])
		}
	}
}

func TestGoMemlimitGuardClampsUnsafeConfig(t *testing.T) {
	// 6G cap on a 7G unit leaves only 1G for etcd/kcm/scheduler —
	// the guard clamps to 7G-2GiB = 5120MiB.
	c, r := gomemlimitEnv(t, "7G", "6G")
	c.k0scontrollerGoMemlimitSumGuard()
	if !hostExists(r, guardPath) {
		t.Fatal("guard drop-in missing for unsafe config")
	}
	body := hostRead(t, r, guardPath)
	if !strings.Contains(body, "Environment=GOMEMLIMIT=5120MiB") {
		t.Fatalf("clamped drop-in content:\n%s", body)
	}

	// Config fixed back to safe → the override is removed again.
	c2, r2 := gomemlimitEnv(t, "7G", "2900MiB")
	hostWrite(t, r2, guardPath, "[Service]\nEnvironment=GOMEMLIMIT=5120MiB\n")
	c2.k0scontrollerGoMemlimitSumGuard()
	if hostExists(r2, guardPath) {
		t.Fatal("guard drop-in not removed once config is safe")
	}
}

func TestGoMemlimitGuardNoVars(t *testing.T) {
	// Missing maps → fail-open, no drop-in.
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.k0scontrollerGoMemlimitSumGuard()
	if hostExists(r, guardPath) {
		t.Fatal("guard drop-in written with no vars")
	}
}

func TestParseByteSize(t *testing.T) {
	for s, want := range map[string]int64{
		"7G":      7 << 30,
		"5G":      5 << 30,
		"512M":    512 << 20,
		"2900MiB": 2900 << 20,
		"2GB":     2 << 30,
		"1500MiB": 1500 << 20,
		"1048576": 1048576,
	} {
		got, ok := parseByteSize(s)
		if !ok || got != want {
			t.Fatalf("parseByteSize(%q)=%v,%v want %v", s, got, ok, want)
		}
	}
	for _, bad := range []string{"", "abc", "7X", "-1G"} {
		if _, ok := parseByteSize(bad); ok {
			t.Fatalf("parseByteSize(%q) unexpectedly ok", bad)
		}
	}
}
