// group_swap_extra_test.go — swap coverage beyond the ensure suite:
// the kineDBHost item-type table, the per-class selection gate, and
// ensureSwapfile's failure arms (active-probe loss, blkid contract,
// mkswap/fstab/swapon/sysctl failures, refuse-gate tail).
package hostconfig

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// swapFileSized materializes the swapfile at the exact converged
// size — the FakeRunner stubs fallocate/dd without creating bytes,
// so tests that must reach the fstab/swapon/sysctl tail pre-seed a
// sparse file that passes ensureSwapfile's size gate.
func swapFileSized(t *testing.T, r *Reconciler, mb int64) {
	t.Helper()
	p := filepath.Join(r.cfg.HostRoot, "swapfile")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(mb * 1048576); err != nil {
		t.Fatal(err)
	}
}

// swapFixture — fresh reconciler + cyc; runner rules added per test.
func swapFixture(t *testing.T, cluster string) (*Reconciler, *testutil.FakeRunner, *cyc) {
	t.Helper()
	vars := writeVarsDir(t, cluster)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r, sr, loadCyc(t, r, vars, "node-b")
}

// TestKineDBHostItemTypes — the kine_db flag's accepted shapes:
// bool, truthy/falsey strings, numbers, other values, unset, and
// non-mapping entries.
func TestKineDBHostItemTypes(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		want bool
	}{
		{"bool_true", "node_exporter_extra_hosts:\n  - name: node-b\n    kine_db: true\n", true},
		{"bool_false", "node_exporter_extra_hosts:\n  - name: node-b\n    kine_db: false\n", false},
		{"string_yes", "node_exporter_extra_hosts:\n  - name: node-b\n    kine_db: \"yes\"\n", true},
		{"string_one", "node_exporter_extra_hosts:\n  - name: node-b\n    kine_db: \"1\"\n", true},
		{"string_no", "node_exporter_extra_hosts:\n  - name: node-b\n    kine_db: \"no\"\n", false},
		{"int_truthy", "node_exporter_extra_hosts:\n  - name: node-b\n    kine_db: 3\n", true},
		{"map_value", "node_exporter_extra_hosts:\n  - name: node-b\n    kine_db:\n      x: 1\n", true},
		{"unset_flag", "node_exporter_extra_hosts:\n  - name: node-b\n", false},
		{"other_node", "node_exporter_extra_hosts:\n  - name: node-a\n    kine_db: true\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vars := writeVarsDir(t, tc.yaml)
			sr := newScripted(nil, nil)
			r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
				VarsDir: vars, Runner: sr}, nil)
			if err != nil {
				t.Fatal(err)
			}
			c := loadCyc(t, r, vars, "node-b")
			if got := c.kineDBHost(); got != tc.want {
				t.Fatalf("kineDBHost(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
	// A scalar (non-mapping) list entry must be skipped, not panic.
	vars := writeVarsDir(t, "node_exporter_extra_hosts:\n  - just-a-string\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	if c.kineDBHost() {
		t.Fatal("scalar entry matched kineDBHost")
	}
}

// TestGroupSwapClassSelection — only controllers and kine-db hosts
// get a swapfile; everyone else is untouched.
func TestGroupSwapClassSelection(t *testing.T) {
	// Neither controller nor kine-db: no swap work at all.
	r, sr, c := swapFixture(t, "")
	c.groupSwap()
	if len(sr.CallsMatching("swapon")) > 0 || hostExists(r, "/swapfile") {
		t.Fatal("swap converged on a plain node")
	}

	// kine-db host: db class paths + swappiness 10 default.
	vars := writeVarsDir(t, `node_exporter_extra_hosts:
  - name: node-b
    kine_db: true
`)
	sr2 := newScripted(nil, nil)
	r2, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c2 := loadCyc(t, r2, vars, "node-b")
	swapFileSized(t, r2, 2048) // db class default: 2048 MiB
	sr2.On("blkid -o value -s TYPE /swapfile", "swap")
	sr2.On("swapon /swapfile", "")
	c2.groupSwap()
	fstab := hostRead(t, r2, "/etc/fstab")
	if !strings.Contains(fstab, "/swapfile none swap sw 0 0") {
		t.Fatalf("db swap fstab line missing:\n%s", fstab)
	}
	sw := hostRead(t, r2, "/etc/sysctl.d/99-kine-swap.conf")
	if !strings.Contains(sw, "vm.swappiness = 10") {
		t.Fatalf("db swappiness default missing:\n%s", sw)
	}
}

// TestEnsureSwapfileFailureArms — the fail-closed probes and the
// per-step failure arms of the swapfile lifecycle.
func TestEnsureSwapfileFailureArms(t *testing.T) {
	t.Run("swapon_probe_lost", func(t *testing.T) {
		_, sr, c := swapFixture(t, "")
		sr.FailOn("swapon --show", nil)
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the lost-probe skip counted", c.errs)
		}
	})
	t.Run("blkid_probe_lost", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		sr.On("fallocate", "")
		swapFileSized(t, r, 64)
		sr.On("blkid -o value -s TYPE /swapfile", "")
		sr.FailOn("blkid -o value -s TYPE /swapfile", nil)
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the blkid failure skip counted", c.errs)
		}
	})
	t.Run("blkid_exit2_mkswap_fail", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		swapFileSized(t, r, 64)
		sr.On("fallocate", "")
		// exit 2 = the documented no-signature answer.
		ee := exitErr(2)
		sr.FailOn("blkid -o value -s TYPE /swapfile", ee)
		sr.FailOn("mkswap /swapfile", nil)
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the mkswap failure counted", c.errs)
		}
	})
	t.Run("active_but_unsigned", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show=NAME --noheadings", "/swapfile\n")
		swapFileSized(t, r, 64)
		ee := exitErr(2)
		sr.FailOn("blkid -o value -s TYPE /swapfile", ee)
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the active+unsigned disagreement counted", c.errs)
		}
		if len(sr.CallsMatching("mkswap")) > 0 {
			t.Fatal("mkswap ran on an ACTIVE swapfile")
		}
	})
	t.Run("dd_fallback_and_its_failure", func(t *testing.T) {
		_, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		// fallocate fails (no file appears), dd fails too → counted.
		sr.FailOn("fallocate -l 64M /swapfile", nil)
		sr.FailOn("dd if=/dev/zero", nil)
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the dd failure counted", c.errs)
		}
		if len(sr.CallsMatching("dd if=/dev/zero")) == 0 {
			t.Fatal("dd fallback not attempted after fallocate failure")
		}
	})
	t.Run("wrong_size_remove_fail", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		// A non-empty directory at the swap path: stat size != want
		// and os.Remove of a non-empty dir fails → counted.
		hostWrite(t, r, "/swapfile/junk", "x\n")
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the remove failure counted", c.errs)
		}
	})
	t.Run("fstab_read_fail", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		swapFileSized(t, r, 64)
		sr.On("blkid -o value -s TYPE /swapfile", "swap")
		hostWrite(t, r, "/etc/fstab", "blocker\n")
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 0 {
			t.Fatalf("errs = %d — fstab read failure is a warning only", c.errs)
		}
	})
	t.Run("swapon_fail", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		swapFileSized(t, r, 64)
		sr.On("blkid -o value -s TYPE /swapfile", "swap")
		sr.FailOn("swapon /swapfile", nil)
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the swapon failure counted", c.errs)
		}
	})
	t.Run("swappiness_gate_and_sysctl_fail", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		swapFileSized(t, r, 64)
		sr.On("blkid -o value -s TYPE /swapfile", "swap")
		sr.FailOn("sysctl -w vm.swappiness=10", nil)
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the live sysctl failure counted", c.errs)
		}
		if !strings.Contains(hostRead(t, r, "/etc/sysctl.d/99-kine-swap.conf"), "vm.swappiness = 10") {
			t.Fatal("drop-in not converged despite the live-apply failure")
		}
		// A refused swappiness skips only the tail, counts the gate.
		c.errs = 0
		c.ensureSwapfile("/swapfile", 64, "1\n2")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the refused swappiness counted", c.errs)
		}
	})
	t.Run("fstab_line_replaced", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		swapFileSized(t, r, 64)
		sr.On("blkid -o value -s TYPE /swapfile", "swap")
		hostWrite(t, r, "/etc/fstab", "/swapfile none swap sw,nofail 0 0\nother line\n")
		c.ensureSwapfile("/swapfile", 64, "10")
		fstab := hostRead(t, r, "/etc/fstab")
		if strings.Contains(fstab, "nofail") || !strings.Contains(fstab, "/swapfile none swap sw 0 0\n") {
			t.Fatalf("stale swap line not replaced:\n%s", fstab)
		}
	})
	t.Run("fstab_no_trailing_newline", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		swapFileSized(t, r, 64)
		sr.On("blkid -o value -s TYPE /swapfile", "swap")
		hostWrite(t, r, "/etc/fstab", "no trailing newline")
		c.ensureSwapfile("/swapfile", 64, "10")
		fstab := hostRead(t, r, "/etc/fstab")
		if !strings.Contains(fstab, "no trailing newline\n/swapfile none swap sw 0 0\n") {
			t.Fatalf("appended fstab line glued onto the prior entry:\n%q", fstab)
		}
	})
}

// TestEnsureSwapfileActiveUntouched — an active swapfile at the WRONG
// size is never removed or recreated out from under the kernel.
func TestEnsureSwapfileActiveUntouched(t *testing.T) {
	r, sr, c := swapFixture(t, "")
	sr.On("swapon --show=NAME --noheadings", "/swapfile\n")
	hostWrite(t, r, "/swapfile", "small\n")
	sr.On("blkid -o value -s TYPE /swapfile", "swap")
	c.ensureSwapfile("/swapfile", 64, "10")
	if got := hostRead(t, r, "/swapfile"); got != "small\n" {
		t.Fatalf("active swapfile rewritten: %q", got)
	}
	if len(sr.CallsMatching("fallocate")) > 0 {
		t.Fatal("recreate ran for an active swapfile")
	}
	if len(sr.CallsMatching("swapon /swapfile")) > 0 {
		t.Fatal("swapon re-issued for an already-active file")
	}
}

// TestEnsureSwapfileChmodAndFstabReadArms — a staged file that the
// fake fallocate never materializes fails the 0600 chmod (counted);
// an unreadable fstab warns before the write path fails.
func TestEnsureSwapfileChmodAndFstabReadArms(t *testing.T) {
	t.Run("chmod_failed", func(t *testing.T) {
		_, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		// fallocate "succeeds" in the runner but no real file exists.
		sr.On("fallocate -l 64M /swapfile", "")
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the chmod-on-missing-file failure", c.errs)
		}
		if len(sr.CallsMatching("blkid")) > 0 {
			t.Fatal("signature probe ran although the swapfile never existed")
		}
	})
	t.Run("fstab_unreadable", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		swapFileSized(t, r, 64) // exists at the pinned size — no create
		sr.On("blkid -o value -s TYPE /swapfile", "swap")
		hostWrite(t, r, "/etc/fstab/keep", "blocker\n") // fstab as dir
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the failed fstab write counted", c.errs)
		}
	})
}

// exitErr — a REAL *exec.ExitError with the given code (local shell,
// no root/network): the only way blkid's exit-2 contract can be
// recognized via errors.As.
func exitErr(code int) error {
	cmd := exec.Command("sh", "-c", "exit "+itoa(code))
	err := cmd.Run()
	ee, ok := err.(*exec.ExitError)
	if !ok {
		panic("exitErr: expected ExitError, got " + err.Error())
	}
	return ee
}

func itoa(i int) string {
	return strconv.Itoa(i)
}
