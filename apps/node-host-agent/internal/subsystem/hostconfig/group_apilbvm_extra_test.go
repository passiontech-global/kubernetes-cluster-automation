// group_apilbvm_extra_test.go — api-lb-vm coverage beyond the
// converge suite: apiLBHaproxy's docker-inspect parse arms (failed,
// unparseable, empty, missing labels), unreadable cfg/compose
// preconditions, the already-mounted socket path, validation and
// recreate failure arms, the admin-socket wait's ctx exit, and the
// group's sock-dir/chmod failure counting.
package hostconfig

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// vmFixture — the lb-vm-1 entry + the files TestAPILBVMConverge
// seeds, for direct apiLBHaproxy calls.
func vmFixture(t *testing.T, inspectOut string, failInspect bool) (*Reconciler, *testutil.FakeRunner, *cyc) {
	t.Helper()
	vars := writeVarsDir(t, `api_lb_guard_vms:
  - name: lb-vm-1
    ip: 203.0.113.27
    api_backends: "api_dc1=10.0.1.10:6443"
`)
	sr := newScripted(nil, nil)
	if failInspect {
		sr.FailOn("docker inspect", nil)
	} else if inspectOut != "" {
		sr.On("docker inspect haproxy", inspectOut)
	}
	r, err := New(Config{NodeName: "lb-vm-1", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r, sr, loadCyc(t, r, vars, "lb-vm-1")
}

// goodInspect — labels + cfg mount + the /run/haproxy bind mount so
// the happy path needs no recreate.
const goodInspect = `[{"Config":{"Image":"haproxy:2.8-alpine","Labels":{"com.docker.compose.project.config_files":"/opt/haproxy/docker-compose.yml"}},"Mounts":[{"Source":"/opt/haproxy/haproxy.cfg","Destination":"/usr/local/etc/haproxy/haproxy.cfg"},{"Source":"/run/haproxy-admin","Destination":"/run/haproxy"}]}]`

// TestAPILBHaproxyInspectArms — the docker-inspect precondition arms:
// a failed inspect, unparseable JSON, an empty container list, and
// missing compose/cfg labels each skip with a counted error.
func TestAPILBHaproxyInspectArms(t *testing.T) {
	for _, tc := range []struct {
		name    string
		out     string
		fail    bool
		wantErr string
	}{
		{"inspect_failed", "", true, "docker inspect failed"},
		{"unparseable", "not json at all", false, "unparseable"},
		{"empty_list", "[]", false, "returned no containers"},
		{"missing_labels", `[{"Config":{"Image":"haproxy:2.8-alpine"},"Mounts":[]}]`, false, "cannot locate compose file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _, c := vmFixture(t, tc.out, tc.fail)
			c.apiLBHaproxy("haproxy", "/run/haproxy-admin", "/run/haproxy-admin/admin.sock")
			if c.errs == 0 {
				t.Fatalf("inspect failure arm did not count an error (want %q)", tc.wantErr)
			}
			_ = r
		})
	}
}

// TestAPILBHaproxyPreconditions — unreadable haproxy.cfg/compose warn
// without counting; a cfg that already carries the stats socket and a
// compose that already binds the socket dir change nothing; a changed
// cfg with the mount present takes the docker-restart arm.
func TestAPILBHaproxyPreconditions(t *testing.T) {
	r, sr, c := vmFixture(t, goodInspect, false)
	hostWrite(t, r, "/opt/haproxy/docker-compose.yml",
		"services:\n  haproxy:\n    volumes:\n      - /opt/haproxy/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro\n"+
			"      - /run/haproxy-admin:/run/haproxy\n")
	hostWrite(t, r, "/opt/haproxy/haproxy.cfg",
		"global\n    stats socket /run/haproxy/admin.sock mode 660 level admin\n")
	// Pre-seed the admin socket so the wait_for exits immediately.
	hostWrite(t, r, "/run/haproxy-admin/admin.sock", "")
	c.apiLBHaproxy("haproxy", "/run/haproxy-admin", "/run/haproxy-admin/admin.sock")
	if c.errs != 0 {
		t.Fatalf("no-drift pass counted errors: %d", c.errs)
	}
	if len(sr.CallsMatching("docker restart haproxy")) > 0 {
		t.Fatal("docker restart ran on an unchanged cfg")
	}

	// cfg drift + mount already present → validate, then restart.
	sr.ClearLog()
	hostWrite(t, r, "/opt/haproxy/haproxy.cfg", "global\n    maxconn 100\n")
	c.apiLBHaproxy("haproxy", "/run/haproxy-admin", "/run/haproxy-admin/admin.sock")
	if len(sr.CallsMatching("docker restart haproxy")) != 1 {
		t.Fatalf("cfg drift did not restart the container: %v", sr.Calls())
	}
	if len(sr.CallsMatching("docker compose")) > 0 {
		t.Fatal("compose up ran although the socket mount already exists")
	}

	// unreadable files: warn-only preconditions — swap the cfg file
	// for a directory so the read fails.
	sr.ClearLog()
	cfgPath := filepath.Join(r.cfg.HostRoot, "opt/haproxy/haproxy.cfg")
	if err := os.Remove(cfgPath); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfgPath, 0o755); err != nil {
		t.Fatal(err)
	}
	c.apiLBHaproxy("haproxy", "/run/haproxy-admin", "/run/haproxy-admin/admin.sock")
	if c.errs != 0 {
		t.Fatalf("unreadable cfg counted an error: %d", c.errs)
	}
}

// TestAPILBHaproxyValidationFailure — haproxy -c in the throwaway
// container failing must abort before recreate/restart, error counted.
func TestAPILBHaproxyValidationFailure(t *testing.T) {
	r, sr, c := vmFixture(t, goodInspect, false)
	hostWrite(t, r, "/opt/haproxy/docker-compose.yml", "services:\n  haproxy: {}\n")
	hostWrite(t, r, "/opt/haproxy/haproxy.cfg", "global\n    maxconn 100\n")
	sr.FailOn("haproxy -c -f /tmp/haproxy.cfg", nil)
	c.apiLBHaproxy("haproxy", "/run/haproxy-admin", "/run/haproxy-admin/admin.sock")
	if c.errs == 0 {
		t.Fatal("failed validation did not count a cycle error")
	}
	if len(sr.CallsMatching("docker compose")) > 0 || len(sr.CallsMatching("docker restart")) > 0 {
		t.Fatal("live container touched despite failed validation")
	}
}

// TestAPILBHaproxyRecreateArms — compose-up failure and restart
// failure each count; the admin-socket wait exits through ctx.Done on
// a canceled context instead of burning the full 30s.
func TestAPILBHaproxyRecreateArms(t *testing.T) {
	r, sr, c := vmFixture(t, goodInspect, false)
	hostWrite(t, r, "/opt/haproxy/docker-compose.yml", "services:\n  haproxy: {}\n")
	hostWrite(t, r, "/opt/haproxy/haproxy.cfg", "global\n    maxconn 100\n")

	t.Run("compose_up_failed", func(t *testing.T) {
		sr.FailOn("docker compose", nil)
		// Canceled ctx: after the counted failure the admin-socket
		// wait must exit via ctx.Done, not burn its full 30s.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c.ctx = ctx
		c.apiLBHaproxy("haproxy", "/run/haproxy-admin", "/run/haproxy-admin/admin.sock")
		c.ctx = context.Background()
		if c.errs == 0 {
			t.Fatal("failed compose up did not count a cycle error")
		}
		sr.ClearFails()
		c.errs = 0
	})
	t.Run("restart_failed", func(t *testing.T) {
		// Mount now present → cfg-only drift → restart arm.
		hostWrite(t, r, "/opt/haproxy/docker-compose.yml",
			"services:\n  haproxy:\n    volumes:\n      - /run/haproxy-admin:/run/haproxy\n")
		hostWrite(t, r, "/opt/haproxy/haproxy.cfg", "global\n    maxconn 200\n")
		sr.FailOn("docker restart haproxy", nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c.ctx = ctx
		c.apiLBHaproxy("haproxy", "/run/haproxy-admin", "/run/haproxy-admin/admin.sock")
		c.ctx = context.Background()
		if c.errs == 0 {
			t.Fatal("failed docker restart did not count a cycle error")
		}
		sr.ClearFails()
		c.errs = 0
	})
	t.Run("wait_ctx_cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c.ctx = ctx
		c.apiLBHaproxy("haproxy", "/run/haproxy-admin", "/run/haproxy-admin/never.sock")
		c.ctx = context.Background()
	})
}

// TestAPILBHaproxyUnreadableCompose — an unreadable compose file is a
// warn-only precondition like the cfg (the socket-wait is the
// definitive signal).
func TestAPILBHaproxyUnreadableCompose(t *testing.T) {
	r, _, c := vmFixture(t, goodInspect, false)
	hostWrite(t, r, "/opt/haproxy/haproxy.cfg", "global\n    stats socket /run/haproxy/admin.sock\n")
	hostWrite(t, r, "/opt/haproxy/docker-compose.yml/keep", "x\n") // compose as dir
	hostWrite(t, r, "/run/haproxy-admin/admin.sock", "")
	c.apiLBHaproxy("haproxy", "/run/haproxy-admin", "/run/haproxy-admin/admin.sock")
	if c.errs != 0 {
		t.Fatalf("unreadable compose counted an error: %d", c.errs)
	}
}

// TestAPILBVMCredentialDirChmodFailure — /etc/api-backend-guard as a
// dangling symlink: the 0700 re-tighten fails ENOENT and counts (a
// readable token dir crash-loops the VIP).
func TestAPILBVMCredentialDirChmodFailure(t *testing.T) {
	vars := writeVarsDir(t, `api_lb_guard_vms:
  - name: lb-vm-1
    ip: 203.0.113.27
`)
	sr := newScripted(map[string]string{"docker inspect haproxy": "[]"}, nil)
	r, err := New(Config{NodeName: "lb-vm-1", HostRoot: t.TempDir(),
		VarsDir: vars, Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Dangling symlink, not /dev/null: os.Chmod follows the link, so a
	// live target would be chmodded on the REAL host when tests run as
	// root — a dangling target fails ENOENT for every uid instead.
	if err := os.Symlink(filepath.Join(r.cfg.HostRoot, "etc", "no-such-target"),
		filepath.Join(r.cfg.HostRoot, "etc/api-backend-guard")); err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "lb-vm-1")
	c.groupAPILBVM()
	if c.errs == 0 {
		t.Fatal("credential dir chmod failure did not count a cycle error")
	}
}

// TestAPILBVMGroupFailureArms — through the group entry: a scalar
// entry in api_lb_guard_vms is skipped, an unwritable sock dir counts,
// and the chmod re-tighten failure on the credential dir counts.
func TestAPILBVMGroupFailureArms(t *testing.T) {
	t.Run("sock_dir_create_failed", func(t *testing.T) {
		vars := writeVarsDir(t, `api_lb_guard_vms:
  - name: lb-vm-1
    ip: 203.0.113.27
`)
		sr := newScripted(map[string]string{"docker inspect haproxy": "[]"}, nil)
		r, err := New(Config{NodeName: "lb-vm-1", HostRoot: t.TempDir(),
			VarsDir: vars, Standalone: true, Runner: sr}, nil)
		if err != nil {
			t.Fatal(err)
		}
		// /run is a FILE — MkdirAll of the sock dir beneath fails.
		hostWrite(t, r, "/run", "not a dir\n")
		c := loadCyc(t, r, vars, "lb-vm-1")
		c.groupAPILBVM()
		if c.errs == 0 {
			t.Fatal("sock dir create failure did not count a cycle error")
		}
	})
	t.Run("scalar_vm_entry_skipped", func(t *testing.T) {
		vars := writeVarsDir(t, `api_lb_guard_vms:
  - lb-vm-1-as-string
`)
		sr := newScripted(nil, nil)
		r, err := New(Config{NodeName: "lb-vm-1", HostRoot: t.TempDir(),
			VarsDir: vars, Standalone: true, Runner: sr}, nil)
		if err != nil {
			t.Fatal(err)
		}
		c := loadCyc(t, r, vars, "lb-vm-1")
		if e := c.apiLBVMEntry(); e != nil {
			t.Fatalf("scalar entry matched: %v", e)
		}
		c.groupAPILBVM()
		if hostExists(r, "/etc/api-backend-guard.conf") {
			t.Fatal("guard conf written for a scalar entry")
		}
	})
}
