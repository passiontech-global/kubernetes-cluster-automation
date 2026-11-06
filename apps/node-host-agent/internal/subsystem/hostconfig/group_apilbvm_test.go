// group_apilbvm_test.go — api-lb-vm guard converge: tmpfiles,
// journald + admin-socket bind-mount, guard conf render, and
// legacy api-backend-guard cleanup.
package hostconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- api-lb-vm ----------

func TestAPILBVMConverge(t *testing.T) {
	vars := writeVarsDir(t, `api_lb_guard_vms:
  - name: lb-vm-1
    ip: 203.0.113.27
    api_backends: "api_dc1=10.0.1.10:6443"
    mode: enforce
`)
	inspectJSON := `[{"Config":{"Image":"haproxy:2.8-alpine","Labels":{"com.docker.compose.project.config_files":"/opt/haproxy/docker-compose.yml"}},"Mounts":[{"Source":"/opt/haproxy/haproxy.cfg","Destination":"/usr/local/etc/haproxy/haproxy.cfg"}]}]`
	sr := &scriptedRunner{res: map[string]string{
		"docker inspect haproxy": inspectJSON,
	}, errs: map[string]bool{}}
	r, err := New(Config{NodeName: "lb-vm-1", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/opt/haproxy/haproxy.cfg", "global\n    maxconn 2000\n\ndefaults\n    mode tcp\n")
	hostWrite(t, r, "/opt/haproxy/docker-compose.yml",
		"services:\n  haproxy:\n    image: haproxy:2.8-alpine\n    volumes:\n"+
			"      - /opt/haproxy/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro\n")
	hostWrite(t, r, "/etc/machine-id", "abcdef1234567890\n")
	// pre-seed the admin socket so the wait_for exits immediately
	hostWrite(t, r, "/run/haproxy-admin/admin.sock", "")
	// legacy shell guard present
	hostWrite(t, r, "/etc/systemd/system/api-backend-guard.timer", "[Unit]\n")
	hostWrite(t, r, "/usr/local/sbin/api-backend-guard.sh", "#!/bin/sh\n")
	// credential dir pre-exists with drifted 0755 — converge must
	// tighten it back to 0700 (MkdirAll alone never re-chmods).
	gd := filepath.Join(r.cfg.HostRoot, "/etc/api-backend-guard")
	if err := os.MkdirAll(gd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(gd, 0o755); err != nil {
		t.Fatal(err)
	}

	c := loadCyc(t, r, vars, "lb-vm-1")
	c.groupAPILBVM()

	tf := hostRead(t, r, "/etc/tmpfiles.d/api-lb-guard.conf")
	if !strings.Contains(tf, "d /run/haproxy-admin 0755 99 99 -") {
		t.Fatalf("bad tmpfiles conf:\n%s", tf)
	}
	jd := hostRead(t, r, "/etc/systemd/journald.conf.d/50-api-lb-guard.conf")
	if !strings.Contains(jd, "Storage=persistent") || !strings.Contains(jd, "SystemMaxUse=500M") {
		t.Fatalf("bad journald drop-in:\n%s", jd)
	}
	cfg := hostRead(t, r, "/opt/haproxy/haproxy.cfg")
	if !strings.Contains(cfg, "stats socket /run/haproxy/admin.sock mode 660 level admin") {
		t.Fatalf("stats socket block missing:\n%s", cfg)
	}
	cmp := hostRead(t, r, "/opt/haproxy/docker-compose.yml")
	if !strings.Contains(cmp, "- /run/haproxy-admin:/run/haproxy") {
		t.Fatalf("bind-mount line missing:\n%s", cmp)
	}
	if len(sr.callsMatching("haproxy -c -f /tmp/haproxy.cfg")) == 0 {
		t.Fatal("cfg not validated in throwaway container")
	}
	if len(sr.callsMatching("docker compose -f '/opt/haproxy/docker-compose.yml' up -d")) == 0 {
		t.Fatal("container not recreated for missing sock mount")
	}
	conf := hostRead(t, r, "/etc/api-backend-guard.conf")
	for _, want := range []string{
		"MODE=enforce", `API_BACKENDS="api_dc1=10.0.1.10:6443"`,
		"HAPROXY_BACKEND=kubeAPI_backend", `HAPROXY_BACKENDS="kubeAPI_backend"`,
		"HAPROXY_SOCKET=/run/haproxy-admin/admin.sock",
		// Original ansible contract (deployed VMs carry this
		// spelling) — plus the short-spelling compat keys.
		"API_TOKEN_FILE=/etc/api-backend-guard/token",
		"API_CA_FILE=/etc/api-backend-guard/ca.crt",
		"TOKEN_FILE=/etc/api-backend-guard/token",
		"CA_FILE=/etc/api-backend-guard/ca.crt",
	} {
		if !strings.Contains(conf, want) {
			t.Fatalf("guard conf missing %q:\n%s", want, conf)
		}
	}
	if fi, err := os.Stat(gd); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("credential dir mode = %v want 0700 (drift re-tightened)", fi)
	}
	if len(sr.callsMatching("systemctl disable --now api-backend-guard.timer api-backend-guard.service")) == 0 {
		t.Fatal("legacy guard units not disabled")
	}
	if hostExists(r, "/etc/systemd/system/api-backend-guard.timer") ||
		hostExists(r, "/usr/local/sbin/api-backend-guard.sh") {
		t.Fatal("legacy guard files not removed")
	}
}

func TestAPILBVMSkipsUnlisted(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupAPILBVM()
	if hostExists(r, "/etc/api-backend-guard.conf") ||
		hostExists(r, "/etc/tmpfiles.d/api-lb-guard.conf") {
		t.Fatal("api-lb files written on a non api_lb_guard_vms node")
	}
}
