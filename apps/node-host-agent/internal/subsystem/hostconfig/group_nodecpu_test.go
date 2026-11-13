// group_nodecpu_test.go — T8/T10 coverage: the wait-for-nodeip
// drop-in on plain workers, its absence on lighthouses, the CPU
// weight/quota drop-ins with best-effort live set-property (failure
// warn-only), and the un-found-registry skip.
package hostconfig

import (
	"strings"
	"testing"
)

// TestNodeCPUWorkerDropins — a plain worker gets the neb1 wait
// ExecStartPre, the CPUWeight drop-in, and the live set-property.
func TestNodeCPUWorkerDropins(t *testing.T) {
	vars := writeVarsDir(t, `critical_cpu_weight: 750
interdc_nebula_cpu_quota: 180%
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupNodeCPU()

	wait := hostRead(t, r, "/etc/systemd/system/k0sworker.service.d/20-wait-nodeip.conf")
	if !strings.Contains(wait, "After=nebula@interdc.service") ||
		!strings.Contains(wait, "ip addr show dev neb1") {
		t.Fatalf("wait-nodeip drop-in wrong:\n%s", wait)
	}
	w := hostRead(t, r, "/etc/systemd/system/k0sworker.service.d/30-cpu-weight.conf")
	if !strings.Contains(w, "CPUWeight=750") {
		t.Fatalf("worker CPU weight wrong:\n%s", w)
	}
	for _, call := range []string{
		"systemctl set-property k0sworker.service CPUWeight=750",
		"systemctl set-property nebula@interdc.service CPUQuota=180%",
	} {
		if len(sr.CallsMatching(call)) == 0 {
			t.Fatalf("live set-property missing %q: %v", call, sr.Calls())
		}
	}
	q := hostRead(t, r, "/etc/systemd/system/nebula@interdc.service.d/10-cpu-quota.conf")
	if !strings.Contains(q, "CPUQuota=180%") {
		t.Fatalf("nebula quota wrong:\n%s", q)
	}
	if c.errs != 0 {
		t.Fatalf("happy nodecpu converge counted errors: %d", c.errs)
	}
}

// TestNodeCPULighthouseSkipsWaitDropin — a lighthouse worker binds no
// --node-ip from neb1: the wait drop-in must NOT exist, the CPU
// weight still applies.
func TestNodeCPULighthouseSkipsWaitDropin(t *testing.T) {
	vars := writeVarsDir(t, "")
	patchVarsFile(t, vars, "interdc_nodes.yaml", twoHubNodes)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker\n")
	c := loadCyc(t, r, vars, "node-a")
	c.groupNodeCPU()
	if hostExists(r, "/etc/systemd/system/k0sworker.service.d/20-wait-nodeip.conf") {
		t.Fatal("wait-nodeip drop-in written on a lighthouse")
	}
	if !hostExists(r, "/etc/systemd/system/k0sworker.service.d/30-cpu-weight.conf") {
		t.Fatal("CPU weight drop-in missing on a lighthouse worker")
	}
}

// TestNodeCPUSetPropertyFailureWarnOnly — the live apply failing
// leaves the drop-in converged and does NOT count (the unit applies
// it at the next natural restart).
func TestNodeCPUSetPropertyFailureWarnOnly(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	sr.FailOn("systemctl set-property", nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupNodeCPU()
	if c.errs != 0 {
		t.Fatalf("errs = %d — set-property failures are best-effort", c.errs)
	}
	if !strings.Contains(hostRead(t, r, "/etc/systemd/system/k0sworker.service.d/30-cpu-weight.conf"),
		"CPUWeight=500") {
		t.Fatal("default CPU weight drop-in not converged")
	}
}

// TestNodeCPUUnknownNodeSkipsQuota — no registry entry (t.Found
// false): no nebula quota drop-in.
func TestNodeCPUUnknownNodeSkipsQuota(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-z", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-z")
	c.groupNodeCPU()
	if hostExists(r, "/etc/systemd/system/nebula@interdc.service.d/10-cpu-quota.conf") {
		t.Fatal("nebula quota written for an unknown node")
	}
}
