// group_kubelet_extra_test.go — T7/T17 coverage beyond the pull-flag
// suite: the kubelet config discovery ladder, the unit/config
// unreadable skip arms, and the evictionMinimumReclaim map/block
// helpers' custom-var + non-string paths.
package hostconfig

import (
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/jinja"
)

// TestKubeletCfgPathDiscovery — the running-kubelet probe wins over
// the candidate ladder; a silent probe falls back to the first
// EXISTING candidate; nothing present returns "".
func TestKubeletCfgPathDiscovery(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")

	// Probe answers with the live --config path.
	sr.On("pgrep -x kubelet", "/etc/kubelet/custom.yaml")
	hostWrite(t, r, "/etc/kubelet/custom.yaml", "apiVersion: kubelet.config.k8s.io/v1beta1\n")
	if got := c.kubeletCfgPath(); got != "/etc/kubelet/custom.yaml" {
		t.Fatalf("kubeletCfgPath = %q, want the probed path", got)
	}

	// Probe silent → first existing candidate.
	sr.ClearLog()
	sr.On("pgrep -x kubelet", "")
	hostWrite(t, r, "/var/lib/k0s/kubelet/config.yaml", "apiVersion: kubelet.config.k8s.io/v1beta1\n")
	if got := c.kubeletCfgPath(); got != "/var/lib/k0s/kubelet/config.yaml" {
		t.Fatalf("kubeletCfgPath = %q, want the first existing candidate", got)
	}

	// Nothing anywhere → "".
	sr.ClearLog()
	r2, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: newScripted(nil, nil)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c2 := loadCyc(t, r2, vars, "node-b")
	if got := c2.kubeletCfgPath(); got != "" {
		t.Fatalf("kubeletCfgPath = %q on a bare host, want \"\"", got)
	}
}

// TestGroupPullsUnreadableArms — an unreadable unit file skips its
// pull-flag converge with a counted error; an unreadable kubelet
// config skips the live patch the same way. The other unit still
// converges.
func TestGroupPullsUnreadableArms(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service",
		"[Service]\nExecStart=/usr/bin/k0s controller\n")
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service/keep", "x\n") // unit as dir
	hostWrite(t, r, "/var/lib/k0s/kubelet/config.yaml/keep", "x\n")      // cfg as dir
	c := loadCyc(t, r, vars, "node-b")
	c.groupPulls()
	if c.errs != 2 {
		t.Fatalf("errs = %d, want the unreadable unit + unreadable config counted", c.errs)
	}
}

// TestEvictionMinReclaimCustomAndNonString — a vars mapping wins over
// the ansible defaults; a non-string value renders via %v (sub-keys
// quoted only when string).
func TestEvictionMinReclaimCustomAndNonString(t *testing.T) {
	vars := writeVarsDir(t, `kubelet_eviction_min_reclaim:
  memory.available: 100Mi
  imagefs.available: 7Gi
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	m := c.evictionMinReclaimMap()
	if v, _ := m.Get("memory.available"); v != "100Mi" {
		t.Fatalf("custom eviction map not used: memory.available = %v", v)
	}
	if v, _ := m.Get("nodefs.available"); v != nil {
		t.Fatalf("custom map must not fall back to defaults: nodefs = %v", v)
	}

	// Non-string values render bare (no quotes).
	om := jinja.NewOMap()
	om.Set("keepalive", int64(3))
	om.Set("nodefs.available", "2Gi")
	blk := evictionBlock(om)
	if !strings.Contains(blk, "  keepalive: 3\n") || strings.Contains(blk, `"3"`) {
		t.Fatalf("non-string sub-key rendered quoted:\n%s", blk)
	}
	if !strings.Contains(blk, `  nodefs.available: "2Gi"`) {
		t.Fatalf("string sub-key not quoted:\n%s", blk)
	}

	// emrMapEqual compares the SUB-KEY lines (emrDump output shape —
	// the parent key stripped, leading indent kept). A missing key on
	// the on-disk block is unequal; identical sub-keys are equal.
	om2 := jinja.NewOMap()
	om2.Set("nodefs.available", "2Gi")
	om2.Set("memory.available", "100Mi")
	missing := "  memory.available: \"100Mi\"\n"
	equal := "  memory.available: \"100Mi\"\n  nodefs.available: \"2Gi\"\n"
	// Same LENGTH but a different key name: the lookup miss arm.
	renamed := "  memory.available: \"100Mi\"\n  imagefs.available: \"2Gi\"\n"
	if emrMapEqual(missing, om2) {
		t.Fatal("emrMapEqual ignored a missing key")
	}
	if emrMapEqual(renamed, om2) {
		t.Fatal("emrMapEqual accepted a renamed key")
	}
	if !emrMapEqual(equal, om2) {
		t.Fatal("emrMapEqual rejected a semantically equal block")
	}
}
