// group_kubelet_test.go — groupPulls: --kubelet-extra-args
// flag merge (quoted/unterminated handling), kubelet-config
// converge, and registry-qps charset gating.
package hostconfig

import (
	"strings"
	"testing"
)

// ---------- #3: groupPulls ----------

func TestGroupPullsUnitsAndKubeletCfg(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker --data-dir=/var/lib/k0s "+
			`--kubelet-extra-args="--node-ip=172.29.0.14 --node-labels=zone=x"`+"\n")
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service",
		"[Service]\nExecStart=/usr/bin/k0s controller --data-dir=/var/lib/k0s\n")
	hostWrite(t, r, "/var/lib/k0s/kubelet-config.yaml",
		"kind: KubeletConfiguration\nevictionHard:\n  memory.available: \"500Mi\"\n")

	c := loadCyc(t, r, vars, "node-b")
	c.groupPulls()

	unit := hostRead(t, r, "/etc/systemd/system/k0sworker.service")
	// flags must live INSIDE --kubelet-extra-args with literal \x20
	if !strings.Contains(unit, `\x20--serialize-image-pulls=false`) ||
		!strings.Contains(unit, `\x20--registry-qps=2\x20--registry-burst=4`) {
		t.Fatalf("pull flags not inside extra-args:\n%s", unit)
	}
	ctl := hostRead(t, r, "/etc/systemd/system/k0scontroller.service")
	if !strings.Contains(ctl,
		`--kubelet-extra-args=--serialize-image-pulls=false\x20--registry-qps=2\x20--registry-burst=4`) {
		t.Fatalf("extra-args injection missing on controller unit:\n%s", ctl)
	}
	kf := hostRead(t, r, "/var/lib/k0s/kubelet-config.yaml")
	for _, want := range []string{
		"maxParallelImagePulls: 4", "kubeAPIQPS: 100", "kubeAPIBurst: 50",
		"podPidsLimit: 4096",
		"evictionMinimumReclaim:\n  memory.available: \"200Mi\"\n  nodefs.available: \"1Gi\"\n  imagefs.available: \"2Gi\"",
	} {
		if !strings.Contains(kf, want) {
			t.Fatalf("kubelet cfg missing %q:\n%s", want, kf)
		}
	}
	t90 := hostRead(t, r, "/etc/k0s/containerd.d/90-parallel-pulls.toml")
	if !strings.Contains(t90, "[plugins.'io.containerd.cri.v1.images']") ||
		!strings.Contains(t90, "max_concurrent_downloads = 5") {
		t.Fatalf("bad parallel-pulls toml:\n%s", t90)
	}
	t91 := hostRead(t, r, "/etc/k0s/containerd.d/91-registry-mirror.toml")
	if !strings.Contains(t91, "discard_unpacked_layers = false") ||
		!strings.Contains(t91, "config_path = '/etc/containerd/certs.d'") {
		t.Fatalf("bad registry-mirror toml:\n%s", t91)
	}
	// ansible header contract: agent NEVER restarts k0s/containerd.
	for _, c2 := range sr.Calls() {
		if strings.Contains(c2, "restart") &&
			(strings.Contains(c2, "k0sworker") || strings.Contains(c2, "k0scontroller") || strings.Contains(c2, "containerd")) {
			t.Fatalf("unexpected restart call: %s", c2)
		}
	}
	if len(sr.CallsMatching("systemctl daemon-reload")) == 0 {
		t.Fatal("daemon-reload not invoked after unit change")
	}
}

// TestGroupPullsQuotedExtraArgs — flags must land INSIDE a quoted
// --kubelet-extra-args value (before the closing quote), both quote
// styles.
func TestGroupPullsQuotedExtraArgs(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker --data-dir=/var/lib/k0s "+
			`--kubelet-extra-args="--node-ip=172.29.0.14"`+"\n")
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service",
		"[Service]\nExecStart=/usr/bin/k0s controller --data-dir=/var/lib/k0s "+
			`--kubelet-extra-args='--node-ip=172.29.0.14'`+"\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupPulls()
	unit := hostRead(t, r, "/etc/systemd/system/k0sworker.service")
	if !strings.Contains(unit,
		`--kubelet-extra-args="--node-ip=172.29.0.14\x20--serialize-image-pulls=false\x20--registry-qps=2\x20--registry-burst=4"`) {
		t.Fatalf("flags not inside the double-quoted value:\n%s", unit)
	}
	ctl := hostRead(t, r, "/etc/systemd/system/k0scontroller.service")
	if !strings.Contains(ctl,
		`--kubelet-extra-args='--node-ip=172.29.0.14\x20--serialize-image-pulls=false\x20--registry-qps=2\x20--registry-burst=4'`) {
		t.Fatalf("flags not inside the single-quoted value:\n%s", ctl)
	}
}

// ---------- t7 extra-args hardening ----------

// TestGroupPullsRefusesUnsafeQPS — a vars value with shell metachars
// interpolated into ExecStart must skip the unit rewrite, not emit a
// mangled unit.
func TestGroupPullsRefusesUnsafeQPS(t *testing.T) {
	vars := writeVarsDir(t, "kubelet_registry_qps: \"2;rm -rf /\"\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker --data-dir=/var/lib/k0s\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupPulls()
	if c.errs == 0 {
		t.Fatal("metachar kubelet_registry_qps not counted")
	}
	unit := hostRead(t, r, "/etc/systemd/system/k0sworker.service")
	if strings.Contains(unit, `\x20`) || strings.Contains(unit, "kubelet-extra-args") {
		t.Fatalf("unit mutated despite a refused qps value:\n%s", unit)
	}
}

// TestGroupPullsUnterminatedExtraArgsQuote — `--kubelet-extra-args="abc`
// (no closing quote) must error and leave the unit untouched rather
// than merge flags into a value systemd tokenizes differently.
func TestGroupPullsUnterminatedExtraArgsQuote(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker --data-dir=/var/lib/k0s "+
			`--kubelet-extra-args="--node-ip=172.29.0.14`+"\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupPulls()
	if c.errs == 0 {
		t.Fatal("unterminated --kubelet-extra-args quote not counted")
	}
	unit := hostRead(t, r, "/etc/systemd/system/k0sworker.service")
	if strings.Contains(unit, `\x20`) {
		t.Fatalf("flags merged into an unterminated value:\n%s", unit)
	}
}

// TestT7AppendExtraArgsUnterminated — direct check of the ok flag on
// open-quote values vs properly quoted/bare ones.
func TestT7AppendExtraArgsUnterminated(t *testing.T) {
	if _, ok := t7AppendExtraArgs(`ExecStart=k0s --kubelet-extra-args="abc`, `\x20--x`); ok {
		t.Fatal("unterminated double-quote accepted")
	}
	if _, ok := t7AppendExtraArgs(`ExecStart=k0s --kubelet-extra-args='abc`, `\x20--x`); ok {
		t.Fatal("unterminated single-quote accepted")
	}
	if out, ok := t7AppendExtraArgs(`ExecStart=k0s --kubelet-extra-args="abc"`, `\x20--x`); !ok ||
		!strings.Contains(out, `--kubelet-extra-args="abc\x20--x"`) {
		t.Fatalf("quoted append wrong: %q ok=%v", out, ok)
	}
	if out, ok := t7AppendExtraArgs(`ExecStart=k0s --kubelet-extra-args=abc`, `\x20--x`); !ok ||
		!strings.Contains(out, `--kubelet-extra-args=abc\x20--x`) {
		t.Fatalf("bare append wrong: %q ok=%v", out, ok)
	}
}
