// group_kubelet_test.go — groupPulls: --kubelet-extra-args
// flag merge (quoted/unterminated handling), kubelet-config
// converge, and registry-qps charset gating.
package hostconfig

import (
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
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
		// host-protection-drop-ins graceful-shutdown contract values.
		"shutdownGracePeriod: 60s",
		"shutdownGracePeriodCriticalPods: 20s",
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

// TestGroupPullsRefusesNewlineInCfgScalar — a vars value carrying a
// newline rendered verbatim into KubeletConfiguration would inject an
// arbitrary key (kubelet parses the file wholesale). The refused key
// is skipped with a counted error while the REST of the YAML (and the
// containerd toml, whose scalars are clean) still converges.
func TestGroupPullsRefusesNewlineInCfgScalar(t *testing.T) {
	vars := writeVarsDir(t, "kubelet_api_qps: \"100\ninjectedKey: evil\"\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker --data-dir=/var/lib/k0s\n")
	hostWrite(t, r, "/var/lib/k0s/kubelet-config.yaml",
		"kind: KubeletConfiguration\nevictionHard:\n  memory.available: \"500Mi\"\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupPulls()

	if c.errs == 0 {
		t.Fatal("newline-bearing kubelet_api_qps not counted")
	}
	kf := hostRead(t, r, "/var/lib/k0s/kubelet-config.yaml")
	if strings.Contains(kf, "injectedKey") || strings.Contains(kf, "kubeAPIQPS") {
		t.Fatalf("injected/refused key landed in the kubelet cfg:\n%s", kf)
	}
	// The remaining scalars still converge untouched.
	for _, want := range []string{
		"maxParallelImagePulls: 4", "kubeAPIBurst: 50", "podPidsLimit: 4096",
		"shutdownGracePeriod: 60s", "shutdownGracePeriodCriticalPods: 20s",
	} {
		if !strings.Contains(kf, want) {
			t.Fatalf("rest of kubelet cfg lost %q after refusing one scalar:\n%s", want, kf)
		}
	}
	// containerd toml unaffected — its scalars (maxPar/dl) are clean.
	t90 := hostRead(t, r, "/etc/k0s/containerd.d/90-parallel-pulls.toml")
	if !strings.Contains(t90, "max_concurrent_downloads = 5") {
		t.Fatalf("containerd toml collateral damage:\n%s", t90)
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

// ---------- evictionMinimumReclaim compare/dump helpers ----------

func emrWant() *jinja.OMap {
	m := jinja.NewOMap()
	m.Set("memory.available", "200Mi")
	m.Set("nodefs.available", "1Gi")
	return m
}

func TestEmrMapEqual(t *testing.T) {
	want := emrWant()

	if !emrMapEqual("memory.available: 200Mi\nnodefs.available: 1Gi\n", want) {
		t.Fatal("identical block must compare equal")
	}
	// Quoting style is YAML-noise — the semantic compare ignores it.
	if !emrMapEqual("memory.available: \"200Mi\"\nnodefs.available: '1Gi'\n", want) {
		t.Fatal("quoted scalars must compare equal")
	}
	for name, cur := range map[string]string{
		"value drift":    "memory.available: 200Mi\nnodefs.available: 2Gi\n",
		"missing key":    "memory.available: 200Mi\n",
		"extra key":      "memory.available: 200Mi\nnodefs.available: 1Gi\nimagefs.available: 3Gi\n",
		"non-map yaml":   "just a scalar\n",
		"invalid yaml":   "a:\n\tb: c\n",
		"empty document": "",
	} {
		if emrMapEqual(cur, want) {
			t.Fatalf("%s: emrMapEqual must be false for %q", name, cur)
		}
	}
}

func TestEmrDump(t *testing.T) {
	in := "kind: KubeletConfiguration\n" +
		"evictionMinimumReclaim:\n" +
		"  memory.available: \"200Mi\"\n" +
		"  nodefs.available: \"1Gi\"\n" +
		"evictionHard:\n" +
		"  memory.available: \"100Mi\"\n"
	want := "  memory.available: \"200Mi\"\n  nodefs.available: \"1Gi\"\n"
	if got := emrDump(in); got != want {
		t.Fatalf("emrDump=%q want %q", got, want)
	}

	// Absent block → empty; a following top-level key ends the block.
	if got := emrDump("kind: KubeletConfiguration\n"); got != "" {
		t.Fatalf("absent block emrDump=%q want empty", got)
	}

	// Block at EOF with no trailing newline still yields its lines.
	if got := emrDump("evictionMinimumReclaim:\n\ta: b\nnext: 1"); got != "\ta: b\n" {
		t.Fatalf("tab-indented EOF block emrDump=%q", got)
	}
}
