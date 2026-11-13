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

	// The probe WINS over an existing stale candidate: a kubelet
	// running with a non-listed --config beside a stale listed file
	// must get its live config patched, not the leftover.
	sr.ClearLog()
	sr.On("pgrep -x kubelet", "/etc/kubelet/custom.yaml")
	hostWrite(t, r, "/var/lib/k0s/kubelet/config.yaml", "apiVersion: kubelet.config.k8s.io/v1beta1\n")
	if got := c.kubeletCfgPath(); got != "/etc/kubelet/custom.yaml" {
		t.Fatalf("kubeletCfgPath = %q, want the probed path over the stale candidate", got)
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
