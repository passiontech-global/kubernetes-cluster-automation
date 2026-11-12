// cilium_lrp_run_test.go — CiliumLRPCheck.Run driven directly through
// the typed check accessor (bare CycleEnvs): the dormancy/agent/api
// gates, both-transport :53 wedge confirmation → pod delete, the
// delete-failure + cooldown tails, and the BPF service-map desync
// branch that kills the agent and bounces envoy inline.
package cilium_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/cilium"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// lrpFixture arms the cilium datapath (cilium_host under SysClassNet)
// and a live cilium-agent task — the two gates every non-dormant LRP
// Run path needs. objs seed the fake clientset.
func lrpFixture(t *testing.T, objs ...runtime.Object) *env {
	t.Helper()
	e := fixture(t, objs...)
	if err := os.MkdirAll(filepath.Join(e.SysNet, "cilium_host"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.MkProc(t, 4343, "S", "", "")
	e.MkTask(t, wdepstest.UIDB, "cilium-agent", 4343)
	return e
}

// lrpRun drives one LRP round with a bare CycleEnv — the check reads
// its state from the env, not the orchestrator.
func lrpRun(t *testing.T, e *env, cycle *wdeps.CycleEnv) *cilium.CiliumLRPCheck {
	t.Helper()
	c := wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP)
	c.Run(context.Background(), cycle)
	return c
}

// nldPod builds a Ready node-local-dns pod for the CycleEnv pod list.
func nldPod(name, uid string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "kube-system", UID: types.UID(uid),
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
}

// kubeDNSEndpoints seeds the legacy Endpoints fallback with one ready
// address — the deterministic no-desync apiserver verdict (no
// EndpointSlices exist, and default/kubernetes stays unreadable →
// skipped, never counted).
func kubeDNSEndpoints() *corev1.Endpoints {
	return &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"},
		Subsets: []corev1.EndpointSubset{
			{Addresses: []corev1.EndpointAddress{{IP: "10.244.1.7"}}},
		},
	}
}

// kubeDNSSlice builds an EndpointSlice owning kube-dns with one
// endpoint whose readiness is set by ready.
func kubeDNSSlice(ready bool) *discoveryv1.EndpointSlice {
	r := ready
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kube-dns-abc",
			Namespace: "kube-system",
			Labels:    map[string]string{"kubernetes.io/service-name": "kube-dns"},
		},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{"10.244.1.7"},
			Conditions: discoveryv1.EndpointConditions{Ready: &r},
		}},
	}
}

// noDesync is the canned healthy BPF service map.
func noDesync(e *env) {
	e.SvcBackends = map[string]int{
		"kube-system/kube-dns": 1,
		"default/kubernetes":   1,
	}
}

// stubProbeFails hard-fails the :53 UDP seam with a t.Fatal — a
// probe call on a path that must not reach the datapath verdict.
func stubProbeFails(t *testing.T, e *env) {
	t.Helper()
	e.H.Cfg.Seams.Probe.DNSProbe = func(context.Context, string, string, time.Duration) bool {
		t.Error(":53 UDP probe ran on a gate path")
		return false
	}
}

// TestLRPRunDormantWithoutDatapath: no cilium_host → the check is
// dormant (calico node) — the probe must not run and both streaks
// reset instead of carrying evidence across a datapath change.
func TestLRPRunDormantWithoutDatapath(t *testing.T) {
	e := fixture(t) // no cilium_host
	stubProbeFails(t, e)
	c := wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP)
	c.Fails = 7
	c.Run(context.Background(), &wdeps.CycleEnv{APIOK: true, WorkerActive: true})
	if c.Fails != 0 {
		t.Fatalf("Fails=%d want 0 on a non-cilium node", c.Fails)
	}
}

// TestLRPRunGatedWhenAgentAbsent: cilium_host persists while the
// agent is down — a dead agent explains any :53 failure, so the check
// stands down (and resets its streaks) rather than punishing the pod.
func TestLRPRunGatedWhenAgentAbsent(t *testing.T) {
	e := fixture(t)
	if err := os.MkdirAll(filepath.Join(e.SysNet, "cilium_host"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubProbeFails(t, e)
	c := wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP)
	c.Fails = 7
	c.Run(context.Background(), &wdeps.CycleEnv{APIOK: true, WorkerActive: true})
	if c.Fails != 0 {
		t.Fatalf("Fails=%d want 0 with cilium-agent absent", c.Fails)
	}
}

// TestLRPRunAbortsOnUnreachableCtrRoot: an unreadable task root makes
// the agent-task verdict inconclusive → abort, evidence kept.
func TestLRPRunAbortsOnUnreachableCtrRoot(t *testing.T) {
	e := lrpFixture(t)
	e.H.Cfg.CtrTaskRoot = filepath.Join(e.CtrDir, "missing-root")
	stubProbeFails(t, e)
	c := wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP)
	c.Fails = 1
	lrpRun(t, e, &wdeps.CycleEnv{APIOK: true, WorkerActive: true})
	if c.Fails != 1 {
		t.Fatalf("Fails=%d want 1 — ctr-unreachable abort keeps evidence", c.Fails)
	}
}

// TestLRPRunAbortsWhenAPIUnreachable: an inconclusive LIST keeps the
// streak evidence without counting or clearing it.
func TestLRPRunAbortsWhenAPIUnreachable(t *testing.T) {
	e := lrpFixture(t)
	stubProbeFails(t, e)
	c := wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP)
	c.Fails = 1
	c.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
	if c.Fails != 1 {
		t.Fatalf("Fails=%d want 1 — an API flake must keep evidence", c.Fails)
	}
}

// TestLRPRunHealthyProbeResetsStreak: both transports answering →
// the listener is alive, the streak clears.
func TestLRPRunHealthyProbeResetsStreak(t *testing.T) {
	e := lrpFixture(t, kubeDNSEndpoints())
	noDesync(e)
	e.H.Cfg.Seams.Probe.DNSProbe = func(context.Context, string, string, time.Duration) bool { return true }
	e.DNSTCP = true
	c := wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP)
	c.Fails = 1
	pod := nldPod("node-local-dns-aaa111", wdepstest.UIDA)
	c.Run(context.Background(), &wdeps.CycleEnv{
		Pods: []corev1.Pod{*pod}, APIOK: true, WorkerActive: true})
	if c.Fails != 0 {
		t.Fatalf("Fails=%d want 0 after a green :53 round", c.Fails)
	}
}

// TestLRPRunPodDeleteAfterConfirmedWedge: both transports silent
// while the pod claims Ready — ConsecNeeded cycles delete the pod
// with grace 0 through the last-nld-restart budget, then reset.
func TestLRPRunPodDeleteAfterConfirmedWedge(t *testing.T) {
	pod := nldPod("node-local-dns-bbb222", wdepstest.UIDA)
	e := lrpFixture(t, kubeDNSEndpoints(), pod)
	noDesync(e)
	e.H.Cfg.Seams.Probe.DNSProbe = func(context.Context, string, string, time.Duration) bool { return false }
	e.DNSTCP = false
	cycle := &wdeps.CycleEnv{
		Pods: []corev1.Pod{*pod}, APIOK: true, WorkerActive: true}
	lrpRun(t, e, cycle) // streak 1/2
	if _, err := e.CS.CoreV1().Pods("kube-system").Get(
		context.Background(), "node-local-dns-bbb222", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted before ConsecNeeded failed cycles")
	}
	lrpRun(t, e, cycle) // confirmed → delete
	if dels := wdepstest.DeleteActions(e.CS); len(dels) != 1 ||
		dels[0].GetName() != "node-local-dns-bbb222" {
		t.Fatalf("pod delete missing: %+v", dels)
	} else if gp := dels[0].GetDeleteOptions().GracePeriodSeconds; gp == nil || *gp != 5 {
		t.Fatalf("grace period %v want 5", gp)
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "last-nld-restart")); err != nil {
		t.Fatal("last-nld-restart budget not spent before the delete")
	}
	if !strings.Contains(e.LogLines(t),
		"ACTION: cilium-lrp-dns deleted pod kube-system/node-local-dns-bbb222") {
		t.Fatalf("missing delete ACTION line:\n%s", e.LogLines(t))
	}
	if c := wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP); c.Fails != 0 {
		t.Fatalf("Fails=%d want 0 after the pod delete", c.Fails)
	}
}

// TestLRPRunDeleteFailureThenCooldown: a failed delete logs suspect
// and keeps the budget spent — the next confirmed cycle must take the
// cooldown skip instead of retrying every cycle.
func TestLRPRunDeleteFailureThenCooldown(t *testing.T) {
	pod := nldPod("node-local-dns-ccc333", wdepstest.UIDA)
	e := lrpFixture(t, kubeDNSEndpoints(), pod)
	noDesync(e)
	e.H.Cfg.Seams.Probe.DNSProbe = func(context.Context, string, string, time.Duration) bool { return false }
	e.DNSTCP = false
	e.CS.PrependReactor("delete", "pods",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, context.DeadlineExceeded
		})
	cycle := &wdeps.CycleEnv{
		Pods: []corev1.Pod{*pod}, APIOK: true, WorkerActive: true}
	lrpRun(t, e, cycle) // 1/2
	lrpRun(t, e, cycle) // budget spent, delete fails
	log := e.LogLines(t)
	if !strings.Contains(log, "delete kube-system/node-local-dns-ccc333 failed") {
		t.Fatalf("missing delete-failure suspect line:\n%s", log)
	}
	lrpRun(t, e, cycle) // streak 1/2 again (Fails reset after the remedy attempt)
	lrpRun(t, e, cycle) // confirmed → RateTrySpend loses to the 30m cooldown
	if !strings.Contains(e.LogLines(t), "pod restart in cooldown") {
		t.Fatalf("missing cooldown skip line:\n%s", e.LogLines(t))
	}
	if _, err := e.CS.CoreV1().Pods("kube-system").Get(
		context.Background(), "node-local-dns-ccc333", metav1.GetOptions{}); err != nil {
		t.Fatal("pod vanished despite every delete failing")
	}
}

// TestLRPRunDesyncKillsAgentAndBouncesEnvoy: kube-dns shows Ready
// endpoints but the BPF map programs 0 backends — after ConsecNeeded
// cycles the agent is SIGKILLed through last-cilium-restart and envoy
// is bounced inline (it already ran this cycle), while the nld pod
// stays put.
func TestLRPRunDesyncKillsAgentAndBouncesEnvoy(t *testing.T) {
	pod := nldPod("node-local-dns-ddd444", wdepstest.UIDA)
	e := lrpFixture(t, kubeDNSSlice(true), pod)
	e.MkProc(t, 555, "S", "", "")
	e.MkTask(t, wdepstest.UIDF, "cilium-envoy", 555)
	e.SvcBackends = map[string]int{
		"kube-system/kube-dns": 0, // desynced
		"default/kubernetes":   1,
	}
	e.H.Cfg.Seams.Probe.DNSProbe = func(context.Context, string, string, time.Duration) bool {
		t.Error(":53 probe ran while the desync explained the failure")
		return false
	}
	e.DNSTCP = false
	cycle := &wdeps.CycleEnv{
		Pods: []corev1.Pod{*pod}, APIOK: true, WorkerActive: true}
	lrpRun(t, e, cycle) // desync streak 1/2
	killed := func() map[int]bool {
		m := map[int]bool{}
		for _, k := range e.Kills {
			if k.Sig == syscall.SIGKILL {
				m[k.PID] = true
			}
		}
		return m
	}
	if killed()[4343] {
		t.Fatal("agent killed before ConsecNeeded desync cycles")
	}
	lrpRun(t, e, cycle) // confirmed → agent + envoy bounce
	got := killed()
	if !got[4343] || !got[555] {
		t.Fatalf("agent/envoy not killed on desync: kills=%v", e.Kills)
	}
	if !e.H.CiliumAgentKilled {
		t.Fatal("CiliumAgentKilled flag not set by the desync kill")
	}
	for _, budget := range []string{"last-cilium-restart", "last-cilium-envoy-restart"} {
		if _, err := os.Stat(filepath.Join(e.StateDir, budget)); err != nil {
			t.Fatalf("%s budget not spent: %v", budget, err)
		}
	}
	log := e.LogLines(t)
	if !strings.Contains(log, "BPF service-map desync kube-system/kube-dns") ||
		!strings.Contains(log, "killed cilium-envoy container - cilium-agent restarted for BPF service-map desync") {
		t.Fatalf("missing desync ACTION lines:\n%s", log)
	}
	if _, err := e.CS.CoreV1().Pods("kube-system").Get(
		context.Background(), "node-local-dns-ddd444", metav1.GetOptions{}); err != nil {
		t.Fatal("nld pod deleted while the desync explained the :53 failure")
	}
}

// TestLRPRunDesyncNoEnvoyTaskQuiet: no L7 proxy deployed → the envoy
// bounce stands down without touching the agent kill itself.
func TestLRPRunDesyncNoEnvoyTaskQuiet(t *testing.T) {
	e := lrpFixture(t, kubeDNSSlice(true))
	e.SvcBackends = map[string]int{"kube-system/kube-dns": 0}
	e.H.Cfg.Seams.Probe.DNSProbe = func(context.Context, string, string, time.Duration) bool { return false }
	e.DNSTCP = false
	cycle := &wdeps.CycleEnv{APIOK: true, WorkerActive: true}
	lrpRun(t, e, cycle)
	lrpRun(t, e, cycle)
	if len(e.Kills) != 1 || e.Kills[0].PID != 4343 {
		t.Fatalf("kills=%v want exactly the agent kill", e.Kills)
	}
}

// TestLRPRunSliceAllNotReadyIsNoDesync: a Service whose slices exist
// but carry only ready=false endpoints legitimately reports 0 — not
// a missing verdict, so the desync streak resets and the :53 wedge
// proceeds to the pod delete.
func TestLRPRunSliceAllNotReadyIsNoDesync(t *testing.T) {
	pod := nldPod("node-local-dns-eee555", wdepstest.UIDA)
	e := lrpFixture(t, kubeDNSSlice(false), pod)
	e.SvcBackends = map[string]int{"kube-system/kube-dns": 0}
	e.H.Cfg.Seams.Probe.DNSProbe = func(context.Context, string, string, time.Duration) bool { return false }
	e.DNSTCP = false
	cycle := &wdeps.CycleEnv{
		Pods: []corev1.Pod{*pod}, APIOK: true, WorkerActive: true}
	lrpRun(t, e, cycle)
	lrpRun(t, e, cycle) // desync never armed → pod delete fires
	if _, err := e.CS.CoreV1().Pods("kube-system").Get(
		context.Background(), "node-local-dns-eee555", metav1.GetOptions{}); err == nil {
		t.Fatal("pod kept — all-not-ready slices must not read as a desync")
	}
}

// TestLRPRunNoReadyNLDResetsStreak: not-Running/NotReady pods are
// kubelet's problem — nothing owes a datapath answer, streak resets.
func TestLRPRunNoReadyNLDResetsStreak(t *testing.T) {
	e := lrpFixture(t, kubeDNSEndpoints())
	noDesync(e)
	stubProbeFails(t, e)
	pending := nldPod("node-local-dns-fff666", wdepstest.UIDA)
	pending.Status.Conditions = nil // NotReady
	c := wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP)
	c.Fails = 3
	c.Run(context.Background(), &wdeps.CycleEnv{
		Pods: []corev1.Pod{*pending}, APIOK: true, WorkerActive: true})
	if c.Fails != 0 {
		t.Fatalf("Fails=%d want 0 with no Ready nld pod", c.Fails)
	}
}
