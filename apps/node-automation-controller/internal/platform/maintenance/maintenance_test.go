package maintenance

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

// maintenanceDynFake returns a dynamic fake that knows the PlanList
// kind (and every other CRD the modules list) via the shared
// platform/testhelp table — the leaf-level home for the fake
// testutil cannot host (testutil imports internal/shared).
// ctx is the shared background context every test in this file
// passes through — the moved kube maintenance tests all ran on it.
var ctx = context.Background()

func maintenanceDynFake(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return testhelp.NewDynamicClient(objs...)
}

// maintenancePlan builds a Plan CR in `state` — "" renders no status
// at all (a brand-new Plan before the controller writes one).
func maintenancePlan(name, state string) *unstructured.Unstructured {
	u := testhelp.Unstructured(
		kube.AutopilotPlanGVR.GroupVersion().WithKind("Plan"), "", name, nil)
	if state != "" {
		u.Object["status"] = map[string]any{"state": state}
	}
	return u
}

// maintenanceKured builds the kured kube.DaemonSet carrying `annos`.
func maintenanceKured(annos map[string]string) *appsv1.DaemonSet {
	return &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: kuredDaemonSetNS, Name: kuredDaemonSetName,
		Annotations: annos}}
}

// maintenanceCordoned builds a node cordoned `ago` — a negative ago
// yields a timestamp-less cordon (unverifiable → fail closed).
func maintenanceCordoned(name string, ago time.Duration) *corev1.Node {
	n := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{Unschedulable: true},
	}
	if ago >= 0 {
		t := metav1.NewTime(time.Now().Add(-ago))
		n.Spec.Taints = []corev1.Taint{
			{Key: kube.UnschedulableTaintKey, TimeAdded: &t}}
	}
	return n
}

// Signal (a): only an ACTIVE cordon is evidence — a node cordoned
// past the 45m window is deliberate static state and yields none.
func TestNodeCordonEvidenceFreshOnly(t *testing.T) {
	fresh := maintenanceCordoned("w1", 10*time.Minute)
	stale := maintenanceCordoned("w2", 2*time.Hour)
	cs := fake.NewSimpleClientset(fresh, stale)
	ev, err := nodeCordonEvidence(t.Context(), cs, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ev, []string{"node w1 actively cordoned"}) {
		t.Fatalf("evidence = %v, want only the fresh cordon", ev)
	}
}

// A node kube.LIST failure is an error — never a silent clear.
func TestNodeCordonEvidenceListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	if _, err := nodeCordonEvidence(ctx, cs, nil, time.Now()); err == nil {
		t.Fatal("expected error when the node list fails")
	}
}

// The injected clock decides the verdict: ONE fixture evaluated at
// two `now`s flips fresh-evidence → static-cordon without racing
// time.Now at the 45m boundary (the fake-clock plumbing
// MaintenanceActiveWithClock exists for).
func TestNodeCordonEvidenceUsesInjectedClock(t *testing.T) {
	base := time.Now()
	n := maintenanceCordoned("w1", 10*time.Minute) // TimeAdded = base-10m
	cs := fake.NewSimpleClientset(n)
	ev, err := nodeCordonEvidence(ctx, cs, nil, base)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ev, []string{"node w1 actively cordoned"}) {
		t.Fatalf("at base the cordon is fresh evidence, got %v", ev)
	}
	ev, err = nodeCordonEvidence(ctx, cs, nil, base.Add(46*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 0 {
		t.Fatalf("46m later the cordon must read static, got %v", ev)
	}
	// The clock-aware mutex plumbing reaches through to the cordon
	// window identically (a dyn fake is required once the cordon
	// stops answering — the short-circuit then reaches signal (c)).
	held, why, err := MaintenanceActiveWithClock(ctx, cs, maintenanceDynFake(), base)
	if err != nil || !held || why != "node w1 actively cordoned" {
		t.Fatalf("WithClock(base): held=%v why=%q err=%v — want the cordon", held, why, err)
	}
	held, _, err = MaintenanceActiveWithClock(ctx, cs, maintenanceDynFake(), base.Add(46*time.Minute))
	if err != nil || held {
		t.Fatalf("WithClock(base+46m): held=%v err=%v — want static cordon (clear)", held, err)
	}
}

// Signal (b): the held lock is evidence; an unlocked or absent kured
// kube.DaemonSet is none.
func TestKuredLockEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		objs []runtime.Object
		want []string
	}{
		{"absent daemonset", nil, nil},
		{"no lock annotation", []runtime.Object{maintenanceKured(nil)}, nil},
		{"lock held", []runtime.Object{maintenanceKured(
			map[string]string{KuredLockAnno: "w1"})},
			[]string{"kured lock held by w1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(tc.objs...)
			ev, err := KuredLockEvidence(ctx, cs)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(ev, tc.want) {
				t.Fatalf("evidence = %v, want %v", ev, tc.want)
			}
		})
	}
}

// Signal (c): a nil dyn is a wiring bug (error), terminal plans are
// not evidence, and a Plan outside {Schedulable, Completed} —
// including one with no status.state at all — is.
func TestAutopilotPlanEvidence(t *testing.T) {
	if _, err := AutopilotPlanEvidence(ctx, nil); err == nil {
		t.Fatal("expected error when dyn is nil")
	}
	for _, tc := range []struct {
		name  string
		plans []runtime.Object
		want  []string
	}{
		{"no plans", nil, nil},
		{"terminal plans", []runtime.Object{
			maintenancePlan("a", "Schedulable"),
			maintenancePlan("b", "Completed")}, nil},
		{"active plan", []runtime.Object{
			maintenancePlan("up", "InProgress")},
			[]string{"autopilot plan up state=InProgress"}},
		// A status-less plan is not provably terminal — fail closed.
		{"stateless plan", []runtime.Object{
			maintenancePlan("new", "")},
			[]string{"autopilot plan new state="}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := AutopilotPlanEvidence(ctx,
				maintenanceDynFake(tc.plans...))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(ev, tc.want) {
				t.Fatalf("evidence = %v, want %v", ev, tc.want)
			}
		})
	}
}

// MaintenanceActive keeps the historical short-circuit: the FIRST
// held signal answers the verdict and the later checks never run —
// proven here by a cordoned node masking a nil dyn (which would
// error if the autopilot check were reached).
func TestMaintenanceActiveShortCircuitsOnCordon(t *testing.T) {
	cs := fake.NewSimpleClientset(maintenanceCordoned("w1", time.Minute))
	held, why, err := MaintenanceActive(ctx, cs, nil)
	if err != nil {
		t.Fatalf("cordoned node must answer before the nil-dyn check: %v", err)
	}
	if !held || why != "node w1 actively cordoned" {
		t.Fatalf("held=%v why=%q, want the cordon evidence", held, why)
	}
}

// Signal (d): live medik8s remediation objects hold the mutex — a
// SelfNodeRemediation/FenceAgentsRemediation exists only while its
// fencing is in flight and a non-Succeeded NodeMaintenance is a live
// NMO cordon+drain. Succeeded NodeMaintenance records and absent
// CRDs are no evidence; a nil dyn stays unverifiable.
func TestMaintenanceActiveMedik8sRemediation(t *testing.T) {
	remObj := func(gvr schema.GroupVersionResource, kind, ns, name, phase string) *unstructured.Unstructured {
		u := testhelp.Unstructured(
			gvr.GroupVersion().WithKind(kind), ns, name, nil)
		if phase != "" {
			u.Object["status"] = map[string]any{"phase": phase}
		}
		return u
	}

	if _, err := Medik8sRemediationEvidence(ctx, nil); err == nil {
		t.Fatal("expected error when dyn is nil")
	}
	// No remediation objects — no signal, and MaintenanceActive
	// stays clear through the whole signal chain.
	cs := fake.NewSimpleClientset()
	if held, why, err := MaintenanceActive(ctx, cs, maintenanceDynFake()); err != nil || held {
		t.Fatalf("empty cluster: held=%v why=%q err=%v", held, why, err)
	}
	for _, tc := range []struct {
		name string
		objs []runtime.Object
		held bool
	}{
		{"self-node-remediation", []runtime.Object{remObj(
			kube.GVRSelfNodeRemediation, "SelfNodeRemediation", "medik8s", "w1-snr", "")}, true},
		{"fence-agents-remediation", []runtime.Object{remObj(
			kube.GVRFenceAgentsRemediation, "FenceAgentsRemediation", "medik8s", "w1-far", "")}, true},
		{"node-maintenance running", []runtime.Object{remObj(
			kube.GVRNodeMaintenance, "NodeMaintenance", "", "w1", "Running")}, true},
		{"node-maintenance succeeded", []runtime.Object{remObj(
			kube.GVRNodeMaintenance, "NodeMaintenance", "", "w1", "Succeeded")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			held, why, err := MaintenanceActive(ctx, cs,
				maintenanceDynFake(tc.objs...))
			if err != nil {
				t.Fatal(err)
			}
			if held != tc.held {
				t.Fatalf("held=%v (why %q), want %v", held, why, tc.held)
			}
			if tc.held && !strings.Contains(why, "medik8s remediation") {
				t.Fatalf("why=%q, want medik8s remediation evidence", why)
			}
		})
	}
}

// node-hang-precordon — a node cordoned BY node-hang-precordon (the defensive
// quarantine, stamped kube.AnnoPreCordonedBy) is not maintenance: its
// fresh unschedulable taint must not hold the mutex, or every
// heal.AllowedV-gated remediation freezes for 45m exactly while the
// cluster is sick.
func TestMaintenanceActiveIgnoresPreCordoned(t *testing.T) {
	n := maintenanceCordoned("w1", time.Minute)
	n.Annotations = map[string]string{
		kube.AnnoPreCordonedBy: "node-hang-precordon"}
	cs := fake.NewSimpleClientset(n)
	held, why, err := MaintenanceActive(ctx, cs, maintenanceDynFake())
	if err != nil {
		t.Fatal(err)
	}
	if held {
		t.Fatalf("pre-cordoned node held the mutex: %q", why)
	}
}

// A nil dyn still fails closed when reached — the mutex never reads
// "cannot verify" as "clear".
func TestMaintenanceActiveNilDynFailsClosed(t *testing.T) {
	cs := fake.NewSimpleClientset()
	if _, _, err := MaintenanceActive(ctx, cs, nil); err == nil {
		t.Fatal("expected error when dyn is nil")
	}
}

// A held signal's evidence is the verdict's `why` — the first
// active signal in canonical order answers (the cordon beats a
// held kured lock and a live Plan here).
func TestMaintenanceActiveWhyIsFirstSignalEvidence(t *testing.T) {
	cs := fake.NewSimpleClientset(
		maintenanceCordoned("w1", time.Minute),
		maintenanceKured(map[string]string{KuredLockAnno: "w2"}))
	dyn := maintenanceDynFake(maintenancePlan("up", "InProgress"))
	held, why, err := MaintenanceActive(ctx, cs, dyn)
	if err != nil {
		t.Fatal(err)
	}
	if !held || why != "node w1 actively cordoned" {
		t.Fatalf("held=%v why=%q, want the cordon evidence", held, why)
	}
}

// ---------------------------------------------------------------------------
// Pagination — the evidence helpers walk kube.ListAllUnstructured, so a
// cluster whose objects exceed one page (Limit=kube.DefaultListPageSize)
// must contribute evidence from EVERY page via the Continue-token
// walk, and the dynamic fake's single-page reply cannot prove that.
// pagedDyn wraps the CRD-aware dynamic fake and serves each GVR's
// objects in `per`-object pages, honoring Continue — the observable
// difference between a real walk and a one-page List.
// ---------------------------------------------------------------------------

type pagedDyn struct {
	dynamic.Interface
	per   int
	lists *int
}

func (p *pagedDyn) Resource(gvr schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return &pagedResource{nsable: p.Interface.Resource(gvr), per: p.per, lists: p.lists}
}

type pagedResource struct {
	dynamic.NamespaceableResourceInterface
	nsable dynamic.NamespaceableResourceInterface
	per    int
	lists  *int
}

func (p *pagedResource) List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	*p.lists++
	full, err := p.nsable.List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	start := 0
	if opts.Continue != "" {
		if start, err = strconv.Atoi(opts.Continue); err != nil {
			return nil, err
		}
	}
	end := len(full.Items)
	// The SERVER decides the page size: it serves `per` items per
	// response no matter how large a Limit the client asked for —
	// exactly the apiserver behavior the Continue walk exists for.
	if p.per > 0 && start+p.per < end {
		end = start + p.per
	}
	next := ""
	if end < len(full.Items) {
		next = strconv.Itoa(end)
	}
	out := &unstructured.UnstructuredList{Items: full.Items[start:end]}
	if next != "" {
		out.Object = map[string]any{
			"metadata": map[string]any{"continue": next}}
	}
	return out, nil
}

// Signal (c) across pages: plans in a non-terminal state on page 1
// kube.AND page 2 both land as evidence, and the walk really continued
// (more than one List issued).
func TestAutopilotPlanEvidencePagesThroughPlans(t *testing.T) {
	plans := []runtime.Object{
		maintenancePlan("up1", "InProgress"),
		maintenancePlan("done1", "Completed"),
		maintenancePlan("up2", "Draining"),
		maintenancePlan("done2", "Schedulable"),
	}
	var lists int
	dyn := &pagedDyn{Interface: maintenanceDynFake(plans...), per: 2, lists: &lists}
	ev, err := AutopilotPlanEvidence(ctx, dyn)
	if err != nil {
		t.Fatal(err)
	}
	if lists != 2 {
		t.Fatalf("lists=%d, want 2 — the walk must continue past page 1", lists)
	}
	if !slices.Equal(ev, []string{
		"autopilot plan up1 state=InProgress",
		"autopilot plan up2 state=Draining",
	}) {
		t.Fatalf("evidence = %v, want both non-terminal plans across pages", ev)
	}
}

// Signal (d) across pages: live remediation objects past the first
// page still hold the mutex (the first page holds only a finished
// NodeMaintenance record).
func TestMedik8sRemediationEvidencePagesThroughObjects(t *testing.T) {
	rem := func(gvr schema.GroupVersionResource, kind, ns, name string) runtime.Object {
		return testhelp.Unstructured(gvr.GroupVersion().WithKind(kind), ns, name, nil)
	}
	objs := []runtime.Object{
		rem(kube.GVRNodeMaintenance, "NodeMaintenance", "", "done"),
	}
	// Give the finished record its Succeeded phase, then two live
	// objects — the second deliberately beyond a 2-per-page boundary.
	objs[0].(*unstructured.Unstructured).Object["status"] =
		map[string]any{"phase": "Succeeded"}
	live := []runtime.Object{
		rem(kube.GVRSelfNodeRemediation, "SelfNodeRemediation", "medik8s", "w1-snr"),
		rem(kube.GVRFenceAgentsRemediation, "FenceAgentsRemediation", "medik8s", "w1-far"),
	}
	var lists int
	dyn := &pagedDyn{
		Interface: maintenanceDynFake(append(objs, live...)...),
		per:       2, lists: &lists}
	ev, err := Medik8sRemediationEvidence(ctx, dyn)
	if err != nil {
		t.Fatal(err)
	}
	// One List per remediation GVR, each walked through its page(s).
	if lists < 2 {
		t.Fatalf("lists=%d, want ≥2 — evidence must page through", lists)
	}
	if len(ev) != 2 {
		t.Fatalf("evidence = %v, want exactly the two live remediation objects "+
			"(the Succeeded NodeMaintenance record is not live evidence)", ev)
	}
	for _, want := range []string{"w1-snr", "w1-far"} {
		if !strings.Contains(strings.Join(ev, "; "), want) {
			t.Fatalf("evidence %v missing live object %s — the walk dropped a page", ev, want)
		}
	}
}

// Verdict.Active memoizes one MaintenanceActive evaluation for the
// verdict TTL: a signal that appears mid-window must NOT flip the
// held verdict (the sweep's per-target heal preambles share the one
// evaluation), and a fresh evaluation past the TTL sees it. An error
// verdict is sticky for the window too — the fail-closed contract.
func TestVerdictActiveMemoizesWithinTTL(t *testing.T) {
	ctx := t.Context()
	cs := fake.NewSimpleClientset()
	dyn := maintenanceDynFake()
	base := time.Now()

	var v Verdict
	held, why, err := v.Active(ctx, cs, dyn, base)
	if err != nil || held || why != "" {
		t.Fatalf("empty cluster verdict = (%v,%q,%v), want clear", held, why, err)
	}

	// A drain starts mid-window — inside the TTL the memoized clear
	// verdict still answers (one mutex evaluation per sweep, not per
	// target).
	cordoned := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "draining"},
		Spec: corev1.NodeSpec{
			Unschedulable: true,
			Taints: []corev1.Taint{{
				Key:       kube.UnschedulableTaintKey,
				TimeAdded: &metav1.Time{Time: base},
			}},
		},
	}
	if _, err := cs.CoreV1().Nodes().Create(ctx, cordoned, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	held, _, err = v.Active(ctx, cs, dyn, base.Add(verdictTTL-time.Second))
	if err != nil || held {
		t.Fatalf("memoized verdict inside TTL = (%v,%v), want the stale clear", held, err)
	}

	// Past the TTL the verdict re-evaluates and sees the cordon.
	held, why, err = v.Active(ctx, cs, dyn, base.Add(verdictTTL+time.Second))
	if err != nil || !held {
		t.Fatalf("re-evaluated verdict = (%v,%v), want held", held, err)
	}
	if !strings.Contains(why, "draining") {
		t.Fatalf("verdict why = %q, want the cordon evidence", why)
	}
}

// An unverifiable evaluation (nil dyn → the autopilot/medik8s plan
// signals cannot be read) is memoized for the window too — a caller
// looping targets does not re-pay three failing API reads per target,
// and the fail-closed error never silently clears.
func TestVerdictActiveSticksErrorWithinTTL(t *testing.T) {
	ctx := t.Context()
	cs := fake.NewSimpleClientset()
	base := time.Now()

	var v Verdict
	if _, _, err := v.Active(ctx, cs, nil, base); err == nil {
		t.Fatal("nil dyn must make the verdict unverifiable")
	}
	// Wire a working dyn mid-window — the memoized error still
	// answers; only a TTL expiry re-evaluates.
	if _, _, err := v.Active(ctx, cs, maintenanceDynFake(),
		base.Add(verdictTTL-time.Second)); err == nil {
		t.Fatal("error verdict re-evaluated inside the TTL")
	}
	if _, _, err := v.Active(ctx, cs, maintenanceDynFake(),
		base.Add(verdictTTL+time.Second)); err != nil {
		t.Fatalf("post-TTL re-evaluation kept the stale error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// kured lock parsing / medik8s target resolution / verdict read-only /
// StampMaintenanceTargets convergence — the Phase-3 reliability work.
// ---------------------------------------------------------------------------

// kuredLockNodeID decodes the documented {"nodeID":"<node>"} JSON
// shape and falls back to the raw value for anything else — an
// unresolvable value must reach the caller intact so it can degrade
// to the conservative cluster-wide hold instead of silently reading
// as "no lock".
func TestKuredLockNodeID(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{`{"nodeID":"w1"}`, "w1"},
		{`{"nodeID":"w1","extra":1}`, "w1"},
		{"w1", "w1"},                       // legacy raw-node-name writer
		{`{"nodeID":""}`, `{"nodeID":""}`}, // JSON without usable nodeID → raw
		{`{"other":"x"}`, `{"other":"x"}`},
		{"not-json{", "not-json{"},
	} {
		if got := kuredLockNodeID(tc.in); got != tc.want {
			t.Fatalf("kuredLockNodeID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// medik8sTargetNode: the annotation wins outright, an exact node-name
// match beats prefix inference, and among "<node>-<suffix>" CR names
// the LONGEST matching node prefix wins — map iteration order must
// never decide which node a remediation holds.
func TestMedik8sTargetNodeLongestPrefix(t *testing.T) {
	nodeNames := map[string]bool{"worker-1": true, "worker-1-gpu": true}
	obj := func(name string, annos map[string]string) *unstructured.Unstructured {
		u := testhelp.Unstructured(
			kube.GVRSelfNodeRemediation.GroupVersion().WithKind("SelfNodeRemediation"),
			"medik8s", name, nil)
		u.SetAnnotations(annos)
		return u
	}
	for _, tc := range []struct {
		name string
		obj  *unstructured.Unstructured
		want string
	}{
		{"annotation wins", obj("cr-x", map[string]string{
			remediationNodeNameAnno: "annotated-node"}), "annotated-node"},
		{"exact node name", obj("worker-1", nil), "worker-1"},
		{"shortest prefix", obj("worker-1-reboot", nil), "worker-1"},
		// The bug shape: both "worker-1" and "worker-1-gpu" prefix the
		// CR name — the longer node name is the real target.
		{"longest prefix wins", obj("worker-1-gpu-reboot", nil), "worker-1-gpu"},
		{"no match", obj("other-node-x", nil), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Run the resolution repeatedly — a first-prefix-hit
			// implementation flips answers across map orders.
			for i := 0; i < 50; i++ {
				if got := medik8sTargetNode(tc.obj, nodeNames); got != tc.want {
					t.Fatalf("medik8sTargetNode(%q) = %q, want %q",
						tc.obj.GetName(), got, tc.want)
				}
			}
		})
	}
}

// Verdict.Active is READ-ONLY: a held verdict must never patch kube.Nodes
// — stamping is the dedicated runnable's job. A fresh cordon holds
// the verdict and the fake clientset must record ZERO writes.
func TestVerdictActiveIsReadOnly(t *testing.T) {
	ctx := t.Context()
	n := maintenanceCordoned("w1", time.Minute)
	cs := fake.NewSimpleClientset(n)
	dyn := maintenanceDynFake()

	var v Verdict
	held, why, err := v.Active(ctx, cs, dyn, time.Now())
	if err != nil || !held {
		t.Fatalf("verdict = (%v,%q,%v), want held on the fresh cordon",
			held, why, err)
	}
	for _, a := range cs.Actions() {
		if a.GetVerb() == "patch" || a.GetVerb() == "update" ||
			a.GetVerb() == "create" || a.GetVerb() == "delete" {
			t.Fatalf("verdict evaluation issued a write: %v %v",
				a.GetVerb(), a.GetResource())
		}
	}
}

// stampTestNode builds a node carrying an optional
// cluster-maintenance-until stamp, cordoned `cordonAgo` ago (0 = no
// cordon at all — a fresh taint would need a nonzero ago).
func stampTestNode(name string, cordonAgo time.Duration,
	stamp string) *corev1.Node {
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if cordonAgo > 0 {
		n.Spec.Unschedulable = true
		t := metav1.NewTime(time.Now().Add(-cordonAgo))
		n.Spec.Taints = []corev1.Taint{{
			Key: kube.UnschedulableTaintKey, TimeAdded: &t}}
	}
	if stamp != "" {
		n.Annotations = map[string]string{
			"passiontech.dev/cluster-maintenance-until": stamp}
	}
	return n
}

// StampMaintenanceTargets converges the annotation set: the cordoned
// node takes a fresh stamp (~now+15m), a node outside the target set
// loses a stamp THIS controller could have written, and foreign
// values are never touched.
func TestStampMaintenanceTargetsStampsAndUnstamps(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	owned := now.Add(maintenanceStampTTL).UTC().Format(time.RFC3339)
	farFuture := now.Add(3 * time.Hour).UTC().Format(time.RFC3339)
	w1 := stampTestNode("w1", time.Minute, "")     // cordoned → target
	w2 := stampTestNode("w2", 0, owned)            // owned stamp → removed
	w3 := stampTestNode("w3", 0, "manual-forever") // foreign → kept
	w4 := stampTestNode("w4", 0, farFuture)        // out-of-domain → kept
	cs := fake.NewSimpleClientset(w1, w2, w3, w4)

	StampMaintenanceTargets(ctx, cs, maintenanceDynFake(), nil, now)

	get := func(name string) *corev1.Node {
		n, err := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get %s: %v", name, err)
		}
		return n
	}
	if v := get("w1").Annotations["passiontech.dev/cluster-maintenance-until"]; v == "" {
		t.Fatal("cordoned node w1 was not stamped")
	} else if ts, ok := kube.ParseAnnoTime(v); !ok ||
		ts.Before(now.Add(maintenanceStampTTL-time.Minute)) ||
		ts.After(now.Add(maintenanceStampTTL+time.Minute)) {
		t.Fatalf("w1 stamp %q is not ~now+TTL", v)
	}
	if v, ok := get("w2").Annotations["passiontech.dev/cluster-maintenance-until"]; ok {
		t.Fatalf("w2's controller-owned stamp survived maintenance end: %q", v)
	}
	if v := get("w3").Annotations["passiontech.dev/cluster-maintenance-until"]; v != "manual-forever" {
		t.Fatalf("w3's foreign stamp was touched: %q", v)
	}
	if v := get("w4").Annotations["passiontech.dev/cluster-maintenance-until"]; v != farFuture {
		t.Fatalf("w4's out-of-domain stamp was touched: %q", v)
	}
}

// A degraded signal read disables ONLY the unstamp half: with the
// kured GET failing, the cordoned node still gets stamped but the
// owned stamp on the quiet node must survive — dropping a hold on a
// signal we failed to observe is the unsafe direction.
func TestStampMaintenanceTargetsDegradedKeepsStamps(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	owned := now.Add(maintenanceStampTTL).UTC().Format(time.RFC3339)
	w1 := stampTestNode("w1", time.Minute, "")
	w2 := stampTestNode("w2", 0, owned)
	cs := fake.NewSimpleClientset(w1, w2)
	cs.PrependReactor("get", "daemonsets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver flap")
		})

	StampMaintenanceTargets(ctx, cs, maintenanceDynFake(), nil, now)

	w1n, err := cs.CoreV1().Nodes().Get(ctx, "w1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if w1n.Annotations["passiontech.dev/cluster-maintenance-until"] == "" {
		t.Fatal("degraded read must not block stamping the cordoned node")
	}
	w2n, err := cs.CoreV1().Nodes().Get(ctx, "w2", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if v := w2n.Annotations["passiontech.dev/cluster-maintenance-until"]; v != owned {
		t.Fatalf("degraded read dropped an owned hold: got %q want %q", v, owned)
	}
}

// A live autopilot Plan is cluster-wide maintenance: EVERY node
// takes the stamp, including ones with no cordon and no remediation.
func TestStampMaintenanceTargetsClusterWide(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	w1 := stampTestNode("w1", 0, "")
	w2 := stampTestNode("w2", 0, "")
	cs := fake.NewSimpleClientset(w1, w2)
	dyn := maintenanceDynFake(maintenancePlan("upgrade", "InProgress"))

	StampMaintenanceTargets(ctx, cs, dyn, nil, now)

	for _, name := range []string{"w1", "w2"} {
		n, err := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if n.Annotations["passiontech.dev/cluster-maintenance-until"] == "" {
			t.Fatalf("cluster-wide maintenance left %s unstamped", name)
		}
	}
}
