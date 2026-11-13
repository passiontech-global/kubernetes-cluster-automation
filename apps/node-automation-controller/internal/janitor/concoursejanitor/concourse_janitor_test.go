package concoursejanitor

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Fakes + builders (cj-prefixed)
// ---------------------------------------------------------------------------

// cjFakeStats records "stats:<node>" and answers through fn(node,
// callNumber) so tests can return different readings before/after a
// wipe (call is per-node, starting at 1).
type cjFakeStats struct {
	events *[]string
	calls  map[string]int
	fn     func(node string, call int) (int64, int64, int64, error)
}

func (f *cjFakeStats) Summary(_ context.Context, node string) (int64, int64, int64, error) {
	*f.events = append(*f.events, "stats:"+node)
	f.calls[node]++
	return f.fn(node, f.calls[node])
}

// cjFakeATC records every call; landWorker flips the recorded worker
// state to "landed" so the drain loop finishes on the first poll.
// landErr makes the land call fail (drain never starts); stateFn, if
// set, answers workerState calls with per-call control.
type cjFakeATC struct {
	events   *[]string
	loginErr error
	stateErr error
	landErr  error
	states   map[string]string
	stateFn  func(name string) (string, error)
}

func (f *cjFakeATC) login(_ context.Context, user, _ string) error {
	*f.events = append(*f.events, "login:"+user)
	return f.loginErr
}

func (f *cjFakeATC) workerState(_ context.Context, name string) (string, error) {
	*f.events = append(*f.events, "state:"+name)
	if f.stateFn != nil {
		return f.stateFn(name)
	}
	if f.stateErr != nil {
		return "", f.stateErr
	}
	return f.states[name], nil
}

func (f *cjFakeATC) landWorker(_ context.Context, name string) error {
	*f.events = append(*f.events, "land:"+name)
	if f.landErr != nil {
		return f.landErr
	}
	f.states[name] = "landed"
	return nil
}

func (f *cjFakeATC) pruneWorker(_ context.Context, name string) error {
	*f.events = append(*f.events, "prune:"+name)
	return nil
}

func cjWorkerPod(name, uid, node string, ready bool, annos map[string]string) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: cjNamespace, Name: name,
			UID: types.UID(uid), Annotations: annos,
		},
		Spec: corev1.PodSpec{NodeName: node},
	}
	if ready {
		p.Status.Conditions = []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionTrue,
				LastTransitionTime: metav1.NewTime(time.Now())},
		}
	}
	return p
}

func cjWorkerSTS(replicas int32) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: cjNamespace, Name: cjStatefulSet},
		Spec:       appsv1.StatefulSetSpec{Replicas: &replicas},
	}
}

// cjReadySibling is the always-Ready second worker the keep-one-Ready
// guard requires: single-worker fixtures add it so the wipe under
// test still has a serving sibling (the guard skips a wipe that
// would leave zero Ready workers — a lone worker is never a wipe
// candidate).
func cjReadySibling() *corev1.Pod {
	return cjWorkerPod("concourse-worker-99", "uid-sibling", "node-b", true, nil)
}

func cjLocalUsers() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: cjNamespace, Name: cjSecretName},
		Data:       map[string][]byte{cjSecretKey: []byte("admin:s3cr3t\nbackup:x\n")},
	}
}

var cjPodsGVR = schema.GroupVersionResource{Version: "v1", Resource: "pods"}

// cjPlanDynFake returns a dynamic fake that knows the PlanList kind
// for the maintenance-mutex autopilot check (the autopilot Plan CRD
// is in testutil.NewDynamicClient's baked-in table).

func cjPlanDynFake(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return testutil.NewDynamicClient(objs...)
}

// cjAutopilotPlan builds a Plan CR in `state`.
func cjAutopilotPlan(name, state string) *unstructured.Unstructured {
	return testutil.Unstructured(
		kube.AutopilotPlanGVR.GroupVersion().WithKind("Plan"), "", name,
		map[string]any{"status": map[string]any{"state": state}})
}

// cjReplaceOnDelete makes the fake apiserver behave like the
// StatefulSet controller + init-rm: deleting a worker pod instantly
// installs a successor (same node) with a fresh UID, Ready when the
// caller says so.
func cjReplaceOnDelete(cs *fake.Clientset, events *[]string, ready bool) {
	cs.PrependReactor("delete", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
		d := a.(ktesting.DeleteAction)
		*events = append(*events, "delete:"+d.GetName())
		node := "node-a"
		if old, err := cs.Tracker().Get(cjPodsGVR, d.GetNamespace(), d.GetName()); err == nil {
			if p, ok := old.(*corev1.Pod); ok {
				node = p.Spec.NodeName
			}
		}
		if err := cs.Tracker().Delete(cjPodsGVR, d.GetNamespace(), d.GetName()); err != nil {
			return true, nil, err
		}
		return true, nil, cs.Tracker().Add(
			cjWorkerPod(d.GetName(), "uid-new-"+d.GetName(), node, ready, nil))
	})
}

// cjTestJanitor builds a janitor with shrunk timeouts — every poll
// fires immediately on the first check; timeouts only matter for the
// failure tests. dyn is an empty autopilot-aware fake — tests that
// exercise the maintenance mutex install a real Plan themselves.
func cjTestJanitor(cs *fake.Clientset, st nodeStatsReader, atc atcIface) *concourseWorkdirJanitor {
	return &concourseWorkdirJanitor{queue: "concourse-workdir-janitor",
		cs: cs, stats: st, atc: atc,
		dyn: cjPlanDynFake(),
		cfg: cjConfig{
			runTimeout:     10 * time.Second,
			reqTimeout:     10 * time.Second,
			drainTimeout:   50 * time.Millisecond,
			landFailWait:   10 * time.Millisecond,
			pruneStateWait: 10 * time.Millisecond,
			deleteTimeout:  100 * time.Millisecond,
			uidPollTimeout: 100 * time.Millisecond,
			readyTimeout:   100 * time.Millisecond,
			fastPoll:       time.Millisecond,
			slowPoll:       time.Millisecond,
		},
	}
}

func cjPod(t *testing.T, cs *fake.Clientset, name string) *corev1.Pod {
	t.Helper()
	p, err := cs.CoreV1().Pods(cjNamespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get pod %s: %v", name, err)
	}
	return p
}
