// pod_ops.go — the Kubernetes object operations of the janitor's
// wipe cycle: pod get/delete and the replacement-pod waits (split
// out of concourse_janitor.go — see its header for the module
// contract).
package concoursejanitor

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

// ---------------------------------------------------------------------------
// Kubernetes API helpers — every call carries ctx (+ reqTimeout where
// bash used --request-timeout).
// ---------------------------------------------------------------------------

func (j *concourseWorkdirJanitor) getPod(ctx context.Context, name string) (*corev1.Pod, error) {
	cctx, cancel := context.WithTimeout(ctx, j.reqTimeout)
	defer cancel()
	return j.cs.CoreV1().Pods(cjNamespace).Get(cctx, name, metav1.GetOptions{})
}

func (j *concourseWorkdirJanitor) workerReplicas(ctx context.Context) (int32, error) {
	cctx, cancel := context.WithTimeout(ctx, j.reqTimeout)
	defer cancel()
	sts, err := j.cs.AppsV1().StatefulSets(cjNamespace).Get(cctx, cjStatefulSet, metav1.GetOptions{})
	if err != nil {
		return 0, fmt.Errorf("get sts %s: %w", cjStatefulSet, err)
	}
	if sts.Spec.Replicas == nil {
		return 0, fmt.Errorf("sts %s: spec.replicas unset", cjStatefulSet)
	}
	return *sts.Spec.Replicas, nil
}

// deletePod issues the delete and waits (bounded by deleteTimeout)
// until the OLD object is actually gone — `kubectl delete --wait`.
// "Gone" is uid-scoped: a same-named replacement created before our
// first poll still confirms the old object's deletion.
func (j *concourseWorkdirJanitor) deletePod(ctx context.Context, name string, oldUID types.UID) error {
	dctx, cancel := context.WithTimeout(ctx, j.deleteTimeout)
	defer cancel()
	// UID precondition: oldUID was re-fetched right before this call
	// — if the object already churned to a new UID, the delete must
	// conflict rather than remove a pod we never vetted.
	if err := j.cs.CoreV1().Pods(cjNamespace).Delete(dctx, name,
		shared.UIDDeleteOptions(oldUID, "")); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete pod %s: %w", name, err)
	}
	err := wait.PollUntilContextCancel(dctx, j.fastPoll, true,
		func(ctx context.Context) (bool, error) {
			p, err := j.cs.CoreV1().Pods(cjNamespace).Get(ctx, name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return true, nil
			}
			if err != nil {
				logf.FromContext(ctx).V(1).Info("pod get failed — keep waiting", "pod", name, "error", err)
				return false, nil // transient — keep waiting
			}
			return p.UID != oldUID, nil // old object deleted (or still terminating)
		})
	if err != nil {
		return fmt.Errorf("pod %s still present after %s: %w", name, j.deleteTimeout, err)
	}
	return nil
}

// waitNewPod blocks until a pod with a DIFFERENT uid exists — the old
// object can linger in terminating, so waiting on the name alone
// would pin onto the old pod. No replacement inside uidPollTimeout is
// a run error (bash `exit 1`: "new pod not created").
func (j *concourseWorkdirJanitor) waitNewPod(ctx context.Context, name string, oldUID types.UID) error {
	dctx, cancel := context.WithTimeout(ctx, j.uidPollTimeout)
	defer cancel()
	err := wait.PollUntilContextCancel(dctx, j.fastPoll, true,
		func(ctx context.Context) (bool, error) {
			p, err := j.cs.CoreV1().Pods(cjNamespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				logf.FromContext(ctx).V(1).Info("pod get failed — keep polling", "pod", name, "error", err)
				return false, nil // not created yet / transient — keep polling
			}
			return p.UID != oldUID, nil
		})
	if err != nil {
		return fmt.Errorf("pod %s: new pod not created within %s: %w", name, j.uidPollTimeout, err)
	}
	return nil
}

// waitReady blocks until the pod's Ready condition is True — init-rm
// of a huge work-dir is why the window is so generous.
func (j *concourseWorkdirJanitor) waitReady(ctx context.Context, name string) error {
	dctx, cancel := context.WithTimeout(ctx, j.readyTimeout)
	defer cancel()
	err := wait.PollUntilContextCancel(dctx, j.slowPoll, true,
		func(ctx context.Context) (bool, error) {
			p, err := j.cs.CoreV1().Pods(cjNamespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				logf.FromContext(ctx).V(1).Info("pod get failed — keep polling", "pod", name, "error", err)
				return false, nil // transient — keep polling
			}
			return shared.PodReadyCond(p), nil
		})
	if err != nil {
		return fmt.Errorf("pod %s not Ready after %s: %w", name, j.readyTimeout, err)
	}
	return nil
}
