// stalled_deployment.go — workload resolution for
// helm_stall_unwedge.go: which Deployment helm was waiting on when
// it aborted. An explicit "Deployment/<name>" (or "<ns>/<name>")
// token in ANY HR condition message wins — helm names its stalled
// resource; with no token the fallback scans the release namespace
// for the single ProgressDeadlineExceeded Deployment. Zero or
// several candidates is a refusal — guessing is not a remediation.
package helmreleaseunlocker

import (
	"context"
	"fmt"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// stalledDeployment resolves which Deployment helm was waiting on.
// A "Deployment/<name>" (or "<ns>/<name>") token in ANY condition
// message wins — helm names its stalled resource explicitly; with no
// token the fallback scans the release namespace for a Deployment
// showing Progressing=False/ProgressDeadlineExceeded (refusal when
// zero or several candidates — guessing is not a remediation).
func (u *helmReleaseUnlocker) stalledDeployment(ctx context.Context,
	hr *unstructured.Unstructured) (*appsv1.Deployment, string, error) {
	releaseNS := hrReleaseNS(hr)
	for _, c := range kube.Conditions(hr.Object, "status", "conditions") {
		m := stalledWorkloadRe.FindStringSubmatch(c.Message)
		if m == nil {
			continue
		}
		ns, name := releaseNS, m[1]
		if m[2] != "" {
			ns, name = m[1], m[2]
		}
		dep, err := u.cs.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, fmt.Sprintf(
					"stalled workload Deployment/%s reported by the HR is gone from ns %s",
					name, ns), nil
			}
			return nil, "", fmt.Errorf("get deployment %s/%s: %w", ns, name, err)
		}
		return dep, "", nil
	}
	// No explicit workload: scan the release namespace for the one
	// Deployment stuck in ProgressDeadlineExceeded — the condition
	// helm's waiter read when it aborted.
	deps, err := u.cs.AppsV1().Deployments(releaseNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, "", fmt.Errorf("list deployments in %s: %w", releaseNS, err)
	}
	var candidates []string
	var found *appsv1.Deployment
	for i := range deps.Items {
		d := &deps.Items[i]
		if deploymentProgressDeadlineExceeded(d) {
			candidates = append(candidates, d.Name)
			found = d
		}
	}
	switch len(candidates) {
	case 0:
		return nil, "no Deployment named in the message and none ProgressDeadlineExceeded in ns " +
			releaseNS, nil
	case 1:
		return found, "", nil
	default:
		sort.Strings(candidates)
		return nil, fmt.Sprintf(
			"ambiguous stalled workload — %d ProgressDeadlineExceeded Deployments in ns %s (%s)",
			len(candidates), releaseNS, strings.Join(candidates, ",")), nil
	}
}

// deploymentProgressDeadlineExceeded reports the rollout-gave-up
// condition — what helm's stalled-resource waiter actually read.
func deploymentProgressDeadlineExceeded(d *appsv1.Deployment) bool {
	for _, c := range d.Status.Conditions {
		if c.Type == appsv1.DeploymentProgressing &&
			c.Status == corev1.ConditionFalse &&
			c.Reason == "ProgressDeadlineExceeded" {
			return true
		}
	}
	return false
}
