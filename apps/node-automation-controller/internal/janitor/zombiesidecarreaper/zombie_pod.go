// zombie_pod.go — zombie detection: the fail-closed qualification
// that decides whether a Running, Job-owned pod is a finished-app /
// stuck-sidecar zombie. zombiePod returns the still-Running mesh
// sidecar's name (which doubles as the admin-endpoint selector for
// sidecar_shutdown.go); "" means any clause failed and the pod is
// left alone.
package zombiesidecarreaper

import (
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	// zombieSidecarTermAge: how long every app container must have
	// been Terminated before the pod counts as a zombie — covers
	// legit post-completion grace (preStop of the sidecar, log
	// shipping) so a normally-finishing pod is never touched.
	zombieSidecarTermAge = 5 * time.Minute
)

// zombieSidecarNames are the injected sidecars that keep a finished
// Job pod Running — linkerd is the offender this module was built
// for, istio shares the shape.
var zombieSidecarNames = map[string]bool{
	kube.LinkerdProxyContainer: true,
	"istio-proxy":              true,
}

// zombiePod returns the name of the still-Running mesh sidecar when
// the pod matches every zombie clause — phase Running and not already
// terminating, Job-owned, all app containers Terminated >= termAge
// with a final exit, every non-sidecar init container finished, at
// least one sidecar still Running in EITHER status list (native
// sidecars live in spec.initContainers + status.initContainerStatuses).
// "" means not a zombie — the empty string doubles as the sentinel so
// the caller picks the right admin endpoint per sidecar.
func (r *zombieSidecarReaper) zombiePod(p *corev1.Pod, now time.Time) string {
	if p.Status.Phase != corev1.PodRunning {
		return ""
	}
	if !p.DeletionTimestamp.IsZero() {
		return "" // already terminating — a delete is in flight, don't pile on
	}
	jobOwned := false
	for _, ref := range p.OwnerReferences {
		if ref.Kind == "Job" {
			jobOwned = true
			break
		}
	}
	if !jobOwned {
		return ""
	}

	statusByName := make(map[string]*corev1.ContainerStatus, len(p.Status.ContainerStatuses))
	for i := range p.Status.ContainerStatuses {
		statusByName[p.Status.ContainerStatuses[i].Name] = &p.Status.ContainerStatuses[i]
	}
	initStatusByName := make(map[string]*corev1.ContainerStatus, len(p.Status.InitContainerStatuses))
	for i := range p.Status.InitContainerStatuses {
		initStatusByName[p.Status.InitContainerStatuses[i].Name] = &p.Status.InitContainerStatuses[i]
	}

	appSeen := false
	for _, c := range p.Spec.Containers {
		if zombieSidecarNames[c.Name] {
			continue
		}
		appSeen = true
		st := statusByName[c.Name]
		if st == nil || st.State.Terminated == nil {
			return "" // app container still running or never started
		}
		term := st.State.Terminated
		if !kube.AgeAtLeast(term.FinishedAt.Time, now, zombieSidecarTermAge) {
			return "" // too fresh or missing FinishedAt — fail closed
		}
		if term.ExitCode != 0 && p.Spec.RestartPolicy != corev1.RestartPolicyNever {
			return "" // non-zero exit with a restartable policy — not final
		}
	}
	if !appSeen {
		return "" // no app containers — nothing to prove the job finished
	}

	// Native sidecars (K8s 1.29+: initContainers with
	// restartPolicy:Always) hold the pod Running exactly like an
	// injected regular container. Only init containers that carry BOTH
	// RestartPolicy==Always AND a known mesh sidecar name qualify as
	// native sidecar liveness candidates; every OTHER init container
	// (including regular non-Always init containers even if named like
	// a sidecar, and non-mesh always-restart init containers) must have
	// terminated cleanly or we fail closed.
	nativeMeshSidecars := make(map[string]bool)
	for _, c := range p.Spec.InitContainers {
		if isNativeSidecarContainer(c) && zombieSidecarNames[c.Name] {
			nativeMeshSidecars[c.Name] = true
			continue
		}
		st := initStatusByName[c.Name]
		if st == nil || st.State.Terminated == nil {
			return ""
		}
		if st.State.Terminated.ExitCode != 0 && p.Spec.RestartPolicy != corev1.RestartPolicyNever {
			return ""
		}
	}

	// At least one sidecar must still be Running — either a regular
	// sidecar in status.containerStatuses or a K8s 1.29+ native sidecar
	// (restartPolicy: Always) in status.initContainerStatuses. A pod
	// whose sidecar also exited is just a finishing Job pod, not a
	// zombie.
	for i := range p.Status.ContainerStatuses {
		st := &p.Status.ContainerStatuses[i]
		if zombieSidecarNames[st.Name] && st.State.Running != nil {
			return st.Name
		}
	}
	for i := range p.Status.InitContainerStatuses {
		st := &p.Status.InitContainerStatuses[i]
		if nativeMeshSidecars[st.Name] && st.State.Running != nil {
			return st.Name
		}
	}
	return ""
}

// isNativeSidecarContainer reports whether c is a K8s 1.29+ native
// sidecar (initContainer with restartPolicy: Always).
func isNativeSidecarContainer(c corev1.Container) bool {
	return c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways
}
