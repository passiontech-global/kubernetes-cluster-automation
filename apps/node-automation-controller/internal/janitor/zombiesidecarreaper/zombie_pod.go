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
	"linkerd-proxy": true,
	"istio-proxy":   true,
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
		if now.Sub(term.FinishedAt.Time) < zombieSidecarTermAge {
			return "" // too fresh — may still be inside normal completion
		}
		if term.ExitCode != 0 && p.Spec.RestartPolicy != corev1.RestartPolicyNever {
			return "" // non-zero exit with a restartable policy — not final
		}
	}
	if !appSeen {
		return "" // no app containers — nothing to prove the job finished
	}

	// Native sidecars (initContainers with restartPolicy:Always)
	// hold the pod Running exactly like an injected regular
	// container. Named mesh sidecars are the liveness candidates
	// below; every OTHER init container must have finished — a
	// plain init still running means the pod is not done starting,
	// and a non-mesh always-restart init still running is a shape
	// this reaper does not understand: fail closed either way.
	for _, c := range p.Spec.InitContainers {
		if zombieSidecarNames[c.Name] {
			continue
		}
		st := initStatusByName[c.Name]
		if st == nil || st.State.Terminated == nil {
			return ""
		}
	}

	// At least one sidecar must still be Running — a pod whose
	// sidecar also exited is just a finishing Job pod, not a zombie.
	for _, statuses := range [][]corev1.ContainerStatus{
		p.Status.ContainerStatuses, p.Status.InitContainerStatuses} {
		for i := range statuses {
			st := &statuses[i]
			if zombieSidecarNames[st.Name] && st.State.Running != nil {
				return st.Name
			}
		}
	}
	return ""
}
