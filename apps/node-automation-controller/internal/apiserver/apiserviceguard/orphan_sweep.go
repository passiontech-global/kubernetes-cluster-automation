// orphan_sweep.go — duty (a) of apiservice-guard: the fail-closed
// orphan-APIService cleanup. An aggregated APIService whose
// spec.service.namespace no longer exists keeps wedging the
// namespace-terminating controller and the garbage collector —
// the object is reaped only after the apiserver itself confirms
// the namespace NotFound. The sweep is stateless — every cluster
// input arrives through the shared apiServiceSnapshot and the
// guard's clients are reached via snap.g.
package apiserviceguard

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// orphanSweep owns the orphan-APIService sweep — embedded in
// apiServiceGuard so the facade's method set (and every in-package
// test fixture built on it) is unchanged by the split. The sweep
// keeps no per-run state: every cluster input arrives through the
// shared apiServiceSnapshot and the guard's clients are reached via
// snap.g.
type orphanSweep struct{}

// sweepOrphans consumes the shared per-run APIService snapshot — a
// list error is delivered via snap.err (recorded by run, not returned
// there) so this pass can still abort itself while the watchdog
// reports its own verdict on the same failure.
func (o *orphanSweep) sweepOrphans(ctx context.Context, snap *apiServiceSnapshot) error {
	g := snap.g
	log := logf.FromContext(ctx)

	// Namespace snapshot — the ONLY source of "deleted" truth, listed
	// once per run on the shared snapshot (the unblock pass consumes
	// the same census). An error aborts the whole pass; an EMPTY
	// list means the apiserver/RBAC lied (every APIService would look
	// orphaned), so the pass skips itself without failing the run —
	// the availability watchdog still evaluates.
	nss, err := snap.nss, snap.nsErr
	if err != nil {
		return fmt.Errorf("list namespaces (API flap) — abort orphan pass: %w", err)
	}
	if len(nss) == 0 {
		log.Info("WARN: empty namespace list (API flap) — orphan pass skipped")
		return nil
	}
	namespaces := make(map[string]bool, len(nss))
	for _, ns := range nss {
		namespaces[ns.Name] = true
	}
	if snap.err != nil {
		return fmt.Errorf("list apiservices — abort orphan pass: %w", snap.err)
	}

	deleted := 0
	for i := range snap.svcs.Items {
		svc := &snap.svcs.Items[i]
		svcNs, svcName, ok := apiServiceBackend(svc)
		if !ok {
			continue // no Service backend — nothing to orphan-check
		}
		if namespaces[svcNs] {
			continue
		}
		// The snapshot says the namespace is gone — but a List can be
		// stale where a Get is fresh, so the delete only fires after
		// the apiserver itself confirms NotFound (fail closed).
		_, getErr := g.cs.CoreV1().Namespaces().Get(ctx, svcNs, metav1.GetOptions{})
		gone, err := kube.ConfirmAbsent(getErr)
		if err != nil {
			log.Info("WARN: namespace confirm failed — APIService kept (fail closed)",
				"apiservice", svc.GetName(), "namespace", svcNs, "error", err)
			metrics.IncError(g.queue)
			continue
		}
		if !gone {
			// Namespace actually exists — the snapshot was stale.
			continue
		}
		log.Info("DELETE: orphan APIService (backend namespace gone)",
			"apiservice", svc.GetName(), "service", svcNs+"/"+svcName)
		// UID precondition closes the TOCTOU window between the
		// IsNotFound re-confirm and the delete — a same-named
		// APIService recreated in between is not ours to reap.
		uid := svc.GetUID()
		if err := g.dyn.Resource(apiServiceGVR).
			Delete(ctx, svc.GetName(), kube.UIDDeleteOptions(uid, "")); err != nil {
			log.Error(err, "orphan apiservice delete failed",
				"apiservice", svc.GetName())
			metrics.IncError(g.queue)
			continue
		}
		deleted++
	}
	log.Info("orphan pass done", "deleted", deleted, "apiservices", len(snap.svcs.Items))
	return nil
}
