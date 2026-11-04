// orphan-endpointslice-cleaner — C4, reaps EndpointSlices that
// outlive their parent Service.
//
// The kube-controller-manager normally garbage-collects an
// EndpointSlice when its Service is deleted — but slices orphaned by
// a controller outage, a force-deleted Service, or a buggy
// third-party controller (mirror/endpoint-slice controllers write
// slices by hand) linger forever: stale slices keep feeding
// kube-proxy dead backends and keep DNS/endpoint consumers pointing
// at pods that will never exist.
//
// Every 15m the cleaner scans EndpointSlices carrying the
// kubernetes.io/service-name label. A slice is a candidate when the
// same-named Service in the same namespace is absent from the
// cluster-wide Service snapshot — but deletion requires ALL of:
//
//   - the Service snapshot listed successfully AND non-empty
//     (an empty list means the apiserver/RBAC lied — every slice
//     would look orphaned; same fail-closed rule the
//     volumeattachment-cleaner applies to its node list);
//   - the Service missing in >= orphanEndpointSliceStreak
//     CONSECUTIVE cycles — one bad List must never reap;
//   - the slice is older than orphanEndpointSliceMinAge (a fresh
//     slice can legitimately race ahead of its Service during a
//     rollout);
//   - a live Services(ns).Get re-confirms IsNotFound right before
//     the delete.
//
// default/kubernetes* is skipped — the apiserver's own Service and
// its slices belong to the control plane, not to any cleanup
// heuristic.
package orphanendpointslicecleaner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	orphanEndpointSliceQueue    = "orphan-endpointslice-cleaner"
	orphanEndpointSliceInterval = 15 * time.Minute
	// orphanEndpointSliceMinAge: a slice must exist this long before
	// its missing Service counts against it — created-before-service
	// races resolve themselves inside this window.
	orphanEndpointSliceMinAge = 15 * time.Minute
	// orphanEndpointSliceStreak: consecutive cycles the Service must
	// be absent before the slice is reaped — a single bad snapshot
	// can never delete.
	orphanEndpointSliceStreak = 2
	// orphanEndpointSliceListPageSize bounds each cluster-wide
	// Service/EndpointSlice List page — continue-token pagination
	// keeps a large endpoint fleet from arriving as one giant
	// response body.
	orphanEndpointSliceListPageSize = 500
)

type orphanEndpointSliceCleaner struct {
	cs kubernetes.Interface
	// dyn is accepted for Setup-signature parity with the other
	// wave modules — EndpointSlices are typed via cs.DiscoveryV1().
	dyn dynamic.Interface
	// nowFn is the clock seam — tests pin it so the >15m age gate
	// is deterministic. nil → time.Now.
	nowFn func() time.Time
	mu    sync.Mutex
	// absentStreak counts consecutive cycles each "ns/name/uid"
	// slice has been seen without its Service — reaching
	// orphanEndpointSliceStreak unlocks the re-confirm + delete.
	// UID is part of the key so a recreated slice never inherits
	// another object's streak.
	absentStreak map[string]int
}

// Setup registers the 15-minute sweep.
// Disabled clusters (ORPHAN_ENDPOINTSLICE_CLEANER_ENABLED=false) skip
// registration entirely — same contract as volumeattachment-cleaner.
func Setup(mgr ctrl.Manager, cs kubernetes.Interface, dyn dynamic.Interface, enabled bool) error {
	if !enabled {
		logf.Log.WithName(orphanEndpointSliceQueue).Info("disabled — module not registered")
		return nil
	}
	c := &orphanEndpointSliceCleaner{cs: cs, dyn: dyn, nowFn: time.Now,
		absentStreak: map[string]int{}}
	return shared.AddPeriodic(mgr, orphanEndpointSliceQueue, orphanEndpointSliceInterval, c.run)
}

func (c *orphanEndpointSliceCleaner) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	// Lazily arm the zero-value struct — unit tests construct the
	// cleaner literally without the Setup path.
	if c.nowFn == nil {
		c.nowFn = time.Now
	}
	if c.absentStreak == nil {
		c.absentStreak = map[string]int{}
	}

	// Fail closed: the Service snapshot is the ONLY source of
	// "deleted" truth. An error or an empty list aborts the run —
	// every cluster has at least the default/kubernetes Service, so
	// an empty answer is an apiserver/RBAC flap, never a real state.
	svcCount := 0
	services := map[string]bool{}
	cont := ""
	for {
		page, err := c.cs.CoreV1().Services(metav1.NamespaceAll).
			List(ctx, metav1.ListOptions{
				Limit: orphanEndpointSliceListPageSize, Continue: cont})
		if err != nil {
			return fmt.Errorf("list services (API flap) — abort: %w", err)
		}
		for _, s := range page.Items {
			services[s.Namespace+"/"+s.Name] = true
		}
		svcCount += len(page.Items)
		if cont = page.Continue; cont == "" {
			break
		}
	}
	if svcCount == 0 {
		return fmt.Errorf("empty service list (API flap) — abort")
	}

	// Server-side label filter; the in-code check stays because
	// fake clientsets ignore ListOptions selectors.
	var slices []discoveryv1.EndpointSlice
	for {
		page, err := c.cs.DiscoveryV1().EndpointSlices(metav1.NamespaceAll).
			List(ctx, metav1.ListOptions{
				LabelSelector: discoveryv1.LabelServiceName,
				Limit:         orphanEndpointSliceListPageSize,
				Continue:      cont,
			})
		if err != nil {
			return fmt.Errorf("list endpointslices: %w", err)
		}
		slices = append(slices, page.Items...)
		if cont = page.Continue; cont == "" {
			break
		}
	}

	now := c.nowFn()
	absentNow := map[string]bool{}
	deleted := 0
	for i := range slices {
		s := &slices[i]
		if s.DeletionTimestamp != nil {
			// Already terminating — the API owns it now; it must not
			// feed the streak ledger or the delete count.
			continue
		}
		svcName := s.Labels[discoveryv1.LabelServiceName]
		if svcName == "" {
			continue // no owning Service label — not ours to judge
		}
		if s.Namespace == "default" && strings.HasPrefix(svcName, "kubernetes") {
			continue // control-plane Service — never touched
		}
		if services[s.Namespace+"/"+svcName] {
			continue // parent Service alive
		}
		key := s.Namespace + "/" + s.Name + "/" + string(s.UID)
		absentNow[key] = true
		c.absentStreak[key]++
		if c.absentStreak[key] < orphanEndpointSliceStreak {
			log.Info("orphan candidate: Service missing — tracking",
				"endpointslice", s.Namespace+"/"+s.Name,
				"service", svcName, "streak", c.absentStreak[key])
			continue
		}
		if now.Sub(s.CreationTimestamp.Time) < orphanEndpointSliceMinAge {
			continue // too fresh — the Service may still be landing
		}
		// Streak + age gates passed — re-confirm against the live
		// apiserver before deleting (a List can lag a Get).
		_, getErr := c.cs.CoreV1().Services(s.Namespace).
			Get(ctx, svcName, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(getErr):
		case getErr != nil:
			log.Info("WARN: service confirm failed — slice kept (fail closed)",
				"endpointslice", s.Namespace+"/"+s.Name,
				"service", svcName, "error", getErr)
			metrics.IncError(orphanEndpointSliceQueue)
			continue
		default:
			// Service actually exists — the snapshot was stale.
			// Clear the streak so the slice re-arms from zero.
			delete(c.absentStreak, key)
			absentNow[key] = false
			continue
		}
		log.Info("DELETE: orphan EndpointSlice (Service gone)",
			"endpointslice", s.Namespace+"/"+s.Name, "service", svcName)
		// UID precondition closes the TOCTOU window between the
		// IsNotFound re-confirm and the delete — a same-named slice
		// recreated in between is not the object we vetted.
		uid := s.UID
		if err := c.cs.DiscoveryV1().EndpointSlices(s.Namespace).
			Delete(ctx, s.Name, metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			log.Error(err, "orphan endpointslice delete failed",
				"endpointslice", s.Namespace+"/"+s.Name)
			metrics.IncError(orphanEndpointSliceQueue)
			continue
		}
		delete(c.absentStreak, key)
		delete(absentNow, key)
		metrics.OrphanEndpointSlicesCleanedTotal.WithLabelValues(s.Namespace).Inc()
		deleted++
	}
	slices = nil

	// Prune streaks for slices that vanished or whose Service came
	// back — "consecutive" means any cycle with the Service present
	// resets the count to zero.
	for k := range c.absentStreak {
		if !absentNow[k] {
			delete(c.absentStreak, k)
		}
	}
	log.Info("sweep done", "absent", len(absentNow), "deleted", deleted)
	return nil
}
