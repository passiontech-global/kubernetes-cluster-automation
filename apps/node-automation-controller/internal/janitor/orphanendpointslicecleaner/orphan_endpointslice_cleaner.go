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
	json "encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/reap"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

const (
	orphanEndpointSliceInterval = 15 * time.Minute
	// orphanEndpointSliceMinAge: a slice must exist this long before
	// its missing Service counts against it — created-before-service
	// races resolve themselves inside this window.
	orphanEndpointSliceMinAge = 15 * time.Minute
	// orphanEndpointSliceStreak: consecutive cycles the Service must
	// be absent before the slice is reaped — a single bad snapshot
	// can never delete.
	orphanEndpointSliceStreak = 2
	// orphanEndpointSliceDeleteCap bounds delete attempts per sweep —
	// a mass Service teardown (namespace deletion) can orphan
	// hundreds of slices at once, and one uncapped sweep is exactly
	// the apiserver churn every sibling janitor caps. The streak +
	// age ledgers are per-slice, so capped survivors simply reap
	// across the following cycles.
	orphanEndpointSliceDeleteCap = 50
)

type orphanEndpointSliceCleaner struct {
	cs kubernetes.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	// dyn is accepted for Setup-signature parity with the other
	// janitor modules — EndpointSlices are typed via cs.DiscoveryV1().
	dyn dynamic.Interface
	// meta feeds kube.ListPartialOrFallback: both censuses this sweep
	// makes (Services existence, EndpointSlice candidates) read only
	// ObjectMeta — names, labels, age, UID — so production lists
	// PartialObjectMetadata and skips the resource payloads entirely.
	// Nil in tests; ListPartialOrFallback's typed fallback serves the
	// same objects identically.
	meta metadata.Interface
	// now is the clock seam — tests pin it so the >15m age gate
	// is deterministic. nil → time.Now.
	now shared.Clock
	// absentStreak counts consecutive cycles each "ns/name/uid"
	// slice has been seen without its Service — reaching
	// orphanEndpointSliceStreak unlocks the re-confirm + delete.
	// UID is part of the key so a recreated slice never inherits
	// another object's streak.
	absentStreak state.StreakLedger
	// ghostStreak counts consecutive cycles a Pod-backed endpoint
	// inside a live-Service EndpointSlice has referenced a missing or
	// UID-mismatched Pod ("ghost:<ns>/<slice>/<sliceUID>/<podUID>").
	ghostStreak state.StreakLedger
}

// Setup registers the 15-minute sweep.
// Disabled clusters (ORPHAN_ENDPOINTSLICE_CLEANER_ENABLED=false —
// resolved by setupModules into Deps.Disabled) skip registration
// entirely — same contract as volumeattachment-cleaner.
func Setup(d shared.Deps) error {
	return shared.SetupNoConfig(d, func() error {
		c := &orphanEndpointSliceCleaner{cs: d.CS, dyn: d.Dyn, meta: d.Meta,
			queue: d.Name, now: shared.SystemClock}
		return shared.AddPeriodic(d.Mgr, c.queue, orphanEndpointSliceInterval, c.run)
	})
}

func (c *orphanEndpointSliceCleaner) run(ctx context.Context) error {
	log := logf.FromContext(ctx)

	// Fail closed: the Service snapshot is the ONLY source of
	// "deleted" truth. An error or an empty list aborts the run —
	// every cluster has at least the default/kubernetes Service, so
	// an empty answer is an apiserver/RBAC flap, never a real state.
	// Metadata-only census: the map keys off namespace/name — no
	// Service body is ever read.
	svcs, err := kube.ListPartialOrFallback(ctx, c.meta, c.cs, c.dyn,
		corev1.SchemeGroupVersion.WithResource("services"), metav1.NamespaceAll,
		metav1.ListOptions{
			Limit:           kube.DefaultListPageSize,
			ResourceVersion: "0",
		})
	if err != nil {
		return fmt.Errorf("list services (API flap) — abort: %w", err)
	}
	if len(svcs) == 0 {
		return errors.New("empty service list (API flap) — abort")
	}
	services := make(map[string]bool, len(svcs))
	for i := range svcs {
		services[svcs[i].Namespace+"/"+svcs[i].Name] = true
	}

	// Server-side label filter; the in-code check stays because
	// fake clientsets ignore ListOptions selectors. Full typed objects
	// are needed here (RV="0" watch-cache) so Track 2 can inspect
	// s.Endpoints[].TargetRef without losing endpoint payloads.
	slices, err := kube.ListAll(ctx, metav1.ListOptions{
		LabelSelector:   discoveryv1.LabelServiceName,
		Limit:           kube.DefaultListPageSize,
		ResourceVersion: "0",
	}, kube.EndpointSlices(c.cs, metav1.NamespaceAll))
	if err != nil {
		return fmt.Errorf("list endpointslices: %w", err)
	}

	now := c.now.Now()
	absentNow := map[string]bool{}

	// target carries a streak-qualified slice into the sweep: key is
	// the "ns/name/uid" ledger key so the re-confirm and the
	// post-delete bookkeeping find the same streak entry again.
	type target struct {
		ns, name, svcName, key string
		uid                    types.UID
	}
	var targets []target
	var podSlices []discoveryv1.EndpointSlice
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
			if sliceHasPodTargetRef(s) {
				podSlices = append(podSlices, *s)
			}
			continue // parent Service alive
		}
		key := s.Namespace + "/" + s.Name + "/" + string(s.UID)
		absentNow[key] = true
		streak := c.absentStreak.Hit(key)
		if streak < orphanEndpointSliceStreak {
			log.Info("orphan candidate: Service missing — tracking",
				"endpointslice", s.Namespace+"/"+s.Name,
				"service", svcName, "streak", streak)
			continue
		}
		if now.Sub(s.CreationTimestamp.Time) < orphanEndpointSliceMinAge {
			continue // too fresh — the Service may still be landing
		}
		targets = append(targets, target{
			ns: s.Namespace, name: s.Name,
			svcName: svcName, key: key, uid: s.UID,
		})
	}
	slices = nil

	deleted, _, _ := reap.Sweep(ctx, log, targets, reap.Options[target]{
		// Deterministic victims: ns/name order, so a capped sweep
		// reaps the same candidates every cycle instead of whichever
		// order the apiserver returned.
		Less: func(a, b target) bool {
			if a.ns != b.ns {
				return a.ns < b.ns
			}
			return a.name < b.name
		},
		Cap: orphanEndpointSliceDeleteCap,
		// Streak + age gates passed — re-confirm against the live
		// apiserver before deleting (a List can lag a Get).
		Confirm: func(ctx context.Context, t target) (bool, error) {
			_, getErr := c.cs.CoreV1().Services(t.ns).
				Get(ctx, t.svcName, metav1.GetOptions{})
			gone, confirmErr := kube.ConfirmAbsent(getErr)
			switch {
			case gone:
				return true, nil
			case confirmErr != nil:
				log.Info("WARN: service confirm failed — slice kept (fail closed)",
					"endpointslice", t.ns+"/"+t.name,
					"service", t.svcName, "error", confirmErr)
				metrics.IncError(c.queue)
				return false, nil
			default:
				// Service actually exists — the snapshot was stale.
				// Clear the streak so the slice re-arms from zero.
				c.absentStreak.Reset(t.key)
				absentNow[t.key] = false
				return false, nil
			}
		},
		LogTarget: func(log logr.Logger, t target) {
			log.Info("DELETE: orphan EndpointSlice (Service gone)",
				"endpointslice", t.ns+"/"+t.name, "service", t.svcName)
		},
		Delete: func(ctx context.Context, t target) error {
			// UID precondition closes the TOCTOU window between the
			// IsNotFound re-confirm and the delete — a same-named slice
			// recreated in between is not the object we vetted.
			if err := c.cs.DiscoveryV1().EndpointSlices(t.ns).
				Delete(ctx, t.name, kube.UIDDeleteOptions(t.uid, "")); err != nil {
				return err
			}
			c.absentStreak.Reset(t.key)
			delete(absentNow, t.key)
			metrics.OrphanEndpointSlicesCleanedTotal.WithLabelValues(t.ns).Inc()
			return nil
		},
		OnError: reap.DeleteErrorHandler("endpointslice",
			func(t target) string { return t.ns + "/" + t.name },
			func() { metrics.IncError(c.queue) }),
	})

	// Prune streaks for slices that vanished or whose Service came
	// back — "consecutive" means any cycle with the Service present
	// resets the count to zero.
	c.absentStreak.Prune(func(k string) bool { return absentNow[k] })

	// Track 2: ghost Pod UID detection & remediation on live-Service slices.
	ghostRemediated, err := c.sweepGhostPodEndpoints(ctx, log, now, podSlices)
	if err != nil {
		return err
	}
	log.Info("sweep done", "absent", len(absentNow), "deleted", deleted, "ghostRemediated", ghostRemediated)
	return nil
}

type ghostCandidate struct {
	podNS, podName, key string
	podUID              types.UID
}

type ghostPlan struct {
	live        *discoveryv1.EndpointSlice
	remaining   []discoveryv1.Endpoint
	removedKeys []string
	deleteWhole bool
}

type ghostTarget struct {
	ns, name   string
	uid        types.UID
	candidates []ghostCandidate
	plan       *ghostPlan
}

func isPodTargetRef(ref *corev1.ObjectReference) bool {
	return ref != nil && ref.Kind == "Pod" && ref.Name != "" && ref.UID != ""
}

func sliceHasPodTargetRef(s *discoveryv1.EndpointSlice) bool {
	for i := range s.Endpoints {
		if isPodTargetRef(s.Endpoints[i].TargetRef) {
			return true
		}
	}
	return false
}

func (c *orphanEndpointSliceCleaner) sweepGhostPodEndpoints(ctx context.Context,
	log logr.Logger, now time.Time, podSlices []discoveryv1.EndpointSlice) (int, error) {
	if len(podSlices) == 0 {
		c.ghostStreak.Prune(func(string) bool { return false })
		return 0, nil
	}

	pods, err := kube.ListPartialOrFallback(ctx, c.meta, c.cs, c.dyn,
		corev1.SchemeGroupVersion.WithResource("pods"),
		metav1.NamespaceAll,
		metav1.ListOptions{
			Limit:           kube.DefaultListPageSize,
			ResourceVersion: "0",
		})
	if err != nil {
		// Fail closed without pruning ghostStreak so transient API flaps
		// preserve accumulated streaks (Track 1 already completed above).
		return 0, fmt.Errorf("list pods (API flap): %w", err)
	}

	podUIDByKey := make(map[string]types.UID, len(pods))
	for i := range pods {
		podUIDByKey[pods[i].Namespace+"/"+pods[i].Name] = pods[i].UID
	}

	ghostNow := map[string]bool{}
	var ghostTargets []ghostTarget
	for i := range podSlices {
		s := &podSlices[i]
		seenInSlice := map[string]bool{}
		var candidates []ghostCandidate
		for j := range s.Endpoints {
			ref := s.Endpoints[j].TargetRef
			if !isPodTargetRef(ref) {
				continue
			}
			refNS := ref.Namespace
			if refNS == "" {
				refNS = s.Namespace
			}
			if liveUID, ok := podUIDByKey[refNS+"/"+ref.Name]; ok && liveUID == ref.UID {
				continue
			}
			gkey := "ghost:" + s.Namespace + "/" + s.Name + "/" + string(s.UID) + "/" + string(ref.UID)
			if seenInSlice[gkey] {
				continue
			}
			seenInSlice[gkey] = true
			ghostNow[gkey] = true
			streak := c.ghostStreak.Hit(gkey)
			if streak < orphanEndpointSliceStreak {
				log.Info("ghost endpoint candidate: Pod UID missing — tracking",
					"endpointslice", s.Namespace+"/"+s.Name,
					"pod", refNS+"/"+ref.Name,
					"podUID", string(ref.UID),
					"streak", streak)
				continue
			}
			if now.Sub(s.CreationTimestamp.Time) < orphanEndpointSliceMinAge {
				continue // too fresh — pod/slice propagation may still be landing
			}
			candidates = append(candidates, ghostCandidate{
				podNS:   refNS,
				podName: ref.Name,
				podUID:  ref.UID,
				key:     gkey,
			})
		}
		if len(candidates) > 0 {
			ghostTargets = append(ghostTargets, ghostTarget{
				ns:         s.Namespace,
				name:       s.Name,
				uid:        s.UID,
				candidates: candidates,
				plan:       &ghostPlan{},
			})
		}
	}

	remediated, _, _ := reap.Sweep(ctx, log, ghostTargets, reap.Options[ghostTarget]{
		Less: func(a, b ghostTarget) bool {
			if a.ns != b.ns {
				return a.ns < b.ns
			}
			return a.name < b.name
		},
		Cap: orphanEndpointSliceDeleteCap,
		Confirm: func(ctx context.Context, t ghostTarget) (bool, error) {
			live, getErr := c.cs.DiscoveryV1().EndpointSlices(t.ns).
				Get(ctx, t.name, metav1.GetOptions{})
			if apierrors.IsNotFound(getErr) {
				for _, cand := range t.candidates {
					c.ghostStreak.Reset(cand.key)
					delete(ghostNow, cand.key)
				}
				return false, nil
			}
			if getErr != nil {
				log.Info("WARN: endpointslice confirm failed — slice kept (fail closed)",
					"endpointslice", t.ns+"/"+t.name, "error", getErr)
				metrics.IncError(c.queue)
				return false, nil
			}
			if live.UID != t.uid || live.DeletionTimestamp != nil {
				for _, cand := range t.candidates {
					c.ghostStreak.Reset(cand.key)
					delete(ghostNow, cand.key)
				}
				return false, nil
			}

			type podLookupResult struct {
				pod *corev1.Pod
				err error
			}
			podCache := make(map[string]podLookupResult, len(t.candidates))
			confirmedGhostUIDs := make(map[types.UID]string, len(t.candidates))
			for _, cand := range t.candidates {
				podKey := cand.podNS + "/" + cand.podName
				res, cached := podCache[podKey]
				if !cached {
					p, pErr := c.cs.CoreV1().Pods(cand.podNS).
						Get(ctx, cand.podName, metav1.GetOptions{})
					res = podLookupResult{pod: p, err: pErr}
					podCache[podKey] = res
				}
				gone, confirmErr := kube.ConfirmAbsent(res.err)
				switch {
				case gone:
					confirmedGhostUIDs[cand.podUID] = cand.key
				case confirmErr != nil:
					if !cached {
						log.Info("WARN: ghost pod confirm failed — endpoint kept (fail closed)",
							"endpointslice", t.ns+"/"+t.name,
							"pod", podKey, "error", confirmErr)
						metrics.IncError(c.queue)
					}
				default:
					if res.pod.UID == cand.podUID {
						c.ghostStreak.Reset(cand.key)
						ghostNow[cand.key] = false
					} else {
						confirmedGhostUIDs[cand.podUID] = cand.key
					}
				}
			}
			if len(confirmedGhostUIDs) == 0 {
				return false, nil
			}

			remaining := make([]discoveryv1.Endpoint, 0, len(live.Endpoints))
			removedSet := make(map[string]bool, len(confirmedGhostUIDs))
			var removedKeys []string
			for i := range live.Endpoints {
				ep := &live.Endpoints[i]
				if isPodTargetRef(ep.TargetRef) {
					if gkey, isGhost := confirmedGhostUIDs[ep.TargetRef.UID]; isGhost {
						if !removedSet[gkey] {
							removedSet[gkey] = true
							removedKeys = append(removedKeys, gkey)
						}
						continue
					}
				}
				remaining = append(remaining, *ep)
			}
			if len(removedKeys) == 0 {
				return false, nil
			}
			*t.plan = ghostPlan{
				live:        live,
				remaining:   remaining,
				removedKeys: removedKeys,
				deleteWhole: len(remaining) == 0,
			}
			return true, nil
		},
		LogTarget: func(log logr.Logger, t ghostTarget) {
			if t.plan.deleteWhole {
				log.Info("DELETE: ghost-only EndpointSlice (all Pod UIDs gone)",
					"endpointslice", t.ns+"/"+t.name,
					"removed", len(t.plan.removedKeys))
				return
			}
			log.Info("PATCH: stripped ghost Pod endpoints from EndpointSlice",
				"endpointslice", t.ns+"/"+t.name,
				"removed", len(t.plan.removedKeys),
				"remaining", len(t.plan.remaining))
		},
		Delete: func(ctx context.Context, t ghostTarget) error {
			if t.plan.deleteWhole {
				if err := c.cs.DiscoveryV1().EndpointSlices(t.ns).
					Delete(ctx, t.name, kube.UIDDeleteOptions(t.plan.live.UID, "")); err != nil {
					return err
				}
				for _, k := range t.plan.removedKeys {
					c.ghostStreak.Reset(k)
					delete(ghostNow, k)
				}
				metrics.OrphanEndpointSlicesCleanedTotal.WithLabelValues(t.ns).Inc()
				return nil
			}
			payload, err := json.Marshal(map[string]any{
				"metadata": map[string]any{
					"resourceVersion": t.plan.live.ResourceVersion,
				},
				"endpoints": t.plan.remaining,
			})
			if err != nil {
				return err
			}
			if _, err := c.cs.DiscoveryV1().EndpointSlices(t.ns).Patch(
				ctx, t.name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
				return err
			}
			for _, k := range t.plan.removedKeys {
				c.ghostStreak.Reset(k)
				delete(ghostNow, k)
			}
			return nil
		},
		OnError: reap.DeleteErrorHandler("endpointslice",
			func(t ghostTarget) string { return t.ns + "/" + t.name },
			func() { metrics.IncError(c.queue) }),
	})

	c.ghostStreak.Prune(func(k string) bool { return ghostNow[k] })
	return remediated, nil
}
