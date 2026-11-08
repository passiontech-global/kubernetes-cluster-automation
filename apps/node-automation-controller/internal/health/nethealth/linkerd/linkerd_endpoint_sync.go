// linkerd_endpoint_sync.go — the linkerd-endpoint-sync check
// (W9-NM2/W10-FIX7): audits every selector-bearing Service in
// linkerd-injected namespaces for EndpointSlice desync, deletes
// provably-stale controller-owned slices, and bounces the oldest
// linkerd-destination pod past the persistence window.
//
// W12-NM1b rides the same sweep for the Cilium socket-LB vs Linkerd
// compatibility audit: pod-netns bpf-lb-sock rewrites connect()
// before linkerd-init's iptables rules can steer into the proxy,
// silently killing SO_ORIGINAL_DST/mTLS — reported on
// node_automation_cilium_linkerd_socklb_conflict.
package linkerd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// linkerdEndpointSyncCheck is the W9-NM2 linkerd endpoint-sync
// watchdog — a meshed Service whose EndpointSlice diverges from
// its Ready pod IPs, healed by bouncing linkerd-destination.
type linkerdEndpointSyncCheck struct {
	*probefw.Deps

	// W9-NM2 watchdog state (serial sweep — unguarded):
	//   - linkerdDesyncSince: "ns/svc" → first sweep the Service's
	//     EndpointSlice diverged from its Ready pod IPs. The window
	//     gates the stale-slice delete + destination-pod bounce,
	//     so it runs the persisted variant: the first-seen rides
	//     the Service as an annotation
	//     (kube.AnnoFirstSeenLinkerdEndpointSync) and a restart
	//     resumes it; cleared when the sets converge so a later
	//     desync re-arms the window.
	//   - linkerdDesyncEmitted: gauge tuples held at 1 — a tuple not
	//     re-seen gets DeleteLabelValues, not a stale 1.
	//   - linkerdDesyncHealed: "ns/svc" → last linkerd-destination
	//     bounce — the in-RAM half of the escalating per-service
	//     cooldown (the passiontech.dev/last-linkerd-endpoint-sync-heal
	//     stamp on the Service is the durable half).
	//   - linkerdDesyncBounceFails: "ns/svc" → consecutive bounces
	//     that left the desync standing — the escalation ladder that
	//     stops the never-converging bounce loop (F: a desync caused
	//     by a slice no managed-by deletion can ever touch would
	//     otherwise bounce destination every cooldown forever).
	linkerdDesyncSince   state.FirstSeenLedger
	linkerdDesyncEmitted state.GaugeLedger[string]
	linkerdDesyncHealed  state.CooldownSet
	// linkerdDesyncBounceFails is in-RAM only: the Service annotation
	// carries the cooldown (the durable half) while the ladder count
	// itself restarting at zero after a controller restart merely
	// replays the 1h→6h→24h ramp before the stop trips again.
	linkerdDesyncBounceFails state.StreakLedger
}

// The constructor lives in the package facade (linkerd.go).

const (
	// W9-NM2 — linkerd-endpoint-sync knobs.
	CheckNameLinkerdEndpointSync = "linkerd-endpoint-sync"
	// linkerdDestHealAnno persists the last bounce moment on the
	// desynced Service — the restart-proof half of the escalating
	// bounce cooldown.
	linkerdDestHealAnno         = kube.AnnoLastLinkerdEndpointSyncHeal
	linkerdEndpointDesyncMinAge = 10 * time.Minute
)

// linkerdDestHealEscalation is the per-service bounce cooldown
// ladder. A fresh desync bounces linkerd-destination after 1h; each
// consecutive bounce that left the desync standing defers the next
// one to 6h, then 24h; a bounce whose index reaches len(ladder)
// (three consecutive ineffective bounces) stops the bouncing
// entirely — the gauge + FAIL series stay up and the human alert
// path converges it. The ladder exists for desyncs the managed-by
// delete cannot fix (stale slices owned by a controller we never
// reap): without it the destination pod bounced every cooldown
// forever, for nothing.
var linkerdDestHealEscalation = [3]time.Duration{
	time.Hour, 6 * time.Hour, 24 * time.Hour,
}

const (
	// linkerdDestHealCooldownMax is the longest cooldown the ladder
	// serves — the PruneExpired bound (a shorter bound would drop
	// still-binding stamps, per CooldownSet's widest-window-wins
	// contract).
	linkerdDestHealCooldownMax = 24 * time.Hour
	// linkerdSliceHealMinAge is the fuse on the missing-IP half of
	// the W10-FIX7 stale-slice delete: a Ready pod IP must have been
	// Ready this long before its absence from the service's managed
	// EndpointSlices counts as staleness — younger pods may simply
	// not have been reconciled into the slices yet.
	linkerdSliceHealMinAge = 3 * time.Minute
	// linkerdSliceManagedByESC marks EndpointSlices owned by
	// kube-controller-manager's endpointslice-controller — the only
	// slices the desync heal deletes, since that controller is what
	// recreates them with corrected contents.
	linkerdSliceManagedByESC = "endpointslice-controller.k8s.io"

	// W12-NM1b — ciliumConfigNS/ciliumConfigName locate the Cilium
	// ConfigMap the socket-LB audit reads.
	ciliumConfigNS   = "kube-system"
	ciliumConfigName = "cilium-config"
)

var (
	// W9-NM2 — the endpoint-desync signal: 1 while the Service's
	// EndpointSlice misses a Ready pod IP or holds a deleted pod's
	// address. Past the persistence window the check also
	// rolling-bounces the oldest linkerd-destination pod (1h
	// per-service cooldown) to force a resync.
	linkerdEndpointDesyncGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_linkerd_endpoint_desync",
		Help: "1 while the Service's EndpointSlice misses a Ready pod IP or holds a deleted pod's address.",
	}, []string{"namespace", "service"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(linkerdEndpointDesyncGauge)
}

// ---------------------------------------------------------------------------
// W9-NM2 — linkerd-endpoint-sync
// ---------------------------------------------------------------------------

// checkLinkerdEndpointSync audits every selector-bearing Service in
// namespaces opted into linkerd injection: linkerd-destination builds
// its endpoint table from EndpointSlices, so a slice that misses a
// Ready pod IP — or keeps a deleted pod's address — silently
// blackholes or misroutes traffic for the selected workload. A
// divergence must persist
// linkerdEndpointDesyncMinAge before the gauge fires; past the window
// the oldest linkerd-destination pod is bounced — 1h per-service
// cooldown escalating to 6h and 24h after each bounce that left the
// desync standing, and the bouncing stops entirely after three
// consecutive ineffective bounces (maintenance-gated,
// UID-preconditioned) — to force a full resync. The escalation is
// the same re-roll shape as the W8-NM3 wedged-pod heal.
// W10-FIX7 adds the other half of the heal: the bounce only re-reads
// EndpointSlices, so when the slices themselves are provably stale
// (a Ready address no live pod owns, or a >3m-Ready pod IP absent
// from the whole endpointslice-controller-owned set) the heal first
// deletes those slices — KCM's endpointslice-controller recreates
// them from current pod state and the bounce then resyncs from
// corrected data. Only managed-by=endpointslice-controller.k8s.io
// slices are delete candidates: mirror/third-party slices are not
// ours to reap.
func (p *linkerdEndpointSyncCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()

	// Namespaces opted into injection — the only places a desynced
	// EndpointSlice actually strands mesh traffic.
	nsList, err := p.AllNamespaces(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list namespaces: %w", err)}
	}
	injected := map[string]bool{}
	// linkerdInstalled feeds the W12-NM1b socket-LB audit — the
	// Cilium config only conflicts while the mesh itself is
	// deployed on this cluster.
	linkerdInstalled := false
	for i := range nsList {
		if nsList[i].Labels[kube.LinkerdInjectKey] == "enabled" {
			injected[nsList[i].Name] = true
		}
		if nsList[i].Name == kube.LinkerdNS {
			linkerdInstalled = true
		}
	}

	// desynced maps each "ns/name" diverged this sweep to its
	// Service object — the persisted first-seen variant stamps the
	// window onto the Service itself, so the emit loop needs the
	// object, not just the gauge label tuple.
	desynced := map[string]*corev1.Service{}
	// staleSlices: "ns/svc" → the provably-stale managed EndpointSlices
	// to delete if the service's desync survives the window (W10-FIX7).
	staleSlices := map[string][]linkerdSliceRef{}
	if len(injected) > 0 {
		svcList, err := p.AllServices(ctx)
		if err != nil {
			return probefw.Result{Infra: fmt.Errorf("list services: %w", err)}
		}
		podList, err := p.AllPods(ctx)
		if err != nil {
			return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
		}
		// Audited services — selector + injected ns (+ the
		// ExternalName/publishNotReady exclusions), the same filter
		// the per-service loop applies. Only their controller-owned
		// slices are delete candidates (W10-FIX7).
		audited := map[string]bool{}
		for i := range svcList {
			svc := &svcList[i]
			if linkerdAuditedService(injected, svc) {
				audited[svc.Namespace+"/"+svc.Name] = true
			}
		}
		// Ready endpoint addresses per ns/service — same source and
		// nil-ready-counts-as-ready convention as the masterless
		// census. Paged like every cluster-wide read in this sweep.
		esReady := map[string]map[string]bool{}
		// managedSlices: "ns/svc" → the service's
		// endpointslice-controller-owned EndpointSlices with their
		// Ready address sets — the W10-FIX7 delete candidates.
		managedSlices := map[string][]linkerdSliceRef{}
		slices, err := p.AllEndpointSlices(ctx)
		if err != nil {
			return probefw.Result{Infra: fmt.Errorf("list endpointslices: %w", err)}
		}
		for _, s := range slices {
			svc := s.Labels[discoveryv1.LabelServiceName]
			if svc == "" {
				continue
			}
			key := s.Namespace + "/" + svc
			managed := audited[key] &&
				s.Labels[discoveryv1.LabelManagedBy] == linkerdSliceManagedByESC &&
				s.DeletionTimestamp == nil
			var sliceAddrs map[string]bool
			if managed {
				sliceAddrs = map[string]bool{}
			}
			set := esReady[key]
			if set == nil {
				set = map[string]bool{}
				esReady[key] = set
			}
			for _, ep := range s.Endpoints {
				if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
					continue
				}
				for _, a := range ep.Addresses {
					set[a] = true
					if managed {
						sliceAddrs[a] = true
					}
				}
			}
			if managed {
				managedSlices[key] = append(managedSlices[key],
					linkerdSliceRef{ns: s.Namespace, name: s.Name,
						uid: s.UID, addrs: sliceAddrs})
			}
		}

		podsByNS := map[string][]*corev1.Pod{}
		for i := range podList {
			pod := &podList[i]
			podsByNS[pod.Namespace] = append(podsByNS[pod.Namespace], pod)
		}
		for i := range svcList {
			svc := &svcList[i]
			if !linkerdAuditedService(injected, svc) {
				continue
			}
			sel := labels.SelectorFromSet(svc.Spec.Selector)
			readyIPs := map[string]bool{}
			liveIPs := map[string]bool{}
			readyAgedIPs := map[string]bool{}
			for _, pod := range podsByNS[svc.Namespace] {
				if pod.DeletionTimestamp != nil ||
					!sel.Matches(labels.Set(pod.Labels)) ||
					pod.Status.PodIP == "" {
					continue
				}
				liveIPs[pod.Status.PodIP] = true
				// W10-FIX7: kube.PodReadySince fails closed on a
				// zero LastTransitionTime, but the desync read
				// treats a zero stamp as maximally aged — restore
				// the lenient read for Ready pods (zero →
				// since=zero → the age fuse below always trips).
				since, ready := kube.PodReadySince(pod)
				if !ready && kube.PodReadyCond(pod) {
					since, ready = time.Time{}, true
				}
				if ready {
					readyIPs[pod.Status.PodIP] = true
					// W10-FIX7 fuse — only a pod Ready past
					// linkerdSliceHealMinAge counts as "missing"
					// from the slices.
					if now.Sub(since) >= linkerdSliceHealMinAge {
						readyAgedIPs[pod.Status.PodIP] = true
					}
				}
			}
			key := svc.Namespace + "/" + svc.Name
			if linkerdEndpointSetsDiverge(readyIPs, liveIPs, esReady[key]) {
				desynced[key] = svc
			} else if err := heal.ClearPersistedFirstSeen(ctx, log,
				&p.linkerdDesyncSince, svc,
				kube.AnnoFirstSeenLinkerdEndpointSync, key,
				p.linkerdSvcPatch(svc)); err != nil {
				// CONVERGED services clear any persisted stamp so a
				// later desync re-arms the full window. Tolerated
				// sub-failure — Warn + continue, never fail the
				// sweep; the stamp retries next sweep.
				log.Info("WARN: persisted first-seen clear failed — "+
					"a stale stamp could fast-trip the next desync",
					"service", key, "error", err)
			}
			if stale := staleLinkerdSlices(
				managedSlices[key], readyAgedIPs, liveIPs); len(stale) > 0 {
				staleSlices[key] = stale
			}
		}
	}

	var rep probefw.SweepReport

	// W12-NM1b — Cilium socket-LB vs Linkerd compatibility audit:
	// when Cilium's bpf-lb-sock rewrites connect() inside the pod
	// netns, packets reach linkerd-proxy already resolved to a
	// backend IP — the proxy never sees the Service identity, so
	// mTLS and L7 balancing silently turn off (the classic
	// Buoyant/Isovalent interop trap). The two safe shapes are
	// cni-exclusive="false" (Cilium respects linkerd-init's iptables
	// rules) or bpf-lb-sock-hostns-only="true" (socket-LB stays in
	// the host netns — enough for the node-local-dns LRPs).
	p.auditCiliumLinkerdSockLB(ctx, log, linkerdInstalled, &rep)

	p.linkerdDesyncSince.Prune(func(k string) bool { _, ok := desynced[k]; return ok })
	// The bounce-failure streak resets wherever the desync itself
	// converged this sweep (or its Service vanished) — a later
	// recurrence re-arms the full 1h→6h→24h ladder. Same
	// complete-sweep contract as the first-seen prune above: this
	// point is only reached after the full audit.
	p.linkerdDesyncBounceFails.Prune(
		func(k string) bool { _, ok := desynced[k]; return ok })
	var emitted []string
	for k, svc := range desynced {
		// The window gates the stale-EndpointSlice delete plus the
		// linkerd-destination bounce — an operator restart must not
		// re-arm it, so the first-seen rides the Service as a
		// durable annotation (wider of ledger vs annotation).
		if !heal.FirstSeenPersisted(ctx, log,
			&p.linkerdDesyncSince, svc,
			kube.AnnoFirstSeenLinkerdEndpointSync, k,
			linkerdEndpointDesyncMinAge, now,
			p.linkerdSvcPatch(svc)) {
			continue
		}
		// The detail string must carry the sub-branch trigger — a
		// desync whose stale-EndpointSlice delete fired reads
		// differently in the verdict than a pure pod-IP desync.
		detail := k
		if stale := staleSlices[k]; len(stale) > 0 {
			names := make([]string, len(stale))
			for i, sl := range stale {
				names[i] = sl.ns + "/" + sl.name
			}
			detail = k + " (stale EndpointSlices: " + strings.Join(names, ", ") + ")"
		}
		rep.Emit(linkerdEndpointDesyncGauge, k,
			[]string{svc.Namespace, svc.Name}, detail)
		emitted = append(emitted, k)
	}
	rep.Close(&p.linkerdDesyncEmitted,
		linkerdEndpointDesyncGauge.DeleteLabelValues)

	// Past the window: bounce the oldest linkerd-destination pod so
	// its endpoint table rebuilds from the current EndpointSlices.
	// The cooldown is per desynced SERVICE (escalating — see
	// linkerdDestHealEscalation) — two services stuck on the same
	// root cause share one bounce. Iterates `emitted`, not
	// rep.Findings(): the socket-LB audit (W12-NM1b) also reports
	// findings into rep and must not trigger a desync heal.
	for _, k := range emitted {
		p.healLinkerdDestination(ctx, log, desynced[k], k, now, staleSlices[k])
	}

	return rep.Verdict(fmt.Sprintf(
		"meshed services with EndpointSlice desync >=%s: ",
		linkerdEndpointDesyncMinAge), ", ")
}

// linkerdSvcPatch closes over the Service the persisted first-seen
// stamp rides — the durable half of the desync window lives on the
// Service itself, delivered as a merge patch through the typed
// clientset.
func (p *linkerdEndpointSyncCheck) linkerdSvcPatch(
	svc *corev1.Service) func(context.Context, []byte) error {

	return func(ctx context.Context, data []byte) error {
		_, err := p.CS.CoreV1().Services(svc.Namespace).
			Patch(ctx, svc.Name, types.MergePatchType, data,
				metav1.PatchOptions{})
		return err
	}
}
