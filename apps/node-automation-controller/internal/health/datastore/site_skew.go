// site_skew.go — the stateful-split-brain(ii) cross-DC site-skew signature of
// the stateful-masterless-services check: after maintenance on the
// main site every stateful master can stay pinned to the standby
// site — reads/writes then pay the inter-DC tunnel RTT forever.
// Two triggers raise node_automation_stateful_master_site_skew: a
// master whose Ready endpoint lives in the standby zone while the
// STS still serves Ready replicas in the main zone (trigger A), or
// >=80% of all evaluated stateful masters standby-pinned (trigger
// B). Split out of stateful_masterless_services.go — see that file
// for the check and its Run.
package datastore

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

const (
	// stateful-split-brain — primary-site skew: the two DC zones this cluster
	// spans. After maintenance on the main site every stateful
	// master can stay pinned to the standby site — reads/writes
	// then pay the inter-DC tunnel RTT forever.
	statefulMainSiteZone    = "datahub"
	statefulStandbySiteZone = "lanit"
	// statefulSiteSkewMaxPinned: at or above this share of all
	// evaluated stateful masters pinned to the standby zone the
	// pinning is a cluster-level skew event, not one operator's
	// election outcome.
	statefulSiteSkewMaxPinned = 0.8
)

var (
	// stateful-split-brain — the cross-DC pinning signal: 1 while a stateful
	// master's Ready endpoint lives in the standby zone (lanit)
	// while the STS also serves Ready replicas in the main zone
	// (datahub) — or while >=80% of all stateful masters are pinned
	// to the standby zone.
	statefulMasterSiteSkewGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_stateful_master_site_skew",
		Help: "1 while a stateful master's Ready endpoint is pinned to the standby topology zone while the main zone serves Ready replicas (or >=80% of all stateful masters are standby-pinned).",
	}, []string{"namespace", "service", "statefulset", "zone"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		statefulMasterSiteSkewGauge)
}

// siteSkewWatch is the stateful-split-brain(ii) cross-DC skew signature's
// watchdog state (serial sweep — unguarded):
//   - emitted: the emitted-gauge ledger for
//     statefulMasterSiteSkewGauge — a skew that resolves loses its
//     series via DeleteLabelValues.
type siteSkewWatch struct {
	emitted state.GaugeLedger[string]
}

// siteSkewSweep is one sweep of the skew signature — the census
// joins, the multi-zone gate and the per-candidate pin bookkeeping,
// all scoped to a single Run; only the emitted ledger (back on the
// watch) crosses sweeps.
type siteSkewSweep struct {
	watch     *siteSkewWatch
	rep       probefw.SweepReport // this signature's flagged tuples
	multiZone bool
	nodeZone  map[string]string // node name → topology zone
	podNode   map[string]string // "ns/pod" → node name
	podItems  []corev1.Pod      // the sweep's pod census (stsReadyInZone scans live pods)
	// Trigger-B bookkeeping:
	//   - totalMasters: candidates with a live master to place.
	//   - lanitPinned: candidate key → label tuple, for masters
	//     whose every resolved endpoint lives in the standby zone.
	//   - emittedSkew: keys already flagged this sweep (dedup A vs
	//     B triggers).
	totalMasters int
	lanitPinned  map[string][]string
	emittedSkew  map[string]bool
}

// begin arms the skew sweep: the memoized node→zone and pod→node
// placement joins (the skew gate + the nodeName/targetRef
// resolution paths). Same full-truth posture — either read failing
// skips the skew eval entirely, never a false pin.
func (w *siteSkewWatch) begin(ctx context.Context, log logr.Logger,
	d *probefw.Deps) *siteSkewSweep {

	s := &siteSkewSweep{
		watch:       w,
		lanitPinned: map[string][]string{},
		emittedSkew: map[string]bool{},
	}
	nodeZone, nerr := d.NodeZones(ctx)
	podNode, perr := d.PodNodes(ctx)
	if nerr != nil || perr != nil {
		// Tolerated: the skew signatures go dark this sweep, the
		// masterless/multimaster ones are unaffected.
		log.Info("WARN: node/pod census failed — site-skew evaluation skipped",
			"nodeErr", fmt.Sprint(nerr), "podErr", fmt.Sprint(perr))
		return s
	}
	s.nodeZone = nodeZone
	s.podNode = podNode
	zoneWorkers := map[string]bool{} // zones with >=1 Ready schedulable worker
	// zoneWorkers and podItems still read the raw censuses —
	// the worker classification needs Ready/schedulable/node-
	// role state and stsReadyInZone scans live pods. Both ride
	// the memoized LISTs the joins already paid for.
	nodes, _ := d.AllNodes(ctx)
	for i := range nodes {
		if kube.NodeReady(&nodes[i]) && !nodes[i].Spec.Unschedulable &&
			!kube.IsControlPlane(&nodes[i]) {
			if z := nodeZone[nodes[i].Name]; z != "" {
				zoneWorkers[z] = true
			}
		}
	}
	s.podItems, _ = d.AllPods(ctx)
	// The skew signatures only mean something on a multi-zone
	// cluster where BOTH sites have live workers — a single-zone
	// cluster or a dead site can't skew.
	s.multiZone = zoneWorkers[statefulMainSiteZone] &&
		zoneWorkers[statefulStandbySiteZone]
	return s
}

// evalMaster runs the trigger-A pin accounting for one candidate —
// only meaningful on a multi-zone cluster with a live master to
// place — and records the standby pin for the trigger-B ratio.
func (s *siteSkewSweep) evalMaster(c masterSvc, key string,
	eps []kube.ReadyEndpoint) {
	// stateful-split-brain(ii) — cross-DC pin accounting: only meaningful on
	// a multi-zone cluster with a live master to place.
	if !s.multiZone || len(eps) == 0 {
		return
	}
	s.totalMasters++
	zones := map[string]bool{}
	resolved := 0
	for _, e := range eps {
		z := endpointZone(e, s.podNode, s.nodeZone)
		if z == "" {
			continue
		}
		resolved++
		zones[z] = true
	}
	if zones[statefulStandbySiteZone] {
		// Trigger A: the master lives in the standby zone
		// while the workload still serves Ready replicas in the
		// main zone — reads/writes pay the inter-DC RTT.
		if workloadReadyInZone(c, s.podItems, s.podNode, s.nodeZone,
			statefulMainSiteZone) {
			s.rep.Flag(statefulMasterSiteSkewGauge,
				key+"/"+statefulStandbySiteZone,
				[]string{c.ns, c.svc, c.workloadName(),
					statefulStandbySiteZone})
			// The finding rides THIS sweep's report — parking it
			// on the zero-endpoints report would render a healthy
			// standby-pinned master under the "0 ready endpoints"
			// verdict prefix.
			s.rep.Find(key + "(site_skew " + statefulStandbySiteZone +
				" while datahub replicas ready)")
			s.emittedSkew[key] = true
		}
	}
	// "Pinned to lanit" = every resolved endpoint lives in
	// the standby zone (an unresolved endpoint can't
	// disprove the pin).
	if resolved > 0 && zones[statefulStandbySiteZone] &&
		!zones[statefulMainSiteZone] {
		s.lanitPinned[key] = []string{c.ns, c.svc, c.workloadName(),
			statefulStandbySiteZone}
	}
}

// close runs trigger B — the cluster-wide pin ratio — then
// reconciles the emitted-gauge ledger.
func (s *siteSkewSweep) close() {
	// stateful-split-brain(ii) trigger B — the pin is cluster-wide when >=80% of
	// evaluated stateful masters live in the standby zone (every
	// resolved endpoint lanit, none datahub). Flag every pinned
	// master not already caught by trigger A.
	if s.multiZone && s.totalMasters > 0 &&
		float64(len(s.lanitPinned))/float64(s.totalMasters) >= statefulSiteSkewMaxPinned {
		for key, lv := range s.lanitPinned {
			if s.emittedSkew[key] {
				continue
			}
			s.rep.Flag(statefulMasterSiteSkewGauge,
				key+"/"+statefulStandbySiteZone, lv)
			s.rep.Find(fmt.Sprintf("%s(site_skew >=%d%% masters pinned to %s)",
				key, int(statefulSiteSkewMaxPinned*100), statefulStandbySiteZone))
		}
	}
	s.rep.Close(&s.watch.emitted, statefulMasterSiteSkewGauge.DeleteLabelValues)
}

// endpointZone resolves the topology zone a Ready endpoint lives in:
// the slice's own zone field first (the endpointslice controller
// copies the node's zone label — custom producers may not fill it),
// then the endpoint's nodeName through the node census, then the
// targetRef pod's spec.nodeName — the fallback chain the spec calls
// for. "" means unresolvable: an unresolvable endpoint can neither
// confirm nor disprove a pin. The endpoint detail arrives as the
// shared kube.ReadyEndpoint — the same fields the check's retired
// private struct carried.
func endpointZone(e kube.ReadyEndpoint, podNode, nodeZone map[string]string) string {
	if e.Zone != "" {
		return e.Zone
	}
	if e.Node != "" {
		return nodeZone[e.Node]
	}
	if e.PodKey != "" {
		return nodeZone[podNode[e.PodKey]]
	}
	return ""
}

// workloadReadyInZone reports whether the candidate's workload has
// at least one Ready pod on a node labeled with the given topology
// zone — the "the workload still serves the main site" half of
// trigger A. A StatefulSet matches through its selector; a CNPG
// Cluster (no StatefulSet) matches on its cnpg.io/cluster label.
func workloadReadyInZone(c masterSvc,
	pods []corev1.Pod, podNode, nodeZone map[string]string, zone string) bool {

	var sel labels.Selector
	if c.sts != nil {
		s, err := metav1.LabelSelectorAsSelector(c.sts.Spec.Selector)
		if err != nil {
			return false
		}
		sel = s
	} else {
		sel = labels.SelectorFromSet(labels.Set{cnpgClusterLabel: c.cnpg})
	}
	for i := range pods {
		pod := &pods[i]
		if pod.Namespace != c.ns ||
			!sel.Matches(labels.Set(pod.Labels)) ||
			pod.DeletionTimestamp != nil ||
			!kube.PodReadyCond(pod) {
			continue
		}
		if nodeZone[podNode[pod.Namespace+"/"+pod.Name]] == zone {
			return true
		}
	}
	return false
}
