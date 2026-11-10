// localpv_stranded_pods.go — the localpv-stranded-pods check
// (localpv-stranded-pods): Pending pods whose bound local PV is nodeAffinity-pinned
// to a dead node get the stranded gauge (and, for disposable
// volumes, a PVC+pod rescue); Pending openebs-hostpath claims with
// Ready workers bounce the localpv provisioner.
package nodehealth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// localPVStrandedCheck is the localpv-stranded-pods local-PV dead-node diagnostic,
// ephemeral-PVC rescue and provisioner watchdog.
type localPVStrandedCheck struct {
	*probefw.Deps

	// localpv-stranded-pods watchdog state (serial sweep — unguarded):
	//   - localPVEmitted: "ns/pod/pvc/node/reason" gauge tuples held
	//     at 1 — pruned via DeleteLabelValues when not re-seen (same
	//     hygiene as stsZeroEmitted).
	//   - pvcStalledEmitted: "ns/pvc/storageclass" gauge tuples held
	//     at 1 — same lifecycle.
	//   - localPVHealed: "ns/pvc" → last ephemeral-PVC heal — the
	//     30m cooldown (in-RAM: the PVC is deleted, nothing durable
	//     can carry the stamp).
	//   - pvcProvHealed: provisioner → last provisioner pod delete —
	//     the in-RAM half of the 1h cooldown (the
	//     passiontech.dev/last-localpv-provisioner-heal stamp on the
	//     provisioner Deployment is the durable half).
	localPVEmitted    state.GaugeLedger[string]
	pvcStalledEmitted state.GaugeLedger[string]
	// strandedStatefulEmitted is the stateful-split-brain ledger for the
	// stranded-stateful-pod tuples — a pod whose node comes back
	// (or whose claim rebinds) loses its series via
	// DeleteLabelValues, same hygiene as localPVEmitted.
	strandedStatefulEmitted state.GaugeLedger[string]
	localPVHealed           state.CooldownSet
	pvcProvHealed           state.CooldownSet
}

// newLocalPVStrandedCheck builds the localpv-stranded-pods check — every ledger is
// zero-value ready, so the constructor carries no initialization
// (the state-map literals retired with the monolithic
// newClusterHealthProber).
func NewLocalPVStrandedCheck(d *probefw.Deps) probefw.Check {
	return &localPVStrandedCheck{Deps: d}
}

// ---------------------------------------------------------------------------
// localpv-stranded-pods (localpv-stranded-pods) — local-PV dead-node diagnostics +
// ephemeral-PVC rescue + provisioner watchdog.
// ---------------------------------------------------------------------------

// localpv-stranded-pods — localpv-stranded-pods knobs.
const (
	// CheckNameLocalPVStranded is the check's kuberhealthy_check
	// label value — agent-added; not a ported HealthCheck but reports under
	// its own check name so the generic FAIL alerting path covers
	// it.
	CheckNameLocalPVStranded = "localpv-stranded-pods"
	// localPVStrandedMinAge: a Pending pod must be this old before
	// its bound PV's node gets audited — younger pods may still be
	// pulling images or waiting on the scheduler, not stranded.
	localPVStrandedMinAge = 5 * time.Minute
	// localPVEphemeralHealMinAge: a stranded ephemeral pod must
	// persist this long before the PVC+pod delete fires — longer
	// than the gauge window so a flap cannot reap a volume.
	localPVEphemeralHealMinAge   = 10 * time.Minute
	localPVEphemeralHealCooldown = 30 * time.Minute
	// localPVEphemeralAnno opts any workload into the disposable-
	// volume heal — set on the pod or its PVC.
	localPVEphemeralAnno = kube.AnnoEphemeralLocalPV
	// concourseWorkerNS/PodPrefix name the workload whose local
	// workdir is disposable by design — losing it on a dead node is
	// the exact rescue the concourse janitor already performs while
	// the node lives.
	concourseWorkerNS        = "concourse"
	concourseWorkerPodPrefix = "concourse-worker"
	// pvcStalledMinAge is the pending window for the provisioner
	// watchdog: a PVC pending this long on the hostpath class while
	// Ready workers exist means the provisioner wedged.
	pvcStalledMinAge           = 15 * time.Minute
	pvcProvisionerHealCooldown = time.Hour
	// pvcProvHealAnno persists the last provisioner heal moment on
	// the provisioner Deployment — the restart-proof half of the 1h
	// cooldown.
	pvcProvHealAnno          = kube.AnnoLastLocalPVProvisionerHeal
	openebsHostpathSC        = "openebs-hostpath"
	openebsProvisionerNS     = "openebs"
	openebsProvisionerPrefix = "openebs-localpv-provisioner"
	openebsProvisionerName   = "openebs-localpv-provisioner"
	// Stranded-reason gauge label values.
	strandedReasonMissingNode  = "missing_node"
	strandedReasonOutOfService = "out_of_service"
	strandedReasonNotReady     = "not_ready"
	strandedReasonCordoned     = "cordoned"
)

var (
	// localpv-stranded-pods — the stranded-pod signal: 1 while the Pod pends on a
	// local PV node-affinity-pinned to an unavailable node. reason is
	// missing_node | out_of_service | not_ready | cordoned.
	localPVStrandedPodsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_localpv_stranded_pods",
		Help: "1 while the Pod pends on a local PV node-affinity-pinned to an unavailable node.",
	}, []string{"namespace", "pod", "pvc", "node", "reason"})

	// localpv-stranded-pods — ephemeral localpv PVC+pod pairs reaped after their
	// bound node was confirmed gone (missing or out-of-service).
	// Counts delivered heals only.
	localPVEphemeralHealsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_automation_localpv_ephemeral_heals_total",
		Help: "Ephemeral localpv PVC+pod pairs reaped after their bound node was confirmed gone.",
	}, []string{"namespace", "pvc", "node"})

	// stateful-split-brain — the stranded-stateful signal: 1 while a
	// NON-ephemeral LocalPV pod pends on a volume pinned to a
	// confirmed-dead node (missing or out-of-service). The generic
	// stranded gauge carries the pvc+reason detail; this one names
	// the dead node so the alert can route straight to the site.
	localPVStrandedStatefulPodGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_localpv_stranded_stateful_pod",
		Help: "1 while a non-ephemeral LocalPV pod pends on a volume nodeAffinity-pinned to a dead (missing/out-of-service) node — data recovery needed, never auto-healed.",
	}, []string{"namespace", "pod", "dead_node"})

	// localpv-stranded-pods — the stalled-provisioning signal: 1 while the PVC
	// pends on a local provisioner despite Ready schedulable
	// workers existing.
	pvcProvisioningStalledGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_pvc_provisioning_stalled",
		Help: "1 while the PVC pends on a local provisioner despite Ready schedulable workers existing.",
	}, []string{"namespace", "pvc", "storageclass"})

	// localpv-stranded-pods — local provisioner pods deleted to unstick Pending
	// claims, by provisioner. Counts delivered heals only.
	pvcProvisionerHealsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_automation_pvc_provisioner_heals_total",
		Help: "Local provisioner pods deleted to unstick Pending claims, by provisioner.",
	}, []string{"provisioner"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		localPVStrandedPodsGauge,
		localPVStrandedStatefulPodGauge,
		localPVEphemeralHealsTotal,
		pvcProvisioningStalledGauge,
		pvcProvisionerHealsTotal)
}

// strandedHeal is one pod+PVC pair eligible for the ephemeral-volume
// rescue — carried out of the pod scan so the maintenance mutex is
// evaluated once per sweep.
type strandedHeal struct {
	pod    *corev1.Pod
	pvc    *corev1.PersistentVolumeClaim
	node   string
	reason string
}

// localPVNodeNames extracts the hostnames a PV's required
// nodeAffinity pins it to — the local volume can only ever exist on
// those nodes.
func localPVNodeNames(pv *corev1.PersistentVolume) []string {
	na := pv.Spec.NodeAffinity
	if na == nil || na.Required == nil {
		return nil
	}
	var out []string
	for _, term := range na.Required.NodeSelectorTerms {
		for _, expr := range term.MatchExpressions {
			if expr.Key != corev1.LabelHostname ||
				expr.Operator != corev1.NodeSelectorOpIn {
				continue
			}
			out = append(out, expr.Values...)
		}
	}
	return out
}

// strandedNodeReason classifies a PV-pinned node that can never host
// the pod again — "" when the node is fine (the pod pends for some
// other reason: CPU, scheduling, image).
func strandedNodeReason(nodes map[string]*corev1.Node, name string) string {
	n := nodes[name]
	if n == nil {
		return strandedReasonMissingNode
	}
	if kube.HasTaint(n.Spec.Taints, corev1.TaintNodeOutOfService) {
		return strandedReasonOutOfService
	}
	if !kube.NodeReady(n) {
		return strandedReasonNotReady
	}
	if n.Spec.Unschedulable {
		return strandedReasonCordoned
	}
	return ""
}

// ephemeralLocalPV reports whether the workload's local volume is
// disposable: concourse-worker workdirs (rebuilt by the init
// container on the new node) or anything explicitly annotated
// passiontech.dev/ephemeral-localpv on the pod or the PVC.
func ephemeralLocalPV(pod *corev1.Pod, pvc *corev1.PersistentVolumeClaim) bool {
	if pod.Namespace == concourseWorkerNS &&
		strings.HasPrefix(pod.Name, concourseWorkerPodPrefix) {
		return true
	}
	return pod.Annotations[localPVEphemeralAnno] == "true" ||
		pvc.Annotations[localPVEphemeralAnno] == "true"
}

// checkLocalPVStrandedPods covers the two local-PV failure shapes
// that leave workloads Pending forever with no signal:
//
//	a) STRANDED — a Pending pod's bound PVC points at a PV whose
//	   nodeAffinity pins it to a node that is missing, out-of-
//	   service, NotReady or cordoned. The volume can never follow
//	   the pod to a new node, so the pod pends forever. Every such
//	   pod emits localpv_stranded_pods=1 — and for workloads whose
//	   volume is disposable (concourse-worker, or pod/PVC annotated
//	   passiontech.dev/ephemeral-localpv) stranded on a confirmed-gone
//	   node (missing or out-of-service) the heal deletes PVC+pod so
//	   the StatefulSet rebinds on a live node while the Released PV
//	   gets swept by the node-host-agent. Database volumes are
//	   NEVER touched — alerting only.
//	b) STALLED — a Pending pod waits on a Pending openebs-hostpath
//	   PVC the provisioner already selected a node for
//	   (volume.kubernetes.io/selected-node) while Ready+schedulable
//	   workers exist: the localpv provisioner wedged mid-provision.
//	   A claim without the annotation was never selected — no
//	   pvc_provisioning_stalled signal. =1 fires and — outside
//	   maintenance, past the 1h cooldown — the provisioner pod is
//	   deleted to force a resync.
func (p *localPVStrandedCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()

	// localPVHealed keys "ns/pvc" — claim names outlive the PVC
	// object the heal deletes, so bound the map once per sweep at
	// the ephemeral-heal cooldown. pvcProvHealed keys the
	// provisioner name — a single entry in practice, but prune it
	// on the same pass so a renamed provisioner cannot wedge the
	// 1h cooldown forever.
	p.localPVHealed.PruneExpired(now, localPVEphemeralHealCooldown)
	p.pvcProvHealed.PruneExpired(now, pvcProvisionerHealCooldown)

	snap, err := p.collectLocalPVSnapshot(ctx)
	if err != nil {
		return probefw.Result{Infra: err}
	}

	// stranded/stalled/statefulRep accumulate each live gauge key's
	// label values — the reports feed the ledgers so no key gets
	// SplitN'd apart.
	var stranded, stalledRep, statefulRep probefw.SweepReport
	heals := scanStrandedPods(snap, now,
		&stranded, &stalledRep, &statefulRep)

	// Prune the gauges' series for tuples not re-seen — same
	// DeleteLabelValues hygiene as stsZeroEmitted; the ledgers hold
	// the label tuples so no key gets re-split.
	stranded.Close(&p.localPVEmitted,
		localPVStrandedPodsGauge.DeleteLabelValues)
	stalledRep.Close(&p.pvcStalledEmitted,
		pvcProvisioningStalledGauge.DeleteLabelValues)
	statefulRep.Close(&p.strandedStatefulEmitted,
		localPVStrandedStatefulPodGauge.DeleteLabelValues)

	// Heals run last — after the gauge ledgers reconcile — the
	// monolithic Run's exact sequence: alert state lands before
	// remediation (see localpv_heals.go).
	p.healStrandedEphemeral(ctx, log, heals, now)
	if stalledRep.Flagged() > 0 {
		p.healLocalPVProvisioner(ctx, log, now)
	}

	return stranded.Verdict("localpv-stranded/stalled volumes: ", ", ")
}

// ---------------------------------------------------------------------------
// localpv-stranded-pods (localpv-stranded-pods) — per-sweep collectors (split out of
// the monolithic Run; behavior byte-identical).
// ---------------------------------------------------------------------------

// localPVSnapshot is the sweep inventory the stranded/stalled scan
// classifies against: nodes by name plus the schedulable-worker
// gate, PVs by name, PVCs by "ns/name" and the pod snapshot.
type localPVSnapshot struct {
	nodesByName          map[string]*corev1.Node
	hasSchedulableWorker bool
	pvsByName            map[string]*corev1.PersistentVolume
	pvcsByKey            map[string]*corev1.PersistentVolumeClaim
	pods                 []corev1.Pod
}

// collectLocalPVSnapshot gathers the sweep inventory in the exact
// call order the monolithic Run used — nodes, then the paged
// cluster-wide PV/PVC reads, the shared pod snapshot last. The
// wrapped "list <resource>" errors become Result.Infra verbatim.
func (p *localPVStrandedCheck) collectLocalPVSnapshot(ctx context.Context) (*localPVSnapshot, error) {
	snap := &localPVSnapshot{}
	nodes, err := p.AllNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	snap.nodesByName = make(map[string]*corev1.Node, len(nodes))
	for i := range nodes {
		snap.nodesByName[nodes[i].Name] = &nodes[i]
		if kube.NodeReady(&nodes[i]) && !nodes[i].Spec.Unschedulable &&
			!kube.IsControlPlane(&nodes[i]) {
			snap.hasSchedulableWorker = true
		}
	}

	// Paged cluster-wide reads — the same full-truth posture as the
	// masterless EndpointSlice census: a partial read cannot tell
	// "stranded" from "no data", so a list error aborts the check.
	snap.pvsByName = map[string]*corev1.PersistentVolume{}
	err = kube.ListEach(ctx,
		metav1.ListOptions{Limit: probefw.HealthListPageSize},
		kube.PersistentVolumes(p.CS),
		func(items []corev1.PersistentVolume) error {
			for i := range items {
				snap.pvsByName[items[i].Name] = &items[i]
			}
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("list persistentvolumes: %w", err)
	}
	snap.pvcsByKey = map[string]*corev1.PersistentVolumeClaim{}
	pvcs, err := p.AllPVCs(ctx)
	if err != nil {
		return nil, fmt.Errorf("list persistentvolumeclaims: %w", err)
	}
	for i := range pvcs {
		snap.pvcsByKey[pvcs[i].Namespace+"/"+pvcs[i].Name] = &pvcs[i]
	}

	// Pending pods only — the old status.phase=Pending FieldSelector,
	// evaluated client-side over the shared sweep snapshot.
	snap.pods, err = p.AllPods(ctx)
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	return snap, nil
}

// scanStrandedPods classifies the snapshot pod-by-pod: (a) a bound
// local PV nodeAffinity-pinned to an unavailable node raises the
// stranded gauge — plus the stateful-split-brain stateful gauge for non-ephemeral
// workloads on a confirmed-dead node — and queues a strandedHeal for
// disposable volumes past localPVEphemeralHealMinAge; (b) a Pending
// openebs-hostpath claim past pvcStalledMinAge while schedulable
// workers exist raises the stalled gauge. Emitted keys land on the
// caller's reports so the gauge lifecycle (Close) stays with Run;
// the returned heals are consumed by healStrandedEphemeral AFTER the
// reports close — the monolithic Run's exact order.
func scanStrandedPods(snap *localPVSnapshot, now time.Time,
	stranded, stalledRep, statefulRep *probefw.SweepReport) []strandedHeal {
	var heals []strandedHeal
	for i := range snap.pods {
		pod := &snap.pods[i]
		if pod.Status.Phase != corev1.PodPending {
			continue // mirrors the FieldSelector for fake clients
		}
		age := now.Sub(pod.CreationTimestamp.Time)
		if age < localPVStrandedMinAge {
			continue
		}
		for _, vol := range pod.Spec.Volumes {
			claim := vol.PersistentVolumeClaim
			if claim == nil {
				continue
			}
			pvc := snap.pvcsByKey[pod.Namespace+"/"+claim.ClaimName]
			if pvc == nil {
				continue
			}
			// Branch A — bound local PV on an unavailable node.
			if pvc.Status.Phase == corev1.ClaimBound &&
				pvc.Spec.VolumeName != "" {
				if pv := snap.pvsByName[pvc.Spec.VolumeName]; pv != nil {
					for _, node := range localPVNodeNames(pv) {
						reason := strandedNodeReason(snap.nodesByName, node)
						if reason == "" {
							continue
						}
						key := pod.Namespace + "/" + pod.Name + "/" +
							pvc.Name + "/" + node + "/" + reason
						stranded.Emit(localPVStrandedPodsGauge, key,
							[]string{pod.Namespace, pod.Name, pvc.Name,
								node, reason}, key)
						// stateful-split-brain — a NON-ephemeral workload
						// stranded on a confirmed-dead node is
						// the data-loss class the ephemeral heal
						// deliberately never touches; the
						// dedicated gauge names the dead node so
						// the alert routes to the site.
						if (reason == strandedReasonMissingNode ||
							reason == strandedReasonOutOfService) &&
							!ephemeralLocalPV(pod, pvc) {
							skey := pod.Namespace + "/" + pod.Name + "/" + node
							statefulRep.Flag(localPVStrandedStatefulPodGauge,
								skey, []string{pod.Namespace, pod.Name, node})
							stranded.Find("stateful:" + skey + "(" + reason + ")")
						}
						// Confirmed-gone nodes only: NotReady/
						// cordoned can come back — a missing or
						// fenced (out-of-service) node cannot.
						if ephemeralLocalPV(pod, pvc) &&
							(reason == strandedReasonMissingNode ||
								reason == strandedReasonOutOfService) &&
							age >= localPVEphemeralHealMinAge {
							heals = append(heals, strandedHeal{
								pod: pod, pvc: pvc, node: node, reason: reason})
						}
					}
				}
			}
			// Branch B — claim still Pending on the hostpath
			// provisioner while schedulable workers exist AND the
			// provisioner already picked a node for it
			// (volume.kubernetes.io/selected-node): the annotation
			// is the provisioner's own scheduling decision, so a
			// claim past the window WITHOUT it was never selected —
			// a fresh or queued claim, not wedge evidence.
			if pvc.Status.Phase == corev1.ClaimPending &&
				snap.hasSchedulableWorker &&
				pvc.Spec.StorageClassName != nil &&
				*pvc.Spec.StorageClassName == openebsHostpathSC &&
				pvc.Annotations[kube.AnnoVolumeSelectedNode] != "" &&
				age >= pvcStalledMinAge {
				key := pod.Namespace + "/" + pvc.Name + "/" + openebsHostpathSC
				stalledRep.Flag(pvcProvisioningStalledGauge, key,
					[]string{pod.Namespace, pvc.Name, openebsHostpathSC})
				stranded.Find("stalled:" + key)
			}
		}
	}
	return heals
}
