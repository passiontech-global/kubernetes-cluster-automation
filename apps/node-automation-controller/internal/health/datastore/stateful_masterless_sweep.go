// stateful_masterless_sweep.go — the per-sweep phases of
// checkStatefulMasterlessServices.Run: census (STS/Service/
// EndpointSlice lists + ready-endpoint rollup + site-skew arming),
// master-role candidate pairing, the per-candidate zero-endpoint
// streak + signature eval, the ledger/report close, the heal
// dispatch for due candidates, and the verdict composition. The
// dragonfly/db-operator heals themselves live in dragonfly_heals.go
// / db_operator_heals.go.
package datastore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// masterlessSweep carries one Run's working state: the armed
// site-skew sweep, the ready-endpoint census, the paired candidates,
// the two SweepReports (zero-endpoints + split-brain), the heal-due
// list and the keep-sets the ledgers prune against.
type masterlessSweep struct {
	p          *statefulMasterlessCheck
	log        logr.Logger
	now        time.Time
	skew       *siteSkewSweep
	ready      map[string][]kube.ReadyEndpoint
	candidates []masterSvc
	seen       map[string]bool     // tuples observed at 0 ready this sweep
	evaluated  map[string]bool     // candidate keys evaluated this sweep — the streak's keep set
	rep        probefw.SweepReport // tuples past the gauge window
	multiRep   probefw.SweepReport // split-brain tuples
	due        []masterlessDue     // past the heal window
}

// beginMasterlessSweep runs the census half of Run: the three
// cluster-wide lists (any failure is an infra error — "0 ready" is
// indistinguishable from "no data"), the shared ready-endpoint
// rollup, the site-skew arming and the candidate pairing.
func (p *statefulMasterlessCheck) beginMasterlessSweep(ctx context.Context) (*masterlessSweep, error) {
	log := logf.FromContext(ctx)

	stsList, err := p.AllStatefulSets(ctx)
	if err != nil {
		return nil, fmt.Errorf("list statefulsets: %w", err)
	}
	svcList, err := p.AllServices(ctx)
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	// Ready-endpoint census per ns/service — the shared rollup the
	// endpoint censuses converge on (service-name label binding,
	// nil ready counts as ready — kube.ReadyEndpointsByService). A
	// list error skips the whole check: "0 ready" is
	// indistinguishable from "no data". stateful-split-brain keeps the endpoint
	// detail (zone/node/targetRef) the rollup captures so the
	// split-brain and site-skew signatures can place each endpoint.
	// The census rides the per-sweep snapshot — this check was the
	// last one paying its own cluster-wide list.
	esSlices, err := p.AllEndpointSlices(ctx)
	if err != nil {
		return nil, fmt.Errorf("list endpointslices: %w", err)
	}

	s := &masterlessSweep{
		p:         p,
		log:       log,
		now:       p.Now(),
		ready:     kube.ReadyEndpointsByService(esSlices),
		seen:      map[string]bool{},
		evaluated: map[string]bool{},
	}
	// stateful-split-brain(ii) — arm the cross-DC site-skew sweep: the census
	// reads, the multi-zone gate and the trigger bookkeeping live
	// in site_skew.go.
	s.skew = p.siteSkew.begin(ctx, log, p.Deps)
	// Candidates: a ready STS paired with a master-role Service
	// routing to its pods, plus CNPG Clusters — CloudNativePG owns
	// bare Pods (no StatefulSet), so its clusters are aggregated from
	// the pod census's cnpg.io/cluster label instead.
	s.candidates = masterlessCandidates(stsList, svcList)
	pods, perr := p.AllPods(ctx)
	if perr != nil {
		return nil, fmt.Errorf("list pods: %w", perr)
	}
	s.candidates = append(s.candidates, cnpgMasterlessCandidates(pods, svcList)...)
	return s, nil
}

// masterlessCandidates pairs each ready, non-downscaled StatefulSet
// with the master-role Services whose selectors route to its pods.
// A StatefulSet the go-kube-downscaler parked at spec.replicas:0
// (downscaler/* annotations present) is asleep on purpose — its
// master Service reading 0 ready endpoints is intent, not a wedged
// operator. Headless services are deliberately per-pod and skipped.
func masterlessCandidates(stsList []appsv1.StatefulSet,
	svcList []corev1.Service) []masterSvc {
	var candidates []masterSvc
	for i := range stsList {
		sts := &stsList[i]
		if kube.IsIntentionallyDownscaled(sts.Annotations, sts.Spec.Replicas) {
			continue
		}
		if sts.Status.ReadyReplicas == 0 {
			continue
		}
		for j := range svcList {
			svc := &svcList[j]
			if svc.Namespace != sts.Namespace ||
				svc.Spec.ClusterIP == "" ||
				svc.Spec.ClusterIP == corev1.ClusterIPNone {
				continue // headless services are deliberately per-pod
			}
			if !masterRoleService(svc) ||
				!selectorMatchesSTS(svc, sts.Spec.Template.Labels) {
				continue
			}
			candidates = append(candidates,
				masterSvc{ns: svc.Namespace, svc: svc.Name, sts: sts, svcObj: svc})
		}
	}
	return candidates
}

// cnpgClusterLabel is the label CloudNativePG stamps on every Pod of
// a Cluster — the grouping key the masterless sweep aggregates CNPG
// workloads by (there is no StatefulSet to pair against).
const cnpgClusterLabel = "cnpg.io/cluster"

// cnpgMasterlessCandidates aggregates Ready CloudNativePG pods by
// cnpg.io/cluster and pairs each cluster with the master-role
// Services routing to its pods — the CNPG twin of
// masterlessCandidates for an operator that manages bare Pods.
func cnpgMasterlessCandidates(pods []corev1.Pod,
	svcList []corev1.Service) []masterSvc {
	// clusterLabels: "ns/cluster" → representative pod labels (every
	// pod of a cluster shares cnpg.io/cluster; role labels differ but
	// selectorMatchesSTS strips them).
	clusterLabels := map[string]map[string]string{}
	for i := range pods {
		pod := &pods[i]
		cluster := pod.Labels[cnpgClusterLabel]
		if cluster == "" || pod.DeletionTimestamp != nil ||
			!kube.PodReadyCond(pod) {
			continue
		}
		key := pod.Namespace + "/" + cluster
		if _, ok := clusterLabels[key]; !ok {
			clusterLabels[key] = pod.Labels
		}
	}
	var candidates []masterSvc
	for key, podLabels := range clusterLabels {
		ns, cluster, _ := strings.Cut(key, "/")
		for j := range svcList {
			svc := &svcList[j]
			if svc.Namespace != ns ||
				svc.Spec.ClusterIP == "" ||
				svc.Spec.ClusterIP == corev1.ClusterIPNone {
				continue // headless services are deliberately per-pod
			}
			if !masterRoleService(svc) ||
				!selectorMatchesSTS(svc, podLabels) {
				continue
			}
			candidates = append(candidates, masterSvc{
				ns: svc.Namespace, svc: svc.Name, svcObj: svc,
				cnpg: cluster, podLabels: podLabels})
		}
	}
	return candidates
}

// stampTarget returns the object carrying the persisted first-seen
// annotation plus the merge-patch closure writing it — the
// StatefulSet for STS-backed workloads, the Service itself for a
// CNPG Cluster (which has no StatefulSet to stamp).
func (p *statefulMasterlessCheck) stampTarget(c masterSvc) (metav1.Object,
	func(ctx context.Context, data []byte) error) {

	if c.sts != nil {
		return c.sts, func(ctx context.Context, data []byte) error {
			if _, err := p.CS.AppsV1().StatefulSets(c.sts.Namespace).Patch(ctx,
				c.sts.Name, types.MergePatchType, data,
				metav1.PatchOptions{}); err != nil {
				return err
			}
			// Mirror the landed annotation patch onto the LISTED
			// object — one StatefulSet can back several master-role
			// Services, and each candidate's stamp reads the shared
			// copy: without the mirror a second stamp computes its
			// first-seen map from pre-patch state and drops the
			// sibling's just-written key.
			probefw.MergeAnnoPatchLocally(ctx, c.sts, data)
			return nil
		}
	}
	return c.svcObj, func(ctx context.Context, data []byte) error {
		if _, err := p.CS.CoreV1().Services(c.ns).Patch(ctx,
			c.svc, types.MergePatchType, data,
			metav1.PatchOptions{}); err != nil {
			return err
		}
		probefw.MergeAnnoPatchLocally(ctx, c.svcObj, data)
		return nil
	}
}

// evalCandidates runs the per-candidate streak + signature eval:
// the split-brain and site-skew signatures, the persisted
// zero-endpoint first-seen (annotation-backed so an operator
// restart cannot re-arm the gauge/heal windows mid-wedge), the
// gauge emit and the heal-due collection.
func (s *masterlessSweep) evalCandidates(ctx context.Context) {
	p := s.p
	for _, c := range s.candidates {
		key := c.ns + "/" + c.svc + "/" + c.workloadName()
		s.evaluated[key] = true
		// The persisted first-seen stamp lands on the StatefulSet
		// when one exists; a CNPG Cluster has no STS so its stamp
		// rides the Service itself.
		stampObj, patch := p.stampTarget(c)
		eps := s.ready[c.ns+"/"+c.svc]
		// stateful-split-brain(i)/(ii) — the split-brain streak and the cross-DC
		// pin accounting, one signature per file.
		p.splitBrain.eval(c, key, len(eps), &s.multiRep)
		s.skew.evalMaster(c, key, eps)
		if len(eps) > 0 {
			// Master reachable — the signature resolved on a live
			// object: drop the persisted stamp so a recurrence
			// re-arms the full window (a stale stamp would
			// fast-trip the heal). Tolerated sub-failure — the
			// ledger Forget already landed, the annotation retry
			// is Warn-only.
			if err := heal.ClearPersistedFirstSeen(ctx, s.log,
				&p.stsZeroSince, stampObj,
				kube.AnnoFirstSeenStatefulMasterless, key,
				patch); err != nil {
				s.log.Info("WARN: masterless first-seen clear failed",
					"workload", c.workloadName(),
					"error", err)
			}
			continue
		}
		s.seen[key] = true
		// The zero-endpoint streak gates the dragonfly/db-operator
		// bounce and the dual-replica-deadlock ordinal-0 pod delete, so it runs the
		// persisted (annotation-backed) variant — the stamp on the
		// STS survives an operator restart that would otherwise
		// re-arm the gauge and heal windows mid-wedge.
		if !heal.FirstSeenPersisted(ctx, s.log, &p.stsZeroSince, stampObj,
			kube.AnnoFirstSeenStatefulMasterless, key,
			masterlessZeroMinAge, s.now, patch) {
			continue
		}
		s.rep.Emit(statefulServiceZeroEndpointsGauge, key,
			[]string{c.ns, c.svc, c.workloadName()}, key)
		// The heal window reads the same streak — Seen never
		// re-stamps, and reports the WIDER window once
		// FirstSeenPersisted Seeds a resumed persisted stamp back
		// into the ledger (a streak that crossed a restart keeps
		// its full age).
		if age, _ := p.stsZeroSince.Seen(key, s.now); age >= masterlessHealMinAge {
			s.due = append(s.due, masterlessDue{svc: c, since: s.now.Add(-age)})
		}
	}
}

// closeReports prunes the streak/emitted ledgers against this
// sweep's keep-sets and closes both SweepReports — tuples not
// re-seen lose their gauge series instead of pinning stale 1s.
func (s *masterlessSweep) closeReports() {
	p := s.p
	s.skew.close()
	p.stsZeroSince.Prune(func(k string) bool { return s.seen[k] })
	p.splitBrain.streak.Prune(func(k string) bool { return s.evaluated[k] })
	s.rep.Close(&p.stsZeroEmitted, statefulServiceZeroEndpointsGauge.DeleteLabelValues)
	s.multiRep.Close(&p.splitBrain.emitted, statefulServiceMultipleMastersGauge.DeleteLabelValues)
}

// healDue dispatches each past-window candidate to its owner
// signature's heal: Dragonfly-owned STS get the operator bounce
// (step 1) plus the dual-replica-deadlock ordinal-0 pod delete once
// the streak reaches that window and the bounce has settled; a
// non-dragonfly masterless STS owned by a known db operator gets
// the same re-election nudge on its own cooldown, and anything
// else gets per-pod role diagnostics instead — its election
// contract is operand-specific and a generic pod kill is not safe
// to automate.
func (s *masterlessSweep) healDue(ctx context.Context) {
	p := s.p
	for _, d := range s.due {
		if d.svc.cnpg == "" && dragonflyOwned(d.svc.sts) {
			p.healDragonflyOperator(ctx, s.log, d.svc, s.now)
			if s.now.Sub(d.since) >= dragonflyReplicaDeadlockMinAge {
				p.healDragonflyReplicaDeadlock(ctx, s.log, d.svc, s.now)
			}
			continue
		}
		// va-stuck-terminating: a masterless stateful service owned by a known db
		// operator gets the operator pod bounced to force
		// re-election — the same re-election nudge as the
		// dragonfly heal, on its own per-operator 30m cooldown. A
		// CNPG candidate has no StatefulSet; its pre-aggregated pod
		// and Service labels go through dbOperatorForLabels so a
		// cluster carrying app.kubernetes.io/managed-by=cloudnative-pg
		// bounces cnpg-controller-manager, while an unattributed
		// cluster falls to the diagnostics-only path.
		var op string
		if d.svc.cnpg != "" {
			op = dbOperatorForLabels(
				[]map[string]string{d.svc.podLabels, d.svc.svcObj.Labels}, nil)
		} else {
			op = dbOperatorFor(d.svc.sts)
		}
		if op != "" {
			p.healDBOperator(ctx, s.log, d.svc, op, s.now)
		} else {
			p.logStatefulPodRoles(ctx, s.log, d.svc)
		}
	}
}

// verdict composes the run result: zero-endpoints and split-brain
// are OPPOSITE signatures (0 ready masters vs >1) — each renders
// under its own verdict wording instead of the split-brain findings
// hiding behind the "0 ready endpoints" prefix (heal-budget
// verdict-detail fix).
func (s *masterlessSweep) verdict() probefw.Result {
	res := s.rep.Verdict(fmt.Sprintf(
		"master-role services at 0 ready endpoints >=%s: ",
		masterlessZeroMinAge), ", ")
	if split := s.multiRep.Verdict(
		"master-role services with multiple ready masters (split brain) "+
			">=2 sweeps: ", ", "); split.Why != "" {
		if res.Why != "" {
			res.Why += " | " + split.Why
		} else {
			res.Why = split.Why
			res.Pass = false
		}
		if res.Infra == nil {
			res.Infra = split.Infra
		}
	}
	// Site-skew findings live on the skew sweep's own report — they
	// get their own verdict wording instead of masquerading as a
	// zero-endpoints or split-brain signature.
	if skew := s.skew.rep.Verdict(
		"stateful masters pinned to the standby site: ", ", "); skew.Why != "" {
		if res.Why != "" {
			res.Why += " | " + skew.Why
		} else {
			res.Why = skew.Why
			res.Pass = false
		}
		if res.Infra == nil {
			res.Infra = skew.Infra
		}
	}
	return res
}
