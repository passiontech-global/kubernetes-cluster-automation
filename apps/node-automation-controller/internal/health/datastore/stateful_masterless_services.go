package datastore

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/health/probefw"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// statefulMasterlessCheck is the W6.2 masterless service guard plus
// the Dragonfly/db-operator auto-heals.
type statefulMasterlessCheck struct {
	*probefw.Deps

	// W6.2 watchdog state (serial sweep — unguarded):
	//   - stsZeroSince: "ns/svc/sts" → first sweep the master-role
	//     Service showed 0 Ready endpoints.
	//   - stsZeroEmitted: series ledger for
	//     StatefulServiceZeroEndpoints — a tuple not re-seen gets
	//     DeleteLabelValues, not a stale 1 (same hygiene as the
	//     webhook guard's brokenEmitted).
	//   - drHealed: operator pod "ns/name" → last delete — the
	//     in-RAM half of the 30m dragonfly heal cooldown (the STS
	//     annotation stamp is the durable half).
	//   - drPodHealed: "ns/sts" → last ordinal-0 pod delete — the
	//     in-RAM half of the 30m dual-replica-deadlock cooldown
	//     (W7-C3; the STS annotation is the durable half).
	stsZeroSince   map[string]time.Time
	stsZeroEmitted map[string]bool
	drHealed       map[string]time.Time
	drPodHealed    map[string]time.Time
}

// newStatefulMasterlessCheck builds the W6.2 check with fresh
// tracking maps — the state-map initialization that used to live in
// the monolithic newClusterHealthProber literal.
func NewStatefulMasterlessCheck(d *probefw.Deps) probefw.Check {
	return &statefulMasterlessCheck{Deps: d,
		stsZeroSince:   map[string]time.Time{},
		stsZeroEmitted: map[string]bool{},
		drHealed:       map[string]time.Time{},
		drPodHealed:    map[string]time.Time{},
	}
}

// W6.2 — stateful-masterless-services knobs.
const (
	// CheckNameStatefulMasterless is the check's kuberhealthy_check
	// label value — W6.2; not a ported HealthCheck but reports
	// under its own check name so the generic FAIL alerting path
	// covers it.
	CheckNameStatefulMasterless = "stateful-masterless-services"
	// masterlessZeroMinAge: a master-role Service must report 0
	// Ready endpoints this long before the gauge fires.
	masterlessZeroMinAge = 3 * time.Minute
	// masterlessHealMinAge: the zero-endpoint streak must reach this
	// before the dragonfly-operator leader gets bounced (5m —
	// longer than the gauge so a flap doesn't kill the operator).
	masterlessHealMinAge  = 5 * time.Minute
	dragonflyHealCooldown = 30 * time.Minute
	// DragonflyOperatorNS + dragonflyOperatorPodPrefix locate
	// the operator pods the heal deletes to force re-election (the
	// namespace is shared with the watchdogs operator-target table).
	dragonflyOperatorPodPrefix = "dragonfly-operator-controller-manager"
	// dragonflyHealAnno persists the last heal moment on the STS —
	// the restart-proof half of the cooldown.
	dragonflyHealAnno = "node.ops/last-dragonfly-operator-heal"

	// W7-C3 — dual-replica deadlock: past this zero-endpoint streak
	// the operator restart (step 1) demonstrably failed to re-elect
	// a master, so the STS ordinal-0 pod is deleted to force the
	// whole election from scratch.
	dragonflyReplicaDeadlockMinAge = 10 * time.Minute
	// dragonflyOperatorSettleMin bounds how fresh the operator heal
	// must be before the pod kill is allowed — step 1 needs a few
	// minutes to relabel the pods; deleting ordinal-0 while the new
	// operator is still reconciling reaps the pod pointlessly.
	dragonflyOperatorSettleMin = 3 * time.Minute
	// dragonflyPodHealCooldown bounds ordinal-0 pod deletes to one
	// per STS — wider of the in-RAM ledger and the persisted
	// node.ops/last-dragonfly-pod-heal stamp (same wider-of-both
	// shape as the operator heal above).
	dragonflyPodHealCooldown = 30 * time.Minute
	// dragonflyPodHealAnno persists the last ordinal-0 pod delete on
	// the STS — the restart-proof half of the cooldown.
	dragonflyPodHealAnno = "node.ops/last-dragonfly-pod-heal"
)

// ---------------------------------------------------------------------------
// stateful-masterless-services (W6.2) — masterless service guard +
// dragonfly auto-heal.
// ---------------------------------------------------------------------------

// masterlessRoleKeys are the label keys marking a Service that routes
// only to the master/primary of a stateful set — 0 Ready endpoints on
// it means the workload is leaderless.
var masterlessRoleKeys = []string{"role", "redis-role", "app.kubernetes.io/role"}

// masterlessRoleValues are the role values identifying the master
// side of a replicated stateful service.
var masterlessRoleValues = []string{"master", "primary", "leader"}

// masterRoleService reports whether svc carries a master-role key —
// in its selector (selects only the leader pods) or its own labels
// (the Service is labeled as the master endpoint).
func masterRoleService(svc *corev1.Service) bool {
	for _, k := range masterlessRoleKeys {
		if v := svc.Spec.Selector[k]; slices.Contains(masterlessRoleValues, v) {
			return true
		}
	}
	for _, k := range masterlessRoleKeys {
		if v := svc.Labels[k]; slices.Contains(masterlessRoleValues, v) {
			return true
		}
	}
	return false
}

// selectorMatchesSTS reports whether the Service routes to the
// StatefulSet's pods: every NON-role key in svc.Spec.Selector must
// appear in the STS pod-template labels. Role keys are stripped —
// operators write role=master/replica onto the POD at runtime, never
// into the template, so a literal subset match would never fire for
// exactly the services this check exists to watch (dragonfly/redis
// master services). A selector that carries nothing but role keys
// cannot be attributed to one STS — it matches every workload, so it
// is excluded.
func selectorMatchesSTS(svc *corev1.Service, podLabels map[string]string) bool {
	nonRole := map[string]string{}
	for k, v := range svc.Spec.Selector {
		if slices.Contains(masterlessRoleKeys, k) {
			continue
		}
		nonRole[k] = v
	}
	if len(nonRole) == 0 {
		return false
	}
	return labels.SelectorFromSet(nonRole).Matches(labels.Set(podLabels))
}

// masterSvc pairs a master-role Service with the ready StatefulSet
// whose pod labels its selector matches.
type masterSvc struct {
	ns, svc string
	sts     *appsv1.StatefulSet
}

// masterlessDue pairs a master-role service past the heal window
// with the moment its zero-endpoint streak began — the W7-C3
// deadlock heal needs the streak length, not just "past 5m".
type masterlessDue struct {
	svc   masterSvc
	since time.Time
}

// dragonflyOwned reports whether the StatefulSet is managed by the
// dragonfly-operator — via app.kubernetes.io/part-of=dragonfly or
// app.kubernetes.io/created-by=dragonfly-operator on the STS metadata
// or its pod template.
func dragonflyOwned(sts *appsv1.StatefulSet) bool {
	for _, lbls := range []map[string]string{sts.Labels, sts.Spec.Template.Labels} {
		if lbls["app.kubernetes.io/part-of"] == "dragonfly" ||
			lbls["app.kubernetes.io/created-by"] == "dragonfly-operator" {
			return true
		}
	}
	return false
}

// checkStatefulMasterlessServices detects a masterless stateful
// service: a non-headless Service routing to a ready StatefulSet's
// pods under a master-role key whose EndpointSlices report 0 Ready
// endpoints — the STS is alive but clients have no master to reach
// (the operator that assigns the role wedged).
//
// Past masterlessZeroMinAge the gauge
// node_automation_stateful_service_zero_endpoints{ns,svc,sts} goes to
// 1 and the check FAILs; past masterlessHealMinAge a Dragonfly-owned
// STS additionally triggers a dragonfly-operator leader delete (30m
// cooldown) — a wedged operator is the common cause of a missing
// master label/election.
func (p *statefulMasterlessCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	if p.stsZeroSince == nil {
		p.stsZeroSince = map[string]time.Time{}
	}
	if p.stsZeroEmitted == nil {
		p.stsZeroEmitted = map[string]bool{}
	}
	if p.drHealed == nil {
		p.drHealed = map[string]time.Time{}
	}
	if p.drPodHealed == nil {
		p.drPodHealed = map[string]time.Time{}
	}

	stsList, err := p.CS.AppsV1().StatefulSets(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list statefulsets: %w", err)}
	}
	svcList, err := p.CS.CoreV1().Services(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list services: %w", err)}
	}
	// Ready-endpoint census per ns/service — same source as the
	// webhook guard (paged, service-name label binding, nil ready
	// counts as ready). A list error skips the whole check: "0
	// ready" is indistinguishable from "no data".
	ready := map[string]int{}
	err = shared.ListEach(ctx,
		metav1.ListOptions{Limit: probefw.HealthListPageSize},
		shared.EndpointSlices(p.CS, metav1.NamespaceAll),
		func(items []discoveryv1.EndpointSlice) error {
			for _, s := range items {
				svc := s.Labels[discoveryv1.LabelServiceName]
				if svc == "" {
					continue
				}
				key := s.Namespace + "/" + svc
				for _, ep := range s.Endpoints {
					if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
						ready[key]++
					}
				}
			}
			return nil
		})
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list endpointslices: %w", err)}
	}

	// Candidates: a ready STS paired with a master-role Service
	// routing to its pods.
	var candidates []masterSvc
	for i := range stsList.Items {
		sts := &stsList.Items[i]
		if sts.Status.ReadyReplicas == 0 {
			continue
		}
		for j := range svcList.Items {
			svc := &svcList.Items[j]
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
				masterSvc{ns: svc.Namespace, svc: svc.Name, sts: sts})
		}
	}

	seen := map[string]bool{}    // tuples observed at 0 ready this sweep
	emitted := map[string]bool{} // tuples past the gauge window
	var due []masterlessDue      // past the heal window
	for _, c := range candidates {
		key := c.ns + "/" + c.svc + "/" + c.sts.Name
		if ready[c.ns+"/"+c.svc] > 0 {
			continue // master reachable — drop any streak
		}
		seen[key] = true
		first, ok := p.stsZeroSince[key]
		if !ok {
			p.stsZeroSince[key] = now
		}
		if !ok {
			log.Info("master-role service at 0 ready endpoints — tracking first-seen",
				"service", c.ns+"/"+c.svc, "statefulset", c.sts.Name)
			continue
		}
		if now.Sub(first) < masterlessZeroMinAge {
			continue
		}
		emitted[key] = true
		metrics.StatefulServiceZeroEndpoints.
			WithLabelValues(c.ns, c.svc, c.sts.Name).Set(1)
		if now.Sub(first) >= masterlessHealMinAge {
			due = append(due, masterlessDue{svc: c, since: first})
		}
	}

	for k := range p.stsZeroSince {
		if !seen[k] {
			delete(p.stsZeroSince, k)
		}
	}
	for k := range p.stsZeroEmitted {
		if emitted[k] {
			continue
		}
		if parts := strings.SplitN(k, "/", 3); len(parts) == 3 {
			metrics.StatefulServiceZeroEndpoints.
				DeleteLabelValues(parts[0], parts[1], parts[2])
		}
		delete(p.stsZeroEmitted, k)
	}
	maps.Copy(p.stsZeroEmitted, emitted)

	// Dragonfly auto-heal — a masterless dragonfly past the heal
	// window bounces the operator leader to force re-election (step
	// 1); past the deadlock window and >=3m after that bounce the
	// dual-replica heal deletes the lowest-ordinal pod to restart
	// the election from scratch (step 2, W7-C3). A non-dragonfly
	// masterless STS gets per-pod role diagnostics instead — its
	// election contract is operand-specific and a generic pod kill
	// is not safe to automate.
	for _, d := range due {
		if !dragonflyOwned(d.svc.sts) {
			// W4: a masterless stateful service owned by a known db
			// operator gets the operator pod bounced to force
			// re-election — the same re-election nudge as the
			// dragonfly heal, on its own per-operator 30m cooldown.
			if op := dbOperatorFor(d.svc.sts); op != "" {
				p.healDBOperator(ctx, log, d.svc, op, now)
			} else {
				p.logStatefulPodRoles(ctx, log, d.svc)
			}
			continue
		}
		p.healDragonflyOperator(ctx, log, d.svc, now)
		if now.Sub(d.since) >= dragonflyReplicaDeadlockMinAge {
			p.healDragonflyReplicaDeadlock(ctx, log, d.svc, now)
		}
	}

	if len(emitted) == 0 {
		return probefw.Result{Pass: true}
	}
	keys := make([]string, 0, len(emitted))
	for k := range emitted {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return probefw.Result{Why: fmt.Sprintf(
		"master-role services at 0 ready endpoints >=%s: %s",
		masterlessZeroMinAge, strings.Join(keys, ", "))}
}

// healDragonflyOperator deletes the dragonfly-operator controller
// pod(s) — the same re-election nudge the operator watchdog applies,
// keyed on its own 30m cooldown so the leader is never churned. The
// cooldown is the wider of the in-RAM ledger and the
// node.ops/last-dragonfly-operator-heal stamp persisted on the STS
// that triggered it (survives operator restarts).
func (p *statefulMasterlessCheck) healDragonflyOperator(ctx context.Context, log logr.Logger,
	sig masterSvc, now time.Time) {
	// Maintenance mutex — never kill an operator mid-drain/upgrade;
	// "cannot verify" fails closed like healOperatorLeader (W5.8).
	held, why, err := shared.MaintenanceActive(ctx, p.CS, p.Dyn)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: maintenance check unverifiable — heal deferred (fail closed)",
			"statefulset", sig.sts.Namespace+"/"+sig.sts.Name, "error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — heal deferred",
			"statefulset", sig.sts.Namespace+"/"+sig.sts.Name, "why", why)
		return
	}
	if ts := sig.sts.Annotations[dragonflyHealAnno]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil &&
			now.Sub(t) < dragonflyHealCooldown {
			log.Info("skip heal: persisted stamp inside cooldown",
				"statefulset", sig.sts.Namespace+"/"+sig.sts.Name,
				"ago", now.Sub(t).Truncate(time.Minute))
			return
		}
	}
	pods, err := p.CS.CoreV1().Pods(probefw.DragonflyOperatorNS).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list dragonfly-operator pods failed — heal deferred",
			"error", err)
		return
	}
	deleted := false
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !strings.HasPrefix(pod.Name, dragonflyOperatorPodPrefix) {
			continue
		}
		key := pod.Namespace + "/" + pod.Name
		last, ok := p.drHealed[key]
		if ok && now.Sub(last) < dragonflyHealCooldown {
			log.Info("skip heal: dragonfly operator inside cooldown",
				"pod", key, "ago", now.Sub(last).Truncate(time.Minute))
			continue
		}
		uid := pod.UID
		if err := p.CS.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "dragonfly operator delete failed", "pod", key)
			continue
		}
		p.drHealed[key] = now
		deleted = true
		log.Info("DELETE: dragonfly operator pod — masterless service, forcing re-election",
			"pod", key, "service", sig.ns+"/"+sig.svc,
			"statefulset", sig.sts.Name)
	}
	if !deleted {
		return
	}
	// Persist the stamp on the STS — the durable half of the
	// cooldown. A patch failure leaves the in-RAM half holding.
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{
			dragonflyHealAnno: now.UTC().Format(time.RFC3339),
		}},
	})
	if err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "marshal dragonfly heal stamp", "statefulset", sig.sts.Name)
		return
	}
	if _, err := p.CS.AppsV1().StatefulSets(sig.sts.Namespace).Patch(ctx,
		sig.sts.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "persist dragonfly heal stamp failed",
			"statefulset", sig.sts.Namespace+"/"+sig.sts.Name)
	}
}

// dragonflyOperatorHealedAt returns the most recent moment a
// dragonfly-operator leader pod was deleted by step 1 — the wider
// of the persisted node.ops/last-dragonfly-operator-heal stamp on
// this STS and the in-RAM per-pod ledger (which survives an STS
// patch failure). ok=false means no heal has landed yet: the
// dual-replica heal must not skip ahead of step 1.
func (p *statefulMasterlessCheck) dragonflyOperatorHealedAt(sig masterSvc) (time.Time, bool) {
	var latest time.Time
	if ts := sig.sts.Annotations[dragonflyHealAnno]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil && t.After(latest) {
			latest = t
		}
	}
	for _, t := range p.drHealed {
		if t.After(latest) {
			latest = t
		}
	}
	return latest, !latest.IsZero()
}

// podMasterRole reports whether the pod carries a master/primary/
// leader value under any master-role label key — the positive form
// of the dual-replica deadlock check (a pod already holding the
// master role means the election produced a winner and a pod kill
// would fight it).
func podMasterRole(pod *corev1.Pod) bool {
	for _, k := range masterlessRoleKeys {
		if slices.Contains(masterlessRoleValues, pod.Labels[k]) {
			return true
		}
	}
	return false
}

// smallestOrdinalPod returns the pod with the lowest StatefulSet
// ordinal — "<sts>-0" in the common case — or nil when none of the
// pods match the "<sts>-<n>" naming. StatefulSet pod names are the
// only source of truth for the ordinal (there is no field for it).
func smallestOrdinalPod(pods []corev1.Pod, stsName string) *corev1.Pod {
	var best *corev1.Pod
	bestOrd := -1
	for i := range pods {
		name := pods[i].Name
		if !strings.HasPrefix(name, stsName+"-") {
			continue
		}
		ord, err := strconv.Atoi(name[len(stsName)+1:])
		if err != nil {
			continue
		}
		if bestOrd < 0 || ord < bestOrd {
			bestOrd = ord
			best = &pods[i]
		}
	}
	return best
}

// dbOperatorNames are the operators whose role-assignment wedge this
// check heals — matched against the StatefulSet's labels, pod-template
// labels and ownerReferences. The long Percona deployment names sit
// alongside the short chart aliases (W10-FIX4): an STS owned by the
// percona-xtradb-cluster-operator Deployment labels itself with the
// long name, while older charts/labels still carry pxc-operator.
var dbOperatorNames = []string{
	"mariadb-operator", "pxc-operator", "psmdb-operator",
	"pg-operator", "scylla-operator",
	"percona-xtradb-cluster-operator", "percona-server-mongodb-operator",
	"percona-postgresql-operator",
}

// dbOperatorDeploymentAliases groups the Deployment/pod-name spellings
// one logical db operator answers to (W10-FIX4): the short chart alias
// (pxc-operator) and the long upstream Deployment name
// (percona-xtradb-cluster-operator) produce DIFFERENT pod name
// prefixes, so a heal keyed on whichever spelling dbOperatorFor
// matched would miss the real pods.
var dbOperatorDeploymentAliases = map[string][]string{
	"percona-xtradb-cluster-operator": {"percona-xtradb-cluster-operator", "pxc-operator"},
	"percona-server-mongodb-operator": {"percona-server-mongodb-operator", "psmdb-operator"},
	"percona-postgresql-operator":     {"percona-postgresql-operator", "pg-operator"},
}

// dbOperatorPodPrefixes returns every pod-name prefix the logical
// operator may deploy under — the alias group when one exists, else
// the bare operator name. Order is stable: the canonical (key) name
// first, then aliases.
func dbOperatorPodPrefixes(operator string) []string {
	if aliases, ok := dbOperatorDeploymentAliases[operator]; ok {
		return aliases
	}
	for _, aliases := range dbOperatorDeploymentAliases {
		for _, a := range aliases {
			if a == operator {
				return aliases
			}
		}
	}
	return []string{operator}
}

// dbOperatorFor returns the db operator name owning this StatefulSet,
// or "" — matching any label value on the STS or its pod template
// containing the operator name (managed-by/part-of/created-by and
// operator-specific labels all end up containing it), plus
// ownerReference names.
func dbOperatorFor(sts *appsv1.StatefulSet) string {
	for _, lbls := range []map[string]string{sts.Labels, sts.Spec.Template.Labels} {
		for _, v := range lbls {
			for _, op := range dbOperatorNames {
				if strings.Contains(v, op) {
					return op
				}
			}
		}
	}
	for _, ref := range sts.OwnerReferences {
		for _, op := range dbOperatorNames {
			if strings.Contains(ref.Name, op) {
				return op
			}
		}
	}
	return ""
}

// healDBOperator deletes a pod of the responsible db operator to
// force master re-election — only fires while !MaintenanceActive
// (the caller guarantees the >=5m zero-endpoint streak and
// sts.Status.ReadyReplicas > 0; the check itself only reaches here
// for ready STS). 30m per-operator cooldown on the in-RAM ledger.
func (p *statefulMasterlessCheck) healDBOperator(ctx context.Context, log logr.Logger,
	sig masterSvc, operator string, now time.Time) {
	const dbOperatorHealCooldown = 30 * time.Minute
	if p.Heals.CooledDown(operator, dbOperatorHealCooldown, now) {
		log.Info("skip heal: db operator inside cooldown", "operator", operator)
		return
	}
	held, why, err := shared.MaintenanceActive(ctx, p.CS, p.Dyn)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: maintenance check unverifiable — heal deferred (fail closed)",
			"operator", operator, "error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — heal deferred", "operator", operator, "why", why)
		return
	}
	pods, err := p.CS.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list pods failed — db operator heal deferred", "error", err)
		return
	}
	// Find the oldest Running pod of the operator — its namespace is
	// not fixed across installs, so the prefix match runs
	// cluster-wide and the blast radius is capped at one pod. The
	// Percona operators answer to two Deployment spellings (W10-FIX4)
	// — every alias prefix is tried so a short-name match still finds
	// the long-named pods.
	prefixes := dbOperatorPodPrefixes(operator)
	var target *corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.Phase != corev1.PodRunning ||
			pod.DeletionTimestamp != nil {
			continue
		}
		matched := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(pod.Name, prefix+"-") {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if target == nil || pod.CreationTimestamp.Before(&target.CreationTimestamp) {
			target = pod
		}
	}
	if target == nil {
		log.Info("no running pod found for db operator — heal deferred",
			"operator", operator)
		return
	}
	uid := target.UID
	if err := p.CS.CoreV1().Pods(target.Namespace).Delete(ctx, target.Name,
		metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "db operator pod delete failed",
			"pod", target.Namespace+"/"+target.Name, "operator", operator)
		return
	}
	p.Heals.Stamp(operator, now)
	metrics.ControlPlanePodHealsTotal.WithLabelValues(operator).Inc()
	log.Info("DELETE: db operator pod — masterless service, forcing re-election",
		"operator", operator, "pod", target.Namespace+"/"+target.Name,
		"service", sig.ns+"/"+sig.svc, "statefulset", sig.sts.Name)
}

// logStatefulPodRoles dumps per-pod role-label diagnostics for a
// masterless non-dragonfly StatefulSet — the W7-C3 pod-delete heal
// is dragonfly-only (its election contract is operator-driven), so
// for Percona/PostgreSQL/NATS the check leaves this evidence trail
// for the on-call engineer instead of acting on it. Diagnostics
// only: a list failure must not escalate into a run error.
func (p *statefulMasterlessCheck) logStatefulPodRoles(ctx context.Context, log logr.Logger, sig masterSvc) {
	sel, err := metav1.LabelSelectorAsSelector(sig.sts.Spec.Selector)
	if err != nil {
		return
	}
	pods, err := p.CS.CoreV1().Pods(sig.sts.Namespace).List(ctx,
		metav1.ListOptions{LabelSelector: sel.String()})
	if err != nil {
		return
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		roles := map[string]string{}
		for _, k := range masterlessRoleKeys {
			if v := pod.Labels[k]; v != "" {
				roles[k] = v
			}
		}
		log.Info("masterless service — pod role diagnostic",
			"service", sig.ns+"/"+sig.svc,
			"statefulset", sig.sts.Namespace+"/"+sig.sts.Name,
			"pod", pod.Name,
			"ready", shared.PodReadyCond(pod),
			"roles", fmt.Sprintf("%v", roles))
	}
}

// healDragonflyReplicaDeadlock is the W7-C3 step-2 heal: the
// dragonfly-operator leader was already bounced (step 1, W6.2) but
// the masterless streak outlived it — the dual-replica deadlock
// where every pod holds role=replica (each still executing
// REPLICAOF <old-dead-ip>) and an operator restart alone cannot
// re-elect. Deleting the lowest-ordinal pod forces the election
// from scratch.
//
// Gates, in order:
//  1. the operator heal must have actually landed >=
//     dragonflyOperatorSettleMin ago — deleting a pod before the new
//     leader had time to relabel reaps it pointlessly, and no heal
//     record at all means step 1 never ran: keep waiting rather
//     than skipping to pod kills;
//  2. the deadlock itself: every STS pod Ready AND zero pods
//     carrying a master-role label — an unready pod or an existing
//     master means the wedge sits elsewhere and a pod kill helps
//     nothing;
//  3. the 30m cooldown (wider of in-RAM ledger and persisted STS
//     stamp) and the maintenance mutex — the same shape every
//     pod-delete heal in this sweep carries.
func (p *statefulMasterlessCheck) healDragonflyReplicaDeadlock(ctx context.Context, log logr.Logger,
	sig masterSvc, now time.Time) {

	stsKey := sig.sts.Namespace + "/" + sig.sts.Name

	// Gate 1 — the operator heal must have settled first.
	opHealedAt, healed := p.dragonflyOperatorHealedAt(sig)
	switch {
	case !healed:
		log.Info("dual-replica deadlock: no operator heal recorded — waiting for step 1",
			"statefulset", stsKey)
		return
	case now.Sub(opHealedAt) < dragonflyOperatorSettleMin:
		log.Info("dual-replica deadlock: operator heal still settling — waiting",
			"statefulset", stsKey,
			"ago", now.Sub(opHealedAt).Truncate(time.Minute))
		return
	}

	sel, err := metav1.LabelSelectorAsSelector(sig.sts.Spec.Selector)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: statefulset selector unparseable — deadlock heal deferred",
			"statefulset", stsKey, "error", err)
		return
	}
	pods, err := p.CS.CoreV1().Pods(sig.sts.Namespace).List(ctx,
		metav1.ListOptions{LabelSelector: sel.String()})
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list statefulset pods failed — deadlock heal deferred",
			"statefulset", stsKey, "error", err)
		return
	}

	// Gate 2 — confirm the deadlock shape: all replicas Ready but
	// nobody holds the master role.
	if len(pods.Items) == 0 {
		return // no pods — nothing safe to delete
	}
	allReady := true
	hasMaster := false
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !shared.PodReadyCond(pod) {
			allReady = false
		}
		if podMasterRole(pod) {
			hasMaster = true
		}
	}
	switch {
	case !allReady:
		log.Info("dual-replica deadlock not confirmed: unready pod — heal deferred",
			"statefulset", stsKey)
		return
	case hasMaster:
		// A pod already carries the master role — endpoints will
		// follow; a pod kill now would fight a live re-election.
		return
	}

	// Gate 3 — the 30m cooldown (wider of in-RAM + persisted), then
	// the maintenance mutex.
	last, ok := p.drPodHealed[stsKey]
	if ok && now.Sub(last) < dragonflyPodHealCooldown {
		log.Info("skip heal: dragonfly pod inside cooldown",
			"statefulset", stsKey, "ago", now.Sub(last).Truncate(time.Minute))
		return
	}
	if ts := sig.sts.Annotations[dragonflyPodHealAnno]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil &&
			now.Sub(t) < dragonflyPodHealCooldown {
			log.Info("skip heal: persisted stamp inside cooldown",
				"statefulset", stsKey,
				"ago", now.Sub(t).Truncate(time.Minute))
			return
		}
	}
	// Maintenance mutex — never kill a stateful pod mid-drain/
	// upgrade; "cannot verify" fails closed like every other caller.
	held, why, err := shared.MaintenanceActive(ctx, p.CS, p.Dyn)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: maintenance check unverifiable — heal deferred (fail closed)",
			"statefulset", stsKey, "error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — heal deferred",
			"statefulset", stsKey, "why", why)
		return
	}

	target := smallestOrdinalPod(pods.Items, sig.sts.Name)
	if target == nil {
		return // no STS-named pod found — nothing safe to delete
	}
	// UID precondition closes the list→delete TOCTOU: a same-named
	// replacement pod is not ours to reap.
	uid := target.UID
	if err := p.CS.CoreV1().Pods(target.Namespace).Delete(ctx, target.Name,
		metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "dragonfly dual-replica pod delete failed",
			"pod", target.Namespace+"/"+target.Name)
		return
	}
	metrics.DragonflyMasterlessPodHealsTotal.
		WithLabelValues(sig.sts.Namespace, sig.sts.Name).Inc()
	p.drPodHealed[stsKey] = now
	log.Info("DELETE: dragonfly dual-replica deadlock — lowest-ordinal pod deleted to force master re-election",
		"pod", target.Namespace+"/"+target.Name,
		"statefulset", stsKey, "service", sig.ns+"/"+sig.svc)

	// Persist the stamp on the STS — the durable half of the
	// cooldown. A patch failure leaves the in-RAM half holding.
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{
			dragonflyPodHealAnno: now.UTC().Format(time.RFC3339),
		}},
	})
	if err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "marshal dragonfly pod heal stamp", "statefulset", stsKey)
		return
	}
	if _, err := p.CS.AppsV1().StatefulSets(sig.sts.Namespace).Patch(ctx,
		sig.sts.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "persist dragonfly pod heal stamp failed",
			"statefulset", stsKey)
	}
}
