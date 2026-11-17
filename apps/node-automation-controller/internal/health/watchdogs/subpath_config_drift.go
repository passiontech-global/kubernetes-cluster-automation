// subpath_config_drift.go — the subpath-config-drift check
// (P1.10): a pod that mounts a ConfigMap/Secret key via subPath
// gets a plain file bind — the kubelet does NOT propagate ConfigMap
// updates into it, and the container never reloads. The workload
// keeps running stale config until someone restarts it; the classic
// shape is a feature-flag or endpoint list that changed hours ago
// and the pods still serve the old value.
//
// Detection: every subPathScanInterval (30m — the heavy-scan
// cadence) the check hashes, per workload, the exact set of
// (configMap|secret, key) pairs its pod template mounts via
// subPath — SHA-256 over the sorted "ns/name/kind/key" tuples.
// The FIRST hash seen after boot seeds the baseline (in-RAM — a
// restart re-baselines, it does not mass-restart the fleet). A
// hash CHANGE must persist subPathDriftMinAge (15m — a config
// rollout in progress gets time to settle, and a flap back to the
// old value cancels the pending heal) before the check applies
// kube.RestartTemplatePatch to the workload — the pod-template
// annotation nudge that rolls fresh pods picking up the new keys.
//
// Exclusions: system namespaces (kube-system, kube-public,
// kube-node-lease, flux-system, node-ops), workloads whose pod
// template carries a stateful data-store quorum label (a restart
// there can breach quorum — same label set the PDB deadlock
// watchdog uses), and workloads stamped
// kube.AnnoSubPathReloadOptOut=="false". The heal itself rides the
// persisted cooldown kube.AnnoLastSubPathReload (1h, wider-of
// in-RAM+annotation) behind the maintenance mutex.
package watchdogs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// subpathConfigDriftCheck is the subPath staleness detector +
// restart-template healer.
type subpathConfigDriftCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger.
	emitted state.GaugeLedger[string]
	// eventHealed dedupes the cluster Event per window.
	eventHealed state.CooldownSet
	// reloadHeals is the in-RAM half of the persisted reload
	// cooldown (kube.AnnoLastSubPathReload is the durable half).
	reloadHeals state.CooldownSet
	// hashes is the per-workload subPath signature baseline —
	// seeded on first sight, in-RAM only per the plan ("seed
	// baseline ở lần thấy đầu tiên sau boot").
	hashes map[string]string
	// driftSince records when each workload's hash first diverged
	// from baseline — the 15m settle window.
	driftSince map[string]time.Time
	// lastScan throttles the census to the 30m heavy-scan cadence.
	lastScan time.Time
}

// NewSubPathConfigDriftCheck builds the check.
func NewSubPathConfigDriftCheck(d *probefw.Deps) probefw.Check {
	return &subpathConfigDriftCheck{
		Deps:       d,
		hashes:     map[string]string{},
		driftSince: map[string]time.Time{},
	}
}

const (
	CheckNameSubPathConfigDrift = "subpath-config-drift"

	// The heavy scan runs at most this often — the ConfigMap/Secret
	// + workload census is the expensive half.
	subPathScanInterval = 30 * time.Minute
	// A hash change must persist this long before the restart
	// nudge — covers a config rollout in flight and hash flapping.
	subPathDriftMinAge = 15 * time.Minute
	// One cluster Event per window.
	subPathEventCooldown = time.Hour
	// Persisted reload cooldown per workload.
	subPathReloadCooldown = time.Hour
	// subPathMaxReloadsPerScan caps restart nudges per heavy scan —
	// a cluster-wide config push can flag hundreds of workloads and
	// each nudge rolls a fleet; the remainder retries next scan.
	subPathMaxReloadsPerScan = 8
)

var (
	// subpath-config-drift — 1 per workload whose subPath-mounted
	// config drifted past the settle window.
	subPathConfigDriftGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_subpath_config_drift",
		Help: "1 while a workload's subPath-mounted ConfigMap/Secret keys drifted past the settle window — subpath-config-drift.",
	}, []string{"namespace", "name", "kind"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(subPathConfigDriftGauge)
}

// subPathSystemNamespaces never get the restart nudge — control-
// plane and GitOps-owned workloads restart on their own cadence.
var subPathSystemNamespaces = map[string]bool{
	"kube-system":      true,
	"kube-public":      true,
	"kube-node-lease":  true,
	"flux-system":      true,
	"node-ops":         true,
	"cert-manager":     true,
	"linkerd":          true,
	"linkerd-cni":      true,
	"external-secrets": true,
}

// subPathDBQuorumLabels bind a pod template to a stateful data
// store's cluster membership — restarting one can breach quorum
// (same label set the PDB deadlock watchdog excludes).
var subPathDBQuorumLabels = []string{
	"cnpg.io/cluster",
	"postgres-operator.crunchydata.com/cluster",
	"pgv2.percona.com/cluster",
	"everest.percona.com/cluster",
	"scylla.scylladb.com/cluster",
	"apps.rabbitmq.com/cluster",
}

// subPathWorkload is one census row the drift scan evaluates.
type subPathWorkload struct {
	kind     string
	ns, name string
	podSpec  *corev1.PodSpec
	template map[string]string
	annos    map[string]string
	obj      metav1.Object
}

// subPathDrifted reports whether the check should even consider
// this workload: not a system namespace, no quorum label on the
// pod template, and not opted out via
// kube.AnnoSubPathReloadOptOut=="false" (the plan's literal
// exclusion value).
func subPathDrifted(ns string, templateLabels, annos map[string]string) bool {
	if subPathSystemNamespaces[ns] {
		return false
	}
	for _, k := range subPathDBQuorumLabels {
		if templateLabels[k] != "" {
			return false
		}
	}
	return !strings.EqualFold(annos[kube.AnnoSubPathReloadOptOut], "false")
}

// allMounts flattens init+regular container mounts — an init
// container's subPath drift wedges the pod just the same.
func allMounts(podSpec *corev1.PodSpec) []corev1.VolumeMount {
	var out []corev1.VolumeMount
	for _, c := range podSpec.InitContainers {
		out = append(out, c.VolumeMounts...)
	}
	for _, c := range podSpec.Containers {
		out = append(out, c.VolumeMounts...)
	}
	return out
}

// Run executes one sweep: throttled to the 30m heavy-scan cadence,
// it recomputes every workload's subPath signature, tracks drift
// windows, and nudges confirmed-stale workloads.
func (p *subpathConfigDriftCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	var rep probefw.SweepReport

	if now.Sub(p.lastScan) < subPathScanInterval && !p.lastScan.IsZero() {
		// Throttled cycle — carry the held drift tuples forward or
		// rep.Result reconciles them OFF the gauge for 30 of every
		// 31 minutes (the gauge would flap to zero between scans).
		for k, lv := range p.emitted.Last() {
			rep.Carry(k, lv)
		}
		return rep.Result(&p.emitted, subPathConfigDriftGauge.DeleteLabelValues,
			"subpath config drift: ", ", ")
	}
	p.lastScan = now

	// Phase 1 — workload census: the typed lists carry the pod
	// template the signature is computed from.
	var workloads []subPathWorkload

	deps, err := p.AllDeployments(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list deployments: %w", err)}
	}
	for i := range deps {
		d := &deps[i]
		workloads = append(workloads, subPathWorkload{
			kind: "Deployment", ns: d.Namespace, name: d.Name,
			podSpec:  &d.Spec.Template.Spec,
			template: d.Spec.Template.Labels,
			annos:    d.Annotations,
			obj:      d,
		})
	}
	sts, err := p.AllStatefulSets(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list statefulsets: %w", err)}
	}
	for i := range sts {
		s := &sts[i]
		workloads = append(workloads, subPathWorkload{
			kind: "StatefulSet", ns: s.Namespace, name: s.Name,
			podSpec:  &s.Spec.Template.Spec,
			template: s.Spec.Template.Labels,
			annos:    s.Annotations,
			obj:      s,
		})
	}
	dss, err := p.AllDaemonSets(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list daemonsets: %w", err)}
	}
	for i := range dss {
		d := &dss[i]
		workloads = append(workloads, subPathWorkload{
			kind: "DaemonSet", ns: d.Namespace, name: d.Name,
			podSpec:  &d.Spec.Template.Spec,
			template: d.Spec.Template.Labels,
			annos:    d.Annotations,
			obj:      d,
		})
	}

	// ConfigMap/Secret content index — the hash input. One paged
	// LIST per kind per scan; only namespaces the workloads live
	// in matter, but the census is cluster-wide anyway (the sweep
	// already pays cluster LISTs).
	cmData := map[string]map[string]string{} // "ns/name" → key→data
	secretData := map[string]map[string][]byte{}
	cms, err := kube.ListAll(ctx, metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.ConfigMaps(p.CS, metav1.NamespaceAll))
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list configmaps: %w", err)}
	}
	for i := range cms {
		cm := &cms[i]
		// BinaryData holds the same key→content contract as Data
		// for non-UTF8 payloads — the API keeps the two maps
		// disjoint per key, so folding bytes into the string view
		// (string(b) preserves the bytes for hashing) covers both
		// without a second lookup path.
		merged := make(map[string]string, len(cm.Data)+len(cm.BinaryData))
		for k, v := range cm.Data {
			merged[k] = v
		}
		for k, v := range cm.BinaryData {
			merged[k] = string(v)
		}
		cmData[cm.Namespace+"/"+cm.Name] = merged
	}
	secs, err := kube.ListAll(ctx, metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Secrets(p.CS, metav1.NamespaceAll))
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list secrets: %w", err)}
	}
	for i := range secs {
		s := &secs[i]
		// Secret.Data is map[string][]byte — binary content (the
		// old binaryData field folded into data in this API
		// version) is already covered; StringData is write-only
		// and never returned by the API.
		secretData[s.Namespace+"/"+s.Name] = s.Data
	}

	seenKeys := map[string]bool{}
	reloads := 0
	var pods []corev1.Pod
	podsLoaded := false
	for _, w := range workloads {
		key := w.kind + "/" + w.ns + "/" + w.name
		if !subPathDrifted(w.ns, w.template, w.annos) {
			continue
		}
		sig := p.subPathContentHash(w.podSpec, w.ns, cmData, secretData)
		if sig == "" {
			continue // no subPath mounts — out of scope
		}
		seenKeys[key] = true
		base, seen := p.hashes[key]
		if !seen {
			p.hashes[key] = sig // baseline seed — never heals first sight
			continue
		}
		if sig == base {
			delete(p.driftSince, key)
			continue
		}
		// Hash diverged — the settle window must hold.
		if _, ok := p.driftSince[key]; !ok {
			p.driftSince[key] = now
		}
		if now.Sub(p.driftSince[key]) < subPathDriftMinAge {
			continue
		}
		rep.Flag(subPathConfigDriftGauge, key,
			[]string{w.ns, w.name, w.kind})
		rep.Find(key)
		// The per-sweep cap bounds PATCH attempts only — a workload
		// whose pods already restarted post-drift resolves for free,
		// and cooldown/Flux-gated ones never spend a slot, so later
		// workloads that DO need the nudge are not starved by cheap
		// resolutions ahead of them. Past the cap the drift stays
		// armed (driftSince untouched) for the next scan.
		mayPatch := reloads < subPathMaxReloadsPerScan
		if !podsLoaded {
			// Pod census loads lazily — only a confirmed drift
			// pays for it, and only once per scan.
			pods, err = p.AllPods(ctx)
			if err != nil {
				return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
			}
			podsLoaded = true
		}
		resolved, spent := p.reloadWorkload(ctx, log, w, pods,
			p.driftSince[key], now, mayPatch)
		if spent {
			reloads++
		}
		if resolved {
			// Re-baseline ONLY when the nudge actually landed or
			// every pod already carries the new content — stamping
			// the new hash after a deferred/failed heal swallowed
			// the drift forever (the next scan saw sig == base and
			// never retried).
			p.hashes[key] = sig
			delete(p.driftSince, key)
		}
	}
	// Prune tracking for workloads that vanished or dropped their
	// subPath mounts.
	for k := range p.hashes {
		if !seenKeys[k] {
			delete(p.hashes, k)
			delete(p.driftSince, k)
		}
	}
	p.emitDriftEvent(ctx, log, rep.Findings(), now)
	return rep.Result(&p.emitted, subPathConfigDriftGauge.DeleteLabelValues,
		"subpath config drift: ", ", ")
}

// subPathContentHash hashes the CONTENT of every ConfigMap/Secret
// key the pod template mounts via subPath — the drift signature
// the plan prescribes ("băm SHA-256 trên đúng key subPath"). A key
// missing from the source object contributes its name only (a
// deleted key is itself drift).
func (p *subpathConfigDriftCheck) subPathContentHash(podSpec *corev1.PodSpec,
	ns string, cmData map[string]map[string]string,
	secretData map[string]map[string][]byte) string {

	// volume name → (kind, objName, path→key)
	type src struct {
		kind string
		name string
		keys map[string]string
	}
	byName := map[string]src{}
	for _, v := range podSpec.Volumes {
		s := src{keys: map[string]string{}}
		switch {
		case v.ConfigMap != nil:
			s.kind, s.name = "configmap", v.ConfigMap.Name
			for _, it := range v.ConfigMap.Items {
				s.keys[it.Path] = it.Key
			}
		case v.Secret != nil:
			s.kind, s.name = "secret", v.Secret.SecretName
			for _, it := range v.Secret.Items {
				s.keys[it.Path] = it.Key
			}
		default:
			continue
		}
		byName[v.Name] = s
	}
	var tuples []string
	for _, m := range allMounts(podSpec) {
		if m.SubPath == "" {
			continue
		}
		s, ok := byName[m.Name]
		if !ok {
			continue
		}
		key := m.SubPath
		if k, found := s.keys[m.SubPath]; found {
			key = k
		}
		objKey := ns + "/" + s.name
		content := "<absent>"
		if s.kind == "configmap" {
			if data, ok := cmData[objKey]; ok {
				if v, ok := data[key]; ok {
					content = v
				}
			}
		} else {
			if data, ok := secretData[objKey]; ok {
				if v, ok := data[key]; ok {
					content = string(v)
				}
			}
		}
		tuples = append(tuples, s.kind+"/"+objKey+"/"+key+"="+
			fmt.Sprintf("%x", sha256.Sum256([]byte(content))))
	}
	if len(tuples) == 0 {
		return ""
	}
	sort.Strings(tuples)
	sum := sha256.Sum256([]byte(strings.Join(tuples, "\n")))
	return hex.EncodeToString(sum[:])
}

// subPathFreshPods reports whether every running pod of the
// workload started AFTER driftStart — pods mount subPath content
// at container start, so a pod born post-drift already carries the
// new keys and the restart nudge would be a no-op roll. Returns
// (fresh, total): fresh only counts when total > 0.
func subPathFreshPods(w subPathWorkload, pods []corev1.Pod,
	driftStart time.Time) (bool, int) {

	sel := labels.SelectorFromSet(w.template)
	total, fresh := 0, 0
	for i := range pods {
		p := &pods[i]
		if p.Namespace != w.ns || p.DeletionTimestamp != nil ||
			p.Status.Phase == corev1.PodSucceeded ||
			p.Status.Phase == corev1.PodFailed {
			continue
		}
		if !sel.Matches(labels.Set(p.Labels)) {
			continue
		}
		total++
		if !p.Status.StartTime.IsZero() &&
			p.Status.StartTime.Time.After(driftStart) {
			fresh++
		}
	}
	return total > 0 && fresh == total, total
}

// subPathGateKind maps the census kind to the FluxPatchGate kind
// string — the gate's managedFields check is per-object anyway,
// the kind only labels the skip log.
func subPathGateKind(kind string) string {
	switch kind {
	case "Deployment":
		return "deployment"
	case "StatefulSet":
		return "statefulset"
	case "DaemonSet":
		return "daemonset"
	}
	return strings.ToLower(kind)
}

// reloadWorkload applies the restart-template nudge behind the
// GitOps conflict gate, the fresh-pod check, the persisted
// cooldown + maintenance gate. Returns (resolved, spent):
// resolved=true means the drift is settled — nudge landed OR every
// pod already restarted onto the new content — so the caller
// re-baselines; spent=true means a patch attempt consumed one of
// the per-sweep cap slots (API write attempted, success or not).
// mayPatch=false (cap reached) still allows the free fresh-pod
// resolution but skips every gate and the patch itself.
func (p *subpathConfigDriftCheck) reloadWorkload(ctx context.Context,
	log logr.Logger, w subPathWorkload, pods []corev1.Pod,
	driftStart, now time.Time, mayPatch bool) (bool, bool) {

	key := w.kind + "/" + w.ns + "/" + w.name
	if fresh, total := subPathFreshPods(w, pods, driftStart); fresh {
		log.Info("subpath drift self-resolved — all pods restarted post-drift",
			"workload", key, "pods", total)
		return true, false
	}
	if !mayPatch {
		return false, false // cap reached — drift stays armed
	}
	// Git-owned objects ping-pong a template nudge every reconcile
	// — the drift belongs in Git, not in a patch.
	if !heal.FluxPatchGate(subPathGateKind(w.kind), w.obj, key, now) {
		log.Info("SKIP: subpath drift nudge — Flux Heal-Revert Loop",
			"workload", key)
		return false, false
	}
	ck := probefw.SelfHealKey(CheckNameSubPathConfigDrift, key)
	proceed, unverifiable := p.HealAllowedPersisted(ctx, log,
		&p.reloadHeals, w.obj, kube.AnnoLastSubPathReload, ck,
		subPathReloadCooldown, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return false, false
	}
	if !proceed {
		return false, false
	}
	patch := kube.RestartTemplatePatch(now)
	var err error
	switch w.kind {
	case "Deployment":
		_, err = p.CS.AppsV1().Deployments(w.ns).Patch(ctx, w.name,
			types.StrategicMergePatchType, patch, metav1.PatchOptions{})
	case "StatefulSet":
		_, err = p.CS.AppsV1().StatefulSets(w.ns).Patch(ctx, w.name,
			types.StrategicMergePatchType, patch, metav1.PatchOptions{})
	case "DaemonSet":
		_, err = p.CS.AppsV1().DaemonSets(w.ns).Patch(ctx, w.name,
			types.StrategicMergePatchType, patch, metav1.PatchOptions{})
	}
	if err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "subpath drift restart-template patch failed",
			"workload", key)
		return false, true // write attempted — the cap bounds API calls, not successes
	}
	if err := heal.StampPersisted(ctx, w.obj,
		func(ctx context.Context, data []byte) error {
			return p.stampSubPathReload(ctx, w, data)
		}, kube.AnnoLastSubPathReload, &p.reloadHeals, ck, now); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "subpath drift reload stamp failed",
			"workload", key)
	}
	log.Info("ACTION: subpath config drift — restart template nudge",
		"workload", key)
	return true, true
}

// stampSubPathReload delivers the persisted-cooldown annotation
// merge patch against the right typed client for the workload kind.
func (p *subpathConfigDriftCheck) stampSubPathReload(ctx context.Context,
	w subPathWorkload, data []byte) error {

	var err error
	switch w.kind {
	case "Deployment":
		_, err = p.CS.AppsV1().Deployments(w.ns).Patch(ctx, w.name,
			types.MergePatchType, data, metav1.PatchOptions{})
	case "StatefulSet":
		_, err = p.CS.AppsV1().StatefulSets(w.ns).Patch(ctx, w.name,
			types.MergePatchType, data, metav1.PatchOptions{})
	case "DaemonSet":
		_, err = p.CS.AppsV1().DaemonSets(w.ns).Patch(ctx, w.name,
			types.MergePatchType, data, metav1.PatchOptions{})
	}
	return err
}

// emitDriftEvent fires ONE deduped Warning event per window naming
// the drifting workloads.
func (p *subpathConfigDriftCheck) emitDriftEvent(ctx context.Context,
	log logr.Logger, findings []string, now time.Time) {

	if len(findings) == 0 {
		return
	}
	ck := probefw.SelfHealKey(CheckNameSubPathConfigDrift, "event")
	if p.eventHealed.CooledDown(ck, subPathEventCooldown, now) {
		return
	}
	msg := fmt.Sprintf("subpath config drift: %d workload(s) (%s)",
		len(findings), findings[0])
	if err := kube.EmitWarningEvent(ctx, p.CS, kube.WarningEvent{
		Name:      "subpath-config-drift-" + now.Format("20060102-150405"),
		Namespace: "kube-system",
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Namespace",
			Name:       "kube-system",
		},
		Reason:            "SubPathConfigDrift",
		Note:              msg,
		ReportingInstance: p.Name,
		Now:               now,
	}); err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: subpath drift event create failed (RBAC?)",
			"error", err)
		return
	}
	p.eventHealed.Stamp(ck, now)
	log.Info("EVENT: SubPathConfigDrift", "detail", msg)
}
