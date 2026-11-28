// pdb_overlap.go — overlapping-PDB detection: identifies namespaces
// where 2+ PodDisruptionBudgets select the same non-terminal Pod,
// reusing the sweep's per-namespace pod cache when already listed.
// Split from pdb_deadlock_watchdog.go.
package pdbdeadlockwatchdog

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

func (w *pdbDeadlockWatchdog) detectOverlappingPDBs(ctx context.Context,
	log logr.Logger, now time.Time, pdbs []policyv1.PodDisruptionBudget,
	nsPods *nsPodsCache) {

	byNS := map[string][]*policyv1.PodDisruptionBudget{}
	for i := range pdbs {
		p := &pdbs[i]
		byNS[p.Namespace] = append(byNS[p.Namespace], p)
	}

	namespaces := make([]string, 0, len(byNS))
	for ns, list := range byNS {
		if len(list) >= 2 {
			namespaces = append(namespaces, ns)
		}
	}
	if len(namespaces) == 0 {
		return
	}
	slices.Sort(namespaces)

	type compiledPDB struct {
		pdb *policyv1.PodDisruptionBudget
		sel labels.Selector
	}
	type overlapGroup struct {
		ns         string
		pdbNames   []string
		firstPDB   *policyv1.PodDisruptionBudget
		podCount   int
		samplePods []string
	}

	groups := map[string]*overlapGroup{}

	for _, ns := range namespaces {
		nsPDBs := byNS[ns]
		compiled := make([]compiledPDB, 0, len(nsPDBs))
		for _, p := range nsPDBs {
			if p.Spec.Selector == nil {
				continue
			}
			sel, err := metav1.LabelSelectorAsSelector(p.Spec.Selector)
			if err != nil {
				log.Error(err, "PDB selector unparseable during overlap check",
					"pdb", p.Namespace+"/"+p.Name)
				continue
			}
			compiled = append(compiled, compiledPDB{pdb: p, sel: sel})
		}
		if len(compiled) < 2 {
			continue
		}
		slices.SortFunc(compiled, func(a, b compiledPDB) int {
			return cmp.Compare(a.pdb.Name, b.pdb.Name)
		})

		pods, err := nsPods.get(ctx, ns)
		if err != nil {
			log.Error(err, "overlap PDB check pod list failed", "namespace", ns)
			for k, lv := range w.overlapEmitted.Last() {
				if k.ns == ns {
					w.overlapEmitted.Emit(k, lv...)
				}
			}
			continue
		}

		for i := range pods {
			pod := &pods[i]
			if pod.DeletionTimestamp != nil ||
				pod.Status.Phase == corev1.PodSucceeded ||
				pod.Status.Phase == corev1.PodFailed {
				continue
			}
			var matching []*policyv1.PodDisruptionBudget
			podLabels := labels.Set(pod.Labels)
			for _, cp := range compiled {
				if cp.sel.Matches(podLabels) {
					matching = append(matching, cp.pdb)
				}
			}
			if len(matching) < 2 {
				continue
			}
			names := make([]string, len(matching))
			for j, m := range matching {
				names[j] = m.Name
			}
			groupKey := ns + "/" + strings.Join(names, ",")
			g, ok := groups[groupKey]
			if !ok {
				g = &overlapGroup{
					ns:       ns,
					pdbNames: names,
					firstPDB: matching[0],
				}
				groups[groupKey] = g
			}
			g.podCount++
			g.samplePods = append(g.samplePods, pod.Name)
		}
	}

	groupKeys := make([]string, 0, len(groups))
	for k := range groups {
		groupKeys = append(groupKeys, k)
	}
	slices.Sort(groupKeys)

	for _, groupKey := range groupKeys {
		g := groups[groupKey]
		slices.Sort(g.samplePods)
		if len(g.samplePods) > pdbOverlapMaxSamplePods {
			g.samplePods = g.samplePods[:pdbOverlapMaxSamplePods]
		}
		pdbsJoined := strings.Join(g.pdbNames, ",")
		w.overlapEmitted.Set(pdbOverlappingGauge, 1,
			pdbOverlapKey{ns: g.ns, pdbs: pdbsJoined},
			g.ns, pdbsJoined)

		log.Info("WARN: overlapping PDBs match same non-terminal pod(s)",
			"namespace", g.ns,
			"pdbs", g.pdbNames,
			"affectedPods", g.podCount,
			"samplePods", g.samplePods)

		if w.overlapEventCooldown.CooledDown(groupKey, pdbOverlapEventCooldown, now) {
			continue
		}
		evKey := "overlappdb." + g.ns + "." + pdbsJoined
		note := fmt.Sprintf(
			"Overlapping PodDisruptionBudgets [%s] in namespace %s match %d non-terminal pod(s) (sample: %s) — Kubernetes Eviction API returns HTTP 500 during drain",
			strings.Join(g.pdbNames, ", "), g.ns, g.podCount, strings.Join(g.samplePods, ", "))
		if err := kube.EmitWarningEvent(ctx, w.cs, kube.WarningEvent{
			Name:      kube.TruncatedEventName("overlapping-pdb."+g.ns+"."+g.firstPDB.Name, evKey, now),
			Namespace: g.ns,
			Regarding: corev1.ObjectReference{
				APIVersion: "policy/v1",
				Kind:       "PodDisruptionBudget",
				Namespace:  g.ns,
				Name:       g.firstPDB.Name,
				UID:        g.firstPDB.UID,
			},
			Reason:            pdbOverlapEventReason,
			Note:              note,
			ReportingInstance: cmp.Or(w.queue, "pdb-deadlock-watchdog"),
			Now:               now,
		}); err != nil {
			log.Info("WARN: OverlappingPDBDetected event create failed (RBAC?)",
				"namespace", g.ns, "pdbs", g.pdbNames, "error", err)
		} else {
			w.overlapEventCooldown.Stamp(groupKey, now)
			log.Info("EVENT: OverlappingPDBDetected",
				"namespace", g.ns, "pdbs", g.pdbNames, "affectedPods", g.podCount)
		}
	}
}
