// crd_stored_versions_guard.go — health check "crd-stored-versions-guard":
// detects CustomResourceDefinitions carrying multi-version storage debt
// (len(status.storedVersions) > 1) or unserved storedVersions entries
// (critical Kubernetes upgrade blocker) and emits Prometheus metrics +
// cooldown-deduped Warning Events.
//
// When opt-in migration is enabled (NODE_AUTOMATION_CRD_STORED_VERSIONS_MIGRATE_ENABLED=true
// or CRD annotation passiontech.dev/crd-auto-migrate: "true", unless explicitly
// opted out with "false"), safely migrates up to 1 CRD and 50 CR instances per
// sweep across a 30m per-CRD cooldown, respecting heal.AllowedV, maintenance
// holds, fleet Budget + RefundGrant, TargetBreaker, and FluxPatchGate. Only when
// ALL CR instances of that CRD are visited and migrated with zero errors and no
// cap truncation does the migrator patch CRD /status to [storageVer].
package watchdogs

import (
	"cmp"
	"context"
	json "encoding/json/v2"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// CheckNameCRDStoredVersionsGuard is the registry check name for CRD storedVersions drift & migration.
	CheckNameCRDStoredVersionsGuard = "crd-stored-versions-guard"

	crdStoredVerEventReason         = "CRDStoredVersionsDrift"
	crdStoredVerAnnoAutoMigrate     = "passiontech.dev/crd-auto-migrate"
	crdStoredVerAnnoMigratedVersion = "passiontech.dev/storage-migrated-version"
	crdStoredVerMigrateCooldown     = 30 * time.Minute
	crdStoredVerEventCooldown       = 6 * time.Hour
	crdStoredVerMaxCRDsPerSweep     = 1
	crdStoredVerMaxCRsPerSweep      = 50
	crdStoredVerReasonMulti         = "multi_stored_versions"
	crdStoredVerReasonUnserved      = "unserved_stored_version"
)

var crdStoredVerDriftGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_crd_stored_versions_drift",
	Help: "1 while a CustomResourceDefinition has >1 status.storedVersions or an unserved storedVersion.",
}, []string{"crd", "reason"})

func init() {
	ctrlmetrics.Registry.MustRegister(crdStoredVerDriftGauge)
}

type crdStoredVerCheck struct {
	*probefw.Deps

	migrateEnabled bool

	emitted         state.GaugeLedger[string]
	eventCooldown   state.CooldownSet
	migrateCooldown state.CooldownSet
}

// NewCRDStoredVersionsGuardCheck constructs the crd-stored-versions-guard check.
func NewCRDStoredVersionsGuardCheck(d *probefw.Deps) probefw.Check {
	return &crdStoredVerCheck{
		Deps:           d,
		migrateEnabled: envx.Gate("NODE_AUTOMATION_CRD_STORED_VERSIONS_MIGRATE_ENABLED", false),
	}
}

type crdStoredVerFinding struct {
	crd        *unstructured.Unstructured
	name       string
	group      string
	plural     string
	kind       string
	storageVer string
	canMigrate bool
	reasons    []string
	stored     []string
}

func (c *crdStoredVerCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, crdStoredVerEventCooldown)
	c.migrateCooldown.PruneExpired(now, crdStoredVerMigrateCooldown)

	var rep probefw.SweepReport
	if c.Dyn == nil {
		return probefw.Result{Infra: fmt.Errorf("no dynamic client — %s unverifiable", CheckNameCRDStoredVersionsGuard)}
	}

	crds, err := c.AllUnstructured(ctx, kube.GVRCustomResourceDefinition)
	if err != nil {
		if apierrors.IsForbidden(err) || kube.IsCRDAbsent(err) {
			log.V(1).Info("CustomResourceDefinition list skipped", "error", err)
			return rep.Result(&c.emitted, crdStoredVerDriftGauge.DeleteLabelValues,
				"crd storedVersions drift: ", ", ")
		}
		for k, lv := range c.emitted.Last() {
			rep.Carry(k, lv)
		}
		rep.Close(&c.emitted, crdStoredVerDriftGauge.DeleteLabelValues)
		return probefw.Result{Infra: fmt.Errorf("list crds: %w", err)}
	}

	var candidates []crdStoredVerFinding
	for i := range crds {
		crd := &crds[i]
		if crd.GetDeletionTimestamp() != nil {
			continue
		}
		finding, drifted := crdStoredVerInspect(crd)
		if !drifted {
			continue
		}
		for _, reason := range finding.reasons {
			tupleKey := finding.name + "/" + reason
			rep.Flag(crdStoredVerDriftGauge, tupleKey, []string{finding.name, reason})
		}
		rep.Find(fmt.Sprintf("%s(%s; stored=%s)",
			finding.name, strings.Join(finding.reasons, "+"), strings.Join(finding.stored, ",")))

		c.crdStoredVerEmitEvent(ctx, log, now, crd, finding)

		if finding.canMigrate && c.crdStoredVerShouldMigrate(crd) {
			candidates = append(candidates, finding)
		}
	}

	if len(candidates) > 0 {
		slices.SortFunc(candidates, func(a, b crdStoredVerFinding) int {
			return cmp.Compare(a.name, b.name)
		})
		c.crdStoredVerRunMigration(ctx, log, now, candidates)
	}

	return rep.Result(&c.emitted, crdStoredVerDriftGauge.DeleteLabelValues,
		"crd storedVersions drift: ", ", ")
}

func crdStoredVerInspect(crd *unstructured.Unstructured) (crdStoredVerFinding, bool) {
	stored, _ := kube.NestedStringSlice(crd.Object, "status", "storedVersions")
	if len(stored) == 0 {
		return crdStoredVerFinding{}, false
	}

	served := map[string]bool{}
	var storageServed []string
	var storageTotal int

	versions, _ := kube.NestedSlice(crd.Object, "spec", "versions")
	for _, rawVer := range versions {
		vm, ok := rawVer.(map[string]any)
		if !ok {
			continue
		}
		vName, _ := kube.NestedString(vm, "name")
		if vName == "" {
			continue
		}
		isServed, _ := kube.NestedBool(vm, "served")
		isStorage, _ := kube.NestedBool(vm, "storage")
		if isServed {
			served[vName] = true
		}
		if isStorage {
			storageTotal++
			if isServed {
				storageServed = append(storageServed, vName)
			}
		}
	}

	var reasons []string
	if len(stored) > 1 {
		reasons = append(reasons, crdStoredVerReasonMulti)
	}
	for _, sv := range stored {
		if !served[sv] {
			reasons = append(reasons, crdStoredVerReasonUnserved)
			break
		}
	}
	if len(reasons) == 0 {
		return crdStoredVerFinding{}, false
	}

	group, _ := kube.NestedString(crd.Object, "spec", "group")
	plural, _ := kube.NestedString(crd.Object, "spec", "names", "plural")
	kind, _ := kube.NestedString(crd.Object, "spec", "names", "kind")
	if kind == "" {
		kind = plural
	}

	var storageVer string
	canMigrate := false
	if storageTotal == 1 && len(storageServed) == 1 && group != "" && plural != "" {
		storageVer = storageServed[0]
		canMigrate = true
	}

	return crdStoredVerFinding{
		crd:        crd,
		name:       crd.GetName(),
		group:      group,
		plural:     plural,
		kind:       kind,
		storageVer: storageVer,
		canMigrate: canMigrate,
		reasons:    reasons,
		stored:     stored,
	}, true
}

func (c *crdStoredVerCheck) crdStoredVerShouldMigrate(crd *unstructured.Unstructured) bool {
	annos := crd.GetAnnotations()
	if val, ok := annos[crdStoredVerAnnoAutoMigrate]; ok {
		switch val {
		case "false":
			return false
		case "true":
			return true
		}
	}
	return c.migrateEnabled
}

func (c *crdStoredVerCheck) crdStoredVerRunMigration(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	candidates []crdStoredVerFinding,
) {
	migratedCRDs := 0
	for _, cand := range candidates {
		if migratedCRDs >= crdStoredVerMaxCRDsPerSweep {
			log.V(1).Info("SKIP rest: CRD storage-version migration per-sweep CRD cap reached",
				"cap", crdStoredVerMaxCRDsPerSweep)
			break
		}
		if c.migrateCooldown.CooledDown(cand.name, crdStoredVerMigrateCooldown, now) {
			continue
		}

		proceed, unverifiable := c.HealAllowed(ctx, log, &c.migrateCooldown,
			cand.name, crdStoredVerMigrateCooldown, now)
		if unverifiable {
			metrics.IncError(c.Name)
			break
		}
		if !proceed {
			continue
		}

		if allowed, reason := heal.TryAcquireTarget(CheckNameCRDStoredVersionsGuard, cand.name, now); !allowed {
			heal.RefundGrant(now)
			log.Info("DEFER: CRD migration target circuit open",
				"crd", cand.name, "reason", reason)
			continue
		}

		crGVR := schema.GroupVersionResource{
			Group:    cand.group,
			Version:  cand.storageVer,
			Resource: cand.plural,
		}
		list, err := kube.ListAllUnstructured(ctx, c.Dyn.Resource(crGVR), metav1.ListOptions{
			Limit:           kube.DefaultListPageSize,
			ResourceVersion: "0",
		})
		if err != nil {
			heal.RefundTarget(CheckNameCRDStoredVersionsGuard, cand.name, now)
			heal.RefundGrant(now)
			if apierrors.IsForbidden(err) || kube.IsCRDAbsent(err) {
				log.V(1).Info("CRD storage migration CR list skipped",
					"crd", cand.name, "gvr", crGVR.String(), "error", err)
				continue
			}
			metrics.IncError(c.Name)
			log.Error(err, "CRD storage migration CR list failed",
				"crd", cand.name, "gvr", crGVR.String())
			continue
		}

		items := list.Items
		slices.SortFunc(items, func(a, b unstructured.Unstructured) int {
			if c := cmp.Compare(a.GetNamespace(), b.GetNamespace()); c != 0 {
				return c
			}
			return cmp.Compare(a.GetName(), b.GetName())
		})

		explicitOptIn := cand.crd.GetAnnotations()[crdStoredVerAnnoAutoMigrate] == "true"
		patchPayload, err := json.Marshal(map[string]any{
			"metadata": map[string]any{
				"annotations": map[string]any{
					crdStoredVerAnnoMigratedVersion: cand.storageVer,
				},
			},
		})
		if err != nil {
			heal.RefundTarget(CheckNameCRDStoredVersionsGuard, cand.name, now)
			heal.RefundGrant(now)
			metrics.IncError(c.Name)
			continue
		}

		patchedCount := 0
		allMigrated := true
		forbidden := false
		for i := range items {
			cr := &items[i]
			if cr.GetDeletionTimestamp() != nil {
				continue
			}
			if cr.GetAnnotations()[crdStoredVerAnnoMigratedVersion] == cand.storageVer {
				continue
			}
			if patchedCount >= crdStoredVerMaxCRsPerSweep {
				allMigrated = false
				log.Info("CRD storage migration capped — deferring /status update until next sweep",
					"crd", cand.name, "cap", crdStoredVerMaxCRsPerSweep)
				break
			}

			crKey := cand.name + "/" + cr.GetName()
			if cr.GetNamespace() != "" {
				crKey = cand.name + "/" + cr.GetNamespace() + "/" + cr.GetName()
			}
			if !explicitOptIn && !heal.FluxPatchGate(strings.ToLower(cand.kind), cr, crKey, now) {
				allMigrated = false
				log.Info("DEFER: FluxPatchGate blocked CR storage migration annotation patch",
					"crd", cand.name, "cr", crKey)
				continue
			}

			var ri interface {
				Patch(context.Context, string, types.PatchType, []byte, metav1.PatchOptions, ...string) (*unstructured.Unstructured, error)
			}
			if cr.GetNamespace() != "" {
				ri = c.Dyn.Resource(crGVR).Namespace(cr.GetNamespace())
			} else {
				ri = c.Dyn.Resource(crGVR)
			}
			if _, perr := ri.Patch(ctx, cr.GetName(), types.MergePatchType, patchPayload, metav1.PatchOptions{}); perr != nil {
				allMigrated = false
				if apierrors.IsForbidden(perr) {
					forbidden = true
					log.V(1).Info("CRD storage migration CR patch skipped (403)",
						"crd", cand.name, "cr", crKey, "error", perr)
					break
				}
				metrics.IncError(c.Name)
				log.Error(perr, "CRD storage migration CR patch failed",
					"crd", cand.name, "cr", crKey)
				break
			}
			patchedCount++
		}

		if !allMigrated {
			if patchedCount == 0 {
				heal.RefundTarget(CheckNameCRDStoredVersionsGuard, cand.name, now)
				if forbidden {
					heal.RefundGrant(now)
				} else if !forbidden {
					// If skipped solely due to FluxPatchGate (no error attempted), refund grant.
					heal.RefundGrant(now)
				}
			} else {
				c.migrateCooldown.Stamp(cand.name, now)
				migratedCRDs++
			}
			continue
		}

		statusPayload, err := json.Marshal(map[string]any{
			"status": map[string]any{
				"storedVersions": []string{cand.storageVer},
			},
		})
		if err != nil {
			metrics.IncError(c.Name)
			continue
		}
		if _, serr := c.Dyn.Resource(kube.GVRCustomResourceDefinition).Patch(
			ctx, cand.name, types.MergePatchType, statusPayload, metav1.PatchOptions{}, "status",
		); serr != nil {
			if apierrors.IsForbidden(serr) {
				log.V(1).Info("CRD /status storedVersions patch skipped (403)",
					"crd", cand.name, "error", serr)
				if patchedCount == 0 {
					heal.RefundTarget(CheckNameCRDStoredVersionsGuard, cand.name, now)
					heal.RefundGrant(now)
				} else {
					c.migrateCooldown.Stamp(cand.name, now)
					migratedCRDs++
				}
				continue
			}
			metrics.IncError(c.Name)
			log.Error(serr, "CRD /status storedVersions patch failed", "crd", cand.name)
			c.migrateCooldown.Stamp(cand.name, now)
			migratedCRDs++
			continue
		}

		c.InvalidateUnstructuredGVR(ctx, kube.GVRCustomResourceDefinition)
		c.migrateCooldown.Stamp(cand.name, now)
		heal.RecordTargetHealthy(CheckNameCRDStoredVersionsGuard, cand.name)
		migratedCRDs++
		log.Info("MIGRATE: CRD storedVersions converged to active storage version",
			"crd", cand.name, "storageVersion", cand.storageVer, "migratedCRs", patchedCount)
	}
}

func (c *crdStoredVerCheck) crdStoredVerEmitEvent(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	crd *unstructured.Unstructured,
	finding crdStoredVerFinding,
) {
	cooldownKey := "crd.storedversions." + finding.name
	if c.eventCooldown.CooledDown(cooldownKey, crdStoredVerEventCooldown, now) {
		return
	}
	note := fmt.Sprintf("CRD %s has status.storedVersions=%v (%s); migrate CRs and prune unserved/stale storedVersions before Kubernetes upgrade",
		finding.name, finding.stored, strings.Join(finding.reasons, ", "))
	if err := kube.EmitWarningEvent(ctx, c.CS, kube.WarningEvent{
		Name:      kube.TruncatedEventName(cooldownKey, cooldownKey, now),
		Namespace: "default",
		Regarding: corev1.ObjectReference{
			APIVersion: "apiextensions.k8s.io/v1",
			Kind:       "CustomResourceDefinition",
			Name:       crd.GetName(),
			UID:        crd.GetUID(),
		},
		Reason:            crdStoredVerEventReason,
		Note:              note,
		ReportingInstance: c.Name,
		Now:               now,
	}); err != nil {
		log.Info("WARN: CRDStoredVersionsDrift event create failed (RBAC?)",
			"crd", finding.name, "error", err)
		return
	}
	c.eventCooldown.Stamp(cooldownKey, now)
	log.Info("EVENT: CRDStoredVersionsDrift", "crd", finding.name, "reasons", finding.reasons)
}
