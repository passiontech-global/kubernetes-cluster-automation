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
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
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
	crdStoredVerPageSize            = 25
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

type crdStoredVerSpecVersion struct {
	name    string
	served  bool
	storage bool
}

type crdStoredVerSummary struct {
	meta           metav1.PartialObjectMetadata
	group          string
	plural         string
	kind           string
	versions       []crdStoredVerSpecVersion
	storedVersions []string
}

type crdStoredVerFinding struct {
	meta       metav1.PartialObjectMetadata
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

	crds, err := c.collectCRDStoredVerSummaries(ctx, log)
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
		summary := &crds[i]
		finding, drifted := crdStoredVerInspect(summary)
		if !drifted {
			continue
		}
		for _, reason := range finding.reasons {
			tupleKey := finding.name + "/" + reason
			rep.Flag(crdStoredVerDriftGauge, tupleKey, []string{finding.name, reason})
		}
		rep.Find(fmt.Sprintf("%s(%s; stored=%s)",
			finding.name, strings.Join(finding.reasons, "+"), strings.Join(finding.stored, ",")))

		c.crdStoredVerEmitEvent(ctx, log, now, &summary.meta, finding)

		if finding.canMigrate && c.crdStoredVerShouldMigrate(ctx, &summary.meta) {
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

func (c *crdStoredVerCheck) collectCRDStoredVerSummaries(
	ctx context.Context,
	log logr.Logger,
) ([]crdStoredVerSummary, error) {
	if c.NodeReader != nil && kube.CRDInformerEnabled() {
		var list apiextensionsv1.CustomResourceDefinitionList
		if err := c.NodeReader.List(ctx, &list); err == nil {
			out := make([]crdStoredVerSummary, 0, len(list.Items))
			for i := range list.Items {
				crd := &list.Items[i]
				if crd.DeletionTimestamp != nil {
					continue
				}
				versions := make([]crdStoredVerSpecVersion, 0, len(crd.Spec.Versions))
				for _, v := range crd.Spec.Versions {
					versions = append(versions, crdStoredVerSpecVersion{
						name:    v.Name,
						served:  v.Served,
						storage: v.Storage,
					})
				}
				out = append(out, crdStoredVerSummary{
					meta: metav1.PartialObjectMetadata{
						TypeMeta: metav1.TypeMeta{
							APIVersion: "apiextensions.k8s.io/v1",
							Kind:       "CustomResourceDefinition",
						},
						ObjectMeta: crd.ObjectMeta,
					},
					group:          crd.Spec.Group,
					plural:         crd.Spec.Names.Plural,
					kind:           crd.Spec.Names.Kind,
					versions:       versions,
					storedVersions: slices.Clone(crd.Status.StoredVersions),
				})
			}
			return out, nil
		} else {
			log.V(1).Info("CRD informer cache read failed — falling back to paged dynamic list", "error", err)
		}
	}

	var out []crdStoredVerSummary
	err := kube.ListEach(ctx,
		metav1.ListOptions{
			Limit:           crdStoredVerPageSize,
			ResourceVersion: "0",
		},
		kube.DynamicPage(c.Dyn.Resource(kube.GVRCustomResourceDefinition)),
		func(page []unstructured.Unstructured) error {
			for i := range page {
				crd := &page[i]
				if crd.GetDeletionTimestamp() != nil {
					continue
				}
				stored, _ := kube.NestedStringSlice(crd.Object, "status", "storedVersions")
				if len(stored) == 0 {
					continue
				}
				rawVersions, _ := kube.NestedSlice(crd.Object, "spec", "versions")
				versions := make([]crdStoredVerSpecVersion, 0, len(rawVersions))
				for _, rawVer := range rawVersions {
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
					versions = append(versions, crdStoredVerSpecVersion{
						name:    vName,
						served:  isServed,
						storage: isStorage,
					})
				}
				group, _ := kube.NestedString(crd.Object, "spec", "group")
				plural, _ := kube.NestedString(crd.Object, "spec", "names", "plural")
				kind, _ := kube.NestedString(crd.Object, "spec", "names", "kind")
				out = append(out, crdStoredVerSummary{
					meta: metav1.PartialObjectMetadata{
						TypeMeta: metav1.TypeMeta{
							APIVersion: "apiextensions.k8s.io/v1",
							Kind:       "CustomResourceDefinition",
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:              crd.GetName(),
							UID:               crd.GetUID(),
							Annotations:       crd.GetAnnotations(),
							DeletionTimestamp: crd.GetDeletionTimestamp(),
						},
					},
					group:          group,
					plural:         plural,
					kind:           kind,
					versions:       versions,
					storedVersions: stored,
				})
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func crdStoredVerInspect(crd *crdStoredVerSummary) (crdStoredVerFinding, bool) {
	stored := crd.storedVersions
	if len(stored) == 0 {
		return crdStoredVerFinding{}, false
	}

	served := map[string]bool{}
	var storageServed []string
	var storageTotal int

	for _, v := range crd.versions {
		if v.name == "" {
			continue
		}
		if v.served {
			served[v.name] = true
		}
		if v.storage {
			storageTotal++
			if v.served {
				storageServed = append(storageServed, v.name)
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

	kind := crd.kind
	if kind == "" {
		kind = crd.plural
	}

	var storageVer string
	canMigrate := false
	if storageTotal == 1 && len(storageServed) == 1 && crd.group != "" && crd.plural != "" {
		storageVer = storageServed[0]
		canMigrate = true
	}

	return crdStoredVerFinding{
		meta:       crd.meta,
		name:       crd.meta.Name,
		group:      crd.group,
		plural:     crd.plural,
		kind:       kind,
		storageVer: storageVer,
		canMigrate: canMigrate,
		reasons:    reasons,
		stored:     stored,
	}, true
}

func (c *crdStoredVerCheck) crdStoredVerShouldMigrate(ctx context.Context, meta metav1.Object) bool {
	annos := kube.EffectiveAnnos(ctx, meta)
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
			ResourceVersion: "",
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

		explicitOptIn := kube.EffectiveAnno(ctx, &cand.meta, crdStoredVerAnnoAutoMigrate) == "true"
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
		hadPatchErr := false
		for i := range items {
			cr := &items[i]
			if cr.GetAnnotations()[crdStoredVerAnnoMigratedVersion] == cand.storageVer {
				continue
			}
			if cr.GetDeletionTimestamp() != nil {
				// Terminating CR still in etcd without migrated annotation: do not prune storedVersions yet.
				allMigrated = false
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
				hadPatchErr = true
				metrics.IncError(c.Name)
				log.Error(perr, "CRD storage migration CR patch failed",
					"crd", cand.name, "cr", crKey)
				break
			}
			patchedCount++
		}

		if !allMigrated {
			if patchedCount == 0 {
				if forbidden || !hadPatchErr {
					// Refund target & grant only on clean skips (403 or FluxPatchGate / terminating CR),
					// never when an attempted CR patch failed with a real error.
					heal.RefundTarget(CheckNameCRDStoredVersionsGuard, cand.name, now)
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
	crd metav1.Object,
	finding crdStoredVerFinding,
) {
	cooldownKey := "crd.storedversions." + finding.name
	note := fmt.Sprintf("CRD %s has status.storedVersions=%v (%s); migrate CRs and prune unserved/stale storedVersions before Kubernetes upgrade",
		finding.name, finding.stored, strings.Join(finding.reasons, ", "))
	probefw.EmitWarningDeduped(ctx, c.CS, log, &c.eventCooldown, cooldownKey, crdStoredVerEventCooldown, now, kube.WarningEvent{
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
	})
}
