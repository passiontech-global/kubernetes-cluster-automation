// kine_large_objects.go — the kine large-object audit of the
// api-object-sprawl-report-gc check: a cluster-wide ConfigMap/Secret
// census plus the CRD-backed kinds (CRDs, OLM CSVs, Argo
// Applications, Flux HelmCharts) guarding the kine datastore row
// size.
package nodehealth

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// kineLargeObjectThreshold is the Kine row-size guard:
// the serialized object size past which a ConfigMap/Secret is a
// large-object risk for the datastore (512 KiB — the same bound
// the host agent's kine-storage top-10 census logs). A
// multi-hundred-KiB row dominates compaction time and the
// apiserver's watch-cache serialization budget no matter which
// Kine backend backs it.
const kineLargeObjectThreshold = 524288

// Serialized size of each ConfigMap/Secret past the Kine
// large-object guard — the bloat census for the
// datastore row itself, whatever backs kine (SQLite or
// PostgreSQL).
var kineLargeObjectBytesGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_kine_large_object_bytes",
	Help: "Serialized bytes of objects above the 512 KiB Kine large-object guard.",
}, []string{"kind", "namespace", "name"})

func init() {
	ctrlmetrics.Registry.MustRegister(kineLargeObjectBytesGauge)
}

// auditKineLargeObjects pages ConfigMaps and Secrets
// cluster-wide and flags every object whose serialized size exceeds
// kineLargeObjectThreshold — the large-object census for the kine
// datastore row itself, whatever backs it (SQLite or PostgreSQL). The
// gauge carries the byte size on kineRep (the kine gauge's OWN
// scope — its "kind/ns/name" tuples never mix with the counts
// report's "resource/ns" tuples); each hit is also a sweep finding on
// objects so the check fails while the bloat is live.
func (p *apiObjectSprawlReportGCCheck) auditKineLargeObjects(ctx context.Context,
	objects, kineRep *probefw.SweepReport) error {

	// Stream pages instead of materializing the whole census — a
	// cluster-wide ConfigMap+Secret list is the biggest read this
	// check makes, and only objects near the size guard ever earn
	// an exact json.Marshal (approxObjectSize gates it).
	err := kube.ListEach(ctx,
		metav1.ListOptions{Limit: probefw.HealthListPageSize},
		kube.ConfigMaps(p.CS, metav1.NamespaceAll),
		func(items []corev1.ConfigMap) error {
			for i := range items {
				cm := &items[i]
				if approxObjectSize(cm,
					strMapLen(cm.Data)+bytesMapLen(cm.BinaryData)) < kineMarshalFloor {
					continue
				}
				p.recordKineLargeObject(ctx, objects, kineRep, "configmap",
					cm.Namespace, cm.Name, cm)
			}
			return nil
		})
	if err != nil {
		return fmt.Errorf("list configmaps: %w", err)
	}
	err = kube.ListEach(ctx,
		metav1.ListOptions{Limit: probefw.HealthListPageSize},
		kube.Secrets(p.CS, metav1.NamespaceAll),
		func(items []corev1.Secret) error {
			for i := range items {
				s := &items[i]
				if approxObjectSize(s, bytesMapLen(s.Data)+
					strMapLen(s.StringData)) < kineMarshalFloor {
					continue
				}
				p.recordKineLargeObject(ctx, objects, kineRep, "secret",
					s.Namespace, s.Name, s)
			}
			return nil
		})
	if err != nil {
		return fmt.Errorf("list secrets: %w", err)
	}

	// CRD-backed kinds — the same row-size guard over the object
	// shapes that historically produced the giant kine rows the
	// host-side census keeps finding: CRD OpenAPI schemas, OLM CSV
	// install descriptors, Argo Application specs and Flux
	// HelmCharts. These lists are small (tens-to-hundreds of
	// objects), so every item earns an exact marshal — no
	// approx-size gate, which cannot see spec-payload bulk on
	// unstructured content anyway. An absent CRD/API resource
	// skips quietly (IsNotFound/IsNoMatchError); any other read
	// failure is infra — the caller bails before the ledger Close
	// so live series are never pruned on a flap.
	for _, rk := range kineLargeObjectCRDGVRs {
		items, err := p.AllUnstructured(ctx, rk.gvr)
		switch {
		case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
			continue // CRD/API absent on this cluster — skip silently
		case err != nil:
			return fmt.Errorf("list %s: %w", rk.gvr.Resource, err)
		}
		for i := range items {
			obj := &items[i]
			p.recordKineLargeObject(ctx, objects, kineRep, rk.kind,
				obj.GetNamespace(), obj.GetName(), obj)
		}
	}
	return nil
}

// kineLargeObjectCRDGVRs is the dynamic-client half of the census —
// the kinds whose serialized size lands in kine rows but which have
// no typed client in this module. kind is the gauge label value,
// lowercase like the "configmap"/"secret" labels.
var kineLargeObjectCRDGVRs = []struct {
	gvr  schema.GroupVersionResource
	kind string
}{
	{kube.GVRCustomResourceDefinition, "customresourcedefinition"},
	{kube.GVROLMClusterServiceVersion, "clusterserviceversion"},
	{kube.GVRArgoCDApplication, "application"},
	{kube.GVRFluxHelmChart, "helmchart"},
}

// kineMarshalFloor is the approx-size below which an object cannot
// reach kineLargeObjectThreshold even after JSON framing overhead —
// only objects at or above it earn an exact json.Marshal, so the
// census never allocates a full serialized copy of every small
// ConfigMap/Secret on the cluster.
const kineMarshalFloor = kineLargeObjectThreshold / 2

func bytesMapLen(m map[string][]byte) int {
	n := 0
	for _, v := range m {
		n += len(v)
	}
	return n
}

func strMapLen(m map[string]string) int {
	n := 0
	for k, v := range m {
		n += len(k) + len(v)
	}
	return n
}

// approxObjectSize estimates an object's serialized footprint from
// its payload fields — the caller-supplied Data/BinaryData byte
// total plus annotation and managedFields bulk — without paying a
// marshal per object. It deliberately over-counts framing (key
// bytes, per-entry slack) so a false negative is impossible: an
// object skipped here cannot marshal past the threshold.
func approxObjectSize(obj metav1.Object, payload int) int {
	size := payload
	for k, v := range obj.GetAnnotations() {
		size += len(k) + len(v)
	}
	for _, mf := range obj.GetManagedFields() {
		// GetRawBytes (not the deprecated .Raw direct access) — may
		// alias the underlying slice, which is fine: only the length
		// is read.
		size += len(mf.FieldsV1.GetRawBytes()) + 160
	}
	return size
}

// recordKineLargeObject measures obj's serialized size — the bytes the
// datastore row actually stores, so Data/BinaryData payloads AND
// metadata (a runaway last-applied-configuration annotation counts —
// it historically duplicated whole manifests) — and past the
// threshold emits the gauge tuple on kineRep (the kine gauge's own
// scope) plus a finding on the shared verdict. A marshal failure is
// unmeasurable, not large: logged and skipped.
func (p *apiObjectSprawlReportGCCheck) recordKineLargeObject(ctx context.Context,
	objects, kineRep *probefw.SweepReport, kind, ns, name string, obj any) {

	b, err := json.Marshal(obj)
	if err != nil {
		logf.FromContext(ctx).Error(err, "marshal object for kine size audit",
			"kind", kind, "object", ns+"/"+name)
		return
	}
	if len(b) <= kineLargeObjectThreshold {
		return
	}
	kineRep.Set(kineLargeObjectBytesGauge, float64(len(b)),
		kind+"/"+ns+"/"+name, []string{kind, ns, name})
	objects.Find(fmt.Sprintf("%s %s/%s carries %d bytes (Kine row guard %d)",
		kind, ns, name, len(b), kineLargeObjectThreshold))
}
