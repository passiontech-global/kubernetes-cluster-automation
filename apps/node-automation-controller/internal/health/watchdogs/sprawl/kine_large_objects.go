// kine_large_objects.go — the kine large-object audit of the
// api-object-sprawl-report-gc check: a cluster-wide ConfigMap/Secret
// census plus the CRD-backed kinds (CRDs, OLM CSVs, Argo
// Applications, Flux HelmCharts) guarding the kine datastore row
// size.
package sprawl

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
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

	// Hits buffer until EVERY read source has succeeded: a partial
	// census must never publish — a ConfigMap page that measured
	// fine followed by a failed Secret list would otherwise leave
	// half the gauge tuples and findings live on an Infra-aborted
	// sweep. Flush happens once, after the last source returns.
	var hits []kineLargeHit

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
				p.recordKineLargeObject(ctx, &hits, "configmap",
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
				p.recordKineLargeObject(ctx, &hits, "secret",
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
	// HelmCharts. The small lists earn an exact measure per item. An
	// absent CRD/API resource skips quietly
	// (IsNotFound/IsNoMatchError); any other read failure is infra —
	// the caller bails before the ledger Close so live series are
	// never pruned on a flap.
	for _, rk := range kineLargeObjectCRDGVRs {
		if rk.gvr == kube.GVRCustomResourceDefinition {
			// CRDs are NOT re-listed as full objects here anymore:
			// the manager's informer cache strips their OpenAPI
			// schemas on the way in and records each object's full
			// serialized size into kube.CRDSizeIndex before the
			// strip — the census reads (name, RV) → size from that
			// side table via a metadata-only name+RV list, so the
			// cycle pays kilobytes where the legacy full-object
			// pages pushed tens of MB through the apiserver/Kine
			// path. A table miss (informer lag on a just-created
			// CRD, or an unwired cache in tests) measures that one
			// object live — the identical legacy measure, so the
			// gauge bytes never change for unchanged objects.
			if p.Dyn == nil {
				return fmt.Errorf("list %s: no dynamic client", rk.gvr.Resource)
			}
			if err := p.auditKineCRDSize(ctx, &hits); err != nil {
				return err
			}
			continue
		}
		items, err := p.AllUnstructured(ctx, rk.gvr)
		switch {
		case kube.IsCRDAbsent(err):
			continue // CRD/API absent on this cluster — skip silently
		case err != nil:
			return fmt.Errorf("list %s: %w", rk.gvr.Resource, err)
		}
		for i := range items {
			obj := &items[i]
			p.recordKineLargeObject(ctx, &hits, rk.kind,
				obj.GetNamespace(), obj.GetName(), obj)
		}
	}

	// All three read sources returned — publish the buffered hits:
	// gauge tuples on kineRep (the kine gauge's own scope) plus a
	// finding per hit on the shared verdict.
	for _, h := range hits {
		kineRep.Set(kineLargeObjectBytesGauge, float64(h.size),
			h.kind+"/"+h.ns+"/"+h.name,
			[]string{h.kind, h.ns, h.name})
		objects.Find(fmt.Sprintf("%s %s/%s carries %d bytes (Kine row guard %d)",
			h.kind, h.ns, h.name, h.size, kineLargeObjectThreshold))
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

// auditKineCRDSize measures the cluster's CRDs against the Kine
// row-size guard WITHOUT re-reading full CRD objects: the census
// lists only name+resourceVersion (metadata-only through
// ListPartialOrFallback — the same partial-meta read path every
// metadata census uses, with the typed/dynamic fallbacks keeping the
// fake-clientset tests working) and reads each object's full
// serialized size from the informer-fed kube.CRDSizeIndex — the
// number the manager's CRD cache transform recorded BEFORE stripping
// the OpenAPI schema, byte-identical to the live json.Marshal measure
// this census used to pay per CRD per cycle. A table miss measures
// that one object live via a single dyn GET. Error semantics are the
// legacy ones: NotFound/NoMatch on the list means the CRD API is
// absent (skip silently), any other list failure aborts the census.
func (p *apiObjectSprawlReportGCCheck) auditKineCRDSize(ctx context.Context,
	hits *[]kineLargeHit) error {

	poms, err := kube.ListPartialOrFallback(ctx, p.Meta, p.CS, p.Dyn,
		kube.GVRCustomResourceDefinition, metav1.NamespaceAll,
		metav1.ListOptions{Limit: 25})
	switch {
	case kube.IsCRDAbsent(err):
		return nil // CRD API absent on this cluster — skip silently
	case err != nil:
		return fmt.Errorf("list %s: %w",
			kube.GVRCustomResourceDefinition.Resource, err)
	}
	crdSize := p.CRDSize
	if crdSize == nil {
		crdSize = kube.CRDSizeIndex
	}
	for i := range poms {
		pom := &poms[i]
		size, ok := crdSize.Lookup(pom.Name, pom.ResourceVersion)
		if !ok {
			// The informer has not stamped this (name, RV) yet —
			// measure live rather than under-report a fresh CRD.
			size = p.liveKineCRDSize(ctx, pom.Name)
			if size <= 0 {
				continue // gone or unreadable — same verdict as a list miss
			}
		}
		if size <= kineLargeObjectThreshold {
			continue
		}
		// CRDs are cluster-scoped — the namespace label is the empty
		// string, matching the legacy unstructured GetNamespace().
		*hits = append(*hits, kineLargeHit{
			kind: "customresourcedefinition", ns: pom.Namespace,
			name: pom.Name, size: size})
	}
	return nil
}

// liveKineCRDSize is the miss-path measure — the legacy dyn GET plus
// JSONSize for one CRD the side table does not cover yet. A NotFound
// (the CRD vanished between the metadata list and this read) and an
// unreadable/unalmeasureable object both return 0: the object is
// skipped this cycle and the informer stamps it for the next one.
func (p *apiObjectSprawlReportGCCheck) liveKineCRDSize(ctx context.Context,
	name string) int64 {

	obj, err := p.Dyn.Resource(kube.GVRCustomResourceDefinition).
		Get(ctx, name, metav1.GetOptions{})
	switch {
	case kube.IsCRDAbsent(err):
		return 0
	case err != nil:
		logf.FromContext(ctx).Info("kine census: CRD size fallback read "+
			"failed — skipped (the informer table covers it next cycle)",
			"crd", name, "error", err)
		return 0
	}
	size, err := kube.JSONSize(obj)
	if err != nil {
		logf.FromContext(ctx).Error(err, "measure object for kine size audit",
			"kind", "customresourcedefinition", "object", name)
		return 0
	}
	return size
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

// kineLargeHit is one over-threshold object buffered by
// recordKineLargeObject — published only after every census source
// succeeds (see auditKineLargeObjects).
type kineLargeHit struct {
	kind, ns, name string
	size           int64
}

// recordKineLargeObject measures obj's serialized size — the bytes the
// datastore row actually stores, so Data/BinaryData payloads AND
// metadata (a runaway last-applied-configuration annotation counts —
// it historically duplicated whole manifests) — and past the
// threshold appends the hit to hits for the caller's end-of-audit
// flush (the gauge tuple lands on kineRep's own scope, the finding
// on the shared verdict). The size counts through kube.JSONSize: a
// full json.Marshal would allocate a multi-MB []byte per CRD schema
// just to read its length. A marshal failure is unmeasurable, not
// large: logged and skipped.
func (p *apiObjectSprawlReportGCCheck) recordKineLargeObject(ctx context.Context,
	hits *[]kineLargeHit, kind, ns, name string, obj any) {

	size, err := kube.JSONSize(obj)
	if err != nil {
		logf.FromContext(ctx).Error(err, "measure object for kine size audit",
			"kind", kind, "object", ns+"/"+name)
		return
	}
	if size <= kineLargeObjectThreshold {
		return
	}
	*hits = append(*hits, kineLargeHit{kind, ns, name, size})
}
