// kine_large_objects.go — the kine large-object audit of the
// api-object-sprawl-report-gc check: a cluster-wide ConfigMap/Secret
// size census guarding the kine datastore row size.
package nodehealth

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	Help: "Serialized bytes of ConfigMap/Secret objects above the 512 KiB Kine large-object guard.",
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

	cms, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: probefw.HealthListPageSize},
		kube.ConfigMaps(p.CS, metav1.NamespaceAll))
	if err != nil {
		return fmt.Errorf("list configmaps: %w", err)
	}
	for i := range cms {
		p.recordKineLargeObject(ctx, objects, kineRep, "configmap",
			cms[i].Namespace, cms[i].Name, &cms[i])
	}
	secrets, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: probefw.HealthListPageSize},
		kube.Secrets(p.CS, metav1.NamespaceAll))
	if err != nil {
		return fmt.Errorf("list secrets: %w", err)
	}
	for i := range secrets {
		p.recordKineLargeObject(ctx, objects, kineRep, "secret",
			secrets[i].Namespace, secrets[i].Name, &secrets[i])
	}
	return nil
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
