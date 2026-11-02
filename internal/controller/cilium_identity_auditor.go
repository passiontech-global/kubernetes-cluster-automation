// cilium-identity-auditor — detect-only (v1) sweep for leaked Cilium
// identities. CiliumIdentity objects are the cluster-scoped backing
// store for security identities; the allocator normally garbage-
// collects them when the last endpoint using one disappears. When GC
// leaks (seen during agent churn/upgrades), identities accumulate
// toward the 65k identity range exhaustion — new pods then get no
// identity and lose all network policy.
//
// An identity is orphaned when no CiliumEndpoint references its
// numeric ID (status.identity.id) and no pod carries the
// cilium.io/identity annotation with it. v1 only logs + surfaces via
// the error metric when orphans exceed the threshold — NO deletion,
// since an in-flight endpoint create can momentarily look orphaned.
package controller

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/node-automation-controller/internal/metrics"
)

const (
	ciliumAuditQueue    = "cilium-identity-auditor"
	ciliumIDAnnotation  = "cilium.io/identity"
	ciliumOrphanMax     = 100 // above this the leak is real, not noise — alert
	ciliumOrphanSamples = 5   // sample names in the warn log
)

var (
	ciliumIdentityGVR = schema.GroupVersionResource{
		Group: "cilium.io", Version: "v2", Resource: "ciliumidentities"}
	ciliumEndpointGVR = schema.GroupVersionResource{
		Group: "cilium.io", Version: "v2", Resource: "ciliumendpoints"}
)

type ciliumIdentityAuditor struct {
	cs  kubernetes.Interface
	dyn dynamic.Interface
}

// SetupCiliumIdentityAuditor registers the 15m sweep. Disabled on
// clusters without the cilium component (Calico/cicd — the CRDs do
// not exist there).
func SetupCiliumIdentityAuditor(mgr ctrl.Manager, cs kubernetes.Interface,
	dyn dynamic.Interface, enabled bool) error {
	if !enabled {
		logf.Log.WithName(ciliumAuditQueue).Info("disabled — module not registered")
		return nil
	}
	a := &ciliumIdentityAuditor{cs: cs, dyn: dyn}
	return addPeriodic(mgr, ciliumAuditQueue, 15*time.Minute, a.run)
}

func (a *ciliumIdentityAuditor) run(ctx context.Context) error {
	log := logf.FromContext(ctx)

	ids, err := a.dyn.Resource(ciliumIdentityGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(ciliumAuditQueue)
		return err
	}

	used := map[string]struct{}{}
	eps, err := a.dyn.Resource(ciliumEndpointGVR).Namespace(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(ciliumAuditQueue)
		return err
	}
	for i := range eps.Items {
		if id := endpointIdentityID(&eps.Items[i]); id != "" {
			used[id] = struct{}{}
		}
	}
	pods, err := a.cs.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(ciliumAuditQueue)
		return err
	}
	for i := range pods.Items {
		if v := strings.TrimSpace(
			pods.Items[i].Annotations[ciliumIDAnnotation]); v != "" {
			used[v] = struct{}{}
		}
	}

	var orphans []string
	for i := range ids.Items {
		name := ids.Items[i].GetName()
		if _, ok := used[name]; !ok {
			orphans = append(orphans, name)
		}
	}
	if len(orphans) == 0 {
		log.Info("cilium identities clean", "total", len(ids.Items))
		return nil
	}
	sort.Strings(orphans)
	sample := orphans
	if len(sample) > ciliumOrphanSamples {
		sample = sample[:ciliumOrphanSamples]
	}
	if len(orphans) > ciliumOrphanMax {
		// Real leak — surface through the existing alert path.
		metrics.IncError(ciliumAuditQueue)
		log.Info("ORPHANED cilium identities above threshold — identity "+
			"leak, 65k range exhaustion risk (detect-only, no deletion)",
			"orphans", len(orphans), "total", len(ids.Items),
			"threshold", ciliumOrphanMax, "sample", sample)
		return nil
	}
	log.Info("orphaned cilium identities detected — below threshold, "+
		"watching (detect-only, no deletion)",
		"orphans", len(orphans), "total", len(ids.Items), "sample", sample)
	return nil
}

// endpointIdentityID extracts .status.identity.id — numeric in real
// objects (int64) but float64 in hand-built fixtures.
func endpointIdentityID(ep *unstructured.Unstructured) string {
	if id, found, _ := unstructured.NestedInt64(
		ep.Object, "status", "identity", "id"); found {
		return strconv.FormatInt(id, 10)
	}
	if f, found, _ := unstructured.NestedFloat64(
		ep.Object, "status", "identity", "id"); found {
		return strconv.FormatInt(int64(f), 10)
	}
	return ""
}
