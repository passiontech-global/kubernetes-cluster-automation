package main

import (
	"context"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	toolscache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/leaderelect"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/httpx/pprofx"
)

// stripManagedFields is the shared managedFields stripper — a factory
// product built once, not re-allocated per transformed object.
var stripManagedFields = cache.TransformStripManagedFields()

// defaultCacheTransform trims informer memory: managedFields is a
// large chunk of every cached object and .Status.Images alone is
// 50-80% of a Node's size — no module reads either field.
func defaultCacheTransform(obj interface{}) (interface{}, error) {
	// A delete delta can arrive wrapped in the DeltaFIFO tombstone —
	// unwrap before the type switch or the strip silently no-ops.
	if tomb, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
		obj = tomb.Obj
	}
	if _, err := stripManagedFields(obj); err != nil {
		return nil, err
	}
	if n, ok := obj.(*corev1.Node); ok {
		n.Status.Images = nil
	}
	return obj, nil
}

var podCacheLabelSelector = func() labels.Selector {
	sel, err := labels.Parse("k8s-app in (cilium,kube-dns)")
	if err != nil {
		return labels.SelectorFromSet(labels.Set{"k8s-app": "cilium"})
	}
	return sel
}()

func buildCacheOptions() cache.Options {
	return cache.Options{
		DefaultTransform: defaultCacheTransform,
		ByObject: map[client.Object]cache.ByObject{
			&appsv1.DaemonSet{}: {
				Namespaces: map[string]cache.Config{"kube-system": {}},
				Field: fields.SelectorFromSet(
					fields.Set{"metadata.name": "konnectivity-agent"}),
			},
			&appsv1.Deployment{}: {
				Namespaces: map[string]cache.Config{"kube-system": {}},
			},
			&corev1.Secret{}: {
				Field: fields.SelectorFromSet(
					fields.Set{"metadata.name": "passiontech-pipeline"}),
			},
			&corev1.Pod{}: {
				Namespaces: map[string]cache.Config{"kube-system": {}},
				Label:      podCacheLabelSelector,
			},
			// The CRD informer backs two consumers: webhookguard's
			// conversion-webhook census (reads .spec.conversion off the
			// cached objects) and the sprawl kine census's size table
			// (see crdCacheTransform). Cluster-wide by need — CRDs are
			// cluster-scoped. RBAC note: this informer needs LIST+WATCH
			// on apiextensions.k8s.io/customresourcedefinitions (the
			// legacy dyn LIST grant already existed; WATCH is new).
			&apiextensionsv1.CustomResourceDefinition{}: {
				Transform: crdCacheTransform,
			},
		},
	}
}

// crdCacheTransform is the CRD-specific informer transform — the
// ByObject entry REPLACES defaultCacheTransform for this type, so it
// does the managedFields strip itself. Two jobs:
//
//   - Record the CRD's full serialized size into kube.CRDSizeIndex
//     BEFORE any stripping: the sprawl kine large-object census reads
//     (name, RV) → size from that table instead of re-listing CRD
//     bodies every cycle, and the recorded number is the exact
//     json.Marshal-equivalent byte count of the UNSTRIPPED object —
//     byte-identical to what the legacy live measure produced, so the
//     gauge series and findings are unchanged for unchanged clusters.
//     The cost is one size pass per CRD per watch event (CRDs update
//     a handful of times a day), not per sweep.
//   - Strip the informer-memory bulk: .spec.versions[*].schema (the
//     OpenAPI v3 trees are the fattest objects any informer here
//     holds — tens of MB per CRD, the very bulk the kine census
//     exists to police), managedFields and the last-applied
//     annotation (which historically duplicated whole manifests).
//     .spec.conversion is deliberately KEPT — webhookguard's
//     conversion-webhook census reads it off the cached objects.
func crdCacheTransform(obj interface{}) (interface{}, error) {
	// Same tombstone unwrap as defaultCacheTransform — a deleted
	// CRD's final state must still record/strip, not pass through
	// as an opaque DeletedFinalStateUnknown.
	if tomb, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
		obj = tomb.Obj
	}
	crd, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
	if !ok {
		return obj, nil
	}
	if size, err := kube.JSONSize(crd); err == nil {
		kube.CRDSizeIndex.Record(crd.Name, crd.ResourceVersion, size)
	}
	for i := range crd.Spec.Versions {
		crd.Spec.Versions[i].Schema = nil
	}
	crd.ManagedFields = nil
	delete(crd.Annotations, corev1.LastAppliedConfigAnnotation)
	return crd, nil
}

// pprofHandlers is the metrics-server ExtraHandlers map — the
// pprof endpoints live on :9115 next to /metrics. The handlers come
// from libs/hostkit/httpx/pprofx so this binary never imports
// net/http/pprof directly: that import's init() registers
// /debug/pprof/* on http.DefaultServeMux unconditionally, growing a
// debug surface on every mux in the process that never asked for it.
func pprofHandlers() map[string]http.Handler {
	return pprofx.Handlers()
}

func resolveLeaderNamespace() string {
	const saNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	if b, err := os.ReadFile(saNamespaceFile); err == nil {
		if ns := strings.TrimSpace(string(b)); ns != "" {
			return ns
		}
	}
	return leaderelect.DefaultNamespace
}

func buildMgrOptions(scheme *runtime.Scheme, metricsAddr, probeAddr string,
	leaderElect bool, leaseDuration, renewDeadline, retryPeriod time.Duration,
	leaderNS string, leaderLock resourcelock.Interface) ctrl.Options {
	mgrOptions := ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress:   metricsAddr,
			ExtraHandlers: pprofHandlers(),
		},
		HealthProbeBindAddress:              probeAddr,
		LeaderElection:                      leaderElect,
		LeaderElectionNamespace:             leaderNS,
		LeaderElectionID:                    leaderElectionID,
		LeaderElectionReleaseOnCancel:       true,
		LeaderElectionResourceLockInterface: leaderLock,
		Cache:                               buildCacheOptions(),
		// RecoverPanic: a panicking reconcile must not take the
		// whole manager down — controller-runtime recovers per
		// invocation and surfaces the panic as a reconcile error.
		Controller: config.Controller{RecoverPanic: ptr.To(true)},
	}
	if leaseDuration > 0 {
		mgrOptions.LeaseDuration = &leaseDuration
	}
	if renewDeadline > 0 {
		mgrOptions.RenewDeadline = &renewDeadline
	}
	if retryPeriod > 0 {
		mgrOptions.RetryPeriod = &retryPeriod
	}
	return mgrOptions
}

type leasePreemptRunnable struct {
	preemptor *leaderelect.Preemptor
	log       logr.Logger
}

func (r *leasePreemptRunnable) NeedLeaderElection() bool { return false }

func (r *leasePreemptRunnable) Start(ctx context.Context) error {
	jitter := time.Duration(rand.Int64N(int64(leaderelect.SweepInterval)))
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(jitter):
	}
	ticker := time.NewTicker(leaderelect.SweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			reason, err := r.preemptor.Sweep(ctx)
			switch {
			case err != nil:
				r.log.Error(err, "leader lease preempt sweep failed")
			case reason != "":
				metrics.LeaderLeasePreemptionsTotal.
					WithLabelValues(reason).Inc()
				r.log.Info("leader lease preempted — holder proved dead",
					"reason", reason)
			}
		}
	}
}
