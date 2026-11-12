package main

import (
	"context"
	"math/rand/v2"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/leaderelect"
)

// stripManagedFields is the shared managedFields stripper — a factory
// product built once, not re-allocated per transformed object.
var stripManagedFields = cache.TransformStripManagedFields()

// defaultCacheTransform trims informer memory: managedFields is a
// large chunk of every cached object and .Status.Images alone is
// 50-80% of a Node's size — no module reads either field.
func defaultCacheTransform(obj interface{}) (interface{}, error) {
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
		},
	}
}

func pprofHandlers() map[string]http.Handler {
	return map[string]http.Handler{
		"/debug/pprof/":        http.HandlerFunc(pprof.Index),
		"/debug/pprof/cmdline": http.HandlerFunc(pprof.Cmdline),
		"/debug/pprof/profile": http.HandlerFunc(pprof.Profile),
		"/debug/pprof/symbol":  http.HandlerFunc(pprof.Symbol),
		"/debug/pprof/trace":   http.HandlerFunc(pprof.Trace),
	}
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
