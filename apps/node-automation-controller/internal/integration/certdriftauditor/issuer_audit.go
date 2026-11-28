// issuer_audit.go — Wave 7 extension for cert-drift-auditor:
// audits cert-manager.io/v1 Issuer and ClusterIssuer resources for sustained
// Ready != True >= 15m -> node_automation_certmanager_issuer_unhealthy.
package certdriftauditor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const issuerUnhealthyMinAge = 15 * time.Minute

var (
	issuerGVR = schema.GroupVersionResource{
		Group: "cert-manager.io", Version: "v1", Resource: "issuers",
	}
	clusterIssuerGVR = schema.GroupVersionResource{
		Group: "cert-manager.io", Version: "v1", Resource: "clusterissuers",
	}

	certManagerIssuerUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_certmanager_issuer_unhealthy",
		Help: "1 while a cert-manager Issuer or ClusterIssuer has Ready != True >=15m.",
	}, []string{"kind", "namespace", "name"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(certManagerIssuerUnhealthyGauge)
}

func (a *certDriftAuditor) auditIssuers(ctx context.Context) error {
	if a.dyn == nil {
		return nil
	}
	a.seenIssuers.Begin()
	log := logf.FromContext(ctx)
	now := a.now.Now()
	var errs []error
	keepSeen := map[string]bool{}

	for _, src := range []struct {
		gvr  schema.GroupVersionResource
		kind string
	}{
		{issuerGVR, "Issuer"},
		{clusterIssuerGVR, "ClusterIssuer"},
	} {
		items, err := kube.ListAll(ctx,
			metav1.ListOptions{Limit: kube.DefaultListPageSize},
			kube.DynamicPage(a.dyn.Resource(src.gvr)))
		switch {
		case err == nil:
		case kube.IsCRDAbsent(err) || apierrors.IsForbidden(err):
			continue
		default:
			errs = append(errs, fmt.Errorf("list %s: %w", src.gvr.Resource, err))
			for k, lv := range a.seenIssuers.Last() {
				if k.kind == src.kind {
					a.seenIssuers.Emit(k, lv...)
				}
			}
			continue
		}

		for i := range items {
			u := &items[i]
			if u.GetDeletionTimestamp() != nil {
				continue
			}
			cond, ok := kube.ConditionOf(u.Object, "Ready")
			if ok && cond.Status == "True" {
				continue
			}
			ns, name := u.GetNamespace(), u.GetName()
			seenKey := src.kind + "/" + ns + "/" + name
			persisted := false
			if ok && !cond.LastTransitionTime.IsZero() {
				persisted = now.Sub(cond.LastTransitionTime) >= issuerUnhealthyMinAge
			} else {
				first, tracked := a.issuerFirstSeen.Observe(seenKey, now)
				keepSeen[seenKey] = true
				persisted = tracked && now.Sub(first) >= issuerUnhealthyMinAge
			}
			if !persisted {
				continue
			}
			mk := issuerMetricKey{kind: src.kind, namespace: ns, name: name}
			a.seenIssuers.Set(certManagerIssuerUnhealthyGauge, 1, mk, src.kind, ns, name)
			log.Info("cert-manager issuer unhealthy >=15m",
				"kind", src.kind, "namespace", ns, "name", name,
				"readyStatus", cond.Status, "reason", cond.Reason)
		}
	}

	a.issuerFirstSeen.Prune(func(k string) bool { return keepSeen[k] })
	if len(errs) == 0 {
		a.seenIssuers.Prune(certManagerIssuerUnhealthyGauge.DeleteLabelValues)
	}
	return errors.Join(errs...)
}
