// coredns_ndots_audit.go — Wave 4C #12B CoreDNS ndots:5 DNS amplification
// audit inside coredns-forward-saturation: queries CoreDNS NXDOMAIN ratio
// and total QPS on every sweep, publishes node_automation_coredns_nxdomain_ratio,
// and when ratio > 0.40 && QPS > 50 audits >=3-replica Deployments and
// StatefulSets lacking spec.template.spec.dnsConfig.options[name=ndots],
// emitting findings and a 6h-deduped CoreDNSNdotsAmplification Warning Event
// suggesting ndots:2.
package nethealth

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

const (
	coreDNSNXDOMAINRatioQuery = `sum(rate(coredns_dns_responses_total{rcode="NXDOMAIN"}[10m])) / sum(rate(coredns_dns_responses_total[10m]))`
	coreDNSQPSQuery           = `sum(rate(coredns_dns_responses_total[10m]))`

	coreDNSNXDOMAINRatioThreshold = 0.40
	coreDNSQPSThreshold           = 50.0
	coreDNSNdotsAuditMinReplicas  = int32(3)
	coreDNSNdotsEventCooldown     = 6 * time.Hour
	coreDNSNdotsEventReason       = "CoreDNSNdotsAmplification"
)

var coreDNSNXDOMAINRatioGauge = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "node_automation_coredns_nxdomain_ratio",
	Help: "Current CoreDNS NXDOMAIN response ratio over 10m (sum(rate(coredns_dns_responses_total{rcode=\"NXDOMAIN\"}[10m])) / sum(rate(coredns_dns_responses_total[10m]))).",
})

func init() {
	ctrlmetrics.Registry.MustRegister(coreDNSNXDOMAINRatioGauge)
}

func (p *coreDNSForwardSaturationCheck) auditNdotsAmplification(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	rep *probefw.SweepReport,
) {
	ratioSamples, ratioErr := p.PromQuery(ctx, coreDNSNXDOMAINRatioQuery)
	qpsSamples, qpsErr := p.PromQuery(ctx, coreDNSQPSQuery)
	if ratioErr != nil || qpsErr != nil {
		err := ratioErr
		if err == nil {
			err = qpsErr
		}
		log.Info("WARN: coredns ndots audit PromQL query failed", "error", err)
		rep.InfraErr(fmt.Errorf("coredns ndots audit query: %w", err))
		return
	}

	ratio := sumSamples(ratioSamples)
	qps := sumSamples(qpsSamples)
	if math.IsNaN(ratio) || math.IsInf(ratio, 0) || ratio < 0 {
		ratio = 0
	}
	if math.IsNaN(qps) || math.IsInf(qps, 0) || qps < 0 {
		qps = 0
	}
	coreDNSNXDOMAINRatioGauge.Set(ratio)

	if ratio <= coreDNSNXDOMAINRatioThreshold || qps <= coreDNSQPSThreshold {
		return
	}

	deps, err := p.AllDeployments(ctx)
	if err != nil {
		rep.InfraErr(fmt.Errorf("list deployments for ndots audit: %w", err))
		return
	}
	stss, err := p.AllStatefulSets(ctx)
	if err != nil {
		rep.InfraErr(fmt.Errorf("list statefulsets for ndots audit: %w", err))
		return
	}

	type ndotsOffender struct {
		kind     string
		ns       string
		name     string
		uid      types.UID
		replicas int32
	}
	var offenders []ndotsOffender

	for i := range deps {
		dep := &deps[i]
		if dep.DeletionTimestamp != nil {
			continue
		}
		replicas := int32(1)
		if dep.Spec.Replicas != nil {
			replicas = *dep.Spec.Replicas
		}
		if replicas < coreDNSNdotsAuditMinReplicas {
			continue
		}
		if hasNdotsDNSOption(dep.Spec.Template.Spec) {
			continue
		}
		offenders = append(offenders, ndotsOffender{
			kind:     "Deployment",
			ns:       dep.Namespace,
			name:     dep.Name,
			uid:      dep.UID,
			replicas: replicas,
		})
	}

	for i := range stss {
		sts := &stss[i]
		if sts.DeletionTimestamp != nil {
			continue
		}
		replicas := int32(1)
		if sts.Spec.Replicas != nil {
			replicas = *sts.Spec.Replicas
		}
		if replicas < coreDNSNdotsAuditMinReplicas {
			continue
		}
		if hasNdotsDNSOption(sts.Spec.Template.Spec) {
			continue
		}
		offenders = append(offenders, ndotsOffender{
			kind:     "StatefulSet",
			ns:       sts.Namespace,
			name:     sts.Name,
			uid:      sts.UID,
			replicas: replicas,
		})
	}

	for _, o := range offenders {
		rep.Find(fmt.Sprintf("%s/%s/%s missing ndots", o.kind, o.ns, o.name))
		p.emitNdotsAuditEvent(ctx, log, now, o.kind, o.ns, o.name, o.uid, o.replicas, ratio, qps)
	}
}

func hasNdotsDNSOption(spec corev1.PodSpec) bool {
	if spec.DNSConfig == nil {
		return false
	}
	for _, opt := range spec.DNSConfig.Options {
		if opt.Name == "ndots" {
			return true
		}
	}
	return false
}

func (p *coreDNSForwardSaturationCheck) emitNdotsAuditEvent(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	kind, ns, name string,
	uid types.UID,
	replicas int32,
	ratio, qps float64,
) {
	ck := probefw.SelfHealKey(CheckNameCoreDNSForwardSaturation, "ndots/"+kind+"/"+ns+"/"+name)
	if p.ndotsEventCooldown.CooledDown(ck, coreDNSNdotsEventCooldown, now) {
		return
	}
	if err := kube.EmitWarningEvent(ctx, p.CS, kube.WarningEvent{
		Name:      kube.TruncatedEventName("coredns-ndots."+kind+"."+ns+"."+name, kind+"/"+ns+"/"+name, now),
		Namespace: ns,
		Regarding: corev1.ObjectReference{
			APIVersion: "apps/v1",
			Kind:       kind,
			Namespace:  ns,
			Name:       name,
			UID:        uid,
		},
		Reason: coreDNSNdotsEventReason,
		Note: fmt.Sprintf(
			"CoreDNS NXDOMAIN ratio %.2f (>%.2f) at %.1f QPS; %s %s/%s (%d replicas) lacks spec.template.spec.dnsConfig.options[name=ndots] — consider setting ndots:2 to reduce search-path DNS amplification",
			ratio, coreDNSNXDOMAINRatioThreshold, qps, kind, ns, name, replicas),
		ReportingInstance: p.Name,
		Now:               now,
	}); err != nil {
		log.Info("WARN: coredns ndots amplification event create failed (RBAC?)",
			"kind", kind, "object", ns+"/"+name, "error", err)
		return
	}
	p.ndotsEventCooldown.Stamp(ck, now)
	log.Info("EVENT: CoreDNSNdotsAmplification", "kind", kind, "object", ns+"/"+name)
}
