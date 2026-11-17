// service_selector_blackhole.go — health check "service-selector-blackhole" (#6):
// detects Services with a non-empty spec.selector (both ClusterIP and Headless)
// reporting 0 Ready endpoints continuously >=10m due to either:
//   - selector_zero_match: no non-terminal Pod in the namespace matches spec.selector
//     (includes nearest-label workload hint in the Warning Event note), or
//   - target_port_mismatch: matching Ready Pods exist, but a ServicePort specifies
//     a named string targetPort that matches no containerPort.name on those Pods.
//
// Skips ExternalName Services, selectorless Services, default/kubernetes, empty
// namespaces, and intentionally scaled-to-0 / downscaled workloads. Uses only
// memoized probefw.Deps censuses (0 additional API list calls).
package nethealth

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

const (
	// CheckNameServiceSelectorBlackhole is the registry check name for #6.
	CheckNameServiceSelectorBlackhole = "service-selector-blackhole"

	serviceBlackholeMinAge        = 10 * time.Minute
	serviceBlackholeEventCooldown = 30 * time.Minute
)

var serviceBlackholeGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_service_blackhole",
	Help: "1 while a Service has 0 Ready endpoints due to selector_zero_match or target_port_mismatch >=10m.",
}, []string{"namespace", "service", "reason"})

func init() {
	ctrlmetrics.Registry.MustRegister(serviceBlackholeGauge)
}

type serviceSelectorBlackholeCheck struct {
	*probefw.Deps

	seen          state.FirstSeenLedger
	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
}

// NewServiceSelectorBlackholeCheck constructs the service-selector-blackhole check.
func NewServiceSelectorBlackholeCheck(d *probefw.Deps) probefw.Check {
	return &serviceSelectorBlackholeCheck{Deps: d}
}

type workloadTemplateInfo struct {
	name       string
	labels     map[string]string
	downscaled bool
}

func (c *serviceSelectorBlackholeCheck) Run(ctx context.Context) probefw.Result {
	now := c.Now()
	c.eventCooldown.PruneExpired(now, serviceBlackholeEventCooldown)
	var rep probefw.SweepReport

	svcs, err := c.AllServices(ctx)
	if err != nil {
		return carryBlackholeOnErr(&rep, &c.emitted, err, "list services")
	}
	slices, err := c.AllEndpointSlices(ctx)
	if err != nil {
		return carryBlackholeOnErr(&rep, &c.emitted, err, "list endpointslices")
	}
	pods, err := c.AllPods(ctx)
	if err != nil {
		return carryBlackholeOnErr(&rep, &c.emitted, err, "list pods")
	}
	deploys, err := c.AllDeployments(ctx)
	if err != nil {
		return carryBlackholeOnErr(&rep, &c.emitted, err, "list deployments")
	}
	stss, err := c.AllStatefulSets(ctx)
	if err != nil {
		return carryBlackholeOnErr(&rep, &c.emitted, err, "list statefulsets")
	}
	dss, err := c.AllDaemonSets(ctx)
	if err != nil {
		return carryBlackholeOnErr(&rep, &c.emitted, err, "list daemonsets")
	}

	readyBySvc := kube.ReadyEndpointsByService(slices)

	podsByNS := map[string][]*corev1.Pod{}
	for i := range pods {
		p := &pods[i]
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		podsByNS[p.Namespace] = append(podsByNS[p.Namespace], p)
	}

	workloadsByNS := map[string][]workloadTemplateInfo{}
	for i := range deploys {
		d := &deploys[i]
		downscaled := (d.Spec.Replicas != nil && *d.Spec.Replicas == 0) ||
			kube.IsIntentionallyDownscaled(d.Annotations, d.Spec.Replicas)
		workloadsByNS[d.Namespace] = append(workloadsByNS[d.Namespace], workloadTemplateInfo{
			name:       "Deployment/" + d.Name,
			labels:     d.Spec.Template.Labels,
			downscaled: downscaled,
		})
	}
	for i := range stss {
		s := &stss[i]
		downscaled := (s.Spec.Replicas != nil && *s.Spec.Replicas == 0) ||
			kube.IsIntentionallyDownscaled(s.Annotations, s.Spec.Replicas)
		workloadsByNS[s.Namespace] = append(workloadsByNS[s.Namespace], workloadTemplateInfo{
			name:       "StatefulSet/" + s.Name,
			labels:     s.Spec.Template.Labels,
			downscaled: downscaled,
		})
	}
	for i := range dss {
		ds := &dss[i]
		workloadsByNS[ds.Namespace] = append(workloadsByNS[ds.Namespace], workloadTemplateInfo{
			name:   "DaemonSet/" + ds.Name,
			labels: ds.Spec.Template.Labels,
		})
	}

	seenKeys := map[string]bool{}
	defer c.seen.Prune(func(k string) bool { return seenKeys[k] })

	for i := range svcs {
		svc := &svcs[i]
		if svc.Spec.Type == corev1.ServiceTypeExternalName || len(svc.Spec.Selector) == 0 {
			continue
		}
		if svc.Namespace == "default" && svc.Name == "kubernetes" {
			continue
		}
		nsPods := podsByNS[svc.Namespace]
		if len(nsPods) == 0 {
			continue
		}
		svcKey := svc.Namespace + "/" + svc.Name
		if len(readyBySvc[svcKey]) > 0 {
			continue
		}
		if matchesDownscaledWorkload(svc.Spec.Selector, workloadsByNS[svc.Namespace]) {
			continue
		}

		matchingPods := filterMatchingPods(svc.Spec.Selector, nsPods)
		var reason, detail string
		switch {
		case len(matchingPods) == 0:
			reason = "selector_zero_match"
			hint := nearestWorkloadHint(svc.Spec.Selector, workloadsByNS[svc.Namespace])
			if hint != "" {
				detail = fmt.Sprintf("Service %s has 0 Ready endpoints (selector matches 0 Pods; nearest workload: %s)", svcKey, hint)
			} else {
				detail = fmt.Sprintf("Service %s has 0 Ready endpoints (selector matches 0 Pods in namespace)", svcKey)
			}
		default:
			if badPort, mismatch := findMissingNamedTargetPort(svc.Spec.Ports, matchingPods); mismatch {
				reason = "target_port_mismatch"
				detail = fmt.Sprintf("Service %s has 0 Ready endpoints (named targetPort %q missing from Ready Pods' containerPort.name)", svcKey, badPort)
			}
		}
		if reason == "" {
			continue
		}

		obsKey := svcKey + "/" + reason
		seenKeys[obsKey] = true
		first, _ := c.seen.Observe(obsKey, now)
		if now.Sub(first) < serviceBlackholeMinAge {
			continue
		}

		rep.Emit(serviceBlackholeGauge, obsKey,
			[]string{svc.Namespace, svc.Name, reason},
			fmt.Sprintf("%s [%s]", svcKey, reason))
		c.emitBlackholeEvent(ctx, svc, reason, detail, now)
	}

	return rep.Result(&c.emitted, serviceBlackholeGauge.DeleteLabelValues,
		"service selector blackhole: ", ", ")
}

func carryBlackholeOnErr(rep *probefw.SweepReport, ledger *state.GaugeLedger[string], err error, what string) probefw.Result {
	for k, lv := range ledger.Last() {
		rep.Carry(k, lv)
	}
	rep.InfraErr(fmt.Errorf("%s: %w", what, err))
	return rep.Result(ledger, serviceBlackholeGauge.DeleteLabelValues,
		"service selector blackhole: ", ", ")
}

func matchesDownscaledWorkload(sel map[string]string, workloads []workloadTemplateInfo) bool {
	matchedAny := false
	for i := range workloads {
		w := &workloads[i]
		if selectorMatchesLabels(sel, w.labels) {
			matchedAny = true
			if !w.downscaled {
				return false
			}
		}
	}
	return matchedAny
}

func filterMatchingPods(sel map[string]string, pods []*corev1.Pod) []*corev1.Pod {
	var out []*corev1.Pod
	for _, p := range pods {
		if selectorMatchesLabels(sel, p.Labels) {
			out = append(out, p)
		}
	}
	return out
}

func selectorMatchesLabels(sel, labels map[string]string) bool {
	if len(sel) == 0 {
		return false
	}
	for k, v := range sel {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func nearestWorkloadHint(sel map[string]string, workloads []workloadTemplateInfo) string {
	bestName := ""
	bestScore := 0
	for i := range workloads {
		w := &workloads[i]
		score := 0
		for k, v := range sel {
			if w.labels[k] == v {
				score += 2
			} else if _, hasKey := w.labels[k]; hasKey {
				score++
			}
		}
		if score > bestScore || (score == bestScore && score > 0 && w.name < bestName) {
			bestScore = score
			bestName = w.name
		}
	}
	return bestName
}

func findMissingNamedTargetPort(svcPorts []corev1.ServicePort, matchingPods []*corev1.Pod) (string, bool) {
	var readyPods []*corev1.Pod
	for _, p := range matchingPods {
		if p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning && kube.PodReadyCond(p) {
			readyPods = append(readyPods, p)
		}
	}
	if len(readyPods) == 0 {
		return "", false
	}
	definedNames := map[string]bool{}
	for _, p := range readyPods {
		for i := range p.Spec.Containers {
			for j := range p.Spec.Containers[i].Ports {
				if n := p.Spec.Containers[i].Ports[j].Name; n != "" {
					definedNames[n] = true
				}
			}
		}
	}
	var badPorts []string
	for i := range svcPorts {
		sp := &svcPorts[i]
		if sp.TargetPort.Type == intstr.String && sp.TargetPort.StrVal != "" {
			if !definedNames[sp.TargetPort.StrVal] {
				badPorts = append(badPorts, sp.TargetPort.StrVal)
			}
		}
	}
	if len(badPorts) == 0 {
		return "", false
	}
	sort.Strings(badPorts)
	return strings.Join(badPorts, ","), true
}

func (c *serviceSelectorBlackholeCheck) emitBlackholeEvent(ctx context.Context, svc *corev1.Service, reason, note string, now time.Time) {
	key := svc.Namespace + "/" + svc.Name + "/" + reason
	if c.eventCooldown.CooledDown(key, serviceBlackholeEventCooldown, now) {
		return
	}
	if err := kube.EmitWarningEvent(ctx, c.CS, kube.WarningEvent{
		Namespace: svc.Namespace,
		Name:      fmt.Sprintf("%s.selector-blackhole.%d", svc.Name, now.Unix()),
		Reason:    "ServiceSelectorBlackhole",
		Note:      note,
		Regarding: corev1.ObjectReference{
			Kind:       "Service",
			APIVersion: "v1",
			Namespace:  svc.Namespace,
			Name:       svc.Name,
			UID:        svc.UID,
		},
		ReportingInstance: c.Name,
		Now:               now,
	}); err == nil {
		c.eventCooldown.Stamp(key, now)
	}
}
