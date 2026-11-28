// netpol_egress_lockout_guard.go — health check "netpol-egress-lockout-guard":
// detect-only guard identifying running Pods silently locked out of DNS
// (UDP/TCP 53) or Kubernetes APIServer egress (443/6443/kube-apiserver) by
// Kubernetes NetworkPolicies (networking.k8s.io/v1), CiliumNetworkPolicies,
// or CiliumClusterwideNetworkPolicies (cilium.io/v2).
//
// Evaluates the effective union of all Egress policies selecting each running
// Pod in a namespace so companion allow-DNS or allow-apiserver policies prevent
// false positives. When a Prometheus endpoint is configured (PromEndpointCtx),
// best-effort correlates Cilium "Policy denied" drops over 15m with policies
// created or modified within 15m.
//
// File layout: this file owns the check struct, Run sweep pipeline, policy
// listing, evaluation dispatch, APIServer need heuristic, and Warning Event
// emission; netpol_egress_lockout_rules.go holds the K8s NetworkPolicy and
// Cilium policy rule matchers.
package nethealth

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

const (
	// CheckNameNetpolEgressLockoutGuard is the registry check name for netpol-egress-lockout-guard.
	CheckNameNetpolEgressLockoutGuard = "netpol-egress-lockout-guard"

	netpolLockoutReasonDNS       = "dns_egress_blocked"
	netpolLockoutReasonAPIServer = "apiserver_egress_blocked"

	netpolLockoutEventReason     = "NetpolEgressLockout"
	netpolLockoutEventCooldown   = 30 * time.Minute
	netpolLockoutRecentPolicyAge = 15 * time.Minute
	netpolLockoutMaxEventPods    = 5
	netpolLockoutIgnoreAnno      = "passiontech.dev/ignore-netpol-egress-lockout"
	netpolLockoutNodeLocalDNSIP  = "169.254.20.10"

	netpolLockoutPromDropQuery = `sum by (namespace) (increase(cilium_drop_count_total{reason="Policy denied"}[15m]))`
)

var netpolLockoutGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_netpol_egress_lockout",
	Help: "1 while a running Pod is selected by Egress NetworkPolicy/CiliumNetworkPolicy that blocks DNS or APIServer egress.",
}, []string{"namespace", "pod", "reason"})

func init() {
	ctrlmetrics.Registry.MustRegister(netpolLockoutGauge)
}

type netpolLockoutCheck struct {
	*probefw.Deps

	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
}

// NewNetpolEgressLockoutGuardCheck constructs the netpol-egress-lockout-guard check.
func NewNetpolEgressLockoutGuardCheck(d *probefw.Deps) probefw.Check {
	return &netpolLockoutCheck{Deps: d}
}

type netpolLockoutPodVerdict struct {
	pod               *corev1.Pod
	reason            string
	selectingPolicies []string
}

type netpolLockoutPolicyMeta struct {
	displayName string
	createdAt   time.Time
}

type netpolLockoutCompiledNP struct {
	np     *networkingv1.NetworkPolicy
	podSel labels.Selector
}

type netpolLockoutParsedCNP struct {
	name        string
	namespace   string
	clusterwide bool
	createdAt   time.Time
	specs       []map[string]any
}

func (c *netpolLockoutCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, netpolLockoutEventCooldown)

	pods, err := c.AllPods(ctx)
	if err != nil {
		return netpolLockoutCarryOnErr(&c.emitted, fmt.Errorf("list pods: %w", err))
	}

	podsByNS := make(map[string][]*corev1.Pod)
	for i := range pods {
		p := &pods[i]
		if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || p.Spec.HostNetwork {
			continue
		}
		podsByNS[p.Namespace] = append(podsByNS[p.Namespace], p)
	}
	if len(podsByNS) == 0 {
		var empty probefw.SweepReport
		return empty.Result(&c.emitted, netpolLockoutGauge.DeleteLabelValues,
			"networkpolicy egress lockout: ", ", ")
	}

	var rep probefw.SweepReport

	nps, npBlocked, npErr := c.netpolLockoutListNetworkPolicies(ctx, log)
	if npErr != nil {
		return netpolLockoutCarryOnErr(&c.emitted, npErr)
	}

	cnps, cnpBlocked, cnpErr := c.netpolLockoutListCiliumPolicies(ctx, log,
		kube.GVRCiliumNetworkPolicy, "CiliumNetworkPolicy")
	if cnpErr != nil {
		return netpolLockoutCarryOnErr(&c.emitted, cnpErr)
	}

	ccnps, ccnpBlocked, ccnpErr := c.netpolLockoutListCiliumPolicies(ctx, log,
		kube.GVRCiliumClusterwideNetworkPolicy, "CiliumClusterwideNetworkPolicy")
	if ccnpErr != nil {
		return netpolLockoutCarryOnErr(&c.emitted, ccnpErr)
	}

	if npBlocked || cnpBlocked || ccnpBlocked {
		for k, lv := range c.emitted.Last() {
			rep.Carry(k, lv)
		}
		return rep.Result(&c.emitted, netpolLockoutGauge.DeleteLabelValues,
			"networkpolicy egress lockout: ", ", ")
	}

	var kubeSystemLabels map[string]string
	if namespaces, nsErr := c.AllNamespaces(ctx); nsErr == nil {
		for i := range namespaces {
			if namespaces[i].Name == "kube-system" {
				kubeSystemLabels = namespaces[i].Labels
				break
			}
		}
	}

	npsByNS := make(map[string][]netpolLockoutCompiledNP)
	for i := range nps {
		np := &nps[i]
		if !kube.NetworkPolicyAffectsEgress(np) {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
		if err != nil {
			continue
		}
		npsByNS[np.Namespace] = append(npsByNS[np.Namespace], netpolLockoutCompiledNP{
			np:     np,
			podSel: sel,
		})
	}

	cnpsByNS := make(map[string][]netpolLockoutParsedCNP)
	for i := range cnps {
		u := &cnps[i]
		if parsed, ok := parseCiliumEgressPolicy(u, false); ok {
			cnpsByNS[u.GetNamespace()] = append(cnpsByNS[u.GetNamespace()], parsed)
		}
	}

	var parsedCCNPs []netpolLockoutParsedCNP
	ccnpByName := make(map[string]netpolLockoutPolicyMeta)
	for i := range ccnps {
		u := &ccnps[i]
		if parsed, ok := parseCiliumEgressPolicy(u, true); ok {
			parsedCCNPs = append(parsedCCNPs, parsed)
			ccnpByName["CiliumClusterwideNetworkPolicy/"+parsed.name] = netpolLockoutPolicyMeta{
				displayName: "CiliumClusterwideNetworkPolicy/" + parsed.name,
				createdAt:   parsed.createdAt,
			}
		}
	}

	verdictsByNS := make(map[string]map[string][]netpolLockoutPodVerdict)
	policyMetaByNS := make(map[string][]netpolLockoutPolicyMeta)
	hasFindings := false

	for ns, nsPods := range podsByNS {
		nsNPs := npsByNS[ns]
		nsCNPs := cnpsByNS[ns]
		if len(nsNPs) == 0 && len(nsCNPs) == 0 && len(parsedCCNPs) == 0 {
			continue
		}
		for _, cnp := range nsNPs {
			policyMetaByNS[ns] = append(policyMetaByNS[ns], netpolLockoutPolicyMeta{
				displayName: "NetworkPolicy/" + cnp.np.Name,
				createdAt:   cnp.np.CreationTimestamp.Time,
			})
		}
		for _, cnp := range nsCNPs {
			policyMetaByNS[ns] = append(policyMetaByNS[ns], netpolLockoutPolicyMeta{
				displayName: "CiliumNetworkPolicy/" + cnp.name,
				createdAt:   cnp.createdAt,
			})
		}

		seenCCNP := map[string]bool{}
		for _, pod := range nsPods {
			if strings.EqualFold(strings.TrimSpace(kube.EffectiveAnno(ctx, pod, netpolLockoutIgnoreAnno)), "true") {
				continue
			}
			selected, dnsAllowed, apiAllowed, matchedPolicies := netpolLockoutEvaluatePod(
				pod, nsNPs, nsCNPs, parsedCCNPs, kubeSystemLabels,
			)
			if !selected {
				continue
			}
			for _, mp := range matchedPolicies {
				if pm, ok := ccnpByName[mp]; ok && !seenCCNP[mp] {
					seenCCNP[mp] = true
					policyMetaByNS[ns] = append(policyMetaByNS[ns], pm)
				}
			}
			if !dnsAllowed {
				hasFindings = true
				if verdictsByNS[ns] == nil {
					verdictsByNS[ns] = make(map[string][]netpolLockoutPodVerdict)
				}
				verdictsByNS[ns][netpolLockoutReasonDNS] = append(verdictsByNS[ns][netpolLockoutReasonDNS], netpolLockoutPodVerdict{
					pod:               pod,
					reason:            netpolLockoutReasonDNS,
					selectingPolicies: matchedPolicies,
				})
			}
			if !apiAllowed && netpolLockoutNeedsAPIServer(pod) {
				hasFindings = true
				if verdictsByNS[ns] == nil {
					verdictsByNS[ns] = make(map[string][]netpolLockoutPodVerdict)
				}
				verdictsByNS[ns][netpolLockoutReasonAPIServer] = append(verdictsByNS[ns][netpolLockoutReasonAPIServer], netpolLockoutPodVerdict{
					pod:               pod,
					reason:            netpolLockoutReasonAPIServer,
					selectingPolicies: matchedPolicies,
				})
			}
		}
	}

	var dropsByNS map[string]float64
	if hasFindings {
		dropsByNS = c.netpolLockoutQueryPolicyDrops(ctx, log)
	}

	nsNames := make([]string, 0, len(verdictsByNS))
	for ns := range verdictsByNS {
		nsNames = append(nsNames, ns)
	}
	sort.Strings(nsNames)

	for _, ns := range nsNames {
		dropCount := dropsByNS[ns]
		var recentPolicies []string
		if dropCount > 0 {
			for _, pm := range policyMetaByNS[ns] {
				if !pm.createdAt.IsZero() && now.Sub(pm.createdAt) >= 0 && now.Sub(pm.createdAt) < netpolLockoutRecentPolicyAge {
					recentPolicies = append(recentPolicies, pm.displayName)
				}
			}
			sort.Strings(recentPolicies)
		}

		corrNote := ""
		if len(recentPolicies) > 0 {
			corrNote = fmt.Sprintf("; recent policy %s correlated with %.0f cilium policy drops/15m",
				strings.Join(recentPolicies, ","), dropCount)
		}

		for _, reason := range []string{netpolLockoutReasonDNS, netpolLockoutReasonAPIServer} {
			verdicts := verdictsByNS[ns][reason]
			if len(verdicts) == 0 {
				continue
			}
			sort.Slice(verdicts, func(i, j int) bool {
				return verdicts[i].pod.Name < verdicts[j].pod.Name
			})

			podNames := make([]string, 0, len(verdicts))
			policySet := make(map[string]bool)
			for _, v := range verdicts {
				podNames = append(podNames, v.pod.Name)
				for _, pn := range v.selectingPolicies {
					policySet[pn] = true
				}
				tupleKey := ns + "/" + v.pod.Name + "/" + reason
				detail := fmt.Sprintf("%s/%s (%s; policies=%s%s)",
					ns, v.pod.Name, reason, strings.Join(v.selectingPolicies, ","), corrNote)
				rep.Emit(netpolLockoutGauge, tupleKey, []string{ns, v.pod.Name, reason}, detail)
			}

			policies := make([]string, 0, len(policySet))
			for pn := range policySet {
				policies = append(policies, pn)
			}
			sort.Strings(policies)

			c.netpolLockoutEmitWarning(ctx, log, now, ns, reason, verdicts[0].pod, podNames, policies, corrNote)
		}
	}

	return rep.Result(&c.emitted, netpolLockoutGauge.DeleteLabelValues,
		"networkpolicy egress lockout: ", ", ")
}

func netpolLockoutCarryOnErr(ledger *state.GaugeLedger[string], err error) probefw.Result {
	var rep probefw.SweepReport
	for k, lv := range ledger.Last() {
		rep.Carry(k, lv)
	}
	rep.InfraErr(err)
	return rep.Result(ledger, netpolLockoutGauge.DeleteLabelValues,
		"networkpolicy egress lockout: ", ", ")
}

func (c *netpolLockoutCheck) netpolLockoutListNetworkPolicies(
	ctx context.Context,
	log logr.Logger,
) (nps []networkingv1.NetworkPolicy, blocked bool, infraErr error) {
	items, err := c.AllNetworkPolicies(ctx)
	if err != nil {
		if apierrors.IsForbidden(err) || kube.IsCRDAbsent(err) {
			log.V(1).Info("NetworkPolicy list skipped", "error", err)
			return nil, true, nil
		}
		return nil, true, fmt.Errorf("list networkpolicies: %w", err)
	}
	return items, false, nil
}

func (c *netpolLockoutCheck) netpolLockoutListCiliumPolicies(
	ctx context.Context,
	log logr.Logger,
	gvr schema.GroupVersionResource,
	kind string,
) (cnps []unstructured.Unstructured, blocked bool, infraErr error) {
	if c.Dyn == nil {
		return nil, false, nil
	}
	items, err := c.AllUnstructured(ctx, gvr)
	if err != nil {
		if kube.IsCRDAbsent(err) {
			return nil, false, nil
		}
		if apierrors.IsForbidden(err) {
			log.V(1).Info(kind+" list skipped (403)", "error", err)
			return nil, true, nil
		}
		return nil, true, fmt.Errorf("list %s: %w", gvr.Resource, err)
	}
	return items, false, nil
}

func (c *netpolLockoutCheck) netpolLockoutQueryPolicyDrops(ctx context.Context, log logr.Logger) map[string]float64 {
	if _, err := c.PromEndpointCtx(ctx); err != nil {
		return nil
	}
	samples, err := c.PromQuery(ctx, netpolLockoutPromDropQuery)
	if err != nil {
		log.V(1).Info("cilium policy drop PromQL correlation skipped", "error", err)
		return nil
	}
	out := make(map[string]float64, len(samples))
	for _, s := range samples {
		ns := s.Label("namespace")
		if ns != "" && s.Value > 0 {
			out[ns] += s.Value
		}
	}
	return out
}

func (c *netpolLockoutCheck) netpolLockoutEmitWarning(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	ns string,
	reason string,
	samplePod *corev1.Pod,
	podNames []string,
	policies []string,
	corrNote string,
) {
	cooldownKey := "netpol-lockout." + ns + "." + reason
	shown := podNames
	extra := ""
	if len(shown) > netpolLockoutMaxEventPods {
		extra = fmt.Sprintf(" (+%d more)", len(shown)-netpolLockoutMaxEventPods)
		shown = shown[:netpolLockoutMaxEventPods]
	}
	note := fmt.Sprintf("Pods [%s]%s in namespace %s are selected by egress policies [%s] with %s%s",
		strings.Join(shown, ","), extra, ns, strings.Join(policies, ","), reason, corrNote)

	probefw.EmitWarningDeduped(ctx, c.CS, log, &c.eventCooldown, cooldownKey, netpolLockoutEventCooldown, now, kube.WarningEvent{
		Namespace: ns,
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Pod",
			Namespace:  samplePod.Namespace,
			Name:       samplePod.Name,
			UID:        samplePod.UID,
		},
		Reason:            netpolLockoutEventReason,
		Note:              note,
		ReportingInstance: c.Name,
	})
}

func netpolLockoutEvaluatePod(
	pod *corev1.Pod,
	nsNPs []netpolLockoutCompiledNP,
	nsCNPs []netpolLockoutParsedCNP,
	ccnps []netpolLockoutParsedCNP,
	kubeSystemLabels map[string]string,
) (selected, dnsAllowed, apiAllowed bool, matchedPolicies []string) {
	podLabels := labels.Set(pod.Labels)
	hasAllowPolicy := false
	dnsDenied := false
	apiDenied := false

	for _, cnp := range nsNPs {
		if !cnp.podSel.Matches(podLabels) {
			continue
		}
		np := cnp.np
		hasAllowPolicy = true
		matchedPolicies = append(matchedPolicies, "NetworkPolicy/"+np.Name)
		for i := range np.Spec.Egress {
			rule := &np.Spec.Egress[i]
			if netpolLockoutNPRuleAllowsDNS(rule, np.Namespace, kubeSystemLabels) {
				dnsAllowed = true
			}
			if netpolLockoutNPRuleAllowsAPIServer(rule) {
				apiAllowed = true
			}
		}
	}

	evalCiliumList := func(list []netpolLockoutParsedCNP, prefix string) {
		for _, cnp := range list {
			cnpMatched := false
			for _, sp := range cnp.specs {
				if !kube.CiliumSpecMatchesPod(sp, pod.Namespace, podLabels, cnp.clusterwide) {
					continue
				}
				egressRules := netpolLockoutCiliumEgressRules(sp)
				egressDenyRules := netpolLockoutCiliumEgressDenyRules(sp)
				if _, hasAllow := sp["egress"]; hasAllow {
					hasAllowPolicy = true
					cnpMatched = true
					for _, rule := range egressRules {
						if netpolLockoutCiliumRuleAllowsDNS(rule, cnp.namespace) {
							dnsAllowed = true
						}
						if netpolLockoutCiliumRuleAllowsAPIServer(rule, cnp.namespace) {
							apiAllowed = true
						}
					}
				}
				for _, denyRule := range egressDenyRules {
					if netpolLockoutCiliumDenyRuleBlocksDNS(denyRule, cnp.namespace) {
						dnsDenied = true
						cnpMatched = true
					}
					if netpolLockoutCiliumDenyRuleBlocksAPIServer(denyRule, cnp.namespace) {
						apiDenied = true
						cnpMatched = true
					}
				}
			}
			if cnpMatched {
				matchedPolicies = append(matchedPolicies, prefix+cnp.name)
			}
		}
	}
	evalCiliumList(nsCNPs, "CiliumNetworkPolicy/")
	evalCiliumList(ccnps, "CiliumClusterwideNetworkPolicy/")

	if !hasAllowPolicy && !dnsDenied && !apiDenied {
		return false, true, true, nil
	}
	if !hasAllowPolicy {
		dnsAllowed = !dnsDenied
		apiAllowed = !apiDenied
	} else {
		if dnsDenied {
			dnsAllowed = false
		}
		if apiDenied {
			apiAllowed = false
		}
	}

	sort.Strings(matchedPolicies)
	return true, dnsAllowed, apiAllowed, matchedPolicies
}

func netpolLockoutNeedsAPIServer(pod *corev1.Pod) bool {
	if pod.Spec.AutomountServiceAccountToken != nil && !*pod.Spec.AutomountServiceAccountToken {
		return false
	}
	if pod.Spec.AutomountServiceAccountToken != nil && *pod.Spec.AutomountServiceAccountToken {
		return true
	}
	for _, c := range append(slices.Clone(pod.Spec.InitContainers), pod.Spec.Containers...) {
		for _, env := range c.Env {
			if env.Name == "KUBERNETES_SERVICE_HOST" || env.Name == "KUBERNETES_PORT" || env.Name == "KUBECONFIG" {
				return true
			}
		}
		for _, arg := range append(slices.Clone(c.Command), c.Args...) {
			lower := strings.ToLower(arg)
			if strings.Contains(lower, "kube-apiserver") || strings.Contains(lower, "leader-elect") {
				return true
			}
		}
	}
	candidates := []string{
		pod.Name,
		pod.Labels["app"],
		pod.Labels["app.kubernetes.io/name"],
		pod.Labels["app.kubernetes.io/component"],
		pod.Labels["k8s-app"],
		pod.Labels["control-plane"],
	}
	for _, s := range candidates {
		lower := strings.ToLower(s)
		for _, tok := range []string{
			"controller", "operator", "webhook", "cert-manager",
			"external-secrets", "argocd", "flux", "keda", "linkerd",
			"cilium", "autoscaler", "velero", "kyverno", "kube-apiserver",
		} {
			if strings.Contains(lower, tok) {
				return true
			}
		}
	}
	return false
}
