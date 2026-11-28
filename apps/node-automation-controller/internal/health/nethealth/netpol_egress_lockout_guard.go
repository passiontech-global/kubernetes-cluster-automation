// netpol_egress_lockout_guard.go — health check "netpol-egress-lockout-guard":
// detect-only guard identifying running Pods silently locked out of DNS
// (UDP/TCP 53) or Kubernetes APIServer egress (443/6443/kube-apiserver) by
// Kubernetes NetworkPolicies (networking.k8s.io/v1) or CiliumNetworkPolicies
// (cilium.io/v2).
//
// Evaluates the effective union of all Egress policies selecting each running
// Pod in a namespace so companion allow-DNS or allow-apiserver policies prevent
// false positives. When a Prometheus endpoint is configured (PromEndpointCtx),
// best-effort correlates Cilium "Policy denied" drops over 15m with policies
// created or modified within 15m.
package nethealth

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
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
	"k8s.io/apimachinery/pkg/util/intstr"
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

type netpolLockoutParsedCNP struct {
	name      string
	namespace string
	createdAt time.Time
	specs     []map[string]any
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

	cnps, cnpBlocked, cnpErr := c.netpolLockoutListCiliumPolicies(ctx, log)
	if cnpErr != nil {
		return netpolLockoutCarryOnErr(&c.emitted, cnpErr)
	}

	// If both policy sources were RBAC-blocked, carry held tuples and avoid false clearing.
	if npBlocked && cnpBlocked {
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

	npsByNS := make(map[string][]*networkingv1.NetworkPolicy)
	for i := range nps {
		np := &nps[i]
		if netpolLockoutNPAffectsEgress(np) {
			npsByNS[np.Namespace] = append(npsByNS[np.Namespace], np)
		}
	}

	cnpsByNS := make(map[string][]netpolLockoutParsedCNP)
	for i := range cnps {
		u := &cnps[i]
		specs := netpolLockoutExtractCiliumSpecs(u)
		var egressSpecs []map[string]any
		for _, sp := range specs {
			if netpolLockoutCiliumSpecHasEgress(sp) {
				egressSpecs = append(egressSpecs, sp)
			}
		}
		if len(egressSpecs) > 0 {
			cnpsByNS[u.GetNamespace()] = append(cnpsByNS[u.GetNamespace()], netpolLockoutParsedCNP{
				name:      u.GetName(),
				namespace: u.GetNamespace(),
				createdAt: u.GetCreationTimestamp().Time,
				specs:     egressSpecs,
			})
		}
	}

	var verdictsByNS = make(map[string]map[string][]netpolLockoutPodVerdict)
	policyMetaByNS := make(map[string][]netpolLockoutPolicyMeta)
	hasFindings := false

	for ns, nsPods := range podsByNS {
		nsNPs := npsByNS[ns]
		nsCNPs := cnpsByNS[ns]
		if len(nsNPs) == 0 && len(nsCNPs) == 0 {
			continue
		}
		for _, np := range nsNPs {
			policyMetaByNS[ns] = append(policyMetaByNS[ns], netpolLockoutPolicyMeta{
				displayName: "NetworkPolicy/" + np.Name,
				createdAt:   np.CreationTimestamp.Time,
			})
		}
		for _, cnp := range nsCNPs {
			policyMetaByNS[ns] = append(policyMetaByNS[ns], netpolLockoutPolicyMeta{
				displayName: "CiliumNetworkPolicy/" + cnp.name,
				createdAt:   cnp.createdAt,
			})
		}

		for _, pod := range nsPods {
			if strings.EqualFold(strings.TrimSpace(kube.EffectiveAnno(ctx, pod, netpolLockoutIgnoreAnno)), "true") {
				continue
			}
			selected, dnsAllowed, apiAllowed, matchedPolicies := netpolLockoutEvaluatePod(
				pod, nsNPs, nsCNPs, kubeSystemLabels,
			)
			if !selected {
				continue
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
	items, err := kube.ListAll(ctx,
		metav1.ListOptions{
			Limit:           kube.DefaultListPageSize,
			ResourceVersion: "0",
		},
		kube.NetworkPolicies(c.CS, metav1.NamespaceAll))
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
) (cnps []unstructured.Unstructured, blocked bool, infraErr error) {
	if c.Dyn == nil {
		return nil, false, nil
	}
	items, err := c.AllUnstructured(ctx, kube.GVRCiliumNetworkPolicy)
	if err != nil {
		if kube.IsCRDAbsent(err) {
			return nil, false, nil
		}
		if apierrors.IsForbidden(err) {
			log.V(1).Info("CiliumNetworkPolicy list skipped (403)", "error", err)
			return nil, true, nil
		}
		return nil, true, fmt.Errorf("list ciliumnetworkpolicies: %w", err)
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
	if c.eventCooldown.CooledDown(cooldownKey, netpolLockoutEventCooldown, now) {
		return
	}
	shown := podNames
	extra := ""
	if len(shown) > netpolLockoutMaxEventPods {
		extra = fmt.Sprintf(" (+%d more)", len(shown)-netpolLockoutMaxEventPods)
		shown = shown[:netpolLockoutMaxEventPods]
	}
	note := fmt.Sprintf("Pods [%s]%s in namespace %s are selected by egress policies [%s] with %s%s",
		strings.Join(shown, ","), extra, ns, strings.Join(policies, ","), reason, corrNote)

	if err := kube.EmitWarningEvent(ctx, c.CS, kube.WarningEvent{
		Name:      kube.TruncatedEventName(cooldownKey, cooldownKey, now),
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
		Now:               now,
	}); err != nil {
		log.Info("WARN: NetpolEgressLockout event create failed (RBAC?)", "namespace", ns, "error", err)
		return
	}
	c.eventCooldown.Stamp(cooldownKey, now)
	log.Info("EVENT: NetpolEgressLockout", "namespace", ns, "reason", reason, "pods", len(podNames))
}

func netpolLockoutEvaluatePod(
	pod *corev1.Pod,
	nsNPs []*networkingv1.NetworkPolicy,
	nsCNPs []netpolLockoutParsedCNP,
	kubeSystemLabels map[string]string,
) (selected, dnsAllowed, apiAllowed bool, matchedPolicies []string) {
	podLabels := labels.Set(pod.Labels)
	hasAllowPolicy := false
	dnsDenied := false
	apiDenied := false

	for _, np := range nsNPs {
		sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
		if err != nil || !sel.Matches(podLabels) {
			continue
		}
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

	for _, cnp := range nsCNPs {
		cnpMatched := false
		for _, sp := range cnp.specs {
			if !netpolLockoutCiliumSpecMatchesPod(sp, pod.Namespace, podLabels) {
				continue
			}
			if _, hasEgress := sp["egress"]; hasEgress && sp["egress"] != nil {
				hasAllowPolicy = true
				cnpMatched = true
				for _, rule := range netpolLockoutCiliumEgressRules(sp) {
					if netpolLockoutCiliumRuleAllowsDNS(rule, cnp.namespace) {
						dnsAllowed = true
					}
					if netpolLockoutCiliumRuleAllowsAPIServer(rule, cnp.namespace) {
						apiAllowed = true
					}
				}
			}
			for _, denyRule := range netpolLockoutCiliumEgressDenyRules(sp) {
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
			matchedPolicies = append(matchedPolicies, "CiliumNetworkPolicy/"+cnp.name)
		}
	}

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

func netpolLockoutNPAffectsEgress(np *networkingv1.NetworkPolicy) bool {
	if len(np.Spec.PolicyTypes) == 0 {
		return len(np.Spec.Egress) > 0
	}
	return slices.Contains(np.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)
}

func netpolLockoutNPRuleAllowsDNS(rule *networkingv1.NetworkPolicyEgressRule, policyNS string, kubeSystemLabels map[string]string) bool {
	if !netpolLockoutNPPortsAllowDNS(rule.Ports) {
		return false
	}
	if len(rule.To) == 0 {
		return true
	}
	for i := range rule.To {
		if netpolLockoutNPPeerAllowsDNS(&rule.To[i], policyNS, kubeSystemLabels) {
			return true
		}
	}
	return false
}

func netpolLockoutNPPortsAllowDNS(ports []networkingv1.NetworkPolicyPort) bool {
	if len(ports) == 0 {
		return true
	}
	for i := range ports {
		p := &ports[i]
		if p.Protocol != nil && *p.Protocol == corev1.ProtocolSCTP {
			continue
		}
		if netpolLockoutNPPortMatches(p, 53, "dns", "dns-udp", "dns-tcp") {
			return true
		}
	}
	return false
}

func netpolLockoutIPBlockEffective(ib *networkingv1.IPBlock) bool {
	if ib == nil || ib.CIDR == "" {
		return false
	}
	return !slices.Contains(ib.Except, ib.CIDR)
}

func netpolLockoutNPPeerAllowsDNS(peer *networkingv1.NetworkPolicyPeer, policyNS string, kubeSystemLabels map[string]string) bool {
	if peer.IPBlock != nil {
		return netpolLockoutIPBlockEffective(peer.IPBlock)
	}
	if peer.NamespaceSelector != nil {
		if !netpolLockoutMatchesKubeSystem(peer.NamespaceSelector, kubeSystemLabels) {
			return false
		}
		if peer.PodSelector == nil {
			return true
		}
		return netpolLockoutPodSelectorAllowsDNS(peer.PodSelector)
	}
	if peer.PodSelector != nil {
		// Same-namespace PodSelector only reaches DNS if the policy is already in kube-system.
		if policyNS == "kube-system" {
			return netpolLockoutPodSelectorAllowsDNS(peer.PodSelector)
		}
		return false
	}
	return false
}

func netpolLockoutMatchesKubeSystem(nsSel *metav1.LabelSelector, kubeSystemLabels map[string]string) bool {
	sel, err := metav1.LabelSelectorAsSelector(nsSel)
	if err != nil {
		return false
	}
	if sel.Empty() {
		return true
	}
	if len(kubeSystemLabels) > 0 && sel.Matches(labels.Set(kubeSystemLabels)) {
		return true
	}
	// Standard Kubernetes 1.21+ immutable namespace label + common fallback labels.
	synthetic := labels.Set{
		"kubernetes.io/metadata.name": "kube-system",
		"name":                        "kube-system",
	}
	return sel.Matches(synthetic)
}

func netpolLockoutPodSelectorAllowsDNS(podSel *metav1.LabelSelector) bool {
	sel, err := metav1.LabelSelectorAsSelector(podSel)
	if err != nil {
		return false
	}
	if sel.Empty() {
		return true
	}
	for _, candidate := range []labels.Set{
		{"k8s-app": "kube-dns"},
		{"app.kubernetes.io/name": "coredns"},
		{"app": "coredns"},
		{"k8s-app": "coredns"},
	} {
		if sel.Matches(candidate) {
			return true
		}
	}
	return false
}

func netpolLockoutNPRuleAllowsAPIServer(rule *networkingv1.NetworkPolicyEgressRule) bool {
	if !netpolLockoutNPPortsAllowAPIServer(rule.Ports) {
		return false
	}
	if len(rule.To) == 0 {
		return true
	}
	for i := range rule.To {
		peer := &rule.To[i]
		if netpolLockoutIPBlockEffective(peer.IPBlock) {
			if pfx, err := netip.ParsePrefix(peer.IPBlock.CIDR); err == nil {
				nodeLocalAddr := netip.MustParseAddr(netpolLockoutNodeLocalDNSIP)
				if pfx.Bits() == 32 && pfx.Addr() == nodeLocalAddr {
					continue
				}
			}
			return true
		}
		if peer.NamespaceSelector != nil {
			if sel, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector); err == nil && sel.Empty() {
				if peer.PodSelector == nil {
					return true
				}
				if psel, err := metav1.LabelSelectorAsSelector(peer.PodSelector); err == nil && psel.Empty() {
					return true
				}
			}
		}
	}
	return false
}

func netpolLockoutNPPortsAllowAPIServer(ports []networkingv1.NetworkPolicyPort) bool {
	if len(ports) == 0 {
		return true
	}
	for i := range ports {
		p := &ports[i]
		if p.Protocol != nil && *p.Protocol == corev1.ProtocolUDP {
			continue
		}
		if netpolLockoutNPPortMatches(p, 443, "https", "apiserver") ||
			netpolLockoutNPPortMatches(p, 6443, "https", "apiserver") {
			return true
		}
	}
	return false
}

func netpolLockoutNPPortMatches(p *networkingv1.NetworkPolicyPort, target int32, named ...string) bool {
	if p.Port == nil {
		return true
	}
	if p.Port.Type == intstr.Int {
		start := p.Port.IntVal
		end := start
		if p.EndPort != nil && *p.EndPort >= start {
			end = *p.EndPort
		}
		return target >= start && target <= end
	}
	name := strings.ToLower(p.Port.StrVal)
	return slices.Contains(named, name)
}

func netpolLockoutExtractCiliumSpecs(u *unstructured.Unstructured) []map[string]any {
	var out []map[string]any
	if sp, ok := kube.NestedMap(u.Object, "spec"); ok {
		out = append(out, sp)
	}
	if specs, ok := kube.NestedSlice(u.Object, "specs"); ok {
		for _, item := range specs {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

func netpolLockoutCiliumSpecHasEgress(sp map[string]any) bool {
	if v, ok := sp["egress"]; ok && v != nil {
		return true
	}
	if v, ok := sp["egressDeny"]; ok && v != nil {
		return true
	}
	return false
}

func netpolLockoutCiliumSpecMatchesPod(sp map[string]any, ns string, podLabels labels.Set) bool {
	epRaw, hasEP := sp["endpointSelector"].(map[string]any)
	if !hasEP {
		// CiliumNetworkPolicy with empty/omitted endpointSelector defaults to selecting all endpoints in namespace.
		return sp["nodeSelector"] == nil
	}
	ls, ok := netpolLockoutCiliumSelectorToK8s(epRaw, ns)
	if !ok {
		return false
	}
	sel, err := metav1.LabelSelectorAsSelector(ls)
	if err != nil {
		return false
	}
	return sel.Matches(podLabels)
}

func netpolLockoutCiliumSelectorToK8s(raw map[string]any, ns string) (*metav1.LabelSelector, bool) {
	ls := &metav1.LabelSelector{}
	if mlRaw, ok := raw["matchLabels"].(map[string]any); ok {
		ml := make(map[string]string, len(mlRaw))
		for k, v := range mlRaw {
			vs, ok := v.(string)
			if !ok {
				return nil, false
			}
			cleanKey := strings.TrimPrefix(k, "k8s:")
			if cleanKey == "io.kubernetes.pod.namespace" {
				if vs != ns {
					return nil, false
				}
				continue
			}
			if strings.HasPrefix(cleanKey, "reserved:") {
				return nil, false
			}
			ml[cleanKey] = vs
		}
		if len(ml) > 0 {
			ls.MatchLabels = ml
		}
	}
	if exprsRaw, ok := raw["matchExpressions"].([]any); ok {
		for _, item := range exprsRaw {
			m, ok := item.(map[string]any)
			if !ok {
				return nil, false
			}
			key, _ := m["key"].(string)
			op, _ := m["operator"].(string)
			key = strings.TrimPrefix(key, "k8s:")
			if strings.HasPrefix(key, "reserved:") {
				return nil, false
			}
			var vals []string
			switch vs := m["values"].(type) {
			case []any:
				for _, v := range vs {
					if s, ok := v.(string); ok {
						vals = append(vals, s)
					}
				}
			case []string:
				vals = append(vals, vs...)
			}
			if key == "io.kubernetes.pod.namespace" {
				if !netpolLockoutCiliumNSExprMatches(ns, metav1.LabelSelectorOperator(op), vals) {
					return nil, false
				}
				continue
			}
			ls.MatchExpressions = append(ls.MatchExpressions, metav1.LabelSelectorRequirement{
				Key:      key,
				Operator: metav1.LabelSelectorOperator(op),
				Values:   vals,
			})
		}
	}
	return ls, true
}

func netpolLockoutCiliumNSExprMatches(ns string, op metav1.LabelSelectorOperator, vals []string) bool {
	switch op {
	case metav1.LabelSelectorOpIn:
		return slices.Contains(vals, ns)
	case metav1.LabelSelectorOpNotIn:
		return !slices.Contains(vals, ns)
	case metav1.LabelSelectorOpExists:
		return ns != ""
	case metav1.LabelSelectorOpDoesNotExist:
		return false
	default:
		return false
	}
}

func netpolLockoutCiliumEgressRules(sp map[string]any) []map[string]any {
	raw, ok := sp["egress"].([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func netpolLockoutCiliumEgressDenyRules(sp map[string]any) []map[string]any {
	raw, ok := sp["egressDeny"].([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func netpolLockoutCiliumSelectorMentionsNS(raw map[string]any) bool {
	if mlRaw, ok := raw["matchLabels"].(map[string]any); ok {
		for k := range mlRaw {
			if strings.TrimPrefix(k, "k8s:") == "io.kubernetes.pod.namespace" {
				return true
			}
		}
	}
	if exprsRaw, ok := raw["matchExpressions"].([]any); ok {
		for _, item := range exprsRaw {
			if m, ok := item.(map[string]any); ok {
				if key, _ := m["key"].(string); strings.TrimPrefix(key, "k8s:") == "io.kubernetes.pod.namespace" {
					return true
				}
			}
		}
	}
	return false
}

func netpolLockoutCiliumRuleIsAllowAll(rule map[string]any) bool {
	for _, key := range []string{
		"toEndpoints", "toEntities", "toCIDR", "toCIDRSet",
		"toServices", "toFQDNs", "toGroups", "toPorts", "icmps",
	} {
		if v, exists := rule[key]; exists && v != nil {
			switch tv := v.(type) {
			case []any:
				if len(tv) > 0 {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}

func netpolLockoutCiliumRuleAllowsDNS(rule map[string]any, policyNS string) bool {
	if netpolLockoutCiliumRuleIsAllowAll(rule) {
		return true
	}
	if !netpolLockoutCiliumToPortsAllows(rule, 53, "dns", "dns-udp", "dns-tcp") {
		return false
	}

	hasDest := false
	if ents := netpolLockoutCiliumStringSlice(rule["toEntities"]); len(ents) > 0 {
		hasDest = true
		for _, ent := range ents {
			switch strings.ToLower(ent) {
			case "world", "cluster", "all":
				return true
			}
		}
	}
	if eps, ok := rule["toEndpoints"].([]any); ok && len(eps) > 0 {
		hasDest = true
		for _, item := range eps {
			epMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if netpolLockoutCiliumEndpointSelectsDNS(epMap, policyNS) {
				return true
			}
		}
	}
	if cidrs, ok := rule["toCIDR"].([]any); ok && len(cidrs) > 0 {
		return true
	}
	if cidrSet, ok := rule["toCIDRSet"].([]any); ok && len(cidrSet) > 0 {
		return true
	}
	if svcs, ok := rule["toServices"].([]any); ok && len(svcs) > 0 {
		hasDest = true
		for _, item := range svcs {
			if m, ok := item.(map[string]any); ok {
				if k8sSvc, ok := m["k8sService"].(map[string]any); ok {
					svcName, _ := k8sSvc["serviceName"].(string)
					if svcName == "kube-dns" || svcName == "coredns" {
						return true
					}
				}
			}
		}
	}
	// If no destination constraint is set, toPorts alone (which already passed port 53) permits DNS.
	return !hasDest
}

func netpolLockoutCiliumRuleAllowsAPIServer(rule map[string]any, policyNS string) bool {
	if netpolLockoutCiliumRuleIsAllowAll(rule) {
		return true
	}
	if !netpolLockoutCiliumToPortsAllows(rule, 443, "https", "apiserver") &&
		!netpolLockoutCiliumToPortsAllows(rule, 6443, "https", "apiserver") {
		return false
	}

	hasDest := false
	if ents := netpolLockoutCiliumStringSlice(rule["toEntities"]); len(ents) > 0 {
		hasDest = true
		for _, ent := range ents {
			switch strings.ToLower(ent) {
			case "kube-apiserver", "world", "cluster", "all", "host", "remote-node":
				return true
			}
		}
	}
	if cidrs, ok := rule["toCIDR"].([]any); ok && len(cidrs) > 0 {
		return true
	}
	if cidrSet, ok := rule["toCIDRSet"].([]any); ok && len(cidrSet) > 0 {
		return true
	}
	if svcs, ok := rule["toServices"].([]any); ok && len(svcs) > 0 {
		hasDest = true
		for _, item := range svcs {
			if m, ok := item.(map[string]any); ok {
				if k8sSvc, ok := m["k8sService"].(map[string]any); ok {
					svcName, _ := k8sSvc["serviceName"].(string)
					nsName, _ := k8sSvc["namespace"].(string)
					if svcName == "kubernetes" && (nsName == "default" || (nsName == "" && policyNS == "default")) {
						return true
					}
				}
			}
		}
	}
	if eps, ok := rule["toEndpoints"].([]any); ok && len(eps) > 0 {
		hasDest = true
		for _, item := range eps {
			epMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if policyNS != "default" && !netpolLockoutCiliumSelectorMentionsNS(epMap) {
				continue
			}
			if ls, ok := netpolLockoutCiliumSelectorToK8s(epMap, "default"); ok {
				if sel, err := metav1.LabelSelectorAsSelector(ls); err == nil && sel.Empty() {
					return true
				}
			}
		}
	}
	return !hasDest
}

func netpolLockoutCiliumDenyRuleBlocksDNS(rule map[string]any, policyNS string) bool {
	if netpolLockoutCiliumRuleIsAllowAll(rule) {
		return true
	}
	if !netpolLockoutCiliumToPortsAllows(rule, 53, "dns", "dns-udp", "dns-tcp") {
		return false
	}

	hasDest := false
	if ents := netpolLockoutCiliumStringSlice(rule["toEntities"]); len(ents) > 0 {
		hasDest = true
		for _, ent := range ents {
			switch strings.ToLower(ent) {
			case "cluster", "all":
				return true
			}
		}
	}
	if eps, ok := rule["toEndpoints"].([]any); ok && len(eps) > 0 {
		hasDest = true
		for _, item := range eps {
			if epMap, ok := item.(map[string]any); ok && netpolLockoutCiliumEndpointSelectsDNS(epMap, policyNS) {
				return true
			}
		}
	}
	if cidrs, ok := rule["toCIDR"].([]any); ok && len(cidrs) > 0 {
		hasDest = true
		if netpolLockoutCiliumCIDRsMatchAny(cidrs, netpolLockoutNodeLocalDNSIP) {
			return true
		}
	}
	if cidrSet, ok := rule["toCIDRSet"].([]any); ok && len(cidrSet) > 0 {
		hasDest = true
		if netpolLockoutCiliumCIDRSetMatchesAny(cidrSet, netpolLockoutNodeLocalDNSIP) {
			return true
		}
	}
	if svcs, ok := rule["toServices"].([]any); ok && len(svcs) > 0 {
		hasDest = true
		for _, item := range svcs {
			if m, ok := item.(map[string]any); ok {
				if k8sSvc, ok := m["k8sService"].(map[string]any); ok {
					svcName, _ := k8sSvc["serviceName"].(string)
					if svcName == "kube-dns" || svcName == "coredns" {
						return true
					}
				}
			}
		}
	}
	return !hasDest
}

func netpolLockoutCiliumDenyRuleBlocksAPIServer(rule map[string]any, policyNS string) bool {
	if netpolLockoutCiliumRuleIsAllowAll(rule) {
		return true
	}
	if !netpolLockoutCiliumToPortsAllows(rule, 443, "https", "apiserver") &&
		!netpolLockoutCiliumToPortsAllows(rule, 6443, "https", "apiserver") {
		return false
	}

	hasDest := false
	if ents := netpolLockoutCiliumStringSlice(rule["toEntities"]); len(ents) > 0 {
		hasDest = true
		for _, ent := range ents {
			switch strings.ToLower(ent) {
			case "kube-apiserver", "cluster", "all":
				return true
			}
		}
	}
	if cidrs, ok := rule["toCIDR"].([]any); ok && len(cidrs) > 0 {
		hasDest = true
		if netpolLockoutCiliumCIDRsMatchAny(cidrs, "") {
			return true
		}
	}
	if cidrSet, ok := rule["toCIDRSet"].([]any); ok && len(cidrSet) > 0 {
		hasDest = true
		if netpolLockoutCiliumCIDRSetMatchesAny(cidrSet, "") {
			return true
		}
	}
	if svcs, ok := rule["toServices"].([]any); ok && len(svcs) > 0 {
		hasDest = true
		for _, item := range svcs {
			if m, ok := item.(map[string]any); ok {
				if k8sSvc, ok := m["k8sService"].(map[string]any); ok {
					svcName, _ := k8sSvc["serviceName"].(string)
					nsName, _ := k8sSvc["namespace"].(string)
					if svcName == "kubernetes" && (nsName == "default" || (nsName == "" && policyNS == "default")) {
						return true
					}
				}
			}
		}
	}
	if eps, ok := rule["toEndpoints"].([]any); ok && len(eps) > 0 {
		hasDest = true
		for _, item := range eps {
			epMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if policyNS != "default" && !netpolLockoutCiliumSelectorMentionsNS(epMap) {
				continue
			}
			if ls, ok := netpolLockoutCiliumSelectorToK8s(epMap, "default"); ok {
				if sel, err := metav1.LabelSelectorAsSelector(ls); err == nil && sel.Empty() {
					return true
				}
			}
		}
	}
	return !hasDest
}

func netpolLockoutCiliumCIDRsMatchAny(cidrs []any, targetIP string) bool {
	var target netip.Addr
	if targetIP != "" {
		target, _ = netip.ParseAddr(targetIP)
	}
	for _, raw := range cidrs {
		s, ok := raw.(string)
		if !ok {
			continue
		}
		pfx, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		if pfx.Bits() == 0 || (target.IsValid() && pfx.Contains(target)) {
			return true
		}
	}
	return false
}

func netpolLockoutCiliumCIDRSetMatchesAny(cidrSet []any, targetIP string) bool {
	var target netip.Addr
	if targetIP != "" {
		target, _ = netip.ParseAddr(targetIP)
	}
	for _, item := range cidrSet {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		s, _ := m["cidr"].(string)
		pfx, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		if pfx.Bits() == 0 || (target.IsValid() && pfx.Contains(target)) {
			return true
		}
	}
	return false
}

func netpolLockoutCiliumEndpointSelectsDNS(epMap map[string]any, policyNS string) bool {
	if policyNS != "kube-system" && !netpolLockoutCiliumSelectorMentionsNS(epMap) {
		return false
	}
	ls, ok := netpolLockoutCiliumSelectorToK8s(epMap, "kube-system")
	if !ok {
		return false
	}
	return netpolLockoutPodSelectorAllowsDNS(ls)
}

func netpolLockoutCiliumToPortsAllows(rule map[string]any, target int, named ...string) bool {
	toPorts, ok := rule["toPorts"].([]any)
	if !ok || len(toPorts) == 0 {
		return true
	}
	for _, tpRaw := range toPorts {
		tp, ok := tpRaw.(map[string]any)
		if !ok {
			continue
		}
		ports, ok := tp["ports"].([]any)
		if !ok || len(ports) == 0 {
			return true
		}
		for _, pRaw := range ports {
			pm, ok := pRaw.(map[string]any)
			if !ok {
				continue
			}
			portStr, _ := pm["port"].(string)
			if portStr == "" {
				// Handle numeric port if constructed directly in tests.
				if n, ok := kube.NestedNumber(pm, "port"); ok {
					portStr = strconv.FormatInt(n, 10)
				}
			}
			endPort, hasEnd := kube.NestedNumber(pm, "endPort")
			if portInt, err := strconv.Atoi(portStr); err == nil {
				end := portInt
				if hasEnd && int(endPort) >= portInt {
					end = int(endPort)
				}
				if target >= portInt && target <= end {
					return true
				}
			} else if slices.Contains(named, strings.ToLower(portStr)) {
				return true
			}
		}
	}
	return false
}

func netpolLockoutCiliumStringSlice(v any) []string {
	switch tv := v.(type) {
	case []string:
		return tv
	case []any:
		out := make([]string, 0, len(tv))
		for _, item := range tv {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func netpolLockoutNeedsAPIServer(pod *corev1.Pod) bool {
	if pod.Spec.AutomountServiceAccountToken != nil && !*pod.Spec.AutomountServiceAccountToken {
		return false
	}
	// Explicit opt-in to ServiceAccount token mount.
	if pod.Spec.AutomountServiceAccountToken != nil && *pod.Spec.AutomountServiceAccountToken {
		return true
	}
	// Non-default ServiceAccount indicates RBAC / Kubernetes API usage.
	if pod.Spec.ServiceAccountName != "" && pod.Spec.ServiceAccountName != "default" {
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
	// Controller / operator / webhook / agent naming signals.
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
