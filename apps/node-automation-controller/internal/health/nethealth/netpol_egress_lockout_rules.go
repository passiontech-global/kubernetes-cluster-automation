// netpol_egress_lockout_rules.go — NetworkPolicy, CiliumNetworkPolicy, and
// CiliumClusterwideNetworkPolicy egress rule evaluators for
// netpol-egress-lockout-guard (DNS/APIServer allow and deny matchers).
// Split from netpol_egress_lockout_guard.go.
package nethealth

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

func parseCiliumEgressPolicy(u *unstructured.Unstructured, clusterwide bool) (netpolLockoutParsedCNP, bool) {
	specs := kube.ExtractCiliumSpecs(u)
	var egressSpecs []map[string]any
	for _, sp := range specs {
		if kube.CiliumSpecHasAnyField(sp, "egress", "egressDeny") {
			egressSpecs = append(egressSpecs, sp)
		}
	}
	if len(egressSpecs) == 0 {
		return netpolLockoutParsedCNP{}, false
	}
	ns := u.GetNamespace()
	if clusterwide {
		ns = ""
	}
	return netpolLockoutParsedCNP{
		name:        u.GetName(),
		namespace:   ns,
		clusterwide: clusterwide,
		createdAt:   u.GetCreationTimestamp().Time,
		specs:       egressSpecs,
	}, true
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
			if ls, ok := kube.CiliumEndpointSelectorToK8s(epMap, "default"); ok {
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
			if ls, ok := kube.CiliumEndpointSelectorToK8s(epMap, "default"); ok {
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
	ls, ok := kube.CiliumEndpointSelectorToK8s(epMap, "kube-system")
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
