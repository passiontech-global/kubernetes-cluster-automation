// admission_security_guard.go — health check "admission-security-guard" (#69):
// audit-only (zero mutation) guard detecting:
//  1. Admission/conversion webhook Services externally exposed
//     (LoadBalancer / NodePort / externalIPs) or lacking Ingress
//     NetworkPolicy / CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy
//     isolation (respecting NODE_AUTOMATION_ADMISSION_SEC_EXEMPT_SERVICES).
//  2. ClusterRoleBindings / RoleBindings granting non-allowlisted roles to
//     system:anonymous or system:unauthenticated (respecting built-in safe
//     defaults + NODE_AUTOMATION_ADMISSION_SEC_ALLOW_ANON_ROLES).
//
// All API reads gracefully skip on 403 Forbidden and 404/NoMatch without
// incrementing error counters or false-flagging.
package watchdogs

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
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
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// CheckNameAdmissionSecurityGuard is the registry check name for #3/#69.
	CheckNameAdmissionSecurityGuard = "admission-security-guard"

	admissionSecEventReason   = "AdmissionSecurityExposure"
	admissionSecEventCooldown = 6 * time.Hour
	admissionSecCRDPageSize   = 25
)

var (
	admissionWebhookExposedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_admission_webhook_exposed",
		Help: "1 while an admission or conversion webhook Service is externally exposed or lacks NetworkPolicy/CiliumNetworkPolicy ingress isolation.",
	}, []string{"namespace", "service", "reason"})

	anonymousRBACBindingGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_anonymous_rbac_binding",
		Help: "1 while a ClusterRoleBinding or RoleBinding grants a non-allowlisted role to system:anonymous or system:unauthenticated.",
	}, []string{"kind", "namespace", "binding", "role"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		admissionWebhookExposedGauge,
		anonymousRBACBindingGauge,
	)
}

type admissionSecurityGuardCheck struct {
	*probefw.Deps

	exemptServices map[string]bool
	allowAnonRoles map[string]bool

	webhookEmitted state.GaugeLedger[string]
	rbacEmitted    state.GaugeLedger[string]
	eventCooldown  state.CooldownSet
}

// NewAdmissionSecurityGuardCheck constructs the admission-security-guard check.
func NewAdmissionSecurityGuardCheck(d *probefw.Deps) probefw.Check {
	exempt := map[string]bool{}
	for _, entry := range envx.List("NODE_AUTOMATION_ADMISSION_SEC_EXEMPT_SERVICES") {
		ns, name, ok := strings.Cut(entry, "/")
		if !ok || ns == "" || name == "" {
			envx.Warnf("NODE_AUTOMATION_ADMISSION_SEC_EXEMPT_SERVICES entry is not namespace/name — skipped",
				"value", entry)
			continue
		}
		exempt[ns+"/"+name] = true
	}

	allowRoles := map[string]bool{
		"system:public-info-viewer": true,
		"system:discovery":          true,
		"system:basic-user":         true,
	}
	for _, role := range envx.List("NODE_AUTOMATION_ADMISSION_SEC_ALLOW_ANON_ROLES") {
		allowRoles[role] = true
	}

	return &admissionSecurityGuardCheck{
		Deps:           d,
		exemptServices: exempt,
		allowAnonRoles: allowRoles,
	}
}

type webhookSvcTarget struct {
	namespace string
	name      string
}

func (c *admissionSecurityGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, admissionSecEventCooldown)

	var webhookRep, rbacRep, summaryRep probefw.SweepReport

	c.auditWebhookExposure(ctx, log, now, &webhookRep, &summaryRep)
	c.auditAnonymousRBAC(ctx, log, now, &rbacRep, &summaryRep)

	webhookRep.Close(&c.webhookEmitted, admissionWebhookExposedGauge.DeleteLabelValues)
	rbacRep.Close(&c.rbacEmitted, anonymousRBACBindingGauge.DeleteLabelValues)
	return summaryRep.Verdict("admission security exposure: ", ", ")
}

func (c *admissionSecurityGuardCheck) auditWebhookExposure(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	webhookRep *probefw.SweepReport,
	summaryRep *probefw.SweepReport,
) {
	targets, targetErr := c.collectWebhookServiceTargets(ctx, log, summaryRep)
	if targetErr {
		for k, lv := range c.webhookEmitted.Last() {
			webhookRep.Carry(k, lv)
		}
		return
	}
	if len(targets) == 0 {
		return
	}

	// Resolve Services via probefw snapshot; only load Pods & NetworkPolicies
	// when there is at least one non-exempt webhook Service target.
	resolved := make([]*corev1.Service, 0, len(targets))
	needNetPol := false
	for _, tgt := range targets {
		svc, err := c.Service(ctx, tgt.namespace, tgt.name)
		if err != nil {
			summaryRep.InfraErr(err)
			for k, lv := range c.webhookEmitted.Last() {
				webhookRep.Carry(k, lv)
			}
			return
		}
		if svc == nil {
			continue
		}
		resolved = append(resolved, svc)
		if len(svc.Spec.Selector) > 0 {
			needNetPol = true
		}
	}

	var podsByNS map[string][]*corev1.Pod
	var nps []networkingv1.NetworkPolicy
	var cnps []unstructured.Unstructured
	var ccnps []unstructured.Unstructured
	var policySourceBlocked bool

	if needNetPol {
		pods, err := c.AllPods(ctx)
		if err != nil {
			summaryRep.InfraErr(err)
			for k, lv := range c.webhookEmitted.Last() {
				webhookRep.Carry(k, lv)
			}
			return
		}
		podsByNS = map[string][]*corev1.Pod{}
		for i := range pods {
			p := &pods[i]
			if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
				continue
			}
			podsByNS[p.Namespace] = append(podsByNS[p.Namespace], p)
		}

		nps, policySourceBlocked = c.listNetworkPolicies(ctx, log, summaryRep, policySourceBlocked)
		cnps, policySourceBlocked = c.listCiliumPolicies(ctx, log, summaryRep, kube.GVRCiliumNetworkPolicy, "CiliumNetworkPolicy", policySourceBlocked)
		ccnps, policySourceBlocked = c.listCiliumPolicies(ctx, log, summaryRep, kube.GVRCiliumClusterwideNetworkPolicy, "CiliumClusterwideNetworkPolicy", policySourceBlocked)
	}

	for _, svc := range resolved {
		svcKey := svc.Namespace + "/" + svc.Name
		if svc.Spec.Type == corev1.ServiceTypeLoadBalancer ||
			svc.Spec.Type == corev1.ServiceTypeNodePort ||
			len(svc.Spec.ExternalIPs) > 0 {
			reason := "service_externally_exposed"
			webhookRep.Flag(admissionWebhookExposedGauge, svcKey+"/"+reason,
				[]string{svc.Namespace, svc.Name, reason})
			summaryRep.Find(svcKey + " (" + reason + ")")
			c.emitExposureEvent(ctx, log, now, svc.Namespace,
				corev1.ObjectReference{
					APIVersion: "v1",
					Kind:       "Service",
					Namespace:  svc.Namespace,
					Name:       svc.Name,
					UID:        svc.UID,
				},
				"webhook."+svc.Namespace+"."+svc.Name+"."+reason,
				fmt.Sprintf("admission webhook Service %s is externally exposed (type=%s externalIPs=%v)",
					svcKey, svc.Spec.Type, svc.Spec.ExternalIPs))
		}

		if len(svc.Spec.Selector) == 0 {
			continue
		}
		if isWebhookServiceIsolated(svc, podsByNS[svc.Namespace], nps, cnps, ccnps) {
			continue
		}
		reason := "webhook_no_networkpolicy"
		tupleKey := svcKey + "/" + reason
		if policySourceBlocked {
			// Carry any previously held tuple rather than false-flagging on 403/error.
			if lv, held := c.webhookEmitted.Last()[tupleKey]; held {
				webhookRep.Carry(tupleKey, lv)
			}
			continue
		}
		webhookRep.Flag(admissionWebhookExposedGauge, tupleKey,
			[]string{svc.Namespace, svc.Name, reason})
		summaryRep.Find(svcKey + " (" + reason + ")")
		c.emitExposureEvent(ctx, log, now, svc.Namespace,
			corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Service",
				Namespace:  svc.Namespace,
				Name:       svc.Name,
				UID:        svc.UID,
			},
			"webhook."+svc.Namespace+"."+svc.Name+"."+reason,
			fmt.Sprintf("admission webhook Service %s has no NetworkPolicy or CiliumNetworkPolicy ingress isolation", svcKey))
	}
}

func (c *admissionSecurityGuardCheck) collectWebhookServiceTargets(
	ctx context.Context,
	log logr.Logger,
	summaryRep *probefw.SweepReport,
) (targets []webhookSvcTarget, realErr bool) {
	seen := map[string]bool{}
	add := func(ns, name string) {
		if ns == "" || name == "" {
			return
		}
		key := ns + "/" + name
		if c.exemptServices[key] || seen[key] {
			return
		}
		seen[key] = true
		targets = append(targets, webhookSvcTarget{namespace: ns, name: name})
	}

	vwcs, err := c.AllValidatingWebhookConfigurations(ctx)
	if err != nil {
		if apierrors.IsForbidden(err) || kube.IsCRDAbsent(err) {
			log.V(1).Info("ValidatingWebhookConfiguration list skipped", "error", err)
		} else {
			summaryRep.InfraErr(err)
			realErr = true
		}
	} else {
		for i := range vwcs {
			for j := range vwcs[i].Webhooks {
				if svc := vwcs[i].Webhooks[j].ClientConfig.Service; svc != nil {
					add(svc.Namespace, svc.Name)
				}
			}
		}
	}

	mwcs, err := c.AllMutatingWebhookConfigurations(ctx)
	if err != nil {
		if apierrors.IsForbidden(err) || kube.IsCRDAbsent(err) {
			log.V(1).Info("MutatingWebhookConfiguration list skipped", "error", err)
		} else {
			summaryRep.InfraErr(err)
			realErr = true
		}
	} else {
		for i := range mwcs {
			for j := range mwcs[i].Webhooks {
				if svc := mwcs[i].Webhooks[j].ClientConfig.Service; svc != nil {
					add(svc.Namespace, svc.Name)
				}
			}
		}
	}

	if err := c.collectCRDWebhookTargets(ctx, log, add); err != nil {
		summaryRep.InfraErr(err)
		realErr = true
	}

	return targets, realErr
}

func (c *admissionSecurityGuardCheck) collectCRDWebhookTargets(
	ctx context.Context,
	log logr.Logger,
	add func(ns, name string),
) error {
	if c.NodeReader != nil && kube.CRDInformerEnabled() {
		var list apiextensionsv1.CustomResourceDefinitionList
		if err := c.NodeReader.List(ctx, &list); err == nil {
			for i := range list.Items {
				conv := list.Items[i].Spec.Conversion
				if conv != nil && conv.Strategy == apiextensionsv1.WebhookConverter &&
					conv.Webhook != nil && conv.Webhook.ClientConfig != nil &&
					conv.Webhook.ClientConfig.Service != nil {
					s := conv.Webhook.ClientConfig.Service
					add(s.Namespace, s.Name)
				}
			}
			return nil
		} else {
			log.V(1).Info("CRD informer cache read failed — falling back to paged dynamic list", "error", err)
		}
	}
	if c.Dyn == nil {
		return nil
	}
	err := kube.ListEach(ctx,
		metav1.ListOptions{Limit: admissionSecCRDPageSize},
		kube.DynamicPage(c.Dyn.Resource(kube.GVRCustomResourceDefinition)),
		func(page []unstructured.Unstructured) error {
			for i := range page {
				strategy, _ := kube.NestedString(page[i].Object, "spec", "conversion", "strategy")
				if strategy != "Webhook" {
					continue
				}
				ns, _ := kube.NestedString(page[i].Object,
					"spec", "conversion", "webhook", "clientConfig", "service", "namespace")
				name, _ := kube.NestedString(page[i].Object,
					"spec", "conversion", "webhook", "clientConfig", "service", "name")
				add(ns, name)
			}
			return nil
		})
	if err != nil {
		if apierrors.IsForbidden(err) || kube.IsCRDAbsent(err) {
			log.V(1).Info("CustomResourceDefinition list skipped", "error", err)
			return nil
		}
		return err
	}
	return nil
}

func (c *admissionSecurityGuardCheck) listNetworkPolicies(
	ctx context.Context,
	log logr.Logger,
	summaryRep *probefw.SweepReport,
	blocked bool,
) ([]networkingv1.NetworkPolicy, bool) {
	nps, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.NetworkPolicies(c.CS, metav1.NamespaceAll))
	if err != nil {
		if apierrors.IsForbidden(err) || kube.IsCRDAbsent(err) {
			log.V(1).Info("NetworkPolicy list skipped", "error", err)
			return nil, true
		}
		summaryRep.InfraErr(err)
		return nil, true
	}
	return nps, blocked
}

func (c *admissionSecurityGuardCheck) listCiliumPolicies(
	ctx context.Context,
	log logr.Logger,
	summaryRep *probefw.SweepReport,
	gvr schema.GroupVersionResource,
	kind string,
	blocked bool,
) ([]unstructured.Unstructured, bool) {
	if c.Dyn == nil {
		return nil, blocked
	}
	items, err := c.AllUnstructured(ctx, gvr)
	if err != nil {
		if kube.IsCRDAbsent(err) {
			return nil, blocked
		}
		if apierrors.IsForbidden(err) {
			log.V(1).Info(kind+" list skipped (403)", "error", err)
			return nil, true
		}
		summaryRep.InfraErr(err)
		return nil, true
	}
	return items, blocked
}

func (c *admissionSecurityGuardCheck) auditAnonymousRBAC(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	rbacRep *probefw.SweepReport,
	summaryRep *probefw.SweepReport,
) {
	crbs, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.ClusterRoleBindings(c.CS))
	if err != nil {
		if apierrors.IsForbidden(err) || kube.IsCRDAbsent(err) {
			log.V(1).Info("ClusterRoleBinding list skipped", "error", err)
		} else {
			summaryRep.InfraErr(err)
		}
		carryRBACByKind(rbacRep, &c.rbacEmitted, "ClusterRoleBinding")
	} else {
		for i := range crbs {
			crb := &crbs[i]
			if !hasAnonymousSubject(crb.Subjects) || c.allowAnonRoles[crb.RoleRef.Name] {
				continue
			}
			key := "ClusterRoleBinding//" + crb.Name + "/" + crb.RoleRef.Name
			rbacRep.Flag(anonymousRBACBindingGauge, key,
				[]string{"ClusterRoleBinding", "", crb.Name, crb.RoleRef.Name})
			summaryRep.Find(fmt.Sprintf("ClusterRoleBinding/%s -> %s", crb.Name, crb.RoleRef.Name))
			c.emitExposureEvent(ctx, log, now, "default",
				corev1.ObjectReference{
					APIVersion: "rbac.authorization.k8s.io/v1",
					Kind:       "ClusterRoleBinding",
					Name:       crb.Name,
					UID:        crb.UID,
				},
				"rbac.crb."+crb.Name,
				fmt.Sprintf("ClusterRoleBinding %s grants non-allowlisted role %q to anonymous/unauthenticated subject",
					crb.Name, crb.RoleRef.Name))
		}
	}

	rbs, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.RoleBindings(c.CS, metav1.NamespaceAll))
	if err != nil {
		if apierrors.IsForbidden(err) || kube.IsCRDAbsent(err) {
			log.V(1).Info("RoleBinding list skipped", "error", err)
		} else {
			summaryRep.InfraErr(err)
		}
		carryRBACByKind(rbacRep, &c.rbacEmitted, "RoleBinding")
	} else {
		for i := range rbs {
			rb := &rbs[i]
			if !hasAnonymousSubject(rb.Subjects) || c.allowAnonRoles[rb.RoleRef.Name] {
				continue
			}
			key := "RoleBinding/" + rb.Namespace + "/" + rb.Name + "/" + rb.RoleRef.Name
			rbacRep.Flag(anonymousRBACBindingGauge, key,
				[]string{"RoleBinding", rb.Namespace, rb.Name, rb.RoleRef.Name})
			summaryRep.Find(fmt.Sprintf("RoleBinding/%s/%s -> %s", rb.Namespace, rb.Name, rb.RoleRef.Name))
			c.emitExposureEvent(ctx, log, now, rb.Namespace,
				corev1.ObjectReference{
					APIVersion: "rbac.authorization.k8s.io/v1",
					Kind:       "RoleBinding",
					Namespace:  rb.Namespace,
					Name:       rb.Name,
					UID:        rb.UID,
				},
				"rbac.rb."+rb.Namespace+"."+rb.Name,
				fmt.Sprintf("RoleBinding %s/%s grants non-allowlisted role %q to anonymous/unauthenticated subject",
					rb.Namespace, rb.Name, rb.RoleRef.Name))
		}
	}
}

func carryRBACByKind(rbacRep *probefw.SweepReport, ledger *state.GaugeLedger[string], kind string) {
	for k, lv := range ledger.Last() {
		if len(lv) >= 1 && lv[0] == kind {
			rbacRep.Carry(k, lv)
		}
	}
}

func hasAnonymousSubject(subjects []rbacv1.Subject) bool {
	for _, s := range subjects {
		switch s.Kind {
		case rbacv1.UserKind:
			if s.Name == "system:anonymous" || s.Name == "system:unauthenticated" {
				return true
			}
		case rbacv1.GroupKind:
			if s.Name == "system:unauthenticated" {
				return true
			}
		}
	}
	return false
}

func (c *admissionSecurityGuardCheck) emitExposureEvent(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	eventNS string,
	regarding corev1.ObjectReference,
	cooldownKey string,
	note string,
) {
	if c.eventCooldown.CooledDown(cooldownKey, admissionSecEventCooldown, now) {
		return
	}
	if err := kube.EmitWarningEvent(ctx, c.CS, kube.WarningEvent{
		Name:              fmt.Sprintf("%s.%x", sanitizeEventNamePrefix(cooldownKey), now.UnixNano()),
		Namespace:         eventNS,
		Regarding:         regarding,
		Reason:            admissionSecEventReason,
		Note:              note,
		ReportingInstance: c.Name,
		Now:               now,
	}); err != nil {
		log.Info("WARN: AdmissionSecurityExposure event create failed (RBAC?)",
			"key", cooldownKey, "error", err)
		return
	}
	c.eventCooldown.Stamp(cooldownKey, now)
	log.Info("EVENT: AdmissionSecurityExposure", "key", cooldownKey)
}

func sanitizeEventNamePrefix(s string) string {
	s = strings.ToLower(s)
	rawLabels := strings.Split(s, ".")
	var cleanLabels []string
	for _, raw := range rawLabels {
		var b strings.Builder
		b.Grow(len(raw))
		prevDash := false
		for i := 0; i < len(raw); i++ {
			c := raw[i]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
				b.WriteByte(c)
				prevDash = false
				continue
			}
			if b.Len() > 0 && !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
		lbl := strings.Trim(b.String(), "-")
		if lbl != "" {
			cleanLabels = append(cleanLabels, lbl)
		}
	}
	if len(cleanLabels) == 0 {
		return "event"
	}
	return strings.Join(cleanLabels, ".")
}

func isWebhookServiceIsolated(
	svc *corev1.Service,
	nsPods []*corev1.Pod,
	nps []networkingv1.NetworkPolicy,
	cnps []unstructured.Unstructured,
	ccnps []unstructured.Unstructured,
) bool {
	svcSel := labels.SelectorFromSet(svc.Spec.Selector)
	var matchingPods []*corev1.Pod
	for _, p := range nsPods {
		if svcSel.Matches(labels.Set(p.Labels)) {
			matchingPods = append(matchingPods, p)
		}
	}

	for i := range nps {
		np := &nps[i]
		if np.Namespace != svc.Namespace || !npAffectsIngress(np) {
			continue
		}
		if labelSelectorCoversTarget(&np.Spec.PodSelector, svc.Spec.Selector, matchingPods) {
			return true
		}
	}

	for i := range cnps {
		if cnpCoversService(&cnps[i], svc.Namespace, svc.Spec.Selector, matchingPods, false) {
			return true
		}
	}

	for i := range ccnps {
		if cnpCoversService(&ccnps[i], svc.Namespace, svc.Spec.Selector, matchingPods, true) {
			return true
		}
	}

	return false
}

func npAffectsIngress(np *networkingv1.NetworkPolicy) bool {
	if len(np.Spec.PolicyTypes) == 0 {
		return true
	}
	return slices.Contains(np.Spec.PolicyTypes, networkingv1.PolicyTypeIngress)
}

func labelSelectorCoversTarget(ls *metav1.LabelSelector, svcSelector map[string]string, matchingPods []*corev1.Pod) bool {
	sel, err := metav1.LabelSelectorAsSelector(ls)
	if err != nil {
		return false
	}
	if len(matchingPods) > 0 {
		for _, p := range matchingPods {
			if !sel.Matches(labels.Set(p.Labels)) {
				return false
			}
		}
		return true
	}
	return sel.Matches(labels.Set(svcSelector))
}

func cnpCoversService(
	u *unstructured.Unstructured,
	svcNS string,
	svcSelector map[string]string,
	matchingPods []*corev1.Pod,
	clusterwide bool,
) bool {
	if !clusterwide && u.GetNamespace() != svcNS {
		return false
	}
	for _, sp := range extractCiliumSpecs(u) {
		if !ciliumSpecHasIngress(sp) {
			continue
		}
		if clusterwide && sp["nodeSelector"] != nil && sp["endpointSelector"] == nil {
			continue
		}
		epRaw, hasEP := sp["endpointSelector"].(map[string]any)
		if !hasEP {
			continue
		}
		ls, ok := ciliumEndpointSelectorToK8s(epRaw, svcNS)
		if !ok {
			continue
		}
		if labelSelectorCoversTarget(ls, svcSelector, matchingPods) {
			return true
		}
	}
	return false
}

func extractCiliumSpecs(u *unstructured.Unstructured) []map[string]any {
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

func ciliumSpecHasIngress(sp map[string]any) bool {
	if v, ok := sp["ingress"]; ok && v != nil {
		return true
	}
	if v, ok := sp["ingressDeny"]; ok && v != nil {
		return true
	}
	return false
}

func ciliumEndpointSelectorToK8s(raw map[string]any, svcNS string) (*metav1.LabelSelector, bool) {
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
				if vs != svcNS {
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
				if !ciliumNamespaceMatchesExpr(svcNS, metav1.LabelSelectorOperator(op), vals) {
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

func ciliumNamespaceMatchesExpr(svcNS string, op metav1.LabelSelectorOperator, vals []string) bool {
	switch op {
	case metav1.LabelSelectorOpIn:
		return slices.Contains(vals, svcNS)
	case metav1.LabelSelectorOpNotIn:
		return !slices.Contains(vals, svcNS)
	case metav1.LabelSelectorOpExists:
		return svcNS != ""
	case metav1.LabelSelectorOpDoesNotExist:
		return false
	default:
		return false
	}
}
