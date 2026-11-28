// admission_security_webhooks.go — admission/conversion webhook Service
// exposure auditing and NetworkPolicy/CiliumNetworkPolicy ingress
// isolation matching for admission-security-guard.
// Split from admission_security_guard.go.
package watchdogs

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

type webhookSvcTarget struct {
	namespace string
	name      string
}

type admissionIngressNP struct {
	sel labels.Selector
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
	var npsByNS map[string][]admissionIngressNP
	var cnpsByNS map[string][]*unstructured.Unstructured
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

		var nps []networkingv1.NetworkPolicy
		nps, policySourceBlocked = c.listNetworkPolicies(ctx, log, summaryRep, policySourceBlocked)
		npsByNS = map[string][]admissionIngressNP{}
		for i := range nps {
			np := &nps[i]
			if !kube.NetworkPolicyAffectsIngress(np) {
				continue
			}
			sel, selErr := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
			if selErr != nil {
				continue
			}
			npsByNS[np.Namespace] = append(npsByNS[np.Namespace], admissionIngressNP{sel: sel})
		}

		var cnps []unstructured.Unstructured
		cnps, policySourceBlocked = c.listCiliumPolicies(ctx, log, summaryRep, kube.GVRCiliumNetworkPolicy, "CiliumNetworkPolicy", policySourceBlocked)
		cnpsByNS = map[string][]*unstructured.Unstructured{}
		for i := range cnps {
			u := &cnps[i]
			cnpsByNS[u.GetNamespace()] = append(cnpsByNS[u.GetNamespace()], u)
		}

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
		if isWebhookServiceIsolated(svc, podsByNS[svc.Namespace], npsByNS[svc.Namespace], cnpsByNS[svc.Namespace], ccnps) {
			continue
		}
		reason := "webhook_no_networkpolicy"
		tupleKey := svcKey + "/" + reason
		if policySourceBlocked {
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
		metav1.ListOptions{
			Limit:           admissionSecCRDPageSize,
			ResourceVersion: "0",
		},
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
	nps, err := c.AllNetworkPolicies(ctx)
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

func isWebhookServiceIsolated(
	svc *corev1.Service,
	nsPods []*corev1.Pod,
	nsNPs []admissionIngressNP,
	nsCNPs []*unstructured.Unstructured,
	ccnps []unstructured.Unstructured,
) bool {
	svcSel := labels.SelectorFromSet(svc.Spec.Selector)
	var matchingPods []*corev1.Pod
	for _, p := range nsPods {
		if svcSel.Matches(labels.Set(p.Labels)) {
			matchingPods = append(matchingPods, p)
		}
	}

	for _, np := range nsNPs {
		if compiledSelectorCoversTarget(np.sel, svc.Spec.Selector, matchingPods) {
			return true
		}
	}

	for _, cnp := range nsCNPs {
		if cnpCoversService(cnp, svc.Namespace, svc.Spec.Selector, matchingPods, false) {
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

func compiledSelectorCoversTarget(sel labels.Selector, svcSelector map[string]string, matchingPods []*corev1.Pod) bool {
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
	for _, sp := range kube.ExtractCiliumSpecs(u) {
		if !kube.CiliumSpecHasAnyField(sp, "ingress", "ingressDeny") {
			continue
		}
		if clusterwide && sp["nodeSelector"] != nil && sp["endpointSelector"] == nil {
			continue
		}
		epRaw, hasEP := sp["endpointSelector"].(map[string]any)
		if !hasEP {
			continue
		}
		ls, ok := kube.CiliumEndpointSelectorToK8s(epRaw, svcNS)
		if !ok {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(ls)
		if err != nil {
			continue
		}
		if compiledSelectorCoversTarget(sel, svcSelector, matchingPods) {
			return true
		}
	}
	return false
}
