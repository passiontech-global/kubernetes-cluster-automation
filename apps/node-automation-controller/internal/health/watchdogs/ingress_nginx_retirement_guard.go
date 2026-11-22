// ingress_nginx_retirement_guard.go — health check "ingress-nginx-retirement-guard" (K9b):
// audits clusters for remaining ingress-nginx workloads and configuration
// ahead of upstream ingress-nginx retirement:
//  1. Running/pending controller Pods matching ingress-nginx labels or images
//  2. Networking IngressClass resources with spec.controller == "k8s.io/ingress-nginx"
//  3. Networking Ingress resources targeting an ingress-nginx IngressClass,
//     legacy "kubernetes.io/ingress.class", or default ingress-nginx IngressClass
//
// Read-only (zero mutation). Gracefully skips 403 Forbidden and 404/NoMatch
// without false-flagging, auto-passes when no ingress-nginx components exist,
// and emits node_automation_ingress_nginx_retirement_detected{kind,namespace,name}
// plus cooldown-deduped Warning Events (IngressNginxRetirement) when present.
package watchdogs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

const (
	// CheckNameIngressNginxRetirementGuard is the registry check name for K9b.
	CheckNameIngressNginxRetirementGuard = "ingress-nginx-retirement-guard"

	ingressNginxControllerName   = "k8s.io/ingress-nginx"
	legacyIngressClassAnnotation = "kubernetes.io/ingress.class"
	ingressNginxEventReason      = "IngressNginxRetirement"
	ingressNginxEventCooldown    = 6 * time.Hour
)

var ingressNginxDetectedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_ingress_nginx_retirement_detected",
	Help: "1 while an ingress-nginx Pod, IngressClass, or Ingress resource is still present in the cluster.",
}, []string{"kind", "namespace", "name"})

func init() {
	ctrlmetrics.Registry.MustRegister(ingressNginxDetectedGauge)
}

type ingressNginxRetirementGuardCheck struct {
	*probefw.Deps

	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
}

// NewIngressNginxRetirementGuardCheck constructs the ingress-nginx-retirement-guard check.
func NewIngressNginxRetirementGuardCheck(d *probefw.Deps) probefw.Check {
	return &ingressNginxRetirementGuardCheck{Deps: d}
}

func (c *ingressNginxRetirementGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, ingressNginxEventCooldown)

	pods, err := c.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}

	var rep probefw.SweepReport

	for i := range pods {
		pod := &pods[i]
		if pod.DeletionTimestamp != nil ||
			pod.Status.Phase == corev1.PodSucceeded ||
			pod.Status.Phase == corev1.PodFailed {
			continue
		}
		if !isIngressNginxControllerPod(pod) {
			continue
		}
		key := "Pod/" + pod.Namespace + "/" + pod.Name
		rep.Emit(ingressNginxDetectedGauge, key,
			[]string{"Pod", pod.Namespace, pod.Name},
			fmt.Sprintf("Pod/%s/%s", pod.Namespace, pod.Name))
		c.emitRetirementEvent(ctx, log, now, pod.Namespace,
			corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Pod",
				Namespace:  pod.Namespace,
				Name:       pod.Name,
				UID:        pod.UID,
			},
			"ingressnginx.pod."+pod.Namespace+"."+pod.Name,
			fmt.Sprintf("ingress-nginx controller Pod %s/%s detected; ingress-nginx is retiring and should be migrated",
				pod.Namespace, pod.Name))
	}

	nginxClasses := map[string]bool{}
	classControllers := map[string]string{}
	hasDefaultNginxClass := false

	ics, err := kube.ListAll(ctx,
		metav1.ListOptions{
			Limit:           kube.DefaultListPageSize,
			ResourceVersion: "0",
		},
		ingressClassesPage(c.CS))
	icListOK := err == nil
	if !icListOK {
		if apierrors.IsForbidden(err) || kube.IsCRDAbsent(err) {
			log.V(1).Info("IngressClass list skipped", "error", err)
		} else {
			rep.InfraErr(fmt.Errorf("list ingressclasses: %w", err))
		}
		carryIngressNginxByKind(&rep, &c.emitted, "IngressClass")
	} else {
		for i := range ics {
			ic := &ics[i]
			if ic.DeletionTimestamp != nil {
				continue
			}
			classControllers[ic.Name] = ic.Spec.Controller
			if ic.Spec.Controller != ingressNginxControllerName {
				continue
			}
			nginxClasses[ic.Name] = true
			if ic.Annotations[networkingv1.AnnotationIsDefaultIngressClass] == "true" {
				hasDefaultNginxClass = true
			}
			key := "IngressClass//" + ic.Name
			rep.Emit(ingressNginxDetectedGauge, key,
				[]string{"IngressClass", "", ic.Name},
				"IngressClass/"+ic.Name)
			c.emitRetirementEvent(ctx, log, now, "default",
				corev1.ObjectReference{
					APIVersion: networkingv1.SchemeGroupVersion.String(),
					Kind:       "IngressClass",
					Name:       ic.Name,
					UID:        ic.UID,
				},
				"ingressnginx.ic."+ic.Name,
				fmt.Sprintf("IngressClass %s uses retiring controller %s",
					ic.Name, ingressNginxControllerName))
		}
	}

	ings, err := kube.ListAll(ctx,
		metav1.ListOptions{
			Limit:           kube.DefaultListPageSize,
			ResourceVersion: "0",
		},
		kube.Ingresses(c.CS, metav1.NamespaceAll))
	if err != nil {
		if apierrors.IsForbidden(err) || kube.IsCRDAbsent(err) {
			log.V(1).Info("Ingress list skipped", "error", err)
		} else {
			rep.InfraErr(fmt.Errorf("list ingresses: %w", err))
		}
		carryIngressNginxByKind(&rep, &c.emitted, "Ingress")
	} else {
		var activeIngresses, emittedIngresses map[string]bool
		if !icListOK {
			activeIngresses = make(map[string]bool, len(ings))
			emittedIngresses = map[string]bool{}
		}
		for i := range ings {
			ing := &ings[i]
			if ing.DeletionTimestamp != nil {
				continue
			}
			key := "Ingress/" + ing.Namespace + "/" + ing.Name
			if !icListOK {
				activeIngresses[key] = true
			}
			if !ingressTargetsNginx(ing, icListOK, nginxClasses, classControllers, hasDefaultNginxClass) {
				continue
			}
			if !icListOK {
				emittedIngresses[key] = true
			}
			rep.Emit(ingressNginxDetectedGauge, key,
				[]string{"Ingress", ing.Namespace, ing.Name},
				key)
			c.emitRetirementEvent(ctx, log, now, ing.Namespace,
				corev1.ObjectReference{
					APIVersion: networkingv1.SchemeGroupVersion.String(),
					Kind:       "Ingress",
					Namespace:  ing.Namespace,
					Name:       ing.Name,
					UID:        ing.UID,
				},
				"ingressnginx.ing."+ing.Namespace+"."+ing.Name,
				fmt.Sprintf("Ingress %s/%s relies on retiring ingress-nginx controller",
					ing.Namespace, ing.Name))
		}
		if !icListOK {
			for k, lv := range c.emitted.Last() {
				if len(lv) >= 1 && lv[0] == "Ingress" && activeIngresses[k] && !emittedIngresses[k] {
					rep.Carry(k, lv)
				}
			}
		}
	}

	return rep.Result(&c.emitted, ingressNginxDetectedGauge.DeleteLabelValues,
		"ingress-nginx retirement detected: ", ", ")
}

func ingressClassesPage(cs kubernetes.Interface) kube.PageFunc[networkingv1.IngressClass] {
	return func(ctx context.Context, opts metav1.ListOptions) ([]networkingv1.IngressClass, string, error) {
		list, err := cs.NetworkingV1().IngressClasses().List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	}
}

func carryIngressNginxByKind(rep *probefw.SweepReport, ledger *state.GaugeLedger[string], kind string) {
	for k, lv := range ledger.Last() {
		if len(lv) >= 1 && lv[0] == kind {
			rep.Carry(k, lv)
		}
	}
}

func isIngressNginxControllerPod(pod *corev1.Pod) bool {
	comp := pod.Labels["app.kubernetes.io/component"]
	if pod.Labels["app.kubernetes.io/name"] == "ingress-nginx" &&
		(comp == "" || comp == "controller") {
		return true
	}
	if pod.Labels["app"] == "ingress-nginx" &&
		(comp == "" || comp == "controller") {
		return true
	}
	for i := range pod.Spec.Containers {
		img := strings.ToLower(pod.Spec.Containers[i].Image)
		if strings.Contains(img, "ingress-nginx/controller") ||
			strings.Contains(img, "kubernetes-ingress-controller/nginx-ingress-controller") ||
			strings.Contains(img, "/nginx-ingress-controller") {
			return true
		}
	}
	return false
}

func ingressTargetsNginx(
	ing *networkingv1.Ingress,
	icListOK bool,
	nginxClasses map[string]bool,
	classControllers map[string]string,
	hasDefaultNginxClass bool,
) bool {
	var className string
	if ing.Spec.IngressClassName != nil {
		className = *ing.Spec.IngressClassName
	}
	if className != "" {
		if nginxClasses[className] {
			return true
		}
		return icListOK && className == "nginx" && classControllers["nginx"] == ""
	}
	if legacy := ing.Annotations[legacyIngressClassAnnotation]; legacy != "" {
		if nginxClasses[legacy] || legacy == ingressNginxControllerName {
			return true
		}
		return icListOK && legacy == "nginx" && classControllers["nginx"] == ""
	}
	return hasDefaultNginxClass
}

func (c *ingressNginxRetirementGuardCheck) emitRetirementEvent(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	eventNS string,
	regarding corev1.ObjectReference,
	cooldownKey string,
	note string,
) {
	if c.eventCooldown.CooledDown(cooldownKey, ingressNginxEventCooldown, now) {
		return
	}
	if err := kube.EmitWarningEvent(ctx, c.CS, kube.WarningEvent{
		Name:              fmt.Sprintf("%s.%x", sanitizeEventNamePrefix(cooldownKey), now.UnixNano()),
		Namespace:         eventNS,
		Regarding:         regarding,
		Reason:            ingressNginxEventReason,
		Note:              note,
		ReportingInstance: c.Name,
		Now:               now,
	}); err != nil {
		log.Info("WARN: IngressNginxRetirement event create failed (RBAC?)",
			"key", cooldownKey, "error", err)
		return
	}
	c.eventCooldown.Stamp(cooldownKey, now)
	log.Info("EVENT: IngressNginxRetirement", "key", cooldownKey)
}
