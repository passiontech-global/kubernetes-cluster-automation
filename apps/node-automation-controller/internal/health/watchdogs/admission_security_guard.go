// admission_security_guard.go — health check "admission-security-guard" (#69):
// audit-only (zero mutation) guard detecting:
//  1. Admission/conversion webhook Services externally exposed
//     (LoadBalancer / NodePort / externalIPs) or lacking Ingress
//     NetworkPolicy / CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy
//     isolation (respecting NODE_AUTOMATION_ADMISSION_SEC_EXEMPT_SERVICES).
//  2. ClusterRoleBindings / RoleBindings granting non-allowlisted roles to
//     system:anonymous or system:unauthenticated (respecting built-in safe
//     defaults + NODE_AUTOMATION_ADMISSION_SEC_ALLOW_ANON_ROLES).
//  3. Non-terminal Pods outside system namespaces (kube-system, kube-public,
//     kube-node-lease, k0s-system) using system-cluster-critical or
//     system-node-critical PriorityClass without opt-out annotation
//     passiontech.dev/allow-system-priority-class: "true".
//
// File layout: this file owns the check struct, Run sweep pipeline, anonymous
// RBAC audit, PriorityClass abuse audit, and Warning Event helper;
// admission_security_webhooks.go holds webhook target collection and
// NetworkPolicy/CiliumNetworkPolicy ingress isolation evaluation.
package watchdogs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

	admissionSecEventReason      = "AdmissionSecurityExposure"
	admissionSecEventCooldown    = 6 * time.Hour
	admissionSecCRDPageSize      = 25
	admissionSecAnnoAllowSysPrio = "passiontech.dev/allow-system-priority-class"
	admissionSecSysClusterCrit   = "system-cluster-critical"
	admissionSecSysNodeCrit      = "system-node-critical"
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

	systemPriorityClassAbuseGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_system_priorityclass_abuse",
		Help: "1 while a non-terminal Pod outside system namespaces uses system-cluster-critical or system-node-critical without opt-out annotation.",
	}, []string{"namespace", "pod", "priority_class"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		admissionWebhookExposedGauge,
		anonymousRBACBindingGauge,
		systemPriorityClassAbuseGauge,
	)
}

type admissionSecurityGuardCheck struct {
	*probefw.Deps

	exemptServices map[string]bool
	allowAnonRoles map[string]bool

	webhookEmitted  state.GaugeLedger[string]
	rbacEmitted     state.GaugeLedger[string]
	priorityEmitted state.GaugeLedger[string]
	eventCooldown   state.CooldownSet
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

func (c *admissionSecurityGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, admissionSecEventCooldown)

	var webhookRep, rbacRep, priorityRep, summaryRep probefw.SweepReport

	c.auditWebhookExposure(ctx, log, now, &webhookRep, &summaryRep)
	c.auditAnonymousRBAC(ctx, log, now, &rbacRep, &summaryRep)
	c.auditSystemPriorityClass(ctx, log, now, &priorityRep, &summaryRep)

	webhookRep.Close(&c.webhookEmitted, admissionWebhookExposedGauge.DeleteLabelValues)
	rbacRep.Close(&c.rbacEmitted, anonymousRBACBindingGauge.DeleteLabelValues)
	priorityRep.Close(&c.priorityEmitted, systemPriorityClassAbuseGauge.DeleteLabelValues)
	return summaryRep.Verdict("admission security exposure: ", ", ")
}

func (c *admissionSecurityGuardCheck) auditAnonymousRBAC(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	rbacRep *probefw.SweepReport,
	summaryRep *probefw.SweepReport,
) {
	crbs, err := c.AllClusterRoleBindings(ctx)
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

	rbs, err := c.AllRoleBindings(ctx)
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
	probefw.EmitWarningDeduped(ctx, c.CS, log, &c.eventCooldown, cooldownKey, admissionSecEventCooldown, now, kube.WarningEvent{
		Namespace:         eventNS,
		Regarding:         regarding,
		Reason:            admissionSecEventReason,
		Note:              note,
		ReportingInstance: c.Name,
	})
}

var admissionSecSystemNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
	"k0s-system":      true,
}

func isAdmissionSecSystemNamespace(ns string) bool {
	return admissionSecSystemNamespaces[ns]
}

func (c *admissionSecurityGuardCheck) auditSystemPriorityClass(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	priorityRep *probefw.SweepReport,
	summaryRep *probefw.SweepReport,
) {
	pods, err := c.AllPods(ctx)
	if err != nil {
		if apierrors.IsForbidden(err) || kube.IsCRDAbsent(err) {
			log.V(1).Info("Pod list skipped for PriorityClass audit", "error", err)
		} else {
			summaryRep.InfraErr(fmt.Errorf("list pods for priorityclass audit: %w", err))
		}
		for k, lv := range c.priorityEmitted.Last() {
			priorityRep.Carry(k, lv)
		}
		return
	}

	for i := range pods {
		pod := &pods[i]
		if pod.DeletionTimestamp != nil ||
			pod.Status.Phase == corev1.PodSucceeded ||
			pod.Status.Phase == corev1.PodFailed {
			continue
		}
		if isAdmissionSecSystemNamespace(pod.Namespace) {
			continue
		}
		if pod.Annotations["kubernetes.io/config.mirror"] != "" {
			continue
		}
		pc := pod.Spec.PriorityClassName
		if pc != admissionSecSysClusterCrit && pc != admissionSecSysNodeCrit {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(pod.Annotations[admissionSecAnnoAllowSysPrio]), "true") {
			continue
		}

		podKey := pod.Namespace + "/" + pod.Name
		tupleKey := podKey + "/" + pc
		priorityRep.Flag(systemPriorityClassAbuseGauge, tupleKey,
			[]string{pod.Namespace, pod.Name, pc})
		summaryRep.Find(fmt.Sprintf("Pod/%s priorityClass=%s", podKey, pc))
		c.emitExposureEvent(ctx, log, now, pod.Namespace,
			corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Pod",
				Namespace:  pod.Namespace,
				Name:       pod.Name,
				UID:        pod.UID,
			},
			"priorityclass."+pod.Namespace+"."+pod.Name,
			fmt.Sprintf("non-system Pod %s uses privileged PriorityClass %q without %s=true opt-out",
				podKey, pc, admissionSecAnnoAllowSysPrio))
	}
}
