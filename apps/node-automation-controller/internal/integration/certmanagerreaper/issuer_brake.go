// issuer_brake.go — default-ON safety brake for certmanager-reaper:
// checks owning Issuer / ClusterIssuer Ready state and ACME 429 / rateLimited
// signals on Order / Challenge / Issuer so wedged reaps pause rather than
// burning ACME / Let's Encrypt quota.
package certmanagerreaper

import (
	"context"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

var (
	issuerGVR = schema.GroupVersionResource{
		Group: "cert-manager.io", Version: "v1", Resource: "issuers",
	}
	clusterIssuerGVR = schema.GroupVersionResource{
		Group: "cert-manager.io", Version: "v1", Resource: "clusterissuers",
	}
)

type issuerBrakeVerdict struct {
	paused bool
	reason string
}

func (r *certManagerReaper) issuerBrakeEnabled() bool {
	return !r.issuerBrakeDisabled
}

func certIssuerKey(cert *unstructured.Unstructured) (kind, ns, name, key string, ok bool) {
	if cert == nil {
		return "", "", "", "", false
	}
	group, _ := kube.NestedString(cert.Object, "spec", "issuerRef", "group")
	if group != "" && group != "cert-manager.io" {
		return "", "", "", "", false
	}
	name, _ = kube.NestedString(cert.Object, "spec", "issuerRef", "name")
	if name == "" {
		return "", "", "", "", false
	}
	kind, _ = kube.NestedString(cert.Object, "spec", "issuerRef", "kind")
	if kind == "" {
		kind = "Issuer"
	}
	if kind == "ClusterIssuer" {
		return kind, "", name, "ClusterIssuer//" + name, true
	}
	if kind != "Issuer" {
		return "", "", "", "", false
	}
	ns = cert.GetNamespace()
	return kind, ns, name, "Issuer/" + ns + "/" + name, true
}

func (r *certManagerReaper) markIssuerRateLimited(cert *unstructured.Unstructured, reason string) {
	_, _, _, ik, ok := certIssuerKey(cert)
	if !ok {
		return
	}
	if r.issuerBlockedCache == nil {
		r.issuerBlockedCache = map[string]issuerBrakeVerdict{}
	}
	r.issuerBlockedCache[ik] = issuerBrakeVerdict{paused: true, reason: reason}
}

func (r *certManagerReaper) issuerPaused(ctx context.Context, cert *unstructured.Unstructured) (string, bool) {
	if !r.issuerBrakeEnabled() || r.dyn == nil {
		return "", false
	}
	kind, ns, name, ik, ok := certIssuerKey(cert)
	if !ok {
		return "", false
	}
	if r.issuerBlockedCache != nil {
		if v, cached := r.issuerBlockedCache[ik]; cached {
			return v.reason, v.paused
		}
	}

	var obj *unstructured.Unstructured
	var err error
	if kind == "ClusterIssuer" {
		obj, err = r.dyn.Resource(clusterIssuerGVR).Get(ctx, name, metav1.GetOptions{})
	} else {
		obj, err = r.dyn.Resource(issuerGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	}

	var verdict issuerBrakeVerdict
	switch {
	case err == nil:
		if objectHasACMERateLimit(obj) {
			verdict = issuerBrakeVerdict{
				paused: true,
				reason: ik + " carries ACME rate-limit signal",
			}
		} else if cond, hasCond := kube.ConditionOf(obj.Object, "Ready"); !hasCond || cond.Status != "True" {
			verdict = issuerBrakeVerdict{
				paused: true,
				reason: fmt.Sprintf("%s Ready=%q (%s)", ik, cond.Status, cond.Reason),
			}
		}
	case kube.IsCRDAbsent(err) || apierrors.IsNotFound(err):
		verdict = issuerBrakeVerdict{paused: false}
	case apierrors.IsForbidden(err):
		logf.FromContext(ctx).V(1).Info("issuer read forbidden — skipping issuer readiness brake",
			"issuer", ik, "error", err)
		verdict = issuerBrakeVerdict{paused: false}
	default:
		// Transient API failure on issuer check — pause fail-closed without caching.
		return fmt.Sprintf("read %s: %v", ik, err), true
	}

	if r.issuerBlockedCache == nil {
		r.issuerBlockedCache = map[string]issuerBrakeVerdict{}
	}
	r.issuerBlockedCache[ik] = verdict
	return verdict.reason, verdict.paused
}

func hasACMERateLimitSignal(s string) bool {
	if s == "" {
		return false
	}
	ls := strings.ToLower(s)
	return strings.Contains(ls, "429") ||
		strings.Contains(ls, "ratelimit") ||
		strings.Contains(ls, "rate limit") ||
		strings.Contains(ls, "rate-limit") ||
		strings.Contains(ls, "too many requests")
}

func objectHasACMERateLimit(u *unstructured.Unstructured) bool {
	if u == nil {
		return false
	}
	for _, field := range []string{"reason", "state", "error", "message"} {
		if v, ok := kube.NestedString(u.Object, "status", field); ok && hasACMERateLimitSignal(v) {
			return true
		}
	}
	found := false
	kube.ForEachCondition(u.Object, func(c kube.Condition) bool {
		if hasACMERateLimitSignal(c.Reason) || hasACMERateLimitSignal(c.Message) {
			found = true
			return false
		}
		return true
	}, "status", "conditions")
	return found
}

func anyACMERateLimited(objs []unstructured.Unstructured) bool {
	for i := range objs {
		if objectHasACMERateLimit(&objs[i]) {
			return true
		}
	}
	return false
}
