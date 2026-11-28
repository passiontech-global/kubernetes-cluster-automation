// gateway_route_health_conflicts.go — Wave 7 extensions for
// gateway-route-health: Gateway listener tls.certificateRefs Secret missing /
// expiring audit + cross-namespace HTTPRoute (parentGateway, sectionName,
// hostname, path) conflict/hijack detection.
package gateway

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

func (p *gatewayRouteHealthCheck) emitGatewayWarning(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	obj *unstructured.Unstructured,
	reason, note string,
) {
	ns, name := obj.GetNamespace(), obj.GetName()
	kind := obj.GetKind()
	ck := probefw.SelfHealKey(CheckNameGatewayRouteHealth, "ev/"+reason+"/"+kind+"/"+ns+"/"+name)
	probefw.EmitWarningDeduped(ctx, p.CS, log, &p.eventCooldown, ck, gwConflictEventCooldown, now, kube.WarningEvent{
		Name:      kube.TruncatedEventName("gw."+reason+"."+name, kind+"/"+ns+"/"+name, now),
		Namespace: ns,
		Reason:    reason,
		Note:      note,
		Regarding: corev1.ObjectReference{
			APIVersion: obj.GetAPIVersion(),
			Kind:       kind,
			Namespace:  ns,
			Name:       name,
			UID:        obj.GetUID(),
		},
		ReportingInstance: p.Name,
	})
}

func gatewayAllCertSecretRefs(gw *unstructured.Unstructured) []gatewayCertRef {
	listeners, found := kube.NestedSlice(gw.Object, "spec", "listeners")
	if !found {
		return nil
	}
	gwNS := gw.GetNamespace()
	var out []gatewayCertRef
	for _, l := range listeners {
		lm, ok := l.(map[string]any)
		if !ok {
			continue
		}
		refs, _ := kube.NestedSlice(lm, "tls", "certificateRefs")
		for _, r := range refs {
			rm, ok := r.(map[string]any)
			if !ok {
				continue
			}
			group, _ := kube.NestedString(rm, "group")
			kind, _ := kube.NestedString(rm, "kind")
			if (group != "" && group != "core") || (kind != "" && kind != "Secret") {
				continue
			}
			name, _ := kube.NestedString(rm, "name")
			if name == "" {
				continue
			}
			ns, _ := kube.NestedString(rm, "namespace")
			if ns == "" {
				ns = gwNS
			}
			out = append(out, gatewayCertRef{ns: ns, name: name})
		}
	}
	return out
}

func (p *gatewayRouteHealthCheck) scanGatewayTLSCertRefs(
	ctx context.Context,
	log logr.Logger,
	gws []unstructured.Unstructured,
	live map[string][]string,
	immediate map[string]bool,
	now time.Time,
) {
	if p.CS == nil {
		return
	}
	type secretMemo struct {
		sec *corev1.Secret
		err error
	}
	memo := map[string]secretMemo{}
	getSecret := func(ns, name string) (*corev1.Secret, error) {
		sk := ns + "/" + name
		if m, ok := memo[sk]; ok {
			return m.sec, m.err
		}
		sec, err := p.CS.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
		memo[sk] = secretMemo{sec: sec, err: err}
		return sec, err
	}

	for i := range gws {
		gw := &gws[i]
		ns, name := gw.GetNamespace(), gw.GetName()
		ct := gw.GetCreationTimestamp()
		persistedNow := !ct.IsZero() && now.Sub(ct.Time) >= gatewayRouteUnhealthyMinAge
		for _, ref := range gatewayAllCertSecretRefs(gw) {
			sec, err := getSecret(ref.ns, ref.name)
			if err != nil {
				switch {
				case apierrors.IsNotFound(err):
					k := "Gateway/" + ns + "/" + name + "/" + gwReasonTLSCertMissing
					live[k] = []string{"Gateway", ns, name, gwReasonTLSCertMissing}
					if persistedNow {
						immediate[k] = true
					}
					p.emitGatewayWarning(ctx, log, now, gw, "GatewayTLSCertMissing",
						fmt.Sprintf("Gateway %s/%s tls.certificateRef Secret %s/%s does not exist", ns, name, ref.ns, ref.name))
				case apierrors.IsForbidden(err):
				default:
					for _, r := range []string{gwReasonTLSCertMissing, gwReasonTLSCertExpiring} {
						k := "Gateway/" + ns + "/" + name + "/" + r
						if lv, ok := p.liveLast[k]; ok {
							live[k] = lv
							if p.immediateLast[k] {
								immediate[k] = true
							}
						}
					}
				}
				continue
			}
			pemBytes := sec.Data["tls.crt"]
			if len(pemBytes) == 0 {
				continue
			}
			if soonest, ok := earliestGWCertNotAfter(pemBytes); ok && soonest.Sub(now) <= gwTLSCertExpiringWindow {
				k := "Gateway/" + ns + "/" + name + "/" + gwReasonTLSCertExpiring
				live[k] = []string{"Gateway", ns, name, gwReasonTLSCertExpiring}
				immediate[k] = true
				p.emitGatewayWarning(ctx, log, now, gw, "GatewayTLSCertExpiring",
					fmt.Sprintf("Gateway %s/%s tls.certificateRef Secret %s/%s certificate expires at %s (<30d)",
						ns, name, ref.ns, ref.name, soonest.UTC().Format(time.RFC3339)))
			}
		}
	}
}

func earliestGWCertNotAfter(pemData []byte) (time.Time, bool) {
	var earliest time.Time
	has := false
	rest := pemData
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if !has || cert.NotAfter.Before(earliest) {
			earliest = cert.NotAfter
			has = true
		}
	}
	return earliest, has
}

type routeAttachmentTuple struct {
	gateway  string
	section  string
	hostname string
	path     string
}

func (p *gatewayRouteHealthCheck) scanHTTPRouteConflicts(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	routes []unstructured.Unstructured,
	conflictRep *probefw.SweepReport,
	summaryRep *probefw.SweepReport,
) {
	type tupleClaim struct {
		namespaces map[string]bool
		routes     []*unstructured.Unstructured
	}
	claims := map[routeAttachmentTuple]*tupleClaim{}

	for i := range routes {
		rt := &routes[i]
		if rt.GetDeletionTimestamp() != nil {
			continue
		}
		ns := rt.GetNamespace()
		parentEntries := httpRouteParentTuples(rt)
		if len(parentEntries) == 0 {
			continue
		}
		hosts := httpRouteHostnames(rt)
		paths := httpRoutePaths(rt)

		for _, pe := range parentEntries {
			for _, h := range hosts {
				for _, pt := range paths {
					tup := routeAttachmentTuple{
						gateway:  pe.gw,
						section:  pe.section,
						hostname: h,
						path:     pt,
					}
					c := claims[tup]
					if c == nil {
						c = &tupleClaim{namespaces: map[string]bool{}}
						claims[tup] = c
					}
					c.namespaces[ns] = true
					c.routes = append(c.routes, rt)
				}
			}
		}
	}

	for tup, c := range claims {
		if len(c.namespaces) < 2 {
			continue
		}
		k := tup.gateway + "/" + tup.section + "/" + tup.hostname + "/" + tup.path
		conflictRep.Flag(gatewayRouteConflictGauge, k,
			[]string{tup.gateway, tup.section, tup.hostname, tup.path})
		nsList := make([]string, 0, len(c.namespaces))
		for ns := range c.namespaces {
			nsList = append(nsList, ns)
		}
		slices.Sort(nsList)
		summaryRep.Find(fmt.Sprintf("HTTPRoute conflict on %s section=%q host=%q path=%q (namespaces=%s)",
			tup.gateway, tup.section, tup.hostname, tup.path, strings.Join(nsList, ",")))
		for _, rt := range c.routes {
			p.emitGatewayWarning(ctx, log, now, rt, "HTTPRouteCrossNamespaceConflict",
				fmt.Sprintf("HTTPRoute %s/%s conflicts across namespaces (%s) on Gateway %s section=%q host=%q path=%q",
					rt.GetNamespace(), rt.GetName(), strings.Join(nsList, ","),
					tup.gateway, tup.section, tup.hostname, tup.path))
		}
	}
}

type routeParentTuple struct {
	gw      string
	section string
}

func httpRouteParentTuples(route *unstructured.Unstructured) []routeParentTuple {
	refs, found := kube.NestedSlice(route.Object, "spec", "parentRefs")
	if !found {
		return nil
	}
	var out []routeParentTuple
	for _, r := range refs {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		group, _ := kube.NestedString(rm, "group")
		kind, _ := kube.NestedString(rm, "kind")
		if (group != "" && group != "gateway.networking.k8s.io") ||
			(kind != "" && kind != "Gateway") {
			continue
		}
		name, _ := kube.NestedString(rm, "name")
		if name == "" {
			continue
		}
		ns, _ := kube.NestedString(rm, "namespace")
		if ns == "" {
			ns = route.GetNamespace()
		}
		sec, _ := kube.NestedString(rm, "sectionName")
		out = append(out, routeParentTuple{gw: ns + "/" + name, section: sec})
	}
	return out
}

func httpRouteHostnames(route *unstructured.Unstructured) []string {
	raw, found := kube.NestedSlice(route.Object, "spec", "hostnames")
	if !found || len(raw) == 0 {
		return []string{"*"}
	}
	var hosts []string
	for _, v := range raw {
		if s, ok := v.(string); ok && s != "" {
			hosts = append(hosts, s)
		}
	}
	if len(hosts) == 0 {
		return []string{"*"}
	}
	return hosts
}

func httpRoutePaths(route *unstructured.Unstructured) []string {
	rules, found := kube.NestedSlice(route.Object, "spec", "rules")
	if !found || len(rules) == 0 {
		return []string{"PathPrefix:/"}
	}
	seen := map[string]bool{}
	var out []string
	add := func(pt string) {
		if !seen[pt] {
			seen[pt] = true
			out = append(out, pt)
		}
	}
	for _, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		matches, mfound := kube.NestedSlice(rm, "matches")
		if !mfound || len(matches) == 0 {
			add("PathPrefix:/")
			continue
		}
		for _, m := range matches {
			mm, ok := m.(map[string]any)
			if !ok {
				continue
			}
			pt, _ := kube.NestedString(mm, "path", "type")
			pv, _ := kube.NestedString(mm, "path", "value")
			if pt == "" {
				pt = "PathPrefix"
			}
			if pv == "" {
				pv = "/"
			}
			add(pt + ":" + pv)
		}
	}
	if len(out) == 0 {
		return []string{"PathPrefix:/"}
	}
	return out
}
