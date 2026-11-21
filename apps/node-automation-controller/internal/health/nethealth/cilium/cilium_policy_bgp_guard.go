// cilium_policy_bgp_guard.go — health check "cilium-policy-bgp-guard" (#70):
// detect-only guard monitoring Cilium policy application health and Cilium BGP
// Control Plane peering state:
//  1. CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy: detects policy
//     application errors via legacy status.nodes.<node>.ok == false AND Cilium
//     1.17+ status.conditions (type=Valid, status=False) /
//     status.derivativePolicies.<k>.ok == false, sustained >= 10m.
//  2. CiliumBGPNodeConfig (v2 / v2alpha1 fallback): detects BGP peers whose
//     status.bgpInstances[].peers[].sessionState != "established" (case-
//     insensitive), sustained >= 5m.
//
// CRD absence (404/NoMatch) skips cleanly and prunes stale series/timers;
// RBAC 403 Forbidden logs at V(1) and carries held series without failing or
// incrementing error counters.
package cilium

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

const (
	// CheckNameCiliumPolicyBGPGuard is the registry check name for #5B/#70.
	CheckNameCiliumPolicyBGPGuard = "cilium-policy-bgp-guard"

	ciliumPolicyErrorMinAge = 10 * time.Minute
	ciliumBGPPeerDownMinAge = 5 * time.Minute
)

var (
	ciliumPolicyErrorGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_cilium_policy_error",
		Help: "1 while a CiliumNetworkPolicy or CiliumClusterwideNetworkPolicy has node status errors or Valid=False past 10m.",
	}, []string{"kind", "namespace", "name"})

	ciliumBGPPeerDownGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_cilium_bgp_peer_down",
		Help: "1 while a CiliumBGPNodeConfig BGP peer sessionState is not established past 5m.",
	}, []string{"node", "asn", "peer"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		ciliumPolicyErrorGauge,
		ciliumBGPPeerDownGauge,
	)
}

type ciliumPolicyBGPGuardCheck struct {
	*probefw.Deps

	policySeen state.FirstSeenLedger
	bgpSeen    state.FirstSeenLedger

	policyEmitted state.GaugeLedger[string]
	bgpEmitted    state.GaugeLedger[string]
}

// NewCiliumPolicyBGPGuardCheck builds the cilium-policy-bgp-guard check.
func NewCiliumPolicyBGPGuardCheck(d *probefw.Deps) probefw.Check {
	return &ciliumPolicyBGPGuardCheck{Deps: d}
}

func (c *ciliumPolicyBGPGuardCheck) Run(ctx context.Context) probefw.Result {
	if r := c.RequireDyn("cilium policy and bgp guard"); r != nil {
		return *r
	}
	log := logf.FromContext(ctx)
	now := c.Now()

	var policyRep, bgpRep, summaryRep probefw.SweepReport

	c.scanCiliumPolicies(ctx, log, now, &policyRep, &summaryRep)
	c.scanCiliumBGP(ctx, log, now, &bgpRep, &summaryRep)

	policyRep.Close(&c.policyEmitted, ciliumPolicyErrorGauge.DeleteLabelValues)
	bgpRep.Close(&c.bgpEmitted, ciliumBGPPeerDownGauge.DeleteLabelValues)
	return summaryRep.Verdict("cilium policy/bgp guard: ", ", ")
}

func (c *ciliumPolicyBGPGuardCheck) scanCiliumPolicies(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	policyRep *probefw.SweepReport,
	summaryRep *probefw.SweepReport,
) {
	targets := []struct {
		gvr  schema.GroupVersionResource
		kind string
	}{
		{gvr: kube.GVRCiliumNetworkPolicy, kind: "CiliumNetworkPolicy"},
		{gvr: kube.GVRCiliumClusterwideNetworkPolicy, kind: "CiliumClusterwideNetworkPolicy"},
	}

	policySeenKeep := map[string]bool{}
	holdKinds := map[string]bool{}

	for _, t := range targets {
		items, err := c.AllUnstructured(ctx, t.gvr)
		switch {
		case kube.IsCRDAbsent(err):
			// CRD absent — skip without carrying so stale tuples and timers prune.
			continue
		case apierrors.IsForbidden(err):
			log.V(1).Info(t.kind+" list skipped (403)", "error", err)
			carryPolicyByKind(policyRep, &c.policyEmitted, t.kind)
			holdKinds[t.kind] = true
			continue
		case err != nil:
			summaryRep.InfraErr(fmt.Errorf("list %s: %w", t.kind, err))
			carryPolicyByKind(policyRep, &c.policyEmitted, t.kind)
			holdKinds[t.kind] = true
			continue
		}

		for i := range items {
			u := &items[i]
			detail, since, errored := ciliumPolicyStatusError(u)
			if !errored {
				continue
			}
			ns := u.GetNamespace()
			name := u.GetName()
			key := t.kind + "/" + ns + "/" + name
			persisted := false
			if !since.IsZero() {
				persisted = now.Sub(since) >= ciliumPolicyErrorMinAge
			} else {
				policySeenKeep[key] = true
				persisted = probefw.Persisted(&c.policySeen, key, now, ciliumPolicyErrorMinAge, log)
			}
			if !persisted {
				continue
			}
			policyRep.Flag(ciliumPolicyErrorGauge, key, []string{t.kind, ns, name})
			target := name
			if ns != "" {
				target = ns + "/" + name
			}
			if detail != "" {
				summaryRep.Find(fmt.Sprintf("%s %s (%s)", t.kind, target, detail))
			} else {
				summaryRep.Find(fmt.Sprintf("%s %s", t.kind, target))
			}
		}
	}

	c.policySeen.Prune(func(k string) bool {
		if policySeenKeep[k] {
			return true
		}
		kind, _, _ := strings.Cut(k, "/")
		return holdKinds[kind]
	})
}

func (c *ciliumPolicyBGPGuardCheck) scanCiliumBGP(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	bgpRep *probefw.SweepReport,
	summaryRep *probefw.SweepReport,
) {
	items, _, err := c.AllUnstructuredFirst(ctx, kube.CiliumBGPNodeConfigGVRs)
	switch {
	case kube.IsCRDAbsent(err):
		// CRD absent — prune any stale series and first-seen entries.
		c.bgpSeen.Prune(func(string) bool { return false })
		return
	case apierrors.IsForbidden(err):
		log.V(1).Info("CiliumBGPNodeConfig list skipped (403)", "error", err)
		for k, lv := range c.bgpEmitted.Last() {
			bgpRep.Carry(k, lv)
		}
		return
	case err != nil:
		summaryRep.InfraErr(fmt.Errorf("list ciliumbgpnodeconfigs: %w", err))
		for k, lv := range c.bgpEmitted.Last() {
			bgpRep.Carry(k, lv)
		}
		return
	}

	bgpSeenKeep := map[string]bool{}
	for i := range items {
		cfg := &items[i]
		node := cfg.GetName()
		nodeDownSince := ciliumBGPNodeConditionDownSince(cfg)
		instances, ok := kube.NestedSlice(cfg.Object, "status", "bgpInstances")
		if !ok {
			continue
		}
		for _, instRaw := range instances {
			inst, ok := instRaw.(map[string]any)
			if !ok {
				continue
			}
			asn := "unknown"
			if n, ok := kube.NestedNumber(inst, "localASN"); ok {
				asn = strconv.FormatInt(n, 10)
			}
			peers, ok := kube.NestedSlice(inst, "peers")
			if !ok {
				continue
			}
			for _, peerRaw := range peers {
				peerMap, ok := peerRaw.(map[string]any)
				if !ok {
					continue
				}
				sessionState, _ := kube.NestedString(peerMap, "sessionState")
				if strings.EqualFold(sessionState, "established") {
					continue
				}
				peer, _ := kube.NestedString(peerMap, "peerAddress")
				if peer == "" {
					peer, _ = kube.NestedString(peerMap, "name")
				}
				if peer == "" {
					peer = "unknown"
				}
				since, ok := kube.NestedTime(peerMap, "lastTransitionTime")
				if !ok || since.IsZero() {
					since = nodeDownSince
				}
				key := node + "/" + asn + "/" + peer
				persisted := false
				if !since.IsZero() {
					persisted = now.Sub(since) >= ciliumBGPPeerDownMinAge
				} else {
					bgpSeenKeep[key] = true
					persisted = probefw.Persisted(&c.bgpSeen, key, now, ciliumBGPPeerDownMinAge, log)
				}
				if !persisted {
					continue
				}
				bgpRep.Flag(ciliumBGPPeerDownGauge, key, []string{node, asn, peer})
				stateLabel := sessionState
				if stateLabel == "" {
					stateLabel = "unknown"
				}
				summaryRep.Find(fmt.Sprintf("bgp %s asn=%s peer=%s state=%s", node, asn, peer, stateLabel))
			}
		}
	}

	c.bgpSeen.Prune(func(k string) bool { return bgpSeenKeep[k] })
}

func carryPolicyByKind(rep *probefw.SweepReport, ledger *state.GaugeLedger[string], kind string) {
	for k, lv := range ledger.Last() {
		if len(lv) >= 1 && lv[0] == kind {
			rep.Carry(k, lv)
		}
	}
}

func ciliumBGPNodeConditionDownSince(cfg *unstructured.Unstructured) time.Time {
	if cond, ok := kube.ConditionOf(cfg.Object, "BGPPeerDown"); ok &&
		strings.EqualFold(cond.Status, "True") && !cond.LastTransitionTime.IsZero() {
		return cond.LastTransitionTime
	}
	return time.Time{}
}

func earlierTime(cur, candidate time.Time) time.Time {
	if candidate.IsZero() {
		return cur
	}
	if cur.IsZero() || candidate.Before(cur) {
		return candidate
	}
	return cur
}

// ciliumPolicyStatusError inspects both legacy per-node status
// (status.nodes.<node>.ok == false) and Cilium 1.17+ conditions / derivative
// policy status (status.conditions[type=Valid].status == False or
// status.derivativePolicies.<k>.ok == false). It returns the highest-priority
// detail string, the earliest observed error timestamp across all errored
// entries (zero if none carry a timestamp), and whether an error was found.
func ciliumPolicyStatusError(u *unstructured.Unstructured) (detail string, since time.Time, errored bool) {
	if nodesMap, ok := kube.NestedMap(u.Object, "status", "nodes"); ok {
		nodeNames := make([]string, 0, len(nodesMap))
		for k := range nodesMap {
			nodeNames = append(nodeNames, k)
		}
		sort.Strings(nodeNames)
		for _, node := range nodeNames {
			nm, ok := nodesMap[node].(map[string]any)
			if !ok {
				continue
			}
			okVal, hasOK := kube.NestedBool(nm, "ok")
			if hasOK && !okVal {
				errored = true
				if detail == "" {
					errMsg, _ := kube.NestedString(nm, "error")
					if errMsg != "" {
						detail = "node=" + node + ": " + errMsg
					} else {
						detail = "node=" + node + " ok=false"
					}
				}
				if ts, ok := kube.NestedTime(nm, "lastUpdated"); ok {
					since = earlierTime(since, ts)
				}
			}
		}
	}

	if cond, ok := kube.ConditionOf(u.Object, "Valid"); ok && strings.EqualFold(cond.Status, "False") {
		errored = true
		if detail == "" {
			switch {
			case cond.Message != "":
				detail = cond.Message
			case cond.Reason != "":
				detail = cond.Reason
			default:
				detail = "Valid=False"
			}
		}
		since = earlierTime(since, cond.LastTransitionTime)
	}

	if derivMap, ok := kube.NestedMap(u.Object, "status", "derivativePolicies"); ok {
		names := make([]string, 0, len(derivMap))
		for k := range derivMap {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			dm, ok := derivMap[k].(map[string]any)
			if !ok {
				continue
			}
			okVal, hasOK := kube.NestedBool(dm, "ok")
			if hasOK && !okVal {
				errored = true
				if detail == "" {
					errMsg, _ := kube.NestedString(dm, "error")
					if errMsg != "" {
						detail = "derivative=" + k + ": " + errMsg
					} else {
						detail = "derivative=" + k + " ok=false"
					}
				}
				if ts, ok := kube.NestedTime(dm, "lastUpdated"); ok {
					since = earlierTime(since, ts)
				}
			}
		}
	}

	return detail, since, errored
}
