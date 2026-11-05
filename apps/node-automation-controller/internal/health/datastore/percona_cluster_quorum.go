package datastore

import (
	"context"
	"fmt"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/health/probefw"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// perconaQuorumCheck is the W10-ST5 Percona cluster quorum watchdog.
type perconaQuorumCheck struct {
	*probefw.Deps

	//   - perconaInitSeen: "gvr/ns/name" → first sweep the Percona
	//     cluster read "initializing" — the 30m stuck-initializing
	//     window for checkPerconaClusterQuorum (W10-ST5). Pruned on
	//     resolve so a later re-init re-arms.
	perconaInitSeen map[string]time.Time
}

// newPerconaQuorumCheck builds the W10-ST5 check with a fresh
// first-seen map — the state-map initialization that used to live in
// the monolithic newClusterHealthProber literal.
func NewPerconaQuorumCheck(d *probefw.Deps) probefw.Check {
	return &perconaQuorumCheck{Deps: d,
		perconaInitSeen: map[string]time.Time{},
	}
}

// ---------------------------------------------------------------------------
// W10-ST5 — percona-cluster-quorum.
// ---------------------------------------------------------------------------

const (
	// CheckNamePerconaQuorum is the check's kuberhealthy_check
	// label value — W10-ST5; not a ported HealthCheck but reports
	// under its own check name so the generic FAIL alerting path
	// covers it.
	CheckNamePerconaQuorum = "percona-cluster-quorum"
	// perconaInitMinAge bounds how long a Percona cluster may sit in
	// "initializing" before the quorum check calls it stuck — fresh
	// clusters legitimately take tens of minutes to bootstrap.
	perconaInitMinAge = 30 * time.Minute
)

// perconaClusterGVRs are the three Percona operator CRDs the quorum
// check sweeps cluster-wide; a cluster without a given operator
// simply has no objects (CRD absent → the List misses quietly).
var perconaClusterGVRs = shared.PerconaClusterGVRs

// checkPerconaClusterQuorum flags Percona database clusters that
// report an error state, sit in "initializing" past
// perconaInitMinAge, or show fewer than one ready instance while not
// paused (W10-ST5). Suggested run() registration name:
// "percona-cluster-quorum".
func (p *perconaQuorumCheck) Run(ctx context.Context) probefw.Result {
	if p.Dyn == nil {
		return probefw.Result{Infra: fmt.Errorf(
			"no dynamic client — percona quorum check unverifiable")}
	}
	now := p.Now()
	if p.perconaInitSeen == nil {
		p.perconaInitSeen = map[string]time.Time{}
	}

	var offenders []string
	live := map[string]bool{}
	var firstErr error
	for _, gvr := range perconaClusterGVRs {
		list, err := p.Dyn.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
				continue // operator/CRD not installed on this cluster
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("list %s: %w", gvr.Resource, err)
			}
			continue
		}
		for i := range list.Items {
			o := &list.Items[i]
			key := gvr.Resource + "/" + o.GetNamespace() + "/" + o.GetName()
			live[key] = true
			if perconaClusterPaused(o) {
				p.clearPerconaInit(key)
				continue
			}
			state, _ := shared.NestedString(o.Object, "status", "state")
			statusField, _ := shared.NestedString(o.Object, "status", "status")
			switch {
			case strings.EqualFold(state, "error") ||
				strings.EqualFold(statusField, "error"):
				offenders = append(offenders, fmt.Sprintf(
					"%s/%s state=%s", o.GetNamespace(), o.GetName(),
					perconaStateLabel(state, statusField)))
				p.clearPerconaInit(key)
			case strings.EqualFold(state, "initializing") ||
				strings.EqualFold(statusField, "initializing"):
				// Initializing is checked BEFORE ready<1: a fresh
				// cluster's operator writes status.ready:0 while
				// bootstrapping — flagging it here would bypass
				// the perconaInitMinAge grace and flap new
				// clusters (W10-ST5 review).
				if p.perconaInitAge(key, now) >= perconaInitMinAge {
					offenders = append(offenders, fmt.Sprintf(
						"%s/%s initializing>%s", o.GetNamespace(),
						o.GetName(), perconaInitMinAge))
				}
			case perconaReadyBelowOne(o):
				offenders = append(offenders, fmt.Sprintf(
					"%s/%s ready<1", o.GetNamespace(), o.GetName()))
				p.clearPerconaInit(key)
			default:
				p.clearPerconaInit(key)
			}
		}
	}
	// Prune init timers for clusters that disappeared entirely.
	for k := range p.perconaInitSeen {
		if !live[k] {
			delete(p.perconaInitSeen, k)
		}
	}

	if len(offenders) > 0 {
		return probefw.Result{Why: fmt.Sprintf(
			"percona cluster quorum: %s", strings.Join(offenders, ", "))}
	}
	if firstErr != nil {
		return probefw.Result{Infra: firstErr}
	}
	return probefw.Result{Pass: true}
}

// perconaClusterPaused reports spec.pause==true or spec.mode=="paused"
// — a deliberately parked cluster is not a quorum failure.
func perconaClusterPaused(o *unstructured.Unstructured) bool {
	if paused, _ := shared.NestedBool(o.Object, "spec", "pause"); paused {
		return true
	}
	if mode, _ := shared.NestedString(o.Object, "spec", "mode"); mode == "paused" {
		return true
	}
	return false
}

// perconaReadyBelowOne reads the ready-instance count across the
// Percona status shapes: top-level status.ready (PXC, PSMDB) or the
// nested status.postgres.ready (PGv2 keeps readiness under the
// postgres component). Absent fields read as "unknown", not zero —
// an operator that never wrote a count must not false-positive.
func perconaReadyBelowOne(o *unstructured.Unstructured) bool {
	if ready, found := shared.NestedInt64(o.Object, "status", "ready"); found {
		return ready < 1
	}
	if ready, found := shared.NestedInt64(o.Object, "status", "postgres", "ready"); found {
		return ready < 1
	}
	return false
}

// perconaStateLabel picks the non-empty state/status string for the
// offender message.
func perconaStateLabel(state, statusField string) string {
	if state != "" {
		return state
	}
	return statusField
}

// perconaInitAge records (or returns the age of) the first sweep this
// cluster was seen initializing — the 30m stuck-initializing clock.
func (p *perconaQuorumCheck) perconaInitAge(key string, now time.Time) time.Duration {
	since, ok := p.perconaInitSeen[key]
	if !ok {
		p.perconaInitSeen[key] = now
		return 0
	}
	return now.Sub(since)
}

// clearPerconaInit drops a cluster's initializing timer — resolved,
// errored or otherwise no longer initializing.
func (p *perconaQuorumCheck) clearPerconaInit(key string) {
	delete(p.perconaInitSeen, key)
}
