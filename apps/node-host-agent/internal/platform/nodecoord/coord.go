// Package nodecoord is the L1↔L3 coordination protocol between
// node-host-agent (L1, on-node self-heal) and
// node-automation-controller (L3, cluster-wide remediation). Both
// directions ride surfaces the node-host-agent ClusterRole already
// grants — NO new RBAC is required:
//
//   - nodes [get,list]        → Cluster→Node annotation read
//   - nodes/status [get,patch]→ Node→Cluster LocalRemediationInProgress
//   - pods    [get,list,delete,patch] → per-pod heal attribution
//
// Cluster → Node (cached CacheTTL): the controller stamps
// nodecond.AnnoClusterMaintenanceUntil on every node while the
// maintenance mutex is held (cluster upgrade, kured drain, Autopilot
// plan) — L1 reads it (plus the weave.works/kured-node-lock
// annotation when present) and HOLDS local restorations/deletes:
// bouncing k0sworker while the cluster drains just adds churn the
// L3 side then has to un-wedge.
//
// Node → Cluster (best-effort StampTimeout): before L1 restarts a
// node-local service it marks NodeCondition LocalRemediationInProgress
// on nodes/status so kubeletreaper & co defer remote tainting while
// L1 self-heals (L1 owns the episode first; L3 is the last resort).
// After bouncing an infra pod it patches the pod's
// last-pod-healed-at annotation so L3 can attribute the churn.
// Writes are hints, never mutexes — a failed stamp costs one cache
// window, never a wrong verdict.
//
// The k8s surface stays behind func seams (GetAnnos /
// PatchNodeStatus / PatchPodAnno) so the package is a platform leaf —
// tests stub the transport and exercise the verdict/stamp logic for
// real. NewKube adapts a kubernetes.Interface for production wiring.
package nodecoord

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

const (
	// CacheTTL bounds the Cluster→Node read cache — the controller
	// restamps maintenance annotations on a ~1/min cadence, so a
	// 30s view is never materially stale.
	CacheTTL = 30 * time.Second
	// StampTimeout bounds each Node→Cluster write — best-effort by
	// contract, never worth stalling a heal cycle.
	StampTimeout = 3 * time.Second
	// LocalRemediationLease is how long the
	// LocalRemediationInProgress condition stays meaningful — the
	// cluster side trusts it only while LastHeartbeatTime is fresh
	// (< ~3m), so a crashed agent cannot freeze L3 remediation for
	// the whole episode.
	LocalRemediationLease = 3 * time.Minute
	// kuredLockTTL bounds how long a SUCCESSFULLY READ kured drain
	// lock keeps holding through apiserver errors in the
	// stale-while-error verdict — a brief flap must not drop the
	// drain hold, but an unverifiable lock cannot hold forever.
	// Same freshness quantum as the annotation cache.
	kuredLockTTL = CacheTTL
	// kuredHealTTL is the wider kured-lock window
	// HoldEmergencyHeal trusts through API failure — a kured drain
	// legitimately runs for minutes, and the fail-open self-heal
	// gate only ever holds on POSITIVELY KNOWN maintenance, so the
	// unverifiable hold may live longer than the verdict cache's.
	kuredHealTTL = 10 * time.Minute

	// conditionReason is the NodeCondition Reason stamped with
	// LocalRemediationInProgress — stable string the cluster side
	// matches on.
	conditionReason = "L1SelfHeal"
)

// StatusCondition is the nodes/status patch payload for the
// LocalRemediationInProgress condition — untyped strings so the
// seam stays k8s-free (NewKube renders them into a strategic merge
// patch on the status subresource).
type StatusCondition struct {
	// Type is the condition name (nodecond.CondLocalRemediation).
	Type string
	// Status is corev1.ConditionStatus as a string ("True"/"False").
	Status string
	// Reason is the machine-readable cause (conditionReason).
	Reason string
	// Message is the human-readable detail — carries the lease
	// expiry hint for operators reading kubectl describe.
	Message string
}

// Coord is the per-node coordination handle. GetAnnos returns the
// node's current annotation map; PatchNodeStatus strategic-merge-
// patches a NodeCondition on nodes/status; PatchPodAnno merge-
// patches annotations on a pod. A nil seam makes the matching
// direction a no-op error, never a panic.
type Coord struct {
	GetAnnos        func(ctx context.Context) (map[string]string, error)
	PatchNodeStatus func(ctx context.Context, cond StatusCondition) error
	PatchPodAnno    func(ctx context.Context, ns, name string, annos map[string]string) error
	// Now is the clock seam; nil → time.Now.
	Now func() time.Time

	mu        sync.Mutex
	cached    map[string]string
	cachedAt  time.Time
	cacheGood bool
	// lastMaintUntil is the furthest MaintenanceUntil any SUCCESSFUL
	// verdict confirmed — the fail-open escape hatch: when the API
	// becomes unreachable, HoldLocalAction keeps holding only while
	// now < lastMaintUntil (a verified window), and fails open
	// otherwise so a dead apiserver cannot freeze L1 self-heal.
	lastMaintUntil time.Time
	// lastKuredLocked/lastKuredAt record the kured drain-lock half
	// of the last SUCCESSFUL annotation read — the TTL-bounded
	// escape hatch for the same flap: a confirmed drain lock keeps
	// holding through kuredLockTTL of API failure, a stale FALSE
	// never does (fresh evidence always wins over the cache).
	lastKuredLocked bool
	lastKuredAt     time.Time
	// flight is the in-flight annotation fetch — concurrent
	// Maintenance callers share ONE apiserver GET (singleflight)
	// instead of stampeding it; the fetch runs outside c.mu so the
	// mutex never spans network I/O.
	flight *annoFlight
}

// annoFlight is one shared annotation fetch: done closes after v/err
// are published, so every waiter observes the same verdict.
type annoFlight struct {
	done chan struct{}
	v    Verdict
	err  error
}

func (c *Coord) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Verdict is the cached Cluster→Node maintenance read.
type Verdict struct {
	// MaintenanceUntil is the parsed
	// AnnoClusterMaintenanceUntil — zero when absent/unparseable.
	MaintenanceUntil time.Time
	// KuredLocked reports the kured drain-lock annotation present.
	KuredLocked bool
	// Active is the hold signal: a live maintenance stamp (until >
	// now) OR the kured lock. Consumers pause local restarts and
	// infra-pod deletes while Active.
	Active bool
	// FetchedAt is when the annotation map was actually read —
	// CacheTTL behind `now` at most.
	FetchedAt time.Time
}

// Maintenance returns the node's cluster-maintenance verdict,
// serving the cached read while it is younger than CacheTTL. A
// GetAnnos failure returns the error AND the last good verdict
// (stale-while-error: a flaky API must not un-freeze a drain in
// progress — consumers treat err != nil as "hold anyway" while a
// previously confirmed window is still open).
func (c *Coord) Maintenance(ctx context.Context) (Verdict, error) {
	c.mu.Lock()
	if c.cacheGood && c.now().Sub(c.cachedAt) < CacheTTL {
		v := c.verdictLocked(c.cached, c.cachedAt)
		c.mu.Unlock()
		return v, nil
	}
	if c.GetAnnos == nil {
		c.mu.Unlock()
		return Verdict{}, errors.New("nodecoord: nil GetAnnos")
	}
	// Singleflight: a fetch already in progress is shared — every
	// concurrent caller waits on the same apiserver GET instead of
	// stampeding it (the mutex never spans the network call).
	if f := c.flight; f != nil {
		c.mu.Unlock()
		select {
		case <-f.done:
			return f.v, f.err
		case <-ctx.Done():
			return Verdict{}, ctx.Err()
		}
	}
	f := &annoFlight{done: make(chan struct{})}
	c.flight = f
	c.mu.Unlock()

	annos, err := c.GetAnnos(ctx)

	c.mu.Lock()
	c.flight = nil
	var v Verdict
	if err != nil {
		if c.cacheGood {
			v = c.verdictLocked(c.cached, c.cachedAt)
			// Fresh evidence wins over the error — a cached TRUE
			// verdict keeps holding through the flap, but a cached
			// FALSE is NOT overwritten: an API error is not
			// evidence of a hold. The raw cached annotation map
			// carries no expiry of its own, so bound the kured
			// half by kuredLockTTL measured from the last
			// successful read; the maintenance half stays bounded
			// by its own timestamp.
			kured := c.lastKuredLocked &&
				c.now().Sub(c.lastKuredAt) < kuredLockTTL
			v.KuredLocked = kured
			v.Active = kured || v.MaintenanceUntil.After(c.now())
		}
	} else {
		c.cached = annos
		c.cachedAt = c.now()
		c.cacheGood = true
		v = c.verdictLocked(annos, c.cachedAt)
		c.lastKuredLocked = v.KuredLocked
		c.lastKuredAt = c.cachedAt
		if v.MaintenanceUntil.After(c.now()) &&
			v.MaintenanceUntil.After(c.lastMaintUntil) {
			c.lastMaintUntil = v.MaintenanceUntil
		}
	}
	f.v, f.err = v, err
	close(f.done)
	c.mu.Unlock()
	return v, err
}

// verdictLocked decodes the annotation map through the shared
// nodecond.EvaluateCoordAnnos — the same fold the cluster side
// applies, so L1 and L3 can never drift on the maintenance verdict.
func (c *Coord) verdictLocked(annos map[string]string, at time.Time) Verdict {
	cv := nodecond.EvaluateCoordAnnos(annos, c.now())
	return Verdict{
		MaintenanceUntil: cv.MaintenanceUntil,
		KuredLocked:      cv.KuredLocked,
		Active:           cv.Active,
		FetchedAt:        at,
	}
}

// HoldLocalAction is the fail-CLOSED gate destructive heal paths
// call before deleting local state (pvc-* dirs, pods, files) — a
// wrong verdict here is unrecoverable churn, so the asymmetry is
// deliberate:
//
//   - verdict read OK        → the maintenance signal itself
//   - Get → 404 NotFound     → fail OPEN: a standalone controller
//     VM has no Node object, so maintenance is unverifiable and
//     must never freeze L1 self-heal
//   - any other API/network error on a node that HAS a Node object
//     → fail CLOSED: during a drain an apiserver flap must not drop
//     the hold — that is exactly when pvc-* cleanup or pod eviction
//     would delete state the drain still needs
func (c *Coord) HoldLocalAction(ctx context.Context) bool {
	v, err := c.Maintenance(ctx)
	if err == nil {
		return v.Active
	}
	if apierrors.IsNotFound(err) {
		return false
	}
	return true
}

// HoldEmergencyHeal is the fail-OPEN gate for self-heal paths that
// must never deadlock on an unreachable apiserver — controller
// restarts, CNI recovery, kubelet nudges. It holds ONLY on
// positively-known maintenance:
//
//   - a successful verdict read with Active set, or
//   - a previously CONFIRMED MaintenanceUntil window still open
//     (now < lastMaintUntil), or
//   - a kured drain lock read within kuredHealTTL
//
// Every API failure with none of those returns false — an
// unverifiable state is never a reason to freeze the very heals
// that un-wedge the cluster.
func (c *Coord) HoldEmergencyHeal(ctx context.Context) bool {
	v, err := c.Maintenance(ctx)
	if err == nil {
		return v.Active
	}
	c.mu.Lock()
	until := c.lastMaintUntil
	kured := c.lastKuredLocked && c.now().Sub(c.lastKuredAt) < kuredHealTTL
	c.mu.Unlock()
	return kured || (!until.IsZero() && c.now().Before(until))
}

// StampLocalRemediation marks NodeCondition LocalRemediationInProgress
// on nodes/status — call BEFORE restarting a node-local service so
// the cluster side yields remote remediation while L1 self-heals.
// The condition self-expires via LastHeartbeatTime freshness on the
// cluster side. Best-effort: the write rides its own StampTimeout
// context; a 404 (controller VM with no Node object) is silent,
// other errors are returned for logging, never fatal.
func (c *Coord) StampLocalRemediation(ctx context.Context) error {
	return c.stampCondition(ctx, StatusCondition{
		Type:   nodecond.CondLocalRemediation,
		Status: "True",
		Reason: conditionReason,
		Message: fmt.Sprintf("L1 self-heal in progress; condition trusted while heartbeat < %s",
			LocalRemediationLease),
	})
}

// StampPodHealed records that L1 just bounced an infra pod — patches
// the pod's last-pod-healed-at annotation (pods patch is in the
// ClusterRole) AND refreshes the LocalRemediationInProgress
// heartbeat on nodes/status so the cluster side attributes the churn
// to a deliberate heal. Call AFTER the delete is accepted. Both
// writes are best-effort and independent: a pod-patch failure does
// not suppress the condition refresh.
func (c *Coord) StampPodHealed(ctx context.Context, ns, name string) error {
	var firstErr error
	if c.PatchPodAnno != nil {
		cctx, cancel := context.WithTimeout(ctx, StampTimeout)
		err := c.PatchPodAnno(cctx, ns, name, map[string]string{
			nodecond.AnnoLastPodHealedAt: c.now().UTC().Format(time.RFC3339),
		})
		cancel()
		if err != nil && !apierrors.IsNotFound(err) {
			firstErr = err
		}
	}
	if err := c.stampCondition(ctx, StatusCondition{
		Type:    nodecond.CondLocalRemediation,
		Status:  "True",
		Reason:  conditionReason,
		Message: fmt.Sprintf("L1 bounced pod %s/%s; heartbeat refreshed", ns, name),
	}); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// stampCondition is the shared nodes/status write — 404 (no Node
// object on this host) is silent by contract; every other error is
// returned for the caller's suspect log.
func (c *Coord) stampCondition(ctx context.Context, cond StatusCondition) error {
	if c.PatchNodeStatus == nil {
		return errors.New("nodecoord: nil PatchNodeStatus")
	}
	cctx, cancel := context.WithTimeout(ctx, StampTimeout)
	defer cancel()
	err := c.PatchNodeStatus(cctx, cond)
	if err != nil && apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

// NewKube adapts a kubernetes.Interface + node name into a Coord —
// the production wiring. Get is a direct (non-cached) node read;
// PatchNodeStatus strategic-merge-patches the condition list on the
// status subresource (patchMergeKey=type keeps sibling conditions
// intact); PatchPodAnno merge-patches pod annotations so sibling
// keys survive. Every write stays inside the ClusterRole grants:
// nodes/status patch + pods patch — never nodes metadata patch.
func NewKube(nodeName string, cs kubernetes.Interface) *Coord {
	return &Coord{
		GetAnnos: func(ctx context.Context) (map[string]string, error) {
			// Bound the node read like every other apiserver touch —
			// an unbounded Get can park Maintenance (and every heal
			// gate behind it) for the client's full retry budget
			// during an apiserver flap.
			gctx, cancel := context.WithTimeout(ctx, StampTimeout)
			defer cancel()
			n, err := cs.CoreV1().Nodes().Get(gctx, nodeName, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			out := make(map[string]string, len(n.Annotations))
			for k, v := range n.Annotations {
				out[k] = v
			}
			return out, nil
		},
		PatchNodeStatus: func(ctx context.Context, cond StatusCondition) error {
			now := metav1.Now()
			payload, err := json.Marshal(map[string]any{
				"status": map[string]any{
					"conditions": []map[string]any{{
						"type":               cond.Type,
						"status":             cond.Status,
						"reason":             cond.Reason,
						"message":            cond.Message,
						"lastHeartbeatTime":  now.UTC().Format(time.RFC3339),
						"lastTransitionTime": now.UTC().Format(time.RFC3339),
					}},
				},
			})
			if err != nil {
				return err
			}
			_, err = cs.CoreV1().Nodes().Patch(ctx, nodeName,
				types.StrategicMergePatchType, payload,
				metav1.PatchOptions{}, "status")
			return err
		},
		PatchPodAnno: func(ctx context.Context, ns, name string, annos map[string]string) error {
			payload, err := json.Marshal(map[string]any{
				"metadata": map[string]any{"annotations": annos},
			})
			if err != nil {
				return err
			}
			_, err = cs.CoreV1().Pods(ns).Patch(ctx, name,
				types.MergePatchType, payload, metav1.PatchOptions{})
			return err
		},
	}
}
