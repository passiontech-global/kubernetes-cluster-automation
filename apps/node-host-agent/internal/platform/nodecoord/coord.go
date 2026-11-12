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
	// lock keeps holding local actions through apiserver errors —
	// a brief flap must not drop the drain hold, but an
	// unverifiable lock cannot hold forever (the fail-open
	// contract). Same freshness quantum as the annotation cache.
	kuredLockTTL = CacheTTL

	// conditionReason is the NodeCondition Reason stamped with
	// LocalRemediationInProgress — stable string the cluster side
	// matches on.
	conditionReason = "L1SelfHeal"

	// kuredLockAnno is the reboot-drain lock annotation — the same
	// key the controller's maintenance mutex reads off the kured
	// DaemonSet; L1 checks it on the NODE object (kured stamps the
	// node it holds the lock for on versions that do).
	kuredLockAnno = "weave.works/kured-node-lock"
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
	defer c.mu.Unlock()
	if c.cacheGood && c.now().Sub(c.cachedAt) < CacheTTL {
		return c.verdictLocked(c.cached, c.cachedAt), nil
	}
	if c.GetAnnos == nil {
		return Verdict{}, errors.New("nodecoord: nil GetAnnos")
	}
	annos, err := c.GetAnnos(ctx)
	if err != nil {
		if c.cacheGood {
			v := c.verdictLocked(c.cached, c.cachedAt)
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
			return v, err
		}
		return Verdict{}, err
	}
	c.cached = annos
	c.cachedAt = c.now()
	c.cacheGood = true
	v := c.verdictLocked(annos, c.cachedAt)
	c.lastKuredLocked = v.KuredLocked
	c.lastKuredAt = c.cachedAt
	if v.MaintenanceUntil.After(c.now()) &&
		v.MaintenanceUntil.After(c.lastMaintUntil) {
		c.lastMaintUntil = v.MaintenanceUntil
	}
	return v, nil
}

func (c *Coord) verdictLocked(annos map[string]string, at time.Time) Verdict {
	v := Verdict{FetchedAt: at}
	if t, ok := parseAnnoTime(annos[nodecond.AnnoClusterMaintenanceUntil]); ok {
		v.MaintenanceUntil = t
	}
	v.KuredLocked = annos[kuredLockAnno] != ""
	v.Active = v.KuredLocked || v.MaintenanceUntil.After(c.now())
	return v
}

// HoldLocalAction is the convenience gate heal paths call before a
// node-local restart or infra-pod delete.
//
// Fail-open contract (RBAC reality): the agent's ClusterRole only
// grants nodes [get,list] — on a standalone controller VM with no
// kubelet Node object (Get → 404) or while kube-apiserver is down,
// an unverifiable maintenance state must NOT freeze L1 self-heal
// (that is exactly when k0scontroller needs its own restart guards).
// The hold engages only while a PREVIOUSLY CONFIRMED
// MaintenanceUntil window is still open (now < lastMaintUntil) —
// a drain verified moments ago keeps holding through an API blip,
// everything else fails open.
func (c *Coord) HoldLocalAction(ctx context.Context) bool {
	v, err := c.Maintenance(ctx)
	if err == nil {
		return v.Active
	}
	c.mu.Lock()
	until := c.lastMaintUntil
	kured := c.lastKuredLocked && c.now().Sub(c.lastKuredAt) < kuredLockTTL
	c.mu.Unlock()
	// A confirmed kured drain lock holds through a brief apiserver
	// flap exactly like a confirmed maintenance window does —
	// kuredLockTTL bounds how long the unverifiable hold lasts.
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

// parseAnnoTime reads the RFC3339 stamps the controller writes —
// tolerant of a bare unix-seconds value for hand-set annotations.
func parseAnnoTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	return time.Time{}, false
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
