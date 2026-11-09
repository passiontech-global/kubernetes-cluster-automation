// calico.go — the calico-hygiene calico-hygiene guard: orphan cali* veth
// leak detection + GC, and the felix :9099/readiness wedge detector
// with the calico-node pod restart remedy. Dormant on cilium nodes.
package guards

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	// Guard knobs: felix restart after the latch persisted this
	// many consecutive failed cycles, and the orphan-veth down-age
	// for the cali* GC.
	CalicoFelixRestartFails = 3
	calicoVethGCMinAge      = 15 * time.Minute
	// calicoProbeTimeout is the felix readiness probe deadline (5s,
	// curl --max-time 5 parity with the other admin probes).
	calicoProbeTimeout = 5 * time.Second
)

var (
	// pod matchers — anchored like konnPodRe/dnsPodRe.
	calicoNodePodRe = regexp.MustCompile(`^calico-node-[a-z0-9]+$`) // H7 felix
)

// --- Check: calico-hygiene (calico-hygiene) ---
// The cicd cluster runs Calico, not Cilium — the cilium guard
// family above is all dormant there, while calico has its own leak
// modes: orphan cali* veth pairs left by failed CNI DELs (classic
// on high-churn CI nodes) and a wedged felix datapath whose
// :9099/readiness goes dark while the pod looks Running.
//   - Check 1 (veth leak): cali* iface count > node pod count +
//     CalicoOrphanVethThreshold for ConsecNeeded cycles →
//     state-calico-veth-leak (log-only — mass veth deletion is not
//     an unattended remedy).
//   - Check 2 (felix readiness): a Running calico-node pod whose
//     :9099/readiness fails ConsecNeeded cycles →
//     state-calico-felix-down for the NHC escalation path.
// The check is dormant everywhere cilium_host exists (cilium nodes)
// and on hosts with no cali* ifaces at all (non-calico, hub nodes).

// calicoIfaceCount counts cali* interfaces under SysClassNet; -1
// when the sysfs root is unreadable (inconclusive).
func calicoIfaceCount(d *wdeps.Deps) int {
	entries, err := os.ReadDir(d.Cfg.SysClassNet)
	if err != nil {
		return -1
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "cali") {
			n++
		}
	}
	return n
}

// CalicoCheck is the calico-hygiene calico guard as a Check; it owns the
// veth-leak and felix readiness streaks (ex-Hygiene.calicoVethFails/
// .calicoFelixFails).
type CalicoCheck struct {
	d          *wdeps.Deps
	VethFails  int
	felixFails int
}

// Name returns the check label / WD_SIG key.
func (c *CalicoCheck) Name() string { return wdeps.CheckCalico }

// Run executes one calico-hygiene round.
func (c *CalicoCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCalico) {
		return
	}
	if _, err := os.Stat(filepath.Join(c.d.Cfg.SysClassNet, "cilium_host")); err == nil {
		// Cilium node — every calico verdict belongs to the cilium
		// guard family; drop stale evidence like checkCiliumWGPeers.
		c.VethFails = 0
		c.felixFails = 0
		c.d.State.Exit(latchdefs.LatchCalicoVethLeak, nil)
		c.d.State.Exit(latchdefs.LatchCalicoFelixDown, nil)
		c.d.CycleResult(wdeps.CheckCalico, "ok")
		return
	}
	cali := calicoIfaceCount(c.d)
	if cali <= 0 {
		// No cali* veth at all — not a calico node (unreadable
		// sysfs reports -1 the same way: nothing to verify).
		c.VethFails = 0
		c.felixFails = 0
		c.d.State.Exit(latchdefs.LatchCalicoVethLeak, nil)
		c.d.State.Exit(latchdefs.LatchCalicoFelixDown, nil)
		c.d.CycleResult(wdeps.CheckCalico, "ok")
		return
	}
	if !e.APIOK {
		// Pod count is the leak baseline — an API flake makes the
		// comparison invalid. Keep streaks/latches (inconclusive).
		c.d.CycleResult(wdeps.CheckCalico, "abort")
		return
	}
	// Check 1 — orphan veth leak.
	if cali > len(e.Pods)+c.d.Cfg.Calico.OrphanVethThreshold {
		if !c.d.StreakPending(&c.VethFails, fmt.Sprintf(
			"suspect: calico-hygiene veth leak candidate cali=%d pods=%d",
			cali, len(e.Pods))) {
			if !c.d.State.Exists(latchdefs.LatchCalicoVethLeak) {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: calico-hygiene orphan veth leak cali=%d pods=%d threshold=%d — CNI DEL cleanup is leaking veth pairs",
					cali, len(e.Pods), c.d.Cfg.Calico.OrphanVethThreshold))
			}
			c.d.State.Enter(latchdefs.LatchCalicoVethLeak,
				fmt.Sprintf("cali=%d pods=%d", cali, len(e.Pods)))
		}
	} else {
		c.VethFails = 0
		c.d.State.Exit(latchdefs.LatchCalicoVethLeak, nil)
	}
	// Check 1b — orphan-veth GC (mesh-net-guards): while the leak latch is
	// set, reap cali* host veths that stayed DOWN (carrier 0) for
	// calicoVethGCMinAge. Live veths always answer carrier=1; a
	// leaked one from a failed CNI DEL is DOWN forever. The
	// veth-seen-<name> marker provides the 15m age — same
	// confirm-marker shape as wedged-seen-* (a veth must not be
	// deleted on a single read: an interface mid-creation can read
	// carrier 0 for a moment).
	if c.d.State.Exists(latchdefs.LatchCalicoVethLeak) {
		gcCalicoOrphanVeths(c.d, ctx)
	}
	// Check 2 — felix readiness, gated on a Running calico-node pod
	// on this node (no pod → nothing to probe).
	var felix *corev1.Pod
	for i := range e.Pods {
		p := &e.Pods[i]
		if (p.Namespace == "kube-system" || p.Namespace == "calico-system") &&
			calicoNodePodRe.MatchString(p.Name) &&
			p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning {
			felix = p
			break
		}
	}
	switch {
	case felix == nil || c.d.Cfg.Calico.FelixReadyURL == "":
		c.felixFails = 0
		c.d.State.Exit(latchdefs.LatchCalicoFelixDown, nil)
	default:
		code, err := c.d.Cfg.Seams.Probe.ProbeHTTPStatus(ctx,
			c.d.Cfg.Calico.FelixReadyURL, "", calicoProbeTimeout)
		if err == nil && code == http.StatusOK {
			c.felixFails = 0
			c.d.State.Exit(latchdefs.LatchCalicoFelixDown, nil)
			break
		}
		if c.d.StreakPending(&c.felixFails, fmt.Sprintf(
			"suspect: calico-felix-down readiness probe code=%d err=%v",
			code, err)) {
			break
		}
		c.d.State.Enter(latchdefs.LatchCalicoFelixDown,
			fmt.Sprintf("readiness_probe_fails=%d", c.felixFails))
		// mesh-net-guards: a felix datapath whose readiness stayed dark
		// across CalicoFelixRestartFails consecutive cycles is a
		// real wedge, not a flap — delete the calico-node pod so
		// the DaemonSet rebuilds it (last-calico-restart budget).
		if c.felixFails >= CalicoFelixRestartFails {
			switch {
			case c.d.State.Exists(latchdefs.LatchNodeOverloaded):
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: calico-felix-down %dx but node overloaded — skip pod restart", c.felixFails))
			case !c.d.State.RateTrySpend("last-calico-restart", c.d.Cfg.MinRestartInterval):
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: calico-felix-down %dx but pod restart in cooldown (<30m), skip", c.felixFails))
			default:
				// Budget spent atomically BEFORE the delete.
				c.d.State.AppendLog(fmt.Sprintf(
					"ACTION: calico-hygiene deleted pod %s/%s - felix readiness down %dx",
					felix.Namespace, felix.Name, c.felixFails))
				if derr := c.d.Cfg.Client.CoreV1().Pods(felix.Namespace).Delete(
					ctx, felix.Name, metav1.DeleteOptions{
						GracePeriodSeconds: ptr.To[int64](0)}); derr != nil {
					c.d.State.AppendLog(fmt.Sprintf(
						"suspect: calico-hygiene delete %s/%s failed: %v",
						felix.Namespace, felix.Name, derr))
				} else {
					c.d.Actions.WithLabelValues(wdeps.CheckCalico, "pod_delete").Inc()
				}
			}
		}
	}
	c.d.CycleResult(wdeps.CheckCalico, "ok")
}

// gcCalicoOrphanVeths reaps cali* host veths that have been DOWN
// (carrier 0) for calicoVethGCMinAge — the orphans a failed CNI
// DEL leaks: they still carry iptables routes and keep the leak
// count climbing even after the latch fired. Confirmation goes
// through a veth-seen-<name> marker in the state dir (the
// wedged-seen-* pattern — a single down read is not enough: an
// iface mid-creation reads carrier 0 briefly). Markers for ifaces
// that vanished or came back up are pruned.
func gcCalicoOrphanVeths(d *wdeps.Deps, ctx context.Context) {
	entries, err := os.ReadDir(d.Cfg.SysClassNet)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "cali") {
			continue
		}
		marker := filepath.Join(d.Cfg.WatchdogStateDir, "veth-seen-"+name)
		carrier, err := os.ReadFile(filepath.Join(d.Cfg.SysClassNet, name, "carrier"))
		if err != nil {
			continue // racing an iface add/remove — neither up nor down
		}
		if strings.TrimSpace(string(carrier)) != "0" {
			// Live veth — a stale marker from an earlier leak
			// episode must not carry into this one.
			_ = os.Remove(marker)
			continue
		}
		if !d.StateFileExists("veth-seen-" + name) {
			d.State.RateSpend("veth-seen-" + name)
			d.State.AppendLog(fmt.Sprintf(
				"calico-hygiene: orphan veth candidate %s - carrier down, confirm in %dm",
				name, int(calicoVethGCMinAge.Minutes())))
			continue
		}
		if !d.State.RateOK("veth-seen-"+name, calicoVethGCMinAge) {
			continue
		}
		if d.Cfg.Systemd == nil {
			d.State.AppendLog(fmt.Sprintf(
				"suspect: calico-hygiene orphan veth %s down >%dm but no systemd client — skip delete",
				name, int(calicoVethGCMinAge.Minutes())))
			continue
		}
		out, derr := d.Cfg.Systemd.Exec(ctx, "ip", "link", "delete", name)
		if derr != nil {
			d.State.AppendLog(fmt.Sprintf(
				"suspect: calico-hygiene ip link delete %s failed: %v (%s)",
				name, derr, strings.TrimSpace(out)))
			continue
		}
		_ = os.Remove(marker)
		d.State.AppendLog(fmt.Sprintf(
			"ACTION: calico-hygiene deleted orphan veth %s - carrier down >%dm (CNI DEL leak)",
			name, int(calicoVethGCMinAge.Minutes())))
		d.Actions.WithLabelValues(wdeps.CheckCalico, "veth_delete").Inc()
	}
	// Prune markers for ifaces that no longer exist.
	if ms, err := filepath.Glob(
		filepath.Join(d.Cfg.WatchdogStateDir, "veth-seen-*")); err == nil {
		for _, m := range ms {
			name := strings.TrimPrefix(filepath.Base(m), "veth-seen-")
			if _, err := os.Stat(filepath.Join(d.Cfg.SysClassNet, name)); err != nil {
				_ = os.Remove(m)
			}
		}
	}
}
