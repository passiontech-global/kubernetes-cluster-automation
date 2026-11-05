package workerhygiene

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/hostutil"
)

// ciliumNamedTasks finds containerd tasks of one cilium container
// (cilium-agent / cilium-envoy) by container-name annotation — the
// Go port of `ctr containers ls 'labels."io.kubernetes.container.name"=="<name>"'`.
// reachable=false means the task root itself is unreadable (ctr
// unreachable parity: inconclusive, keep counters/latches).
func (h *Hygiene) ciliumNamedTasks(name string) (tasks []ctrTask, reachable bool) {
	if _, err := os.ReadDir(h.cfg.CtrTaskRoot); err != nil {
		h.state.AppendLog(fmt.Sprintf(
			"suspect: ctr task root %s unreadable: %v — cilium checks inconclusive",
			h.cfg.CtrTaskRoot, err))
		return nil, false
	}
	for _, root := range []string{h.cfg.CtrTaskRoot, h.cfg.SandboxCtlRoot} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			d := filepath.Join(root, e.Name())
			cfgData, err := os.ReadFile(filepath.Join(d, "config.json"))
			if err != nil {
				continue
			}
			nm := containerNameRe.FindSubmatch(cfgData)
			if nm == nil || string(nm[1]) != name {
				continue
			}
			t := ctrTask{}
			if pidData, err := os.ReadFile(filepath.Join(d, "init.pid")); err == nil {
				if pid, err := strconv.Atoi(strings.TrimSpace(string(pidData))); err == nil {
					t.pid = pid
					t.live = h.pidLive(pid)
				}
			}
			tasks = append(tasks, t)
		}
	}
	return tasks, true
}

// ciliumAgentTasks is the cilium-agent specialization kept for the
// 32/35 call sites.
func (h *Hygiene) ciliumAgentTasks() (tasks []ctrTask, reachable bool) {
	return h.ciliumNamedTasks("cilium-agent")
}

// killNamedTasks SIGKILLs every live init pid of the named
// container — `ctr tasks kill -s SIGKILL` parity. true = at least
// one task killed (a dead task can't be signalled; kubelet retries
// on its own).
func (h *Hygiene) killNamedTasks(tasks []ctrTask, name string) bool {
	killed := false
	for _, t := range tasks {
		if t.live && t.pid > 0 {
			if err := h.cfg.Seams.killFn(t.pid, syscall.SIGKILL); err != nil {
				h.state.AppendLog(fmt.Sprintf(
					"suspect: kill %s pid=%d failed: %v", name, t.pid, err))
			} else {
				killed = true
			}
		}
	}
	return killed
}

// killCiliumAgent SIGKILLs the cilium-agent tasks and flags the
// kill so the B1 check restarts cilium-envoy the same cycle.
func (h *Hygiene) killCiliumAgent(tasks []ctrTask) bool {
	if h.killNamedTasks(tasks, "cilium-agent") {
		h.ciliumAgentKilled = true
		return true
	}
	return false
}

// ciliumCheck — sig9: cilium-agent :9879 healthz down → latch
// cilium-agent-down + SIGKILL the agent container (kubelet restarts
// it immediately, bypassing CrashLoopBackOff). Gates: apiOK (restart
// while the API is dead can't resync), node-overloaded, shared
// last-cilium-restart 30m budget. The W8-NM3 BPF map-pressure probe
// rides inside this check (checkBPFMaps) — it only runs on a green
// healthz, off the same agent socket. fails is the healthz streak
// (ex-Hygiene.ciliumFails).
type ciliumCheck struct {
	h     *Hygiene
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *ciliumCheck) Name() string { return checkCilium }

// Run executes one cilium round.
func (c *ciliumCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkCilium, "gated").Inc()
		return
	}
	tasks, reachable := c.h.ciliumAgentTasks()
	if !reachable {
		// ctr unreachable → inconclusive, keep everything.
		c.h.cycles.WithLabelValues(checkCilium, "abort").Inc()
		return
	}
	if len(tasks) == 0 {
		// No cilium-agent container → this node runs no cilium
		// (calico cluster, hub): clear any false-positive state.
		c.fails = 0
		c.h.state.Exit(hoststate.LatchCiliumAgentDown, nil)
		c.h.cycles.WithLabelValues(checkCilium, "ok").Inc()
		return
	}
	err := c.h.probeHTTPSeries(ctx, c.h.cfg.Cilium.HealthzURL,
		probeAttempts, ciliumProbeTime, c.h.cfg.ProbeGap)
	if err == nil {
		c.fails = 0
		c.h.state.Exit(hoststate.LatchCiliumAgentDown, nil)
		// W8-NM3: a healthy healthz doesn't prove the datapath —
		// conntrack/SNAT/LB BPF maps can sit at capacity while the
		// agent still answers 200. Evaluate the map fill ratios on
		// the same agent socket.
		c.checkBPFMaps(ctx)
		c.h.cycles.WithLabelValues(checkCilium, "ok").Inc()
		return
	}
	c.h.state.Enter(hoststate.LatchCiliumAgentDown, "")
	c.fails++
	switch {
	case !e.apiOK:
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-agent-down healthz fail %dx but API unreachable — skip kill (agent still cannot sync even after restart)",
			c.fails))
	case c.fails >= c.h.cfg.ConsecNeeded &&
		!c.h.state.Exists(hoststate.LatchNodeOverloaded) &&
		c.h.state.RateTrySpend("last-cilium-restart", c.h.cfg.MinRestartInterval):
		// Budget spent atomically BEFORE acting (rate_spend
		// parity): a missed kill still consumed it — the feeder
		// goroutine competes for the same file.
		if c.h.killCiliumAgent(tasks) {
			c.h.state.AppendLog(fmt.Sprintf(
				"ACTION: killed cilium-agent container - healthz down %dx (kubelet will restart)",
				c.fails))
			c.fails = 0
			c.h.actions.WithLabelValues(checkCilium, "sigkill").Inc()
		} else {
			c.h.state.AppendLog(fmt.Sprintf(
				"suspect: cilium-agent-down healthz fail %dx, no running task to kill (kubelet retries itself)",
				c.fails))
		}
	default:
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-agent-down healthz 127.0.0.1:9879 fail (check %d/%d)",
			c.fails, c.h.cfg.ConsecNeeded))
	}
	c.h.cycles.WithLabelValues(checkCilium, "ok").Inc()
}

// ciliumInitCheck — sig15: endpoints stuck in reserved:init
// while healthz stays green (informer wedge — every new pod gets a
// black-holed datapath). The shell ran `cilium-dbg endpoint list` via
// ctr exec; the agent reads the same data from the cilium agent unix
// socket (/v1/endpoint) — reserved:init counting is identical.
// Inconclusive (socket/exec fail) → keep counters, never reset. The
// streak stays on Hygiene (ciliumInitFails) — pre-Check tests poke
// it directly.
type ciliumInitCheck struct{ h *Hygiene }

// Name returns the check label / WD_SIG key.
func (c *ciliumInitCheck) Name() string { return checkCiliumInit }

// Run executes one cilium-init-stuck round.
func (c *ciliumInitCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkCiliumInit, "gated").Inc()
		return
	}
	tasks, reachable := c.h.ciliumAgentTasks()
	if !reachable {
		c.h.cycles.WithLabelValues(checkCiliumInit, "abort").Inc()
		return
	}
	if len(tasks) == 0 {
		c.h.cycles.WithLabelValues(checkCiliumInit, "ok").Inc()
		return
	}
	body, err := c.h.cfg.Seams.unixGet(ctx, c.h.cfg.Cilium.Socket, "/v1/endpoint")
	if err != nil {
		// Endpoint list unreadable — inconclusive: don't count, don't
		// reset (shell: tasks exec fail → exit 0).
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck endpoint query on %s failed: %v — inconclusive, keeping state",
			c.h.cfg.Cilium.Socket, err))
		c.h.cycles.WithLabelValues(checkCiliumInit, "abort").Inc()
		return
	}
	initEps := strings.Count(string(body), "reserved:init")
	if initEps == 0 {
		c.h.ciliumInitFails = 0
		c.h.state.Exit(hoststate.LatchCiliumInitStuck, nil)
		c.h.cycles.WithLabelValues(checkCiliumInit, "ok").Inc()
		return
	}
	c.h.ciliumInitFails++
	if c.h.ciliumInitFails < c.h.cfg.ConsecNeeded {
		c.h.state.AppendLog(fmt.Sprintf("suspect: cilium-init-stuck init_eps=%d (check %d/%d)",
			initEps, c.h.ciliumInitFails, c.h.cfg.ConsecNeeded))
		c.h.cycles.WithLabelValues(checkCiliumInit, "ok").Inc()
		return
	}
	// Wedge confirmed — latch before any gate like the shell.
	c.h.state.Enter(hoststate.LatchCiliumInitStuck, fmt.Sprintf("init_eps=%d", initEps))
	switch {
	case !e.apiOK:
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck init_eps=%d %dx but API unreachable — skip kill (agent still cannot resync even after restart)",
			initEps, c.h.ciliumInitFails))
	case c.h.state.Exists(hoststate.LatchNodeOverloaded):
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck init_eps=%d %dx but node overloaded — skip kill",
			initEps, c.h.ciliumInitFails))
	case !c.h.state.RateTrySpend("last-cilium-restart", c.h.cfg.MinRestartInterval):
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-init-stuck init_eps=%d %dx but restart cooldown — skip kill",
			initEps, c.h.ciliumInitFails))
	default:
		// Budget already spent atomically by the rateTrySpend case —
		// the feeder goroutine competes for the same file.
		if c.h.killCiliumAgent(tasks) {
			c.h.state.AppendLog(fmt.Sprintf(
				"ACTION: killed cilium-agent container - init_eps=%d %dx (kubelet will restart -> informer resync)",
				initEps, c.h.ciliumInitFails))
			c.h.ciliumInitFails = 0
			c.h.actions.WithLabelValues(checkCiliumInit, "sigkill").Inc()
		} else {
			c.h.state.AppendLog(fmt.Sprintf(
				"suspect: cilium-init-stuck init_eps=%d %dx, no running task to kill (kubelet retries itself)",
				initEps, c.h.ciliumInitFails))
		}
	}
	c.h.cycles.WithLabelValues(checkCiliumInit, "ok").Inc()
}

// --- W8-NM3: cilium BPF map pressure ---
// The datapath dies silently long before the agent does: once the
// conntrack, SNAT or LB-service maps hit maxEntries, new flows are
// dropped/blackholed while :9879/healthz keeps returning 200. The
// check reads `GET /v1/map` off the agent socket and latches
// state-cilium-bpf-map-pressure when any critical map exceeds
// BPFMapHighRatio of its capacity — the latch is what NPD/NHC sees;
// no remedy is attempted (map growth needs a datapath
// restart/resize decision a node agent must not take alone).

// ciliumBPFMapCritical is the map set whose fill ratio gates the
// latch — the v4 conntrack pair, the SNAT pool and the v2 LB
// services map hit hard maxEntries first and each blackholes a
// different traffic class when full.
var ciliumBPFMapCritical = map[string]bool{
	"cilium_ct4_global":       true,
	"cilium_ct_any4_global":   true,
	"cilium_snat_v4_external": true,
	"cilium_lb4_services_v2":  true,
}

// parseCiliumBPFMaps extracts name → [used, max] from a /v1/map
// body. Wire shapes differ across agent versions: entries are
// objects carrying either "name" or "path" (the map name is the
// path basename), the used count arrives as a "used"/"entries"/
// "count" number or a "cache" array whose length is the live
// entries, and capacity as "size"/"max"/"maxSize"/"capacity". A map
// with no readable used+max pair is skipped — pressure can only be
// claimed on both numbers.
func parseCiliumBPFMaps(body []byte) map[string][2]int64 {
	var top any
	if json.Unmarshal(body, &top) != nil {
		return nil
	}
	numOf := func(m map[string]any, keys ...string) (int64, bool) {
		for _, k := range keys {
			if f, ok := m[k].(float64); ok {
				return int64(f), true
			}
		}
		return 0, false
	}
	out := map[string][2]int64{}
	var walk func(n any)
	walk = func(n any) {
		switch t := n.(type) {
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			name, _ := t["name"].(string)
			if name == "" {
				if p, _ := t["path"].(string); p != "" {
					name = filepath.Base(p)
				}
			}
			if name != "" && ciliumBPFMapCritical[name] {
				used, uok := numOf(t, "used", "entries", "count")
				if !uok {
					// Entry arrays carry the live count as their
					// length ("cache" on the /v1/map wire;
					// "entries" on some dumps).
					for _, k := range []string{"cache", "entries"} {
						if arr, ok := t[k].([]any); ok {
							used, uok = int64(len(arr)), true
							break
						}
					}
				}
				max, mok := numOf(t, "max", "maxSize", "max-size", "capacity", "size")
				if uok && mok && max > 0 {
					out[name] = [2]int64{used, max}
				}
			}
			// Map collections may be nested under "maps"/
			// "dynamicMaps"/"staticMaps" keys.
			for _, v := range t {
				walk(v)
			}
		}
	}
	walk(top)
	return out
}

// checkBPFMaps reads the map fill ratios off the agent socket
// and latches state-cilium-bpf-map-pressure when a critical map
// exceeds BPFMapHighRatio. An unreadable socket or unparseable body
// is inconclusive (the cilium checks' keep-state rule) — the latch
// is neither entered nor cleared on missing evidence.
func (c *ciliumCheck) checkBPFMaps(ctx context.Context) {
	body, err := c.h.cfg.Seams.unixGet(ctx, c.h.cfg.Cilium.Socket, "/v1/map")
	if err != nil {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-bpf-maps map query on %s failed: %v — inconclusive, keeping state",
			c.h.cfg.Cilium.Socket, err))
		c.h.cycles.WithLabelValues(checkCiliumBPF, "abort").Inc()
		return
	}
	maps := parseCiliumBPFMaps(body)
	var over []string
	for name, um := range maps {
		if float64(um[0]) >= c.h.cfg.Cilium.BPFMapHighRatio*float64(um[1]) {
			over = append(over, fmt.Sprintf("%s=%d/%d", name, um[0], um[1]))
		}
	}
	if len(over) == 0 {
		c.h.state.Exit(hoststate.LatchCiliumBPFMapPressure, nil)
		c.h.cycles.WithLabelValues(checkCiliumBPF, "ok").Inc()
		return
	}
	sort.Strings(over)
	c.h.state.Enter(hoststate.LatchCiliumBPFMapPressure, strings.Join(over, " "))
	c.h.cycles.WithLabelValues(checkCiliumBPF, "ok").Inc()
}

// checkCiliumBPFMaps forwards to the migrated Check — tests written
// before the interface still call the old method shape.
func (h *Hygiene) checkCiliumBPFMaps(ctx context.Context) {
	h.cilium.checkBPFMaps(ctx)
}

// --- Check: ctr-image-healer (37-ctr-image-healer.sh) ---

// ipamCount reads one ipam value as a count — accepts a bare number,
// an array (counted by length) or an object/map (counted by keys),
// because the plan's used/available fields may be reported either as
// counters or as the IP collections themselves.
func ipamCount(v json.RawMessage) (int, bool) {
	s := bytes.TrimSpace(v)
	if len(s) == 0 || bytes.Equal(s, []byte("null")) {
		return 0, false
	}
	switch s[0] {
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(s, &arr); err != nil {
			return 0, false
		}
		return len(arr), true
	case '{':
		var m map[string]json.RawMessage
		if err := json.Unmarshal(s, &m); err != nil {
			return 0, false
		}
		return len(m), true
	default:
		var n float64
		if err := json.Unmarshal(s, &n); err != nil {
			return 0, false
		}
		return int(n), true
	}
}

// freeIPAMPool counts ipam.allocations entries marked free — in
// cluster-pool/multi-pool mode that map is the node's WHOLE pool
// (allocated AND free IPs; a free entry carries an empty owner).
// Values on the real wire are owner-name strings ("10.0.0.5":
// "pod-a"), so an EMPTY string is the free marker; the
// {"owner": "…"} object shape is accepted too for older agents.
// ok=false when the map is absent or fully owned: an all-owned map
// can't be told apart from an allocated-only dump (the non-pool
// modes), and reporting "0 free" there would false-latch exhaustion.
func freeIPAMPool(m map[string]json.RawMessage) (int, bool) {
	if len(m) == 0 {
		return 0, false
	}
	free := 0
	for _, v := range m {
		var owner string
		if err := json.Unmarshal(v, &owner); err == nil {
			if owner == "" {
				free++
			}
			continue
		}
		var e struct {
			Owner string `json:"owner"`
		}
		if err := json.Unmarshal(v, &e); err == nil && e.Owner == "" {
			free++
		}
	}
	return free, free > 0
}

// parseCiliumIPAM extracts used/available IPv4 counts from a
// /v1/healthz body. Two wire shapes are accepted:
//   - ipam.ipv4 as an object {"used":…, "available":…} — the shape
//     module 38 consumes; each value may be a number or a collection
//     (counted by length via ipamCount).
//   - ipam.ipv4 as an array — upstream cilium: the array IS the
//     allocated-IP list, so used = len. The healthz payload carries
//     no pool total in that shape; available is only recovered when
//     ipam.allocations exposes free (unowned) pool entries, else -1
//     (unknown — never invent a pool size).
//
// available == -1 means "unknown" — the `available <= 2` trigger is
// then skipped while `leaked > 30` still applies. ok=false means no
// usable ipam section: inconclusive.
func parseCiliumIPAM(body []byte) (used, available int, ok bool) {
	var resp struct {
		IPAM *struct {
			IPV4        json.RawMessage            `json:"ipv4"`
			Allocations map[string]json.RawMessage `json:"allocations"`
		} `json:"ipam"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.IPAM == nil {
		return 0, -1, false
	}
	available = -1
	raw := bytes.TrimSpace(resp.IPAM.IPV4)
	if len(raw) == 0 {
		return 0, -1, false
	}
	switch raw[0] {
	case '{':
		var obj struct {
			Used      json.RawMessage `json:"used"`
			Available json.RawMessage `json:"available"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			return 0, -1, false
		}
		if n, found := ipamCount(obj.Used); found {
			used = n
		}
		if n, found := ipamCount(obj.Available); found {
			available = n
		}
		return used, available, true
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return 0, -1, false
		}
		used = len(arr)
		if free, found := freeIPAMPool(resp.IPAM.Allocations); found {
			available = free
		}
		return used, available, true
	default:
		// Bare number — the allocated count itself.
		if n, found := ipamCount(raw); found {
			return n, -1, true
		}
		return 0, -1, false
	}
}

// ciliumIPAMCheck reads the agent's IPAM usage off the unix socket
// and cross-checks it against the non-hostNetwork Running pods on
// this node: allocated − in-use = leaked IPs still held for dead
// pods (a real pod eventually can't get an address — the black-hole
// datapath this module exists to catch early). A small constant leak
// (~2: router + health reserved IPs) is normal, so the latch needs
// leaked >30 or available <=2 for ConsecNeeded consecutive cycles.
// The gauges update on every successful probe regardless. The
// streak stays on Hygiene (ciliumIPAMFails) — pre-Check tests poke
// it directly.
type ciliumIPAMCheck struct{ h *Hygiene }

// Name returns the check label / WD_SIG key.
func (c *ciliumIPAMCheck) Name() string { return checkCiliumIPAM }

// Run executes one cilium-ipam round.
func (c *ciliumIPAMCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkCiliumIPAM, "gated").Inc()
		return
	}
	if !e.apiOK {
		// The in-use count comes from the API — a failed LIST would
		// make EVERY allocated IP look leaked.
		c.h.cycles.WithLabelValues(checkCiliumIPAM, "abort").Inc()
		return
	}
	body, err := c.h.cfg.Seams.unixGet(ctx, c.h.cfg.Cilium.Socket, "/v1/healthz")
	if err != nil {
		// Socket unreadable — inconclusive: keep counters/latch
		// (same rule as checkCiliumInitStuck).
		c.h.cycles.WithLabelValues(checkCiliumIPAM, "abort").Inc()
		return
	}
	used, available, ok := parseCiliumIPAM(body)
	if !ok {
		c.h.state.AppendLog("suspect: cilium-ipam healthz has no parseable ipam.ipv4 data — inconclusive")
		c.h.cycles.WithLabelValues(checkCiliumIPAM, "abort").Inc()
		return
	}
	inUse := 0
	for i := range e.pods {
		p := &e.pods[i]
		// The denominator is "pods holding an address", not
		// "Running pods": the CNI call happens at sandbox create,
		// so a Pending/ContainerCreating pod already owns its IP —
		// counting only Running would report those allocations as
		// leaks. Terminal pods keep a stale .status.podIP; cilium
		// frees that allocation at teardown, and if it hasn't, that
		// IS the leak this check exists to find.
		if p.Spec.HostNetwork || p.Status.PodIP == "" ||
			p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		inUse++
	}
	leaked := used - inUse
	if leaked < 0 {
		leaked = 0
	}
	c.h.ciliumAllocated.Set(float64(used))
	c.h.ciliumLeaked.Set(float64(leaked))
	exhausted := leaked > 30 || (available >= 0 && available <= 2)
	if !exhausted {
		c.h.ciliumIPAMFails = 0
		c.h.state.Exit(hoststate.LatchCiliumIPAMExhausted, nil)
		c.h.cycles.WithLabelValues(checkCiliumIPAM, "ok").Inc()
		return
	}
	c.h.ciliumIPAMFails++
	if c.h.ciliumIPAMFails >= c.h.cfg.ConsecNeeded {
		c.h.state.Enter(hoststate.LatchCiliumIPAMExhausted, fmt.Sprintf(
			"used=%d in-use=%d leaked=%d available=%d", used, inUse, leaked, available))
	} else {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-ipam-exhausted used=%d in-use=%d leaked=%d available=%d (check %d/%d)",
			used, inUse, leaked, available, c.h.ciliumIPAMFails, c.h.cfg.ConsecNeeded))
	}
	c.h.cycles.WithLabelValues(checkCiliumIPAM, "ok").Inc()
}

// --- kubelet watchdog feeder + remediate (T15) ---
// Port of scripts/k0s-kubelet-watchdog.sh + k0sworker-remediate.sh.
// The shell feeder was a dedicated systemd unit (k0sworker-watchdog)
// feeding WATCHDOG=1 into its own WatchdogSec and dying `exit 1`
// after KWD_MAX_FAIL consecutive :10248 failures — OnFailure then ran
// the remediate oneshot. In-agent there is no watchdog unit to feed:
// the agent IS the loop — probe every KubeletWdInterval, and on
// KubeletWdMaxFail consecutive fails (~60s) run the same ordered
// gates inline, then re-arm like the unit's Restart=always.
//
// Remediate gates (k0sworker-remediate.sh order — every SKIP exits
// without action; restart only when ALL agree):
//   G0 re-probe :10248 twice ~3s apart → one "ok" = steal blip,
//                                      self-correct (the shell's
//                                      Gate-1, numbered G0 here so the
//                                      existing G1–G6 strings stay)
//   G1 uptime <1200s                 → fresh boot, kubelet still up-coming
//   G2 k0sworker active <180s        → settle window (kubelet init)
//   G3 state-node-overloaded latched → wedge is a load symptom
//   G4 no API backend answers /livez → node isolated, restart = churn
//   G5 last-restart <30m             → shared budget spent → latch
//                                      state-kubelet-healthz-down so
//                                      NHC→SNR escalates to reboot
//   G6 spend budget + reset-failed + systemctl restart k0sworker

// ciliumUnhealthySubsystems lists healthz subsystem paths whose
// state is neither Ok nor Disabled — nested maps are walked so
// {"cluster":{"cilium":{"state":"Failure"}}} resolves too.
func ciliumUnhealthySubsystems(body []byte) []string {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return nil
	}
	var bad []string
	var walk func(path string, n any)
	walk = func(path string, n any) {
		m, ok := n.(map[string]any)
		if !ok {
			return
		}
		if s, ok := m["state"].(string); ok && s != "Ok" && s != "Disabled" {
			bad = append(bad, path+"="+s)
		}
		for k, c := range m {
			child := k
			if path != "" {
				child = path + "." + k
			}
			walk(child, c)
		}
	}
	walk("", v)
	sort.Strings(bad)
	return bad
}

// ciliumEnvoyCheck is the B1/W7-H3 envoy guard as a Check. It owns
// the /ready fail streak and the xDS NACK bookkeeping
// (ex-Hygiene.envoyFails/.envoyXDS*). The ciliumAgentKilled flag
// stays on Hygiene — it's shared state: any of the cilium,
// cilium-init or wg-peers checks can set it through
// killCiliumAgent earlier in the same Cycle.
type ciliumEnvoyCheck struct {
	h        *Hygiene
	fails    int    // consecutive /ready fails (ConsecNeeded → kill)
	xdsInit  bool   // baseline update_rejected sum established
	xdsLast  uint64 // last-seen update_rejected sum
	xdsFails int    // consecutive cycles the sum grew
}

// Name returns the check label / WD_SIG key.
func (c *ciliumEnvoyCheck) Name() string { return checkCiliumEnvoy }

// Run executes one cilium-envoy round.
func (c *ciliumEnvoyCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkCiliumEnvoy, "gated").Inc()
		return
	}
	tasks, reachable := c.h.ciliumNamedTasks("cilium-envoy")
	if !reachable {
		c.h.cycles.WithLabelValues(checkCiliumEnvoy, "abort").Inc()
		return
	}
	if len(tasks) == 0 {
		// No cilium-envoy container — older cilium or no L7 proxy:
		// clear any stale latch like checkCilium does.
		c.fails = 0
		c.h.state.Exit(hoststate.LatchCiliumEnvoyDown, nil)
		c.h.cycles.WithLabelValues(checkCiliumEnvoy, "ok").Inc()
		return
	}
	// 2.5: subsystem/datapath health off the agent socket is
	// evidence only — an unreadable socket must not block the envoy
	// verdict (the admin port is the primary signal).
	if body, err := c.h.cfg.Seams.unixGet(ctx, c.h.cfg.Cilium.Socket, "/v1/healthz"); err == nil {
		if bad := ciliumUnhealthySubsystems(body); len(bad) > 0 {
			c.h.state.AppendLog(fmt.Sprintf(
				"suspect: cilium subsystem health degraded: %s",
				strings.Join(bad, ",")))
		}
	}
	// Trigger 1: the agent was SIGKILLed this cycle — envoy may hold
	// the stale socket, restart it alongside (B1).
	if c.h.ciliumAgentKilled {
		c.killCiliumEnvoy(tasks, "cilium-agent restarted this cycle")
		c.h.cycles.WithLabelValues(checkCiliumEnvoy, "ok").Inc()
		return
	}
	// W7-H3: xDS NACK guard — envoy can answer /ready=200 while
	// rejecting every config push (cds/lds/rds update_rejected
	// climbing → Gateway/Gateway API routes 404/503 while their API
	// objects report Accepted:True). Positive deltas for
	// ConsecNeeded consecutive cycles latch
	// state-cilium-envoy-xds-reject and restart envoy through the
	// same last-cilium-envoy-restart budget. Runs BEFORE the ready
	// probe's early-return so a green /ready can't hide the wedge.
	if reject, inconclusive := c.evalEnvoyXDS(ctx); inconclusive {
		// Stats page unreadable — inconclusive, keep the streak
		// (a dead envoy fails its own ready probe next).
	} else if reject {
		c.xdsFails++
	} else {
		c.xdsFails = 0
		c.h.state.Exit(hoststate.LatchCiliumEnvoyXDSReject, nil)
	}
	if c.xdsFails >= c.h.cfg.ConsecNeeded {
		c.h.state.Enter(hoststate.LatchCiliumEnvoyXDSReject,
			fmt.Sprintf("update_rejected=%d fails=%d",
				c.xdsLast, c.xdsFails))
		c.killCiliumEnvoy(tasks,
			fmt.Sprintf("xDS update_rejected deltas %d consecutive cycles",
				c.xdsFails))
	}
	code, err := c.h.cfg.Seams.probeHTTPStatus(ctx,
		c.h.cfg.Cilium.EnvoyReadyURL, "", ciliumProbeTime)
	if err == nil && code == http.StatusOK {
		c.fails = 0
		c.h.state.Exit(hoststate.LatchCiliumEnvoyDown, nil)
		c.h.cycles.WithLabelValues(checkCiliumEnvoy, "ok").Inc()
		return
	}
	c.fails++
	if c.fails < c.h.cfg.ConsecNeeded {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-envoy-down ready probe code=%d err=%v (check %d/%d)",
			code, err, c.fails, c.h.cfg.ConsecNeeded))
		c.h.cycles.WithLabelValues(checkCiliumEnvoy, "ok").Inc()
		return
	}
	c.h.state.Enter(hoststate.LatchCiliumEnvoyDown,
		fmt.Sprintf("ready_probe_fails=%d", c.fails))
	c.killCiliumEnvoy(tasks,
		fmt.Sprintf("unready %d consecutive cycles", c.fails))
	c.h.cycles.WithLabelValues(checkCiliumEnvoy, "ok").Inc()
}

// checkCiliumEnvoy forwards to the migrated Check — tests written
// before the interface still call the old method shape.
func (h *Hygiene) checkCiliumEnvoy(ctx context.Context, workerActive bool) {
	h.ciliumEnvoy.Run(ctx, &cycleEnv{workerActive: workerActive})
}

// killCiliumEnvoy restarts the envoy container through its init
// pids — kubelet rebuilds it like the agent path. The dedicated
// budget keeps envoy kills from eating the agent's restart rate.
func (c *ciliumEnvoyCheck) killCiliumEnvoy(tasks []ctrTask, why string) {
	if !c.h.state.RateTrySpend("last-cilium-envoy-restart", c.h.cfg.MinRestartInterval) {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-envoy kill skipped (%s) — restart cooldown (<30m)", why))
		return
	}
	if c.h.killNamedTasks(tasks, "cilium-envoy") {
		c.h.state.AppendLog(fmt.Sprintf(
			"ACTION: killed cilium-envoy container - %s (kubelet will restart -> xDS resync)", why))
		c.fails = 0
		c.h.actions.WithLabelValues(checkCiliumEnvoy, "sigkill").Inc()
	} else {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-envoy kill skipped (%s) — no running task to kill", why))
	}
}

// --- Check: MTU drift, cilium datapath vs overlay (B4) ---
// A pod created before the MTU change keeps MTU 1500 while the
// overlay neb1 is 1300 — the bpf policy-route then returns
// FRAG_NEEDED and the flow dies after SYN-ACK. Latch +
// ACTION cilium-mtu-drift: so nodereporter raises
// CiliumMTUExceedsOverlay.
//
// The MTU readers themselves are hostutil.MTUOfIface /
// hostutil.RuntimeConfigMTU (sysfs mtu file + agent-runtime-config.json
// fallback, MAX-wins over several `mtu` keys).

// ciliumMTUCheck is the B4 MTU-drift guard as a Check (no streak —
// the latch IS the state).
type ciliumMTUCheck struct{ h *Hygiene }

// Name returns the check label / WD_SIG key.
func (c *ciliumMTUCheck) Name() string { return checkCiliumMTU }

// Run executes one cilium-mtu round.
func (c *ciliumMTUCheck) Run(_ context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkCiliumMTU, "gated").Inc()
		return
	}
	neb, nebOK := hostutil.MTUOfIface(c.h.cfg.Net.SysClassNet, c.h.cfg.Net.NebulaIface)
	cil, cilOK := hostutil.MTUOfIface(c.h.cfg.Net.SysClassNet, c.h.cfg.Cilium.Iface)
	if !cilOK {
		cil, cilOK = hostutil.RuntimeConfigMTU(c.h.cfg.Cilium.RuntimeConfig)
	}
	// W9 double-encap guard: on the WireGuard datapath cilium_wg0
	// carries pod traffic INSIDE the nebula overlay — its MTU must
	// leave room for the WG header (~60B) under the overlay MTU.
	// A wg0 MTU above neb−60 means pod packets exceed what the
	// double-encapsulated path can carry → silent blackhole.
	wg, wgOK := hostutil.MTUOfIface(c.h.cfg.Net.SysClassNet, c.h.cfg.Cilium.WG0Iface)
	if !nebOK {
		// No overlay to compare against — a drift latch from
		// before must not linger.
		c.h.state.Exit(hoststate.LatchCiliumMTUDrift, nil)
		c.h.cycles.WithLabelValues(checkCiliumMTU, "ok").Inc()
		return
	}
	var driftWhy string
	switch {
	case cilOK && cil > neb:
		driftWhy = fmt.Sprintf("cilium_net=%d nebula=%d", cil, neb)
	case wgOK && wg > neb-wgEncapOverheadBytes:
		driftWhy = fmt.Sprintf("cilium_wg0=%d nebula=%d (wg overhead %d)",
			wg, neb, wgEncapOverheadBytes)
	}
	if driftWhy != "" {
		if !c.h.state.Exists(hoststate.LatchCiliumMTUDrift) {
			c.h.state.Enter(hoststate.LatchCiliumMTUDrift, driftWhy)
			// NPD contract: nodereporter maps this line to the
			// CiliumMTUExceedsOverlay Event + problem_counter.
			c.h.state.AppendLog(fmt.Sprintf(
				"ACTION cilium-mtu-drift: %s", driftWhy))
		}
	} else {
		c.h.state.Exit(hoststate.LatchCiliumMTUDrift, nil)
	}
	c.h.cycles.WithLabelValues(checkCiliumMTU, "ok").Inc()
}

// checkCiliumMTU forwards to the migrated Check — tests written
// before the interface still call the old method shape.
func (h *Hygiene) checkCiliumMTU(workerActive bool) {
	h.ciliumMTU.Run(context.Background(), &cycleEnv{workerActive: workerActive})
}

// --- Check: cilium WireGuard peer-gc drift healer (W5.6) ---
// A cilium WireGuard node can lose its wg0 peer table (kernel-side
// peer GC racing agent bookkeeping): cilium_wg0 exists, the agent's
// healthz stays green, but every peer's allowed-ips reads "(none)"
// — the node encrypts nothing while cross-node pod traffic
// blackholes. The healer compares live allowed-ips peers against the
// expected count (cilium-dbg encrypt status, falling back to
// ReadyNodes-1) and restarts the agent through the shared cilium
// budget.

// parseWGAllowedIPs counts peers carrying a real allowed-ips set —
// `wg show <iface> allowed-ips` prints "<pubkey>\t<ip,ip,...>" per
// line, "(none)" for a peer whose routes were wiped.
func parseWGAllowedIPs(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[1] == "(none)" {
			continue
		}
		n++
	}
	return n
}

// encryptPeersRe matches a textual "num-peers"-style field inside
// `cilium-dbg encrypt status` — versions that print a table instead
// of JSON (e.g. "NumPeers: 5", "num_peers=5").
var encryptPeersRe = regexp.MustCompile(`(?i)num.?peers[^0-9]*([0-9]+)`)

// parseCiliumEncryptPeers extracts the expected WireGuard peer count
// from `cilium-dbg encrypt status`. JSON bodies are searched for a
// num-peers-ish key (the largest match wins — interfaces may repeat
// the field); a non-JSON body falls back to a text regex. ok=false
// means no usable number (non-wireguard mode, older agent).
func parseCiliumEncryptPeers(out string) (int, bool) {
	var v any
	if json.Unmarshal([]byte(out), &v) == nil {
		var vals []int64
		hostutil.JSONFindInts(v, &vals, "num-peers", "numpeers", "num_peers")
		if len(vals) > 0 {
			return int(slices.Max(vals)), true
		}
		return 0, false
	}
	if m := encryptPeersRe.FindStringSubmatch(out); m != nil {
		n, err := strconv.Atoi(m[1])
		return n, err == nil
	}
	return 0, false
}

// parseCiliumHealthNodes counts remote cluster members in the
// agent's /v1/healthz payload ({"cluster":{"nodes":[...]}} — the
// same source `cilium status` reports "Cluster health: N/M"). Every
// entry is a remote node running cilium-agent, i.e. one WireGuard
// peer this node should hold; virtual/liqo nodes run no agent and
// never appear. ok=false when the section is absent or empty — the
// caller then falls back to the node-list heuristic.
func parseCiliumHealthNodes(body []byte) (int, bool) {
	var resp struct {
		Cluster *struct {
			Nodes []json.RawMessage `json:"nodes"`
		} `json:"cluster"`
	}
	if err := json.Unmarshal(body, &resp); err != nil ||
		resp.Cluster == nil || len(resp.Cluster.Nodes) == 0 {
		return 0, false
	}
	return len(resp.Cluster.Nodes), true
}

// readyNodeCount lists Ready, REAL nodes — the expected-peers
// fallback (every other real Ready node should be a WireGuard
// peer). Virtual nodes (Liqo/virtual-kubelet) are excluded — they
// run no cilium-agent so they never become peers; control-plane
// members are excluded too: undercounting expected is the
// fail-safe direction (it can only blunt a partial-drift signal,
// never produce the repeated false kill an overcount causes).
func (h *Hygiene) readyNodeCount(ctx context.Context) int {
	list, err := h.cfg.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0
	}
	n := 0
	for i := range list.Items {
		node := &list.Items[i]
		// Virtual nodes run no cilium-agent — never peers.
		if _, ok := node.Labels["liqo.io/type"]; ok {
			continue
		}
		if _, ok := node.Labels["virtual-kubelet.io/provider"]; ok {
			continue
		}
		if node.Labels["type"] == "virtual-kubelet" {
			continue
		}
		// Control-plane members may or may not run the agent —
		// excluding them can only undercount (fail safe).
		if _, ok := node.Labels["node-role.kubernetes.io/control-plane"]; ok {
			continue
		}
		if _, ok := node.Labels["node-role.kubernetes.io/master"]; ok {
			continue
		}
		for _, cond := range node.Status.Conditions {
			if cond.Type == corev1.NodeReady && cond.Status == corev1.ConditionTrue {
				n++
				break
			}
		}
	}
	return n
}

// ciliumWGCheck detects the wiped peer table: it runs only on
// nodes where cilium_wg0 exists, the API answered, and a
// cilium-agent task is running — every other shape is another
// check's signal. actual < expected for ConsecNeeded consecutive
// cycles latches state-cilium-wg-peer-wipe and SIGKILLs the agent
// (kubelet restarts it; the shared last-cilium-restart 30m budget
// and the node-overloaded gate apply like sig9). The streak stays
// on Hygiene (ciliumWGFails) — pre-Check tests poke it directly.
type ciliumWGCheck struct{ h *Hygiene }

// Name returns the check label / WD_SIG key.
func (c *ciliumWGCheck) Name() string { return checkCiliumWG }

// Run executes one cilium-wg-peers round.
func (c *ciliumWGCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkCiliumWG, "gated").Inc()
		return
	}
	if !e.apiOK {
		// Inconclusive — keep counters/latch exactly like the other
		// API-dependent checks.
		c.h.cycles.WithLabelValues(checkCiliumWG, "abort").Inc()
		return
	}
	if _, err := os.Stat(filepath.Join(c.h.cfg.Net.SysClassNet, "cilium_wg0")); err != nil {
		// No WireGuard datapath on this node (calico, tunnel mode,
		// hub) — nothing to heal; drop stale evidence.
		c.h.ciliumWGFails = 0
		c.h.state.Exit(hoststate.LatchCiliumWGPeerWipe, nil)
		c.h.cycles.WithLabelValues(checkCiliumWG, "ok").Inc()
		return
	}
	tasks, reachable := c.h.ciliumAgentTasks()
	if !reachable {
		c.h.cycles.WithLabelValues(checkCiliumWG, "abort").Inc()
		return
	}
	running := false
	for _, t := range tasks {
		if t.live && t.pid > 0 {
			running = true
			break
		}
	}
	if !running {
		// No live cilium-agent — sig9 owns agent-down; killing
		// nothing here is correct, not a miss.
		c.h.ciliumWGFails = 0
		c.h.cycles.WithLabelValues(checkCiliumWG, "ok").Inc()
		return
	}
	actual, err := c.h.cfg.Seams.wgAllowedIPsFn(ctx)
	if err != nil {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-wg-peers wg allowed-ips probe failed: %v — inconclusive, keeping state", err))
		c.h.cycles.WithLabelValues(checkCiliumWG, "abort").Inc()
		return
	}
	expected, err := c.h.cfg.Seams.ciliumEncryptPeersFn(ctx)
	if err != nil || expected <= 0 {
		// encrypt status unreadable or carries no count — fall back
		// to ReadyNodes-1 (every OTHER Ready node is a peer).
		if n := c.h.readyNodeCount(ctx); n > 1 {
			expected = n - 1
		} else {
			expected = 0
		}
	}
	if expected <= 0 {
		// No expectation available — inconclusive but not harmful:
		// neither count nor clear a streak we cannot verify.
		c.h.cycles.WithLabelValues(checkCiliumWG, "ok").Inc()
		return
	}
	if actual >= expected {
		c.h.ciliumWGFails = 0
		c.h.state.Exit(hoststate.LatchCiliumWGPeerWipe, nil)
		c.h.cycles.WithLabelValues(checkCiliumWG, "ok").Inc()
		return
	}
	c.h.ciliumWGFails++
	if c.h.ciliumWGFails < c.h.cfg.ConsecNeeded {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-wg-peers allowed_ips=%d expected=%d (check %d/%d)",
			actual, expected, c.h.ciliumWGFails, c.h.cfg.ConsecNeeded))
		c.h.cycles.WithLabelValues(checkCiliumWG, "ok").Inc()
		return
	}
	c.h.state.Enter(hoststate.LatchCiliumWGPeerWipe,
		fmt.Sprintf("allowed_ips=%d expected=%d", actual, expected))
	switch {
	case c.h.state.Exists(hoststate.LatchNodeOverloaded):
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-wg-peers allowed_ips=%d expected=%d %dx but node overloaded — skip kill",
			actual, expected, c.h.ciliumWGFails))
	case !c.h.state.RateTrySpend("last-cilium-restart", c.h.cfg.MinRestartInterval):
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-wg-peers allowed_ips=%d expected=%d %dx but restart cooldown — skip kill",
			actual, expected, c.h.ciliumWGFails))
	default:
		// Budget already spent atomically by the rateTrySpend case.
		if c.h.killCiliumAgent(tasks) {
			// NPD contract: the cilium_wg0 line feeds
			// CiliumWireGuardPeerDrift (events.go).
			c.h.state.AppendLog(fmt.Sprintf(
				"ACTION: killed cilium-agent container - cilium_wg0 has %d allowed-ip peers while expected %d (kubelet will restart -> wireguard peer resync)",
				actual, expected))
			c.h.ciliumWGFails = 0
			c.h.actions.WithLabelValues(checkCiliumWG, "sigkill").Inc()
		} else {
			c.h.state.AppendLog(fmt.Sprintf(
				"suspect: cilium-wg-peers allowed_ips=%d expected=%d, no running task to kill",
				actual, expected))
		}
	}
	c.h.cycles.WithLabelValues(checkCiliumWG, "ok").Inc()
}

// checkCiliumWGPeers forwards to the migrated Check — tests written
// before the interface still call the old method shape.
func (h *Hygiene) checkCiliumWGPeers(ctx context.Context, apiOK, workerActive bool) {
	h.ciliumWG.Run(ctx, &cycleEnv{apiOK: apiOK, workerActive: workerActive})
}

// --- Check: disk-bloat runaway detector + emergency evictor (W6.3) ---
// A runaway emptyDir (or a leaked containerd snapshot) can fill
// /var/lib/k0s faster than kubelet's eviction thresholds notice —
// the fs going full first kills kubelet/containerd writes and the
// node wedges. Above the warn watermark a bounded walk attributes
// space to pods and snapshots (any single dir past the threshold →
// state-disk-bloat + DiskBloatRunaway event); above the critical
// watermark the largest non-system pod offender is deleted via the
// API under the last-disk-bloat-evict budget.

// parseEnvoyXDSRejected sums the cds/lds/rds update_rejected
// counters out of `envoy admin /stats?filter=update_rejected` —
// lines look like "cluster_manager.cds.update_rejected: 3". A stat
// counts toward the xDS NACK total when one dotted segment is
// cds/lds/rds AND the name ends in update_rejected.
func parseEnvoyXDSRejected(body []byte) uint64 {
	var total uint64
	for _, line := range strings.Split(string(body), "\n") {
		name, val, ok := strings.Cut(line, ":")
		if !ok || !strings.HasSuffix(strings.TrimSpace(name), "update_rejected") {
			continue
		}
		match := false
		for _, seg := range strings.Split(name, ".") {
			if seg == "cds" || seg == "lds" || seg == "rds" {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		if v, err := strconv.ParseUint(strings.TrimSpace(val), 10, 64); err == nil {
			total += v
		}
	}
	return total
}

// evalEnvoyXDS fetches the envoy admin update_rejected page and
// reports whether the summed reject counters GREW since the last
// successful read — the delta is the wedge signal (a node can carry
// old rejects forever; only new NACKs mean pushes are failing now).
// The first successful read only establishes the baseline.
// inconclusive=true means the page could not be evaluated — the
// caller keeps the streak untouched (a dead envoy also fails its
// /ready probe and the B1 path owns that verdict).
func (c *ciliumEnvoyCheck) evalEnvoyXDS(ctx context.Context) (reject, inconclusive bool) {
	if c.h.cfg.Cilium.EnvoyAdminURL == "" {
		return false, true
	}
	body, err := c.h.cfg.Seams.httpGetBody(ctx, c.h.cfg.Cilium.EnvoyAdminURL, ciliumProbeTime)
	if err != nil {
		return false, true
	}
	total := parseEnvoyXDSRejected(body)
	if !c.xdsInit {
		c.xdsInit = true
		c.xdsLast = total
		return false, false
	}
	reject = total > c.xdsLast
	c.xdsLast = total
	return reject, false
}

// probeDNSUDP sends one minimal A-record query to addr over UDP and
// reports whether a well-formed reply returns before the deadline —
// the node-local-dns datapath probe (W7-H3). Any reply matching the
// query id proves :53 answers: NXDOMAIN/SERVFAIL still mean the
// listener is alive; silence means the LRP datapath is wedged.
func probeDNSUDP(addr, name string, timeout time.Duration) bool {
	id := uint16(time.Now().UnixNano())
	// Header: ID, flags 0x0100 (RD), QDCOUNT=1, AN/NS/AR=0.
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1) // root label + QTYPE A + QCLASS IN
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(q); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	// ID echo + QR bit set (a response, not another query or a stray
	// datagram sharing the id).
	return err == nil && n >= 4 && buf[0] == q[0] && buf[1] == q[1] &&
		buf[2]&0x80 != 0
}

// checkCiliumLRPDNS probes the node-local resolver's :53 listener
// while its pod claims Ready — a hung listener inside an LRP path
// blackholes cluster DNS node-wide. Confirmed for ConsecNeeded
// consecutive cycles → delete the node-local-dns pod on this node
// (the DaemonSet respawns it with a fresh socket; last-nld-restart
// 30m budget). Only evaluated on cilium nodes (cilium_host present)
// — calico nodes serve local DNS without the LRP datapath.
// ciliumLRPCheck is the W7-H3 node-local-dns datapath guard as a
// Check; it owns the :53 probe fail streak (ex-Hygiene.nldFails).
type ciliumLRPCheck struct {
	h     *Hygiene
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *ciliumLRPCheck) Name() string { return checkCiliumLRP }

// Run executes one cilium-lrp-dns round.
func (c *ciliumLRPCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkCiliumLRP, "gated").Inc()
		return
	}
	if _, err := os.Stat(filepath.Join(c.h.cfg.Net.SysClassNet, "cilium_host")); err != nil {
		// No cilium datapath — the LRP wedge can't exist here.
		c.fails = 0
		c.h.cycles.WithLabelValues(checkCiliumLRP, "ok").Inc()
		return
	}
	// The plan gates on cilium-agent actually running: cilium_host
	// persists while the agent is down, and a dead/wedged agent can
	// break the :53 datapath itself — killing the nld pod then would
	// mask the real failure (checkCilium owns the agent-down verdict).
	agentTasks, ctrOK := c.h.ciliumAgentTasks()
	if !ctrOK {
		c.h.cycles.WithLabelValues(checkCiliumLRP, "abort").Inc()
		return
	}
	if len(agentTasks) == 0 {
		// Agent absent/dead — datapath verdict inconclusive; the LRP
		// check stands down rather than punish a healthy pod.
		c.fails = 0
		c.h.cycles.WithLabelValues(checkCiliumLRP, "gated").Inc()
		return
	}
	if !e.apiOK {
		// Inconclusive — keep the streak like the other API-gated
		// checks (a LIST flake must not count or clear evidence).
		c.h.cycles.WithLabelValues(checkCiliumLRP, "abort").Inc()
		return
	}
	var nld *corev1.Pod
	for i := range e.pods {
		p := &e.pods[i]
		if p.Namespace == "kube-system" && nldPodRe.MatchString(p.Name) &&
			p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning &&
			podReady(p) {
			nld = p
			break
		}
	}
	if nld == nil {
		// No Ready node-local-dns pod → nothing owes a datapath
		// answer (not-Running/NotReady pods are kubelet's problem).
		c.fails = 0
		c.h.cycles.WithLabelValues(checkCiliumLRP, "ok").Inc()
		return
	}
	if c.h.cfg.Seams.dnsProbe(c.h.cfg.Net.LocalDNSProbeAddr, c.h.cfg.Net.LocalDNSProbeName,
		ciliumProbeTime) {
		c.fails = 0
		c.h.cycles.WithLabelValues(checkCiliumLRP, "ok").Inc()
		return
	}
	c.fails++
	if c.fails < c.h.cfg.ConsecNeeded {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-lrp-dns :53 probe of %s failed while %s/%s Ready=True (check %d/%d)",
			c.h.cfg.Net.LocalDNSProbeAddr, nld.Namespace, nld.Name,
			c.fails, c.h.cfg.ConsecNeeded))
		c.h.cycles.WithLabelValues(checkCiliumLRP, "ok").Inc()
		return
	}
	if !c.h.state.RateTrySpend("last-nld-restart", c.h.cfg.MinRestartInterval) {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-lrp-dns :53 probe fails %dx but pod restart in cooldown (<30m), skip",
			c.fails))
		c.h.cycles.WithLabelValues(checkCiliumLRP, "ok").Inc()
		return
	}
	// Budget spent atomically BEFORE the delete (rate_spend parity).
	c.h.state.AppendLog(fmt.Sprintf(
		"ACTION: cilium-lrp-dns deleted pod %s/%s - :53 probe failed %dx while Ready=True (LRP datapath wedge)",
		nld.Namespace, nld.Name, c.fails))
	if err := c.h.cfg.Client.CoreV1().Pods(nld.Namespace).Delete(ctx, nld.Name,
		metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)}); err != nil {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cilium-lrp-dns delete %s/%s failed: %v",
			nld.Namespace, nld.Name, err))
	} else {
		c.h.actions.WithLabelValues(checkCiliumLRP, "pod_delete").Inc()
	}
	c.fails = 0
	c.h.cycles.WithLabelValues(checkCiliumLRP, "ok").Inc()
}

// checkCiliumLRPDNS forwards to the migrated Check — tests written
// before the interface still call the old method shape.
func (h *Hygiene) checkCiliumLRPDNS(ctx context.Context, pods []corev1.Pod,
	apiOK, workerActive bool) {
	h.ciliumLRP.Run(ctx, &cycleEnv{
		pods: pods, apiOK: apiOK, workerActive: workerActive})
}

// --- Check: spegel-mirror (W7-H4) ---
// Containerd's mirror config on every node points image pulls at
// the LOCAL spegel peer first. A wedged spegel pod (accepts TCP but
// stalls TLS/HTTP headers) makes PullImage eat the full per-mirror
// timeout before falling back — mass ErrImagePull exactly during a
// rollout/drain. A Ready=False spegel DaemonSet pod for
// ConsecNeeded cycles latches state-spegel-mirror-degraded and
// deletes the pod (fresh socket + fresh state; last-spegel-restart
// 30m budget). The 3m age floor keeps a just-scheduled pod from
// being deleted mid-startup.
