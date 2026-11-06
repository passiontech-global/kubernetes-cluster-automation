// cilium_ipam.go — module-38 cilium-bpf-ipam check (CiliumIPAMCheck):
// IPAM allocations held for dead pods — the agent's /v1/healthz
// ipam counts cross-checked against in-use pod IPs — plus the
// healthz-body parsers that feed it.
package cilium

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

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

// ParseCiliumIPAM extracts used/available IPv4 counts from a
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
func ParseCiliumIPAM(body []byte) (used, available int, ok bool) {
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

// CiliumIPAMCheck reads the agent's IPAM usage off the unix socket
// and cross-checks it against the non-hostNetwork Running pods on
// this node: allocated − in-use = leaked IPs still held for dead
// pods (a real pod eventually can't get an address — the black-hole
// datapath this module exists to catch early). A small constant leak
// (~2: router + health reserved IPs) is normal, so the latch needs
// leaked >30 or available <=2 for ConsecNeeded consecutive cycles.
// The gauges update on every successful probe regardless. Fails is
// the consecutive exhausted-pool streak (ex-Deps.CiliumIPAMFails) —
// tests poke it via the named Hygiene field.
type CiliumIPAMCheck struct {
	d     *wdeps.Deps
	Fails int
}

// Name returns the check label / WD_SIG key.
func (c *CiliumIPAMCheck) Name() string { return wdeps.CheckCiliumIPAM }

// Run executes one cilium-ipam round.
func (c *CiliumIPAMCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckCiliumIPAM, "gated").Inc()
		return
	}
	if !e.APIOK {
		// The in-use count comes from the API — a failed LIST would
		// make EVERY allocated IP look leaked.
		c.d.Cycles.WithLabelValues(wdeps.CheckCiliumIPAM, "abort").Inc()
		return
	}
	body, err := c.d.Cfg.Seams.UnixGet(ctx, c.d.Cfg.Cilium.Socket, "/v1/healthz")
	if err != nil {
		// Socket unreadable — inconclusive: keep counters/latch
		// (same rule as checkCiliumInitStuck).
		c.d.Cycles.WithLabelValues(wdeps.CheckCiliumIPAM, "abort").Inc()
		return
	}
	used, available, ok := ParseCiliumIPAM(body)
	if !ok {
		c.d.State.AppendLog("suspect: cilium-ipam healthz has no parseable ipam.ipv4 data — inconclusive")
		c.d.Cycles.WithLabelValues(wdeps.CheckCiliumIPAM, "abort").Inc()
		return
	}
	inUse := 0
	for i := range e.Pods {
		p := &e.Pods[i]
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
	c.d.CiliumAllocated.Set(float64(used))
	c.d.CiliumLeaked.Set(float64(leaked))
	exhausted := leaked > 30 || (available >= 0 && available <= 2)
	if !exhausted {
		c.Fails = 0
		c.d.State.Exit(hoststate.LatchCiliumIPAMExhausted, nil)
		c.d.Cycles.WithLabelValues(wdeps.CheckCiliumIPAM, "ok").Inc()
		return
	}
	c.Fails++
	if c.Fails >= c.d.Cfg.ConsecNeeded {
		c.d.State.Enter(hoststate.LatchCiliumIPAMExhausted, fmt.Sprintf(
			"used=%d in-use=%d leaked=%d available=%d", used, inUse, leaked, available))
	} else {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-ipam-exhausted used=%d in-use=%d leaked=%d available=%d (check %d/%d)",
			used, inUse, leaked, available, c.Fails, c.d.Cfg.ConsecNeeded))
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckCiliumIPAM, "ok").Inc()
}
