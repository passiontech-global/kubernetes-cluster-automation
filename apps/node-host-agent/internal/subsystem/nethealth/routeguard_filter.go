// routeguard_filter.go — delete-event decode: the nebula
// dataplane's numeric identity (pub/marker routing tables, the rule
// prefs nebula-up.sh owns, the dev's kernel ifindex) and the
// RTM_DELROUTE/RTM_DELRULE payload classification the socket
// session's filter runs per datagram. Decode is FAIL-OPEN: a
// message too torn to classify still counts, because a missed real
// delete strands the node off-mesh for minutes while a spurious
// trigger costs one idempotent script run. The netlink socket +
// netns bind mechanics and the generic nlmsg/rtattr decode live in
// subsystem/nethealth/routewatch; below is the nebula policy they filter
// against.
package nethealth

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/nethealth/routewatch"
)

// The numeric identity of the nebula dataplane — constants mirrored
// from nebula-up.sh (hostconfig templates/nebula-up.sh.j2):
// routeGuardTablePub is the $PUB default — a node that overrode
// interdc_nebula_table_pub carries it in watchdog conf as
// OVERLAY_EGRESS_TABLE (hostconfig writes it there), so the conf
// value wins. $MARK (interdc_nebula_table_marker) and the three
// prefs have no conf counterpart — 101/1400/1490/1500 are the only
// values the script renders: 1400 the fwmark-0x1000 underlay bypass
// shared with tinc, 1490 the marker-CIDR lookup into $MARK, 1500
// the per-target lookups into $PUB.
const (
	routeGuardTablePub   = 100
	routeGuardTableMark  = 101
	routeGuardPrefFwmark = 1400
	routeGuardPrefMarker = 1490
	routeGuardPrefPub    = 1500
)

// routeEventFilter is the nebula dataplane identity the delete scan
// matches against: the pub/marker routing tables, the rule prefs
// nebula-up.sh owns, and the nebula dev's kernel ifindex (0 =
// unresolved — the RTA_OIF half of the DELROUTE match then stays
// inert, but tables and prefs still catch the rules).
type routeEventFilter struct {
	tables map[uint32]bool
	prefs  map[uint32]bool
	nebIf  uint32
	// nebIfFn re-resolves the dev ifindex; wired by nebulaRouteFilter
	// so a rebuilt nebula dev (tun recreate renumbers the ifindex)
	// refreshes instead of leaving the whole socket session matching
	// the DEAD index. nil (hand-built test filters) keeps nebIf as
	// constructed.
	nebIfFn func() uint32
	// nebIfAt throttles the re-resolve to one sysfs read per interval.
	nebIfAt time.Time
}

// nebIfRefresh is how stale the armed ifindex may get — a tun
// recreate between refreshes is caught by the next datagram (dev
// churn emits route traffic), so the interval only bounds sysfs
// reads during long delete bursts.
const nebIfRefresh = 30 * time.Second

// nebulaRouteFilter builds the filter once per socket session —
// cheap: a couple of map writes plus one sysfs read. The ifindex
// resolves through the same /sys/class/net view hostmetrics reads
// (the host netns under hostNetwork — exactly the netns the bound
// socket watches); on a non-hostNetwork pod sysfs shows the pod's
// own netns and the dev simply doesn't resolve.
func (n *NetHealth) nebulaRouteFilter() *routeEventFilter {
	f := &routeEventFilter{
		tables: map[uint32]bool{routeGuardTableMark: true},
		prefs: map[uint32]bool{
			routeGuardPrefFwmark: true,
			routeGuardPrefMarker: true,
			routeGuardPrefPub:    true,
		},
	}
	wd := n.watchdogConf()
	if wd == nil {
		f.tables[routeGuardTablePub] = true
		return f
	}
	pub := uint32(wd.OverlayEgressTable)
	if pub == 0 {
		pub = routeGuardTablePub
	}
	f.tables[pub] = true
	f.nebIf = nebulaIfindex(n.cfg.sysClassNet, wd.NebulaDev)
	// Re-resolve hook: the session survives nebula dev recreation, so
	// the ifindex is refreshed lazily per datagram (see refreshNebIf)
	// — the sysClassNet view and the dev name are fixed for the
	// process lifetime, only the kernel's numbering moves.
	dev, sysNet := wd.NebulaDev, n.cfg.sysClassNet
	f.nebIfFn = func() uint32 { return nebulaIfindex(sysNet, dev) }
	f.nebIfAt = time.Now()
	return f
}

// nebulaIfindex reads <dir>/<dev>/ifindex — the numeric id netlink
// puts in RTA_OIF. A missing/unreadable dev (down mid-restart,
// nebula not yet up) yields 0 — never a real ifindex, so the OIF
// match stays inert instead of failing open into the CNI flood.
func nebulaIfindex(dir, dev string) uint32 {
	if dev == "" {
		return 0
	}
	b, err := os.ReadFile(filepath.Join(dir, dev, "ifindex"))
	if err != nil {
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || v <= 0 {
		return 0
	}
	return uint32(v)
}

// scanDeleteEvents reports whether buf carries at least one nlmsg a
// restore must answer — the only events the bash guard reacted to
// (`*Deleted*` lines naming the nebula state). routewatch owns the
// datagram walk and its fail-open contract (a torn header or tail
// can't be proven NOT to be a nebula delete, so it counts); the
// DELROUTE/DELRULE decode below is the nebula policy.
func (f *routeEventFilter) scanDeleteEvents(buf []byte) bool {
	f.refreshNebIf()
	return routewatch.ScanMessages(buf,
		func(typ uint16, payload []byte) bool {
			switch typ {
			case unix.RTM_DELROUTE:
				return f.delRouteRelevant(payload)
			case unix.RTM_DELRULE:
				return f.delRuleRelevant(payload)
			}
			return false
		})
}

// refreshNebIf re-resolves the dev ifindex when the armed one is
// stale — a rebuilt nebula dev (tun recreate) renumbers the ifindex
// while the socket session (and this filter) survives, and a filter
// armed once per session would match the DEAD index forever. The
// re-read throttles to one sysfs read per nebIfRefresh; nil fn
// (hand-built filters) is inert.
func (f *routeEventFilter) refreshNebIf() {
	if f.nebIfFn == nil || time.Since(f.nebIfAt) < nebIfRefresh {
		return
	}
	f.nebIfAt = time.Now()
	f.nebIf = f.nebIfFn()
}

// delRouteRelevant decodes an RTM_DELROUTE payload (struct rtmsg +
// rtattrs). Relevant when the route sat in a nebula table (`default
// dev neb1` in $PUB/$MARK) or egressed the nebula dev — the
// marker-base /24 link route lives in table MAIN (254). rtm_table
// is a u8; ids >255 arrive in RTA_TABLE instead, which wins when
// present. Undecodable payloads are relevant (fail-open).
func (f *routeEventFilter) delRouteRelevant(payload []byte) bool {
	if len(payload) < unix.SizeofRtMsg {
		return true // truncated rtmsg — can't prove it isn't ours
	}
	if payload[0] != unix.AF_INET {
		return false // non-IPv4 — never nebula's (no v6 tables/rules)
	}
	attrs, clean := routewatch.Attrs(payload[unix.SizeofRtMsg:],
		unix.RTA_TABLE, unix.RTA_OIF)
	if !clean {
		return true // torn attribute list — can't prove it isn't ours
	}
	table := uint32(payload[4])
	if v, ok := attrs[unix.RTA_TABLE]; ok {
		table = v
	}
	return f.tables[table] ||
		(f.nebIf != 0 && attrs[unix.RTA_OIF] == f.nebIf)
}

// delRuleRelevant decodes an RTM_DELRULE payload (struct
// fib_rule_hdr + rtattrs): relevant when FRA_PRIORITY is a pref
// nebula-up.sh owns. The kernel sends FRA_PRIORITY unconditionally —
// a payload without it, or with a torn attribute list, is
// undecodable → relevant.
func (f *routeEventFilter) delRuleRelevant(payload []byte) bool {
	if len(payload) < routewatch.FibRuleHdrLen {
		return true
	}
	if payload[0] != unix.AF_INET {
		return false
	}
	attrs, clean := routewatch.Attrs(payload[routewatch.FibRuleHdrLen:],
		unix.FRA_PRIORITY)
	if !clean {
		return true
	}
	prio, ok := attrs[unix.FRA_PRIORITY]
	if !ok {
		return true
	}
	return f.prefs[prio]
}
