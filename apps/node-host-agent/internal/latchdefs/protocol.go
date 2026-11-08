// protocol.go — the watchdog-log LINE protocol layered on the latch
// name registry: the log prefixes and shared line tokens every
// emitter writes into the watchdog log (hoststate.Store.AppendLog)
// and the nodereporter filelog rules (events.go logRules) re-parse.
// Before this file the wording lived twice — as a fmt string in the
// emitting check and as a regex literal in the rule table — so a
// wording edit silently broke the Event/Condition pipeline. Every
// constant below is shared by its emitters and its rule(s);
// consumers build their regexes FROM the constants at init
// (QuoteMeta / StateEnterRe / ActionEntryRe), so emitter drift can
// no longer strand a rule.
//
// The line shapes (each prefixed by the rfc3339 timestamp appendFile
// writes):
//
//	STATE-ENTER: <latch>[ <evidence>]     — latch entry (Store.Enter)
//	STATE-EXIT: <latch>                   — latch exit (Store.Exit)
//	ACTION <name>: <fields>               — latch-entry ACTION line
//	ACTION: <remediation free text>       — remediation ACTION line
//	suspect: <keyword> <detail>           — throttled re-reminder
//
// lib.sh (the retired shell watchdog these checks replaced) wrote
// both ACTION spellings — "ACTION: zombie-storm: ..." with the colon
// attached and "ACTION zombie-storm: ..." with the name between —
// and several rules must also keep matching lines the retired shell
// (or the kernel/kubelet itself) wrote into the same log; those
// legacy alternations are called out per rule in events.go and stay
// literal. Emitted lines must stay BYTE-IDENTICAL: the NPD filelog
// parity is the contract the Event dedup, the problem_counter series
// and every operator grep rely on.
package latchdefs

import (
	"regexp"
	"strings"
)

// --- line prefixes ---

const (
	// StateEnterPrefix opens every latch-transition entry line:
	// Store.Enter writes StateEnterPrefix+<name> (+" "+<evidence>),
	// lib.sh parity. The filelog rules derive their STATE-ENTER
	// matchers from it (StateEnterRe).
	StateEnterPrefix = "STATE-ENTER: "

	// StateExitPrefix opens the latch exit line Store.Exit writes.
	// No filelog rule matches exits today; the emitted form is
	// still the shared log contract (ops grep + tests).
	StateExitPrefix = "STATE-EXIT: "

	// ActionPrefix is the remediation ACTION spelling with the colon
	// attached — "ACTION: restarting k0sworker - ...". The
	// latch-entry spelling keeps the name between keyword and colon
	// ("ACTION <name>: ", ActionEntryPrefix); the filelog rules
	// tolerate both spellings via ActionEntryRe's `ACTION:? *` head.
	ActionPrefix = "ACTION: "

	// ActionClockWarp is the wall-clock-jump detector's ACTION entry
	// name (hostmetrics kernelfail clockskew.go). clock-warp has no
	// state-* latch — the detector keeps a counter + textfile gauge
	// instead — but its line shape is the latch-entry ACTION form
	// and the NodeClockWarpDetected rule parses it like one.
	ActionClockWarp = "clock-warp"
)

// ActionEntryPrefix returns the latch-entry ACTION line head for one
// name — ActionEntryPrefix(LatchDStateStorm)+"count=%d runtime=%d
// wchan=%s" is exactly the line guards/dstate_scopes.go writes once
// per latch entry.
func ActionEntryPrefix(name string) string {
	return "ACTION " + name + ": "
}

// --- derived matchers ---

// StateEnterRe builds the "STATE-ENTER: <latch>" match pattern for
// one or more latch names — the matcher every latch→event rule uses
// (moved verbatim from nodereporter/events.go, where it lived as a
// package-private helper). A renamed latch can never silently drift
// the filelog contract: the filesystem-readonly vs fs-readonly split
// is exactly the drift this prevents (both registered tokens feed
// the one FilesystemReadOnly event reason).
func StateEnterRe(latches ...string) *regexp.Regexp {
	alts := make([]string, 0, len(latches))
	for _, l := range latches {
		alts = append(alts, regexp.QuoteMeta(l))
	}
	return regexp.MustCompile(StateEnterPrefix + `(?:` + strings.Join(alts, "|") + `)`)
}

// ActionEntryRe builds the unanchored ACTION-entry match pattern for
// one or more names — the `ACTION:? *<name>:` form the filelog rules
// use. The `:?` + ` *` head is the lib.sh tolerance: the retired
// shell wrote "ACTION: zombie-storm: ..." (colon attached) while the
// Go emitters write "ACTION zombie-storm: ..." (name between); both
// spellings keep matching.
func ActionEntryRe(names ...string) *regexp.Regexp {
	alts := make([]string, 0, len(names))
	for _, n := range names {
		alts = append(alts, regexp.QuoteMeta(n))
	}
	head := `ACTION:? *`
	if len(alts) == 1 {
		return regexp.MustCompile(head + alts[0] + `:`)
	}
	return regexp.MustCompile(head + `(?:` + strings.Join(alts, "|") + `):`)
}

// ClockRestartUnits lists the NTP sync units the clock guard may
// restart, in pick order (nethealth clock.go probes enabled+active,
// then enabled, then active, restarting the first hit). The
// producers — clock.go's restart line and nebula_health.go's
// timesyncd latch line, which only ever restarts the top pick — and
// the ClockUnsynchronized rule's unit alternation
// (ActionClockRestartRe) share this list, so adding or removing a
// unit moves both sides together.
var ClockRestartUnits = []string{
	"systemd-timesyncd.service", "chrony.service", "chronyd.service",
}

// ActionClockRestartRe builds the ClockUnsynchronized rule's
// remediation half — "ACTION: restarting (?:<unit>|...)\.service"
// derived from ClockRestartUnits (the ".service" suffix is stripped
// for the alternation and re-anchored literally). The retired shell
// rule spelled the alternation with a capturing group; the match set
// is identical.
func ActionClockRestartRe() *regexp.Regexp {
	alts := make([]string, 0, len(ClockRestartUnits))
	for _, u := range ClockRestartUnits {
		alts = append(alts, regexp.QuoteMeta(strings.TrimSuffix(u, ".service")))
	}
	return regexp.MustCompile(ActionPrefix + `restarting (?:` + strings.Join(alts, "|") + `)\.service`)
}

// --- remediation ACTION line tokens ---
//
// Each constant is the exact wording shared by its emitters and the
// filelog rule that fires the Event — producer and consumer
// reference one string, so a wording edit is a compile error, not a
// silent Event loss.
const (
	// ActionK0sworkerRestart heads every k0sworker restart line —
	// kubelet.go's stall path, kubelet_feeder.go's
	// systemd-watchdog path and kubelet_syncloop.go's PLEG/socket
	// paths append the reason tail; the K0sworkerRestarted rule
	// matches the head.
	ActionK0sworkerRestart = ActionPrefix + "restarting k0sworker"

	// ActionNebulaRestart heads nebula_health.go's restart line —
	// the NebulaRestarted rule matches the head (the "@<net>"
	// tail follows).
	ActionNebulaRestart = ActionPrefix + "restarting nebula@"

	// ActionCorruptedImageRemove heads ctr_images.go's corrupted
	// image removal line — the CorruptedImageRemoved rule matches
	// it.
	ActionCorruptedImageRemove = ActionPrefix + "removed corrupted image"

	// ActionCiliumAgentKill heads every cilium-agent SIGKILL
	// remediation line (cilium_agent.go, cilium_init.go,
	// cilium_lrp.go, cilium_wg.go — each continues with
	// " container - <why>"). The CiliumAgentDown rule matches the
	// "killed cilium-agent" half — this constant minus ActionPrefix
	// — because the retired shell killed the agent without the
	// "container -" tail and those legacy lines must keep firing
	// the Event.
	ActionCiliumAgentKill = ActionPrefix + "killed cilium-agent"

	// ActionCiliumWGKill continues ActionCiliumAgentKill for the
	// WireGuard peer-drift healer — the CiliumWireGuardPeerDrift
	// rule matches it; cilium_wg.go appends the " has N allowed-ip
	// peers while expected M" tail.
	ActionCiliumWGKill = ActionCiliumAgentKill + " container - cilium_wg0"

	// ActionEgress heads every overlay-egress commit line —
	// "ACTION: egress <ip> -> overlay relay table N (...)" and
	// "ACTION: egress <ip> -> direct underlay (recovered)". The
	// TincEgressFailover/Recovered rules derive their heads from
	// it; the failover rule's "-> (?:tinc|overlay) relay"
	// alternation keeps the retired shell's "tinc relay" spelling
	// matchable (the Go emitter only ever writes "overlay relay").
	ActionEgress = ActionPrefix + "egress "

	// ActionEgressHeal heads overlay_egress.go's rule-repair line —
	// the TincEgressHeal rule matches it.
	ActionEgressHeal = ActionPrefix + "heal egress"
)

// --- suspect/evidence keyword tokens ---
//
// The exact keywords the checks write into "suspect:"-reminders and
// STATE-ENTER evidence, matched by the filelog rules. Same contract
// as the ACTION tokens: one string shared by emitter + rule.
const (
	// ReasonInformerZombie is kubelet.go's informer-spam reason
	// keyword — the KubeletInformerZombie rule matches it.
	ReasonInformerZombie = "informer-zombie"

	// ReasonPhantomPods is kubelet.go's phantom-pod reason keyword —
	// the KubeletPhantomPods rule matches it and the stall check
	// HasPrefix-gates its restart decision on the same constant, so
	// the gate and the Event share one wording.
	ReasonPhantomPods = "phantom-pods"

	// ReasonCtrTaskWedged is ctr_tasks.go's wedged-task suspect
	// keyword — the CtrTaskWedged rule matches it; the rule's
	// "ctr tasks delete|orphaned task dir" alternation keeps the
	// retired shell's remediation wording matchable.
	ReasonCtrTaskWedged = "ctr-task-wedged"

	// ReasonKonnectivityStaleID is pod_teardown.go's
	// stale-identifier suspect keyword — the KonnectivityStaleId
	// rule matches it.
	ReasonKonnectivityStaleID = "konnectivity stale identifier"

	// ReasonKonnectivityAgentRecreate is the recreate keyword shared
	// by pod_teardown.go's KONNECTIVITY-IP-RESTART line and
	// runtime_clock_jump.go's clock-jump heal line — the
	// KonnectivityStaleId rule matches it too.
	ReasonKonnectivityAgentRecreate = "recreating konnectivity-agent"

	// ReasonForceDeletePod is wdeps.ForceDeletePod's NPD contract
	// keyword — the StuckPodForceDeleted rule matches it. The
	// TRAILING SPACE is part of the contract (the retired shell's
	// rule carried it).
	ReasonForceDeletePod = "force-delete pod "

	// ReasonNebulaDataplaneDegraded, ReasonNebulaDataplaneSlowpath
	// and ReasonNebulaSiteedgeDegraded are nebula_health.go's
	// dataplane-degradation suspect keywords (the retired module-13
	// wording, deliberately distinct from the nebula-degraded/
	// -slowpath/-siteedge LATCH names the same conditions enter) —
	// the NebulaDataplaneDegraded/NebulaSlowPath/NebulaSiteEdge
	// rules match them.
	ReasonNebulaDataplaneDegraded = "nebula-dataplane-degraded"
	ReasonNebulaDataplaneSlowpath = "nebula-dataplane-slowpath"
	ReasonNebulaSiteedgeDegraded  = "nebula-siteedge-degraded"
)
