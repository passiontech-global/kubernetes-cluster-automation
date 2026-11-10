// protocol_test.go — coverage for the derived matcher helpers and
// the ACTION line head shared by emitters and filelog rules.
package latchdefs

import (
	"strings"
	"testing"
)

// TestSharedOwners: the multi-owner registry entry round-trips;
// single-producer latches and unknown names return nil.
func TestSharedOwners(t *testing.T) {
	got := SharedOwners(LatchPodTeardownWedged)
	if len(got) != 2 || got[0] != "pod-teardown" || got[1] != "ctr-tasks" {
		t.Fatalf("SharedOwners(%q)=%v want [pod-teardown ctr-tasks]",
			LatchPodTeardownWedged, got)
	}
	if got := SharedOwners(LatchDiskSlowIO); got != nil {
		t.Fatalf("single-producer latch returned %v, want nil", got)
	}
	if got := SharedOwners("no-such-latch"); got != nil {
		t.Fatalf("unknown latch returned %v, want nil", got)
	}
}

// TestKnownLatchName: exact names match, parameterized families
// match by prefix, and near-misses (a def's name minus its trailing
// dash, unknown names, empty) stay unknown — the janitor's
// known/unknown reap keys on this.
func TestKnownLatchName(t *testing.T) {
	for _, tc := range []struct {
		suffix string
		want   bool
	}{
		{LatchDiskSlowIO, true},
		{LatchPodTeardownWedged, true},
		{"apiserver-backend-stale-10-0-0-1", true}, // prefix family
		{"apiserver-backend-stale-", true},         // bare prefix still HasPrefix-matches
		{"cilium-ipam-10-0-0-1", true},
		{"apiserver-backend-stale", false}, // missing the family's trailing dash
		{"apiserver-backend", false},       // unrelated prefix
		{"disk-slow", false},               // truncated exact name
		{"disk-slow-io-extra", false},      // exact names don't prefix-match
		{"", false},
		{"no-such-latch", false},
	} {
		if got := KnownLatchName(tc.suffix); got != tc.want {
			t.Errorf("KnownLatchName(%q) = %v, want %v", tc.suffix, got, tc.want)
		}
	}
}

// TestActionEntryPrefix: the emitted head is "ACTION <name>: " —
// name between, colon attached (the Go emitter spelling).
func TestActionEntryPrefix(t *testing.T) {
	if got := ActionEntryPrefix(LatchDStateStorm); got != "ACTION d-state-storm: " {
		t.Fatalf("ActionEntryPrefix=%q want %q", got, "ACTION d-state-storm: ")
	}
	if !strings.HasPrefix(ActionEntryPrefix("x")+"count=1", "ACTION x: count=1") {
		t.Fatal("prefix does not compose with a field body")
	}
}

// TestStateEnterRe: builds the "STATE-ENTER: <latch>" matcher over
// multiple names and stays literal for exact-name matching.
func TestStateEnterRe(t *testing.T) {
	re := StateEnterRe(LatchDiskSlowIO, "filesystem-readonly")
	if !re.MatchString(StateEnterPrefix + LatchDiskSlowIO) {
		t.Errorf("re misses %q", StateEnterPrefix+LatchDiskSlowIO)
	}
	if !re.MatchString(StateEnterPrefix + "filesystem-readonly remounted ro") {
		t.Error("re misses an entry with evidence")
	}
	if re.MatchString(StateEnterPrefix + "fs-readonly") {
		t.Error("re matched an unregistered alias")
	}
}

// TestStateExitRe: the exit-line mirror of StateEnterRe — same
// alternation over StateExitPrefix, and it must NOT match enter
// lines (the episode-end rules depend on the distinction).
func TestStateExitRe(t *testing.T) {
	re := StateExitRe(LatchDiskSlowIO, "filesystem-readonly")
	if !re.MatchString(StateExitPrefix + LatchDiskSlowIO) {
		t.Errorf("re misses %q", StateExitPrefix+LatchDiskSlowIO)
	}
	if !re.MatchString(StateExitPrefix + "filesystem-readonly remounted rw") {
		t.Error("re misses an exit line with a trailing note")
	}
	if re.MatchString(StateExitPrefix + "fs-readonly") {
		t.Error("re matched an unregistered alias")
	}
	if re.MatchString(StateEnterPrefix + LatchDiskSlowIO) {
		t.Error("exit re matched a STATE-ENTER line")
	}
}

// TestActionEntryRe: both lib.sh spellings keep matching, exact
// names only, and multi-name alternation works.
func TestActionEntryRe(t *testing.T) {
	single := ActionEntryRe(LatchDStateStorm)
	for _, line := range []string{
		"ACTION d-state-storm: count=3",
		"ACTION: d-state-storm: count=3", // lib.sh colon-attached spelling
	} {
		if !single.MatchString(line) {
			t.Errorf("single-name re misses %q", line)
		}
	}
	if single.MatchString("ACTION d-state-stormy: count=3") {
		t.Error("re matched a longer name sharing the prefix")
	}
	if single.MatchString("ACTION zombie-storm: x") {
		t.Error("re matched a different latch name")
	}

	multi := ActionEntryRe(LatchDStateStorm, "zombie-storm")
	if !multi.MatchString("ACTION zombie-storm: pid=1") ||
		!multi.MatchString("ACTION: d-state-storm: pid=1") {
		t.Error("multi-name re missed a valid line")
	}
	if multi.MatchString("ACTION cilium-agent-down: x") {
		t.Error("multi-name re matched an unlisted name")
	}
}

// TestActionClockRestartRe: every listed unit matches and an
// unlisted one does not.
func TestActionClockRestartRe(t *testing.T) {
	re := ActionClockRestartRe()
	for _, u := range ClockRestartUnits {
		line := ActionPrefix + "restarting " + u
		if !re.MatchString(line) {
			t.Errorf("re misses %q", line)
		}
	}
	if re.MatchString(ActionPrefix + "restarting ntp.service") {
		t.Error("re matched an unlisted unit")
	}
}
