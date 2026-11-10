package nodecond

import (
	"reflect"
	"testing"
)

// allConditionNames enumerates every exported condition constant BY
// IDENTIFIER — a renamed or deleted constant breaks this file's
// compilation instead of silently drifting out of the test's reach.
// 48 latch-backed + 7 monitor/kubelet-owned = 55.
var allConditionNames = []string{
	// Latch-backed (48).
	NodeOverloaded, WatchdogStale,
	CiliumAgentDown, CiliumInitStuck,
	KubeletRuntimeStall, DNSFallbackActive, DNSResolvStale,
	PodTeardownWedged, KubeletWatchWedge, JournaldUnreadable,
	FilesystemReadOnly, KernelHungTasks,
	NebulaIsolated, NebulaDegraded,
	CiliumEnvoyDown, CiliumIPAMExhausted, CiliumBPFMapPressure,
	CiliumMTUDrift, CiliumWGStale,
	SpegelMirrorDegraded, CalicoVethLeak, CalicoFelixDown,
	Fail2banDown, ConntrackPressure, KernelKeysPressure,
	ControlPlaneCertReloadStale, MemoryPSIThrashing,
	ClockUnsynchronized, KernelSlabLeak, NebulaPMTUBlackhole,
	KernelResourceExhaustion, ClockSkewDetected,
	KubeconfigCertExpiring, CPUStealPressure,
	CgroupDyingLeak, SystemdSessionBloat,
	KubeletPLEGUnhealthy, DiskSlowIO, KernelNetShimDegraded,
	ClocksourceUnstable,
	KonnectivityIPMismatch, CiliumEnvoyXDSReject, DiskBloatRunaway,
	NebulaMTUBlackhole, NebulaSlowpath, NebulaSiteedge,
	KernelPageAllocFailure, ApiserverWatchCacheWedged,
	// Monitor- and kubelet-owned (7).
	KernelDeadlock, ReadonlyFilesystem, InodePressure,
	HostNetworkProblems, ClusterNetworkProblems,
	HostNetworkProblem, ClusterNetworkProblem,
}

// notHeartbeatManaged is the complement inside allConditionNames —
// the names a frozen LastHeartbeatTime says nothing about.
var notHeartbeatManaged = []string{
	KernelDeadlock, // permanent latch, never reconciles False
	HostNetworkProblems, ClusterNetworkProblems,
	HostNetworkProblem, ClusterNetworkProblem,
}

// foreignStormGateNames are StormGateNames members with no constant
// here: kubelet-native conditions (corev1 has its own constants)
// and the foreign CiliumLRPDegraded spelling. Pinned by string so a
// typo in the list itself cannot slip through.
var foreignStormGateNames = []string{
	"MemoryPressure", "DiskPressure", "NetworkUnavailable",
	"CiliumLRPDegraded",
}

// legacyControllerSpellings are the controller-side names the plan
// retired — the agent spelling won, so these must appear nowhere.
var legacyControllerSpellings = []string{
	"SystemdSessionLeak", "ConntrackExhausted",
	"JournaldWedged", "ControlPlaneFrozen",
}

func TestConstantsNonEmptyAndUnique(t *testing.T) {
	if len(allConditionNames) != 55 {
		t.Fatalf("allConditionNames = %d entries, want 55 (48 latch-backed + 7 monitor/kubelet)",
			len(allConditionNames))
	}
	seen := make(map[string]bool, len(allConditionNames))
	for _, name := range allConditionNames {
		if name == "" {
			t.Fatal("a condition constant is the empty string")
		}
		if seen[name] {
			t.Fatalf("condition constant %q declared twice", name)
		}
		seen[name] = true
	}
}

func TestListLengths(t *testing.T) {
	// HeartbeatSweptNames: 49 latch-backed (incl. InodePressure,
	// agent-latched since inode-pressure) + ReadonlyFilesystem; KernelDeadlock
	// (permanent) excluded.
	if got, want := len(HeartbeatSweptNames), 50; got != want {
		t.Errorf("len(HeartbeatSweptNames) = %d, want %d", got, want)
	}
	if got, want := len(HangPreCordonNames), 19; got != want {
		t.Errorf("len(HangPreCordonNames) = %d, want %d", got, want)
	}
	if got, want := len(ClockSkewPreCordonNames), 3; got != want {
		t.Errorf("len(ClockSkewPreCordonNames) = %d, want %d", got, want)
	}
	// 37 storm-gate conditions minus 4 legacy spellings, plus
	// CiliumBPFMapPressure and the 4 foreign names already counted
	// in the original list.
	if got, want := len(StormGateNames), 42; got != want {
		t.Errorf("len(StormGateNames) = %d, want %d", got, want)
	}
	if got, want := len(PartitionNames), 6; got != want {
		t.Errorf("len(PartitionNames) = %d, want %d", got, want)
	}
}

func TestListsHaveNoDuplicateEntries(t *testing.T) {
	lists := map[string][]string{
		"HeartbeatSweptNames":     HeartbeatSweptNames,
		"HangPreCordonNames":      HangPreCordonNames,
		"ClockSkewPreCordonNames": ClockSkewPreCordonNames,
		"StormGateNames":          StormGateNames,
		"PartitionNames":          PartitionNames,
	}
	for name, list := range lists {
		seen := make(map[string]bool, len(list))
		for _, entry := range list {
			if seen[entry] {
				t.Errorf("%s lists %q more than once", name, entry)
			}
			seen[entry] = true
		}
	}
}

func TestListEntriesAreDeclaredConstantsOrPinnedForeign(t *testing.T) {
	declared := make(map[string]bool, len(allConditionNames))
	for _, name := range allConditionNames {
		declared[name] = true
	}
	foreign := make(map[string]bool, len(foreignStormGateNames))
	for _, name := range foreignStormGateNames {
		foreign[name] = true
	}
	lists := map[string][]string{
		"HeartbeatSweptNames":     HeartbeatSweptNames,
		"HangPreCordonNames":      HangPreCordonNames,
		"ClockSkewPreCordonNames": ClockSkewPreCordonNames,
		"StormGateNames":          StormGateNames,
		"PartitionNames":          PartitionNames,
	}
	for listName, list := range lists {
		for _, entry := range list {
			if !declared[entry] && !foreign[entry] {
				t.Errorf("%s entry %q is neither a nodecond constant nor a pinned foreign name",
					listName, entry)
			}
		}
	}
}

func TestHeartbeatSweptCoversLatchBackedExactly(t *testing.T) {
	swept := make(map[string]bool, len(HeartbeatSweptNames))
	for _, name := range HeartbeatSweptNames {
		swept[name] = true
	}
	// The 7 monitor/kubelet-owned names split: ReadonlyFilesystem and
	// InodePressure in (the agent latches InodePressure since inode-pressure and
	// kubelet never emits the type), everything else out.
	for _, name := range notHeartbeatManaged {
		if swept[name] {
			t.Errorf("HeartbeatSweptNames must not contain %q (kubelet-owned or permanent latch)", name)
		}
	}
	if !swept[ReadonlyFilesystem] {
		t.Error("HeartbeatSweptNames must contain ReadonlyFilesystem (NPD mount monitor rides the heartbeat)")
	}
	if !swept[InodePressure] {
		t.Error("HeartbeatSweptNames must contain InodePressure (agent inode latch, inode-pressure)")
	}
	// Every remaining constant — exactly the 49 latch-backed — in.
	latchBacked := 0
	for _, name := range allConditionNames {
		if name == ReadonlyFilesystem {
			continue
		}
		managed := true
		for _, ex := range notHeartbeatManaged {
			if ex == name {
				managed = false
				break
			}
		}
		if !managed {
			continue
		}
		latchBacked++
		if !swept[name] {
			t.Errorf("HeartbeatSweptNames must contain latch-backed condition %q", name)
		}
	}
	if latchBacked != 49 {
		t.Fatalf("latch-backed constants enumerated = %d, want 49", latchBacked)
	}
}

func TestHangAndClockSkewListsDisjoint(t *testing.T) {
	hang := make(map[string]bool, len(HangPreCordonNames))
	for _, name := range HangPreCordonNames {
		hang[name] = true
	}
	for _, name := range ClockSkewPreCordonNames {
		if hang[name] {
			t.Errorf("clock condition %q must not be in HangPreCordonNames (own longer fuse)", name)
		}
	}
}

func TestAgentHeartbeatManaged(t *testing.T) {
	for _, name := range HeartbeatSweptNames {
		if !AgentHeartbeatManaged(name) {
			t.Errorf("AgentHeartbeatManaged(%q) = false, want true (HeartbeatSweptNames member)", name)
		}
	}
	notManaged := append(notHeartbeatManaged[:len(notHeartbeatManaged):len(notHeartbeatManaged)],
		"MemoryPressure", "DiskPressure", "NetworkUnavailable",
		"CiliumLRPDegraded", "", "NoSuchCondition")
	for _, name := range notManaged {
		if AgentHeartbeatManaged(name) {
			t.Errorf("AgentHeartbeatManaged(%q) = true, want false", name)
		}
	}
}

func TestLegacyControllerSpellingsAbsent(t *testing.T) {
	lists := map[string][]string{
		"HeartbeatSweptNames":     HeartbeatSweptNames,
		"HangPreCordonNames":      HangPreCordonNames,
		"ClockSkewPreCordonNames": ClockSkewPreCordonNames,
		"StormGateNames":          StormGateNames,
		"PartitionNames":          PartitionNames,
	}
	for listName, list := range lists {
		for _, entry := range list {
			for _, legacy := range legacyControllerSpellings {
				if entry == legacy {
					t.Errorf("%s contains retired spelling %q — agent spelling won",
						listName, legacy)
				}
			}
		}
	}
}

func TestStormGateForeignNamesPinned(t *testing.T) {
	gate := make(map[string]bool, len(StormGateNames))
	for _, name := range StormGateNames {
		gate[name] = true
	}
	for _, name := range foreignStormGateNames {
		if !gate[name] {
			t.Errorf("StormGateNames lost foreign condition %q", name)
		}
	}
}

func TestAllPreCordonConditionsInStormGate(t *testing.T) {
	gate := make(map[string]bool, len(StormGateNames))
	for _, name := range StormGateNames {
		gate[name] = true
	}
	for _, list := range [][]string{HangPreCordonNames, ClockSkewPreCordonNames} {
		for _, name := range list {
			if !gate[name] {
				t.Errorf("StormGateNames must contain pre-cordon condition %q", name)
			}
		}
	}
}

func TestPartitionNamesMembership(t *testing.T) {
	want := map[string]bool{
		HostNetworkProblems:    true,
		ClusterNetworkProblems: true,
		HostNetworkProblem:     true,
		ClusterNetworkProblem:  true,
		NebulaIsolated:         true,
		NebulaPMTUBlackhole:    true,
	}
	got := make(map[string]bool, len(PartitionNames))
	for _, name := range PartitionNames {
		got[name] = true
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PartitionNames = %v, want exactly %v", got, want)
	}
}

func TestStormGateRenamesApplied(t *testing.T) {
	gate := make(map[string]bool, len(StormGateNames))
	for _, name := range StormGateNames {
		gate[name] = true
	}
	for _, renamed := range []string{
		SystemdSessionBloat, ConntrackPressure,
		JournaldUnreadable, ControlPlaneCertReloadStale,
	} {
		if !gate[renamed] {
			t.Errorf("StormGateNames must contain agent spelling %q after the rename", renamed)
		}
	}
	if !gate[CiliumBPFMapPressure] {
		t.Error("StormGateNames must contain CiliumBPFMapPressure (plan adds it to the storm gate)")
	}
}
