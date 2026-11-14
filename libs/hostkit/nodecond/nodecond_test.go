package nodecond

import (
	"reflect"
	"testing"
	"time"
)

// allConditionNames enumerates every exported condition constant BY
// IDENTIFIER — a renamed or deleted constant breaks this file's
// compilation instead of silently drifting out of the test's reach.
// 49 latch-backed + 7 monitor/kubelet-owned = 56.
var allConditionNames = []string{
	// Latch-backed (49).
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
	CgroupDyingLeak, SystemdSessionBloat, SystemdUnresponsive,
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
	if len(allConditionNames) != 56 {
		t.Fatalf("allConditionNames = %d entries, want 56 (49 latch-backed + 7 monitor/kubelet)",
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

// conditionClass is the explicit triage decision for one
// HeartbeatSweptNames member: which reaction lists it belongs to.
// Every swept condition MUST appear in conditionClasses — adding a
// latch-backed condition without a classification decision fails
// TestAllConditionsExplicitlyClassified, so the agent and the
// controller can never drift on how a new condition is handled.
type conditionClass struct {
	partition     bool // PartitionNames — evict pods off a partitioned node
	stormGate     bool // StormGateNames — suppress descheduler storms
	hangPreCordon bool // HangPreCordonNames — sustained True cordons the node
	clockSkew     bool // ClockSkewPreCordonNames — the longer clock fuse
}

// conditionClasses is the exhaustive {Partition, StormGate,
// HangPreCordon, ClockSkew} matrix for HeartbeatSweptNames. Names
// absent from every list (NodeOverloaded, DNSFallbackActive, …)
// carry the all-false row — silence is a decision too.
var conditionClasses = map[string]conditionClass{
	NodeOverloaded:              {},
	WatchdogStale:               {stormGate: true},
	CiliumAgentDown:             {stormGate: true, hangPreCordon: true},
	CiliumInitStuck:             {stormGate: true, hangPreCordon: true},
	KubeletRuntimeStall:         {stormGate: true, hangPreCordon: true},
	DNSFallbackActive:           {},
	DNSResolvStale:              {},
	PodTeardownWedged:           {stormGate: true, hangPreCordon: true},
	KubeletWatchWedge:           {stormGate: true, hangPreCordon: true},
	JournaldUnreadable:          {stormGate: true},
	FilesystemReadOnly:          {stormGate: true, hangPreCordon: true},
	KernelHungTasks:             {stormGate: true, hangPreCordon: true},
	NebulaIsolated:              {stormGate: true, hangPreCordon: true, partition: true},
	NebulaDegraded:              {stormGate: true},
	CiliumEnvoyDown:             {stormGate: true, hangPreCordon: true},
	CiliumIPAMExhausted:         {stormGate: true},
	CiliumBPFMapPressure:        {stormGate: true},
	CiliumMTUDrift:              {stormGate: true},
	CiliumWGStale:               {stormGate: true},
	SpegelMirrorDegraded:        {},
	CalicoVethLeak:              {},
	CalicoFelixDown:             {stormGate: true, hangPreCordon: true},
	Fail2banDown:                {},
	ConntrackPressure:           {stormGate: true},
	KernelKeysPressure:          {},
	ControlPlaneCertReloadStale: {stormGate: true},
	MemoryPSIThrashing:          {stormGate: true, hangPreCordon: true},
	ClockUnsynchronized:         {stormGate: true, clockSkew: true},
	KernelSlabLeak:              {stormGate: true, hangPreCordon: true},
	NebulaPMTUBlackhole:         {stormGate: true, partition: true},
	KernelResourceExhaustion:    {stormGate: true, hangPreCordon: true},
	ClockSkewDetected:           {stormGate: true, clockSkew: true},
	KubeconfigCertExpiring:      {},
	CPUStealPressure:            {},
	CgroupDyingLeak:             {stormGate: true, hangPreCordon: true},
	SystemdSessionBloat:         {stormGate: true},
	SystemdUnresponsive:         {stormGate: true, hangPreCordon: true},
	KubeletPLEGUnhealthy:        {stormGate: true, hangPreCordon: true},
	DiskSlowIO:                  {stormGate: true, hangPreCordon: true},
	KernelNetShimDegraded:       {stormGate: true},
	ClocksourceUnstable:         {stormGate: true, clockSkew: true},
	InodePressure:               {stormGate: true, hangPreCordon: true},
	ReadonlyFilesystem:          {stormGate: true, hangPreCordon: true},
	KonnectivityIPMismatch:      {},
	CiliumEnvoyXDSReject:        {stormGate: true},
	DiskBloatRunaway:            {stormGate: true, hangPreCordon: true},
	NebulaMTUBlackhole:          {stormGate: true, partition: true},
	NebulaSlowpath:              {stormGate: true},
	NebulaSiteedge:              {stormGate: true},
	KernelPageAllocFailure:      {stormGate: true, hangPreCordon: true},
	ApiserverWatchCacheWedged:   {},
}

// TestAllConditionsExplicitlyClassified replaces the old
// TestListLengths: instead of pinning list cardinalities (which
// silently drift when a condition is added to one list but not
// classified), every HeartbeatSweptNames member must carry an
// explicit {Partition, StormGate, HangPreCordon, ClockSkew}
// decision in conditionClasses, and the actual lists must match it
// exactly. Non-swept members (KernelDeadlock, the NPD network
// spellings, the foreign storm-gate names) are covered by
// TestListEntriesAreDeclaredConstantsOrPinnedForeign.
func TestAllConditionsExplicitlyClassified(t *testing.T) {
	swept := make(map[string]bool, len(HeartbeatSweptNames))
	for _, name := range HeartbeatSweptNames {
		swept[name] = true
		if _, ok := conditionClasses[name]; !ok {
			t.Errorf("HeartbeatSweptNames member %q has no explicit classification", name)
		}
	}
	for name := range conditionClasses {
		if !swept[name] {
			t.Errorf("conditionClasses entry %q is not a HeartbeatSweptNames member", name)
		}
	}
	lists := []struct {
		name string
		list []string
		pick func(conditionClass) bool
	}{
		{"PartitionNames", PartitionNames, func(c conditionClass) bool { return c.partition }},
		{"StormGateNames", StormGateNames, func(c conditionClass) bool { return c.stormGate }},
		{"HangPreCordonNames", HangPreCordonNames, func(c conditionClass) bool { return c.hangPreCordon }},
		{"ClockSkewPreCordonNames", ClockSkewPreCordonNames, func(c conditionClass) bool { return c.clockSkew }},
	}
	for _, l := range lists {
		inList := make(map[string]bool, len(l.list))
		for _, entry := range l.list {
			inList[entry] = true
		}
		for name := range swept {
			want := l.pick(conditionClasses[name])
			if inList[name] != want {
				t.Errorf("%s membership of swept condition %q = %v, want %v (classification table)",
					l.name, name, inList[name], want)
			}
		}
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
	// Every remaining constant — exactly the 50 latch-backed — in.
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
	if latchBacked != 50 {
		t.Fatalf("latch-backed constants enumerated = %d, want 50", latchBacked)
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
		NebulaMTUBlackhole:     true,
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

func TestParseAnnoTime(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cases := []struct {
		name string
		in   string
		want time.Time
		ok   bool
	}{
		{"empty", "", time.Time{}, false},
		{"rfc3339", now.Format(time.RFC3339), now, true},
		{"rfc3339nano", now.Add(123 * time.Millisecond).Format(time.RFC3339Nano),
			now.Add(123 * time.Millisecond), true},
		{"unix seconds", "1700000000", time.Unix(1700000000, 0), true},
		{"padded unix seconds", "  1700000000  ", time.Unix(1700000000, 0), true},
		{"garbage", "manual-forever", time.Time{}, false},
		{"negative unix", "-5", time.Time{}, false},
		{"zero unix", "0", time.Time{}, false},
		// Milliseconds pasted as seconds — used to lock maintenance
		// until year 57836; anything past 2100 is rejected.
		{"milliseconds as seconds", "1700000000000", time.Time{}, false},
		{"one past 2100 bound", "4102444801", time.Time{}, false},
		{"2100 bound accepted", "4102444800", time.Unix(4102444800, 0), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseAnnoTime(tc.in)
			if ok != tc.ok {
				t.Fatalf("ParseAnnoTime(%q) ok=%v, want %v", tc.in, ok, tc.ok)
			}
			if ok && !got.Equal(tc.want) {
				t.Fatalf("ParseAnnoTime(%q)=%v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestEvaluateCoordAnnos(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour).UTC().Format(time.RFC3339)
	past := now.Add(-time.Hour).UTC().Format(time.RFC3339)

	// No annotations → inactive verdict.
	if v := EvaluateCoordAnnos(nil, now); v.Active || v.KuredLocked || !v.MaintenanceUntil.IsZero() {
		t.Fatalf("empty annos: %+v, want zero verdict", v)
	}
	// Live maintenance window → active, stamp carried through.
	v := EvaluateCoordAnnos(map[string]string{AnnoClusterMaintenanceUntil: future}, now)
	if !v.Active || v.KuredLocked {
		t.Fatalf("future maintenance: %+v, want active non-kured", v)
	}
	if v.MaintenanceUntil.IsZero() {
		t.Fatal("MaintenanceUntil not decoded")
	}
	// Expired window → inactive.
	if v := EvaluateCoordAnnos(map[string]string{AnnoClusterMaintenanceUntil: past}, now); v.Active {
		t.Fatalf("past maintenance: %+v, want inactive", v)
	}
	// Kured lock alone → active (no timestamp on the lock).
	v = EvaluateCoordAnnos(map[string]string{KuredLockAnno: `{"nodeID":"w1"}`}, now)
	if !v.Active || !v.KuredLocked {
		t.Fatalf("kured lock: %+v, want active+kured", v)
	}
	// Unparseable stamp + no lock → inactive, zero until.
	if v := EvaluateCoordAnnos(map[string]string{AnnoClusterMaintenanceUntil: "bogus"}, now); v.Active {
		t.Fatalf("bogus stamp: %+v, want inactive", v)
	}
}
