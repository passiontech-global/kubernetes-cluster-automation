// ctr_meta_test.go — the meta-db-corruption check: journal-signature
// evidence, the reparented-orphan-shim channel with its exclusion
// rules, the meta.db size gauge, and the evidence streak → latch.
package ctr_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// orphanShim lays down a containerd-shim process aged ageOld whose
// given argv scope flags; ppid is always 1 (reparented) unless
// ppidOverride is set.
func orphanShim(t *testing.T, e *env, pid int, id, address string, ageOld time.Duration) {
	t.Helper()
	e.MkStatProc(t, pid, "containerd-shim", "S", "")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, strconv.Itoa(pid), "cmdline"),
		"containerd-shim-runc-v2\x00-id\x00"+id+"\x00-namespace\x00k8s.io\x00-address\x00"+address+"\x00")
	old := e.Now.Add(-ageOld)
	if err := os.Chtimes(filepath.Join(e.ProcDir, strconv.Itoa(pid)), old, old); err != nil {
		t.Fatal(err)
	}
}

func TestCtrMetaJournalEvidenceLatches(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Ctr.MetaJournalFn = func(context.Context) (string, error) {
		return "Nov 10 01:00:00 node containerd: failed to loadmeta: invalid freelist page", nil
	}
	c := wdepstest.Check[*ctr.CtrMetaCheck](e.H, wdeps.CheckCtrMeta)
	cycle := &wdeps.CycleEnv{PidsOnce: func() []int { return nil }, WorkerActive: true}
	c.Run(context.Background(), cycle)
	if e.H.State.Exists("containerd-corrupt") {
		t.Fatal("corruption latch after one evidence cycle")
	}
	c.Run(context.Background(), cycle)
	if !e.H.State.Exists("containerd-corrupt") {
		t.Fatalf("state-containerd-corrupt not latched:\n%s", e.LogLines(t))
	}

	// A clean cycle clears the latch and the streak.
	e.H.Cfg.Ctr.MetaJournalFn = func(context.Context) (string, error) {
		return "all healthy", nil
	}
	c.Run(context.Background(), cycle)
	if e.H.State.Exists("containerd-corrupt") {
		t.Fatal("corruption latch kept after a clean cycle")
	}
}

func TestCtrMetaJournalErrorInconclusive(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Ctr.MetaJournalFn = func(context.Context) (string, error) {
		return "", errors.New("journal unreadable")
	}
	c := wdepstest.Check[*ctr.CtrMetaCheck](e.H, wdeps.CheckCtrMeta)
	c.Run(context.Background(), &wdeps.CycleEnv{
		PidsOnce: func() []int { return nil }, WorkerActive: true})
	if !strings.Contains(e.LogLines(t), "journal half inconclusive") {
		t.Fatalf("missing inconclusive line:\n%s", e.LogLines(t))
	}
	if e.H.State.Exists("containerd-corrupt") {
		t.Fatal("a journal outage must never read as corruption")
	}
}

// TestCtrMetaDefaultJournalViaSystemd: with no MetaJournalFn override
// the probe rides the systemd ExecCombined seam — the SDReply fake
// feeds the parser for real.
func TestCtrMetaDefaultJournalViaSystemd(t *testing.T) {
	e := fixture(t)
	e.SDReply["journalctl"] = "containerd: bbolt: meta.db: Somethings wrong with freelist"
	c := wdepstest.Check[*ctr.CtrMetaCheck](e.H, wdeps.CheckCtrMeta)
	c.Run(context.Background(), &wdeps.CycleEnv{
		PidsOnce: func() []int { return nil }, WorkerActive: true})
	if !strings.Contains(e.LogLines(t), "journal: ") {
		t.Fatalf("journal evidence missing through the default seam:\n%s", e.LogLines(t))
	}
}

// TestCtrMetaOrphanShims: the shim evidence channel — a reparented
// in-scope shim whose task dir survives with a dead init past 15m
// counts; every deviation is excluded.
func TestCtrMetaOrphanShims(t *testing.T) {
	e := fixture(t)
	orphanID := strings.Repeat("a", 64)
	// The qualifying orphan: ppid=1, in scope, 16m old, task dir
	// under our k8s.io root with a dead init and a stale mtime.
	orphanShim(t, e, 9510, orphanID, "/run/k0s/containerd.sock", 16*time.Minute)
	dir := filepath.Join(filepath.Dir(e.CtrDir), "k8s.io", orphanID)
	wdepstest.WriteFile(t, filepath.Join(dir, "init.pid"), "99999\n")
	stale := e.Now.Add(-16 * time.Minute)
	if err := os.Chtimes(dir, stale, stale); err != nil {
		t.Fatal(err)
	}

	// Exclusions, none of which may count:
	// a foreign-daemon shim (address outside our socket set),
	orphanShim(t, e, 9511, strings.Repeat("b", 64), "/run/docker/containerd.sock", time.Hour)
	// a fresh shim (teardown in flight),
	orphanShim(t, e, 9512, strings.Repeat("c", 64), "/run/k0s/containerd.sock", time.Minute)
	// a shim whose task dir is gone (CheckCtrTasks' orphan case),
	orphanShim(t, e, 9513, strings.Repeat("d", 64), "/run/k0s/containerd.sock", time.Hour)
	// and a non-shim process.
	e.MkStatProc(t, 9514, "kubelet", "S", "")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "9514", "cmdline"),
		"kubelet\x00--node-ip=10.1.2.3\x00")

	c := wdepstest.Check[*ctr.CtrMetaCheck](e.H, wdeps.CheckCtrMeta)
	cycle := &wdeps.CycleEnv{
		PidsOnce:     func() []int { return []int{9510, 9511, 9512, 9513, 9514} },
		WorkerActive: true,
	}
	c.Run(context.Background(), cycle)
	log := e.LogLines(t)
	if !strings.Contains(log, "1 orphan shim(s) ppid=1") {
		t.Fatalf("exactly one qualifying orphan expected:\n%s", log)
	}
	if !strings.Contains(log, "run 1/2") {
		t.Fatalf("evidence streak not visible:\n%s", log)
	}
	c.Run(context.Background(), cycle)
	if !e.H.State.Exists("containerd-corrupt") {
		t.Fatal("orphan evidence did not latch across ConsecNeeded cycles")
	}
}

// TestCtrMetaOrphanLiveInitExcluded: a task dir whose init is alive
// is a normal task — never corruption evidence.
func TestCtrMetaOrphanLiveInitExcluded(t *testing.T) {
	e := fixture(t)
	id := strings.Repeat("e", 64)
	orphanShim(t, e, 9520, id, "/run/k0s/containerd.sock", time.Hour)
	dir := filepath.Join(filepath.Dir(e.CtrDir), "k8s.io", id)
	e.MkProc(t, 9521, "S", "", "")
	wdepstest.WriteFile(t, filepath.Join(dir, "init.pid"), "9521\n")
	stale := e.Now.Add(-time.Hour)
	if err := os.Chtimes(dir, stale, stale); err != nil {
		t.Fatal(err)
	}
	c := wdepstest.Check[*ctr.CtrMetaCheck](e.H, wdeps.CheckCtrMeta)
	c.Run(context.Background(), &wdeps.CycleEnv{
		PidsOnce: func() []int { return []int{9520} }, WorkerActive: true})
	if strings.Contains(e.LogLines(t), "orphan shim") {
		t.Fatalf("live-init task counted as an orphan:\n%s", e.LogLines(t))
	}
}

// TestCtrMetaDBSizeGauge: the bbolt store's size publishes on
// node_agent_ctr_metadb_bytes; a missing file leaves the last value
// instead of faking a 0.
func TestCtrMetaDBSizeGauge(t *testing.T) {
	e := fixture(t)
	db := filepath.Join(e.H.Cfg.K0sDataDir,
		"containerd", "io.containerd.metadata.v1.bolt", "meta.db")
	wdepstest.WriteFile(t, db, strings.Repeat("x", 4096))
	c := wdepstest.Check[*ctr.CtrMetaCheck](e.H, wdeps.CheckCtrMeta)
	c.Run(context.Background(), &wdeps.CycleEnv{
		PidsOnce: func() []int { return nil }, WorkerActive: true})
	if got := e.H.CtrMetaDBBytes; got != 4096 {
		t.Fatalf("CtrMetaDBBytes=%d want 4096", got)
	}

	// Missing file → the gauge keeps its last value.
	if err := os.Remove(db); err != nil {
		t.Fatal(err)
	}
	c.Run(context.Background(), &wdeps.CycleEnv{
		PidsOnce: func() []int { return nil }, WorkerActive: true})
	if got := e.H.CtrMetaDBBytes; got != 4096 {
		t.Fatalf("CtrMetaDBBytes=%d want the last 4096, never a fake 0", got)
	}
}

// TestCtrMetaGatesAndStatlessShim: the worker gate stands the check
// down; a shim with no stat file is unparseable → excluded; a nil
// systemd client skips the journal half without touching evidence.
func TestCtrMetaGatesAndStatlessShim(t *testing.T) {
	// Worker gate down → nothing runs.
	e := fixture(t)
	e.H.Cfg.Ctr.MetaJournalFn = func(context.Context) (string, error) {
		t.Error("journal probe ran with the worker gate down")
		return "", nil
	}
	wdepstest.Check[*ctr.CtrMetaCheck](e.H, wdeps.CheckCtrMeta).
		Run(context.Background(), &wdeps.CycleEnv{})

	// A shim pid with a cmdline but no stat file — ProcStatStatePPID
	// fails → excluded from the orphan count.
	e = fixture(t)
	sid := strings.Repeat("7", 64)
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "9530", "cmdline"),
		"containerd-shim-runc-v2\x00-id\x00"+sid+"\x00-namespace\x00k8s.io\x00-address\x00/run/k0s/containerd.sock\x00")
	c := wdepstest.Check[*ctr.CtrMetaCheck](e.H, wdeps.CheckCtrMeta)
	c.Run(context.Background(), &wdeps.CycleEnv{
		PidsOnce:     func() []int { return []int{9530} },
		WorkerActive: true,
	})
	if strings.Contains(e.LogLines(t), "orphan shim") {
		t.Fatalf("statless shim counted as an orphan:\n%s", e.LogLines(t))
	}

	// No systemd client → the journal half is skipped entirely: the
	// inconclusive line count must not grow on the next round.
	before := strings.Count(e.LogLines(t), "journal half inconclusive")
	e.H.Cfg.Systemd = nil
	c.Run(context.Background(), &wdeps.CycleEnv{
		PidsOnce:     func() []int { return nil },
		WorkerActive: true,
	})
	if after := strings.Count(e.LogLines(t), "journal half inconclusive"); after != before {
		t.Fatalf("nil systemd still probed the journal: %d → %d lines", before, after)
	}
}
