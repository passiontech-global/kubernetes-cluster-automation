package workerhygiene

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// --- W10-KR3: containerd meta.db corruption latch ---

func TestContainerdMetaJournalLatch(t *testing.T) {
	e := fixture(t)
	h := e.h
	ctx := context.Background()
	var journal string
	h.cfg.ContainerdMetaJournalFn = func(context.Context) (string, error) {
		return journal, nil
	}
	pids := func() []int { return nil }
	// Clean journal clears/keeps clear.
	h.checkContainerdHealth(ctx, pids, true)
	if _, err := os.Stat(filepath.Join(e.state,
		"state-containerd-corrupt")); !os.IsNotExist(err) {
		t.Fatal("latch set on clean journal")
	}
	journal = "containerd[123]: failed to loadmeta \"/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db\": timeout"
	h.checkContainerdHealth(ctx, pids, true)
	if _, err := os.Stat(filepath.Join(e.state,
		"state-containerd-corrupt")); !os.IsNotExist(err) {
		t.Fatal("latch set before ConsecNeeded")
	}
	h.checkContainerdHealth(ctx, pids, true)
	if _, err := os.Stat(filepath.Join(e.state,
		"state-containerd-corrupt")); err != nil {
		t.Fatal("containerd-corrupt latch missing after 2 evidence cycles")
	}
	// Clean cycle releases.
	journal = "containerd[123]: healthy heartbeat"
	h.checkContainerdHealth(ctx, pids, true)
	if _, err := os.Stat(filepath.Join(e.state,
		"state-containerd-corrupt")); !os.IsNotExist(err) {
		t.Fatal("latch not cleared on clean journal")
	}
	// Worker gate off → no evaluation.
	h.checkContainerdHealth(ctx, pids, false)
	if _, err := os.Stat(filepath.Join(e.state,
		"state-containerd-corrupt")); !os.IsNotExist(err) {
		t.Fatal("latch touched while worker inactive")
	}
}

// --- W10-KR1 consumer: SystemOOMVictim event ---

func TestHostOOMVictimEvent(t *testing.T) {
	e := fixture(t)
	h := e.h
	ctx := context.Background()
	// No markers → no event.
	h.checkHostOOMVictims(ctx)
	evs, err := e.cs.EventsV1().Events("default").List(ctx,
		metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 0 {
		t.Fatalf("unexpected events: %d", len(evs.Items))
	}
	// Marker pair → one Warning event on the Node.
	now := time.Now().Unix()
	writeFile(t, h.cfg.HostOOMVictimFile,
		strconv.FormatInt(now, 10)+" containerd-shim\n")
	writeFile(t, h.cfg.HostOOMCountFile, "3\n")
	h.checkHostOOMVictims(ctx)
	h.checkHostOOMVictims(ctx) // dedup — same count, no second event
	evs, err = e.cs.EventsV1().Events("default").List(ctx,
		metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 1 {
		t.Fatalf("events=%d want 1 (deduped)", len(evs.Items))
	}
	ev := evs.Items[0]
	if ev.Reason != "SystemOOMVictim" || ev.Type != "Warning" ||
		ev.Regarding.Name != "node-a" {
		t.Fatalf("bad event: reason=%s type=%s regarding=%s",
			ev.Reason, ev.Type, ev.Regarding.Name)
	}
	// Count advances → second event.
	writeFile(t, h.cfg.HostOOMCountFile, "4\n")
	h.checkHostOOMVictims(ctx)
	evs, _ = e.cs.EventsV1().Events("default").List(ctx,
		metav1.ListOptions{})
	if len(evs.Items) != 2 {
		t.Fatalf("events=%d want 2 after count advance", len(evs.Items))
	}
}

// --- W10-ST2: orphan hostPath dirs ---

func TestOrphanHostPathVolumes(t *testing.T) {
	e := fixture(t)
	h := e.h
	ctx := context.Background()
	root := t.TempDir()
	h.cfg.OrphanHostPathDirs = []string{filepath.Join(root, "prov")}
	prov := h.cfg.OrphanHostPathDirs[0]
	if err := os.MkdirAll(filepath.Join(prov, "pvc-orphan1"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Old enough (>24h) + empty → removable under disk pressure.
	old := time.Now().Add(-48 * time.Hour)
	_ = os.Chtimes(filepath.Join(prov, "pvc-orphan1"), old, old)
	e.diskUsed = 0.90
	h.checkOrphanedHostPathVolumes(ctx, true)
	if _, err := os.Stat(filepath.Join(prov, "pvc-orphan1")); !os.IsNotExist(err) {
		t.Fatal("empty orphan dir not removed under disk pressure")
	}
	if h.orphanHostPathDirs != 1 {
		t.Fatalf("orphanHostPathDirs=%d want 1", h.orphanHostPathDirs)
	}
	// Dir holding data is reported but NEVER removed.
	dataDir := filepath.Join(prov, "pvc-data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dataDir, "important.bin"), "x")
	_ = os.Chtimes(dataDir, old, old)
	h.checkOrphanedHostPathVolumes(ctx, true)
	if _, err := os.Stat(filepath.Join(dataDir, "important.bin")); err != nil {
		t.Fatal("data-bearing orphan dir was removed")
	}
	// A live PV matching the dir name → not an orphan.
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pvc-livepv"},
	}
	if _, err := e.cs.CoreV1().PersistentVolumes().Create(ctx, pv,
		metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	liveDir := filepath.Join(prov, "pvc-livepv")
	if err := os.MkdirAll(liveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(liveDir, old, old)
	h.checkOrphanedHostPathVolumes(ctx, true)
	if _, err := os.Stat(liveDir); err != nil {
		t.Fatal("PV-backed dir treated as orphan")
	}
}

func TestWave10PromWrite(t *testing.T) {
	e := fixture(t)
	h := e.h
	dir := t.TempDir()
	wave10PromDirOverride = dir
	defer func() { wave10PromDirOverride = "" }()
	h.orphanHostPathBytes = 4096
	h.orphanHostPathDirs = 2
	h.writeWave10Prom()
	b, err := os.ReadFile(filepath.Join(dir, "node-agent-hygiene.prom"))
	if err != nil {
		t.Fatalf("prom file missing: %v", err)
	}
	s := string(b)
	for _, want := range []string{
		"node_agent_host_oom_kills_total",
		"node_agent_conntrack_drops_detected_total",
		"node_agent_orphan_hostpath_bytes 4096",
		"node_agent_orphan_hostpath_dirs 2",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("prom missing %q:\n%s", want, s)
		}
	}
}
