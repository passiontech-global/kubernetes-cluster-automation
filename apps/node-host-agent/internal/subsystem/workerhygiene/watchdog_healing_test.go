// Wave-8 tests — the agent-owned watchdog heartbeat (BUG-H1),
// A4-latch self-healing (BUG-H4), latch mtime refresh (BUG-H6),
// 2xx-only probeHTTP verdicts (BUG-H7), the disk-bloat log/
// snapshot attribution (BUG-H8), calico felix restart + cali*
// orphan-veth GC (W8-NM3), the cilium BPF-map-pressure latch
// (W8-NM3) and the PSI memory-thrash evictor (W2).

package workerhygiene

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// --- BUG-H1: the Cycle-owned watchdog heartbeat ---

// TestCycleWritesWatchdogHeartbeat: after the reporter's
// self-heartbeat was removed (it blinded WatchdogStale), the
// hygiene Cycle owns the periodic refresh — installed is seeded
// once, last-run is rewritten every cycle.
func TestCycleWritesWatchdogHeartbeat(t *testing.T) {
	e := fixture(t)
	e.h.Cycle(context.Background())

	read := func(name string) int64 {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(e.state, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		if err != nil {
			t.Fatalf("%s content %q is not an epoch", name, string(data))
		}
		return v
	}
	installEpoch := read("installed")
	if installEpoch != e.now.Unix() {
		t.Fatalf("installed = %d, want %d", installEpoch, e.now.Unix())
	}
	if got := read("last-run"); got != e.now.Unix() {
		t.Fatalf("last-run = %d, want %d", got, e.now.Unix())
	}

	// Next cycle refreshes last-run; installed keeps its baseline.
	e.now = e.now.Add(2 * time.Minute)
	e.h.Cycle(context.Background())
	if got := read("last-run"); got != e.now.Unix() {
		t.Fatalf("last-run not refreshed: %d, want %d", got, e.now.Unix())
	}
	if got := read("installed"); got != installEpoch {
		t.Fatalf("installed rewritten: %d, want baseline %d", got, installEpoch)
	}
}

// TestHeartbeatPreexistingFilesKept: a watchdog pair written before
// the agent starts is left alone — installed is force:false and
// last-run only gets the periodic refresh.
func TestHeartbeatPreexistingFilesKept(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.state, "installed"), "1000\n")
	e.h.Cycle(context.Background())
	data, err := os.ReadFile(filepath.Join(e.state, "installed"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "1000" {
		t.Fatalf("installed overwritten: %q", string(data))
	}
}

// --- BUG-H6: latch mtime refresh on maintained latches ---

// TestStateEnterRefreshesLatchMtime: re-entering an existing latch
// refreshes its mtime — the janitor reaps state-* files older than
// 24h and a multi-day live latch must not be reaped mid-episode.
func TestStateEnterRefreshesLatchMtime(t *testing.T) {
	e := fixture(t)
	p := filepath.Join(e.state, "state-d-state-storm")
	writeFile(t, p, "100\n")
	old := e.now.Add(-48 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	e.h.State.Enter("d-state-storm", "count=9")
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.ModTime().Before(e.now.Add(-time.Minute)) {
		t.Fatalf("latch mtime %v not refreshed to now (%v)",
			fi.ModTime(), e.now)
	}
	// Content untouched — the entry epoch records when the
	// condition started, not the last refresh.
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "100" {
		t.Fatalf("latch content = %q, want the original epoch", string(data))
	}
	// Still no second STATE-ENTER line (idempotent).
	if n := strings.Count(logLines(t, e), "STATE-ENTER: d-state-storm"); n != 0 {
		t.Fatalf("STATE-ENTER logged for an existing latch (%d lines)", n)
	}
}

// --- BUG-H7: probeHTTP verdicts are 2xx-only ---

// TestProbeHTTPDefaultNon2xxIsError: the production probeHTTP seam
// must treat HTTP 500/503 as DOWN — the cilium-agent :9879/healthz
// wedge case. Only 2xx answers pass.
func TestProbeHTTPDefaultNon2xxIsError(t *testing.T) {
	e := fixture(t)
	h, err := New(Config{Client: e.cs}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv200 := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv200.Close()
	srv503 := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer srv503.Close()

	if err := h.Cfg.Seams.ProbeHTTP(context.Background(), srv200.URL, time.Second); err != nil {
		t.Fatalf("200 probe = %v, want nil", err)
	}
	if err := h.Cfg.Seams.ProbeHTTP(context.Background(), srv503.URL, time.Second); err == nil {
		t.Fatal("503 probe must error — a wedged /healthz is down")
	}
}

// --- BUG-H4: A4 latches self-heal via the k0sworker restart ---

// TestSyncloopDownRestartsK0sWorker: a frozen PLEG confirmed for
// ConsecNeeded cycles latches state-kubelet-syncloop-down AND
// restarts k0sworker — the A4 signal is no longer latch-only.
func TestSyncloopDownRestartsK0sWorker(t *testing.T) {
	e := fixture(t)
	e.status["https://127.0.0.1:10250/healthz/syncloop"] = 500
	e.h.Cycle(context.Background())
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("k0sworker restarted on the first suspect cycle")
	}
	e.h.Cycle(context.Background())
	if !e.h.State.Exists("kubelet-syncloop-down") {
		t.Fatal("no latch after ConsecNeeded failed probes")
	}
	if !e.sdRan("restart k0sworker.service") {
		t.Fatal("BUG-H4: no k0sworker restart at ConsecNeeded")
	}
	// The shared budget file is stamped — the next latch entry
	// inside 30m skips the restart.
	if _, err := os.Stat(filepath.Join(e.state, "last-restart")); err != nil {
		t.Fatal("last-restart budget not spent")
	}
}

// TestSyncloopDownOverloadedSkipsRestart: under node-overloaded the
// restart is skipped AND the latch is suppressed — a stall under
// CPU starvation is a symptom; latching would escalate NHC→SNR and
// dump 100% of the load onto survivors (amplifier).
func TestSyncloopDownOverloadedSkipsRestart(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.state, "state-node-overloaded"),
		strconv.FormatInt(e.now.Unix(), 10))
	e.status["https://127.0.0.1:10250/healthz/syncloop"] = 500
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart under node-overloaded")
	}
	if e.h.State.Exists("kubelet-syncloop-down") {
		t.Fatal("latch not suppressed under node-overloaded")
	}
	if got := logLines(t, e); !strings.Contains(got, "suppressed-overloaded") {
		t.Fatalf("expected a suppressed-overloaded line, got:\n%s", got)
	}
}

// TestSyncloopDownRestartCooldown: a fresh last-restart budget
// blocks the restart — the latch still fires.
func TestSyncloopDownRestartCooldown(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.state, "last-restart"),
		strconv.FormatInt(e.now.Unix(), 10))
	e.status["https://127.0.0.1:10250/healthz/syncloop"] = 500
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.h.State.Exists("kubelet-syncloop-down") {
		t.Fatal("no latch after ConsecNeeded failed probes")
	}
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart inside the 30m cooldown")
	}
	if got := logLines(t, e); !strings.Contains(got, "restart cooldown") {
		t.Fatalf("expected a cooldown line, got:\n%s", got)
	}
}

// TestContainerdSockDownRestartsK0sWorker: a hung containerd socket
// confirmed for ConsecNeeded cycles latches + restarts k0sworker —
// the socket probe's BUG-H4 remedy.
func TestContainerdSockDownRestartsK0sWorker(t *testing.T) {
	e := fixture(t)
	e.sockErrs[e.h.Cfg.Ctr.Socket] = errors.New("connection refused")
	e.h.Cycle(context.Background())
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("k0sworker restarted on the first suspect cycle")
	}
	e.h.Cycle(context.Background())
	if !e.h.State.Exists("containerd-sock-down") {
		t.Fatal("no latch after ConsecNeeded socket failures")
	}
	if !e.sdRan("restart k0sworker.service") {
		t.Fatal("BUG-H4: no k0sworker restart at ConsecNeeded")
	}
}

// --- BUG-H8: disk-bloat pod-log + snapshot attribution ---

// TestCheckDiskBloatPodLogEvicts: a runaway stdout writer fills
// /var/log/pods while its emptyDir stays small — the log dir must
// attribute to the pod (name embeds ns_pod_uid) and the pod is the
// eviction victim.
func TestCheckDiskBloatPodLogEvicts(t *testing.T) {
	e := fixture(t)
	e.diskUsed = 0.95
	logDir := filepath.Join(e.state, "podlogs")
	e.h.Cfg.Disk.PodLogsDir = logDir
	e.h.Cfg.Disk.BloatPodThresholdBytes = 64
	victim := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "logger", Namespace: "app", UID: types.UID("uid-1")},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if err := os.MkdirAll(filepath.Join(logDir, "app_logger_uid-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(logDir, "app_logger_uid-1", "0.log"),
		strings.Repeat("l", 200))
	if err := os.MkdirAll(filepath.Join(e.kubepods, "uid-1"), 0o755); err != nil {
		t.Fatal(err)
	}

	e.h.checkDiskBloat(context.Background(), []corev1.Pod{*victim}, true, true)

	if len(deleteActions(e.cs)) != 1 {
		t.Fatalf("deletes = %v, want the log-bloating pod",
			deleteActions(e.cs))
	}
	if !e.h.State.Exists("disk-bloat") {
		t.Fatal("disk-bloat latch not set")
	}
	if got := logLines(t, e); !strings.Contains(got, "logs") {
		t.Fatalf("log line must name the pod-logs contributor, got:\n%s", got)
	}
}

// TestCheckDiskBloatSnapshotEvicts: an over-threshold overlayfs
// snapshot attributes to its pod through the CRI task dir (the
// containerd snapshot key is the container ID == task dir name) —
// the pod behind it is the eviction victim.
func TestCheckDiskBloatSnapshotEvicts(t *testing.T) {
	e := fixture(t)
	e.diskUsed = 0.95
	e.h.Cfg.Disk.BloatPodThresholdBytes = 64
	victim := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "layerhog", Namespace: "app", UID: types.UID(uidA)},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	snap := filepath.Join(e.h.Cfg.Disk.K0sDataDir, "containerd",
		"io.containerd.snapshotter.v1.overlayfs", "snapshots", "snapctr1", "fs")
	if err := os.MkdirAll(snap, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(snap, "blob"), strings.Repeat("x", 200))
	// Task dir config.json carries the pod uid annotation.
	if err := os.MkdirAll(filepath.Join(e.ctr, "snapctr1"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(e.ctr, "snapctr1", "config.json"),
		`{"annotations": {"io.kubernetes.pod.uid": "`+uidA+`"}}`)

	e.h.checkDiskBloat(context.Background(), []corev1.Pod{*victim}, true, true)

	if len(deleteActions(e.cs)) != 1 {
		t.Fatalf("deletes = %v, want the snapshot-owning pod",
			deleteActions(e.cs))
	}
}

// --- W8-NM3: calico felix restart + orphan-veth GC ---

// calicoPod builds a Running calico-node-* pod on this node.
func calicoPod(name, uid string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "kube-system", UID: types.UID(uid)},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// TestCheckCalicoFelixRestartDeletesPod: felix readiness dark for
// calicoFelixRestartFails consecutive cycles deletes the calico-node
// pod (DaemonSet rebuilds it) under the last-calico-restart budget.
func TestCheckCalicoFelixRestartDeletesPod(t *testing.T) {
	e := fixture(t)
	pod := calicoPod("calico-node-abc12", "uid-cal")
	// cali* ifaces so the calico gate opens; felix probe fails.
	writeFile(t, filepath.Join(e.sysnet, "cali00", "carrier"), "1\n")
	e.status[e.h.Cfg.Calico.FelixReadyURL] = 500
	pods := []corev1.Pod{*pod}

	for i := 0; i < calicoFelixRestartFails; i++ {
		e.h.checkCalicoHygiene(context.Background(), pods, true, true)
	}
	if !e.h.State.Exists("calico-felix-down") {
		t.Fatal("no calico-felix-down latch")
	}
	del := deleteActions(e.cs)
	if len(del) != 1 {
		t.Fatalf("deletes = %v, want the calico-node pod", del)
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-calico-restart")); err != nil {
		t.Fatal("last-calico-restart budget not spent")
	}
	// Same-pod second attempt inside 30m is cooldown-blocked —
	// the fake clientset was drained by the delete above, so
	// assert on the budget log instead: a new pod still failing
	// gets a cooldown line, not another delete.
	if _, err := e.cs.CoreV1().Pods("kube-system").Create(
		context.Background(), calicoPod("calico-node-def34", "uid-cal2"),
		metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	pods[0] = *calicoPod("calico-node-def34", "uid-cal2")
	e.h.checkCalicoHygiene(context.Background(), pods, true, true)
	if got := logLines(t, e); !strings.Contains(got, "pod restart in cooldown") {
		t.Fatalf("expected a cooldown line, got:\n%s", got)
	}
}

// TestCheckCalicoFelixLatchBeforeRestart: the latch enters at
// ConsecNeeded (2) but the pod delete waits for
// calicoFelixRestartFails (3) — one flaky readiness probe must not
// bounce the datapath pod.
func TestCheckCalicoFelixLatchBeforeRestart(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.sysnet, "cali00", "carrier"), "1\n")
	e.status[e.h.Cfg.Calico.FelixReadyURL] = 500
	pods := []corev1.Pod{*calicoPod("calico-node-abc12", "uid-cal")}

	for i := 0; i < 2; i++ {
		e.h.checkCalicoHygiene(context.Background(), pods, true, true)
	}
	if !e.h.State.Exists("calico-felix-down") {
		t.Fatal("no latch after ConsecNeeded")
	}
	if n := len(deleteActions(e.cs)); n != 0 {
		t.Fatalf("pod deleted at %dx fails — too early (want >= %d)",
			2, calicoFelixRestartFails)
	}
}

// TestCheckCalicoVethGCDeletesOrphan: while state-calico-veth-leak
// is set, a cali* host veth that stays DOWN (carrier 0) for the
// confirm window is reaped via `ip link delete`.
func TestCheckCalicoVethGCDeletesOrphan(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.sysnet, "cali99", "carrier"), "0\n")
	// Leak still detected → latch persists: threshold+1 cali*
	// ifaces over the (empty) pod count, all but cali99 live.
	for i := 0; i < e.h.Cfg.Calico.OrphanVethThreshold+1; i++ {
		writeFile(t, filepath.Join(e.sysnet,
			fmt.Sprintf("cali%02d", i+1), "carrier"), "1\n")
	}
	pods := []corev1.Pod{}
	e.h.checkCalicoHygiene(context.Background(), pods, true, true)
	if e.h.State.Exists("calico-veth-leak") {
		t.Fatal("leak latch before ConsecNeeded")
	}
	e.h.checkCalicoHygiene(context.Background(), pods, true, true)
	if !e.h.State.Exists("calico-veth-leak") {
		t.Fatal("leak latch not set")
	}
	if e.sdRan("ip link delete cali99") {
		t.Fatal("orphan deleted on first sight — needs the down-age confirm")
	}
	if _, err := os.Stat(filepath.Join(e.state, "veth-seen-cali99")); err != nil {
		t.Fatal("no veth-seen marker stamped for the down orphan")
	}
	// 16m later the marker ages out → the delete runs.
	e.now = e.now.Add(16 * time.Minute)
	e.sdReply["ip link delete"] = ""
	e.h.checkCalicoHygiene(context.Background(), pods, true, true)
	if !e.sdRan("ip link delete cali99") {
		t.Fatal("orphan veth not deleted after the down-age window")
	}
	if e.sdRan("ip link delete calilive") {
		t.Fatal("a LIVE veth was deleted")
	}
	if _, err := os.Stat(filepath.Join(e.state, "veth-seen-cali99")); !os.IsNotExist(err) {
		t.Fatal("veth-seen marker not cleaned after the delete")
	}
	if got := logLines(t, e); !strings.Contains(got, "deleted orphan veth cali99") {
		t.Fatalf("expected the delete ACTION line, got:\n%s", got)
	}
}

// TestCheckCalicoVethGCNeedsLeakLatch: the orphan GC only runs while
// state-calico-veth-leak is set — down ifaces outside a leak
// episode are left alone.
func TestCheckCalicoVethGCNeedsLeakLatch(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.sysnet, "cali99", "carrier"), "0\n")
	// Few ifaces → no leak → latch never enters → no GC.
	e.h.checkCalicoHygiene(context.Background(), nil, true, true)
	if _, err := os.Stat(filepath.Join(e.state, "veth-seen-cali99")); !os.IsNotExist(err) {
		t.Fatal("veth-seen marker stamped without the leak latch")
	}
	if e.sdRan("ip link delete cali99") {
		t.Fatal("orphan deleted without the leak latch")
	}
}

// --- W8-NM3: cilium BPF map pressure ---

// TestCheckCiliumBPFMapPressureLatches: a critical map past the
// fill ratio latches state-cilium-bpf-map-pressure; back under the
// ratio clears it.
func TestCheckCiliumBPFMapPressureLatches(t *testing.T) {
	e := fixture(t)
	e.h.checkCiliumBPFMaps(context.Background())
	if e.h.State.Exists("cilium-bpf-map-pressure") {
		t.Fatal("latch on an empty /v1/map body")
	}
	e.unixBody = []byte(`{"maps":[
		{"name":"cilium_ct4_global","used":950,"max":1000},
		{"name":"cilium_lb4_services_v2","used":100,"max":1000}
	]}`)
	e.h.checkCiliumBPFMaps(context.Background())
	if !e.h.State.Exists("cilium-bpf-map-pressure") {
		t.Fatal("no latch with cilium_ct4_global at 95%")
	}
	// Path-shaped entries (the real /v1/map wire) resolve by
	// basename.
	e.unixBody = []byte(`{"maps":[
		{"path":"/sys/fs/bpf/cilium/cilium_ct4_global","size":1000,"cache":[]}
	]}`)
	e.h.checkCiliumBPFMaps(context.Background())
	if e.h.State.Exists("cilium-bpf-map-pressure") {
		t.Fatal("empty cache at 1000 capacity must clear the latch")
	}
}

// TestParseCiliumBPFMapsShapes covers the tolerant wire parser —
// name/path, used/entries/cache, size/max/capacity.
func TestParseCiliumBPFMapsShapes(t *testing.T) {
	m := parseCiliumBPFMaps([]byte(`{
		"maps": [
			{"name": "cilium_ct4_global", "size": 262144, "used": 250000},
			{"path": "/sys/fs/bpf/tc/globals/cilium_snat_v4_external",
			 "cache": [{"key":"a"},{"key":"b"}], "max": 4},
			{"name": "cilium_lb4_services_v2", "maxSize": 1000, "entries": 500},
			{"name": "unrelated_map", "used": 999, "max": 1000}
		]}`))
	if um := m["cilium_ct4_global"]; um != [2]int64{250000, 262144} {
		t.Fatalf("ct4 = %v", um)
	}
	if um := m["cilium_snat_v4_external"]; um != [2]int64{2, 4} {
		t.Fatalf("snat = %v", um)
	}
	if um := m["cilium_lb4_services_v2"]; um != [2]int64{500, 1000} {
		t.Fatalf("lb4 = %v", um)
	}
	if _, ok := m["unrelated_map"]; ok {
		t.Fatal("non-critical map must not parse into the result")
	}
}

// --- W2: PSI memory thrash ---

// writeThrashFiles lays down the PSI pressure/memory + meminfo
// files the thrash check reads: full avg60 (percent) and
// MemAvailable/MemTotal in kB.
func writeThrashFiles(t *testing.T, e *env, avg60 float64, availKB, totalKB int) {
	t.Helper()
	writeFile(t, filepath.Join(e.proc, "pressure", "memory"), fmt.Sprintf(
		"some avg10=1.00 avg60=%.2f avg300=1.00 total=1\nfull avg10=1.00 avg60=%.2f avg300=1.00 total=1\n",
		avg60, avg60))
	writeFile(t, filepath.Join(e.proc, "meminfo"), fmt.Sprintf(
		"MemTotal: %d kB\nMemFree: %d kB\nMemAvailable: %d kB\n",
		totalKB, availKB, availKB))
}

// TestCheckPSIThrashLatchesAndEvicts: sustained full-avg60 > 25%
// with free memory < 8% latches state-psi-memory-thrash, logs the
// NPD ACTION line and evicts the highest-RSS non-system pod.
func TestCheckPSIThrashLatchesAndEvicts(t *testing.T) {
	e := fixture(t)
	writeThrashFiles(t, e, 30.0, 50000, 1000000)
	hog := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "memhog", Namespace: "app", UID: types.UID(uidA)},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	small := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tiny", Namespace: "app", UID: types.UID(uidB)},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	pods := []corev1.Pod{*hog, *small}
	// Two pids: 5001 belongs to memhog (big VmRSS), 5002 to tiny.
	for pid, uid := range map[int]string{5001: uidA, 5002: uidB} {
		d := filepath.Join(e.proc, strconv.Itoa(pid))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		underscored := strings.ReplaceAll(uid, "-", "_")
		writeFile(t, filepath.Join(d, "cgroup"),
			"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod"+underscored+".slice\n")
		rss := 100
		if pid == 5001 {
			rss = 900000
		}
		writeFile(t, filepath.Join(d, "status"),
			fmt.Sprintf("Name:\tc\nVmRSS:\t%d kB\n", rss))
	}
	pids := pidsOf(5001, 5002)

	e.h.checkPSIThrash(context.Background(), pods, true, pids, true)
	if e.h.State.Exists("psi-memory-thrash") {
		t.Fatal("latched on the first thrash cycle")
	}
	e.h.checkPSIThrash(context.Background(), pods, true, pids, true)
	if !e.h.State.Exists("psi-memory-thrash") {
		t.Fatal("no latch after ConsecNeeded thrash cycles")
	}
	if got := logLines(t, e); !strings.Contains(got, "ACTION psi-memory-thrash:") {
		t.Fatalf("the NodeMemoryPSIThrashing Event line missing:\n%s", got)
	}
	evs := evictActions(e.cs)
	if len(evs) != 1 || evs[0] != "memhog" {
		t.Fatalf("evictions = %v, want the highest-RSS pod memhog", evs)
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-psi-evict")); err != nil {
		t.Fatal("last-psi-evict budget not spent")
	}

	// Recovery clears the latch.
	writeThrashFiles(t, e, 5.0, 500000, 1000000)
	e.h.checkPSIThrash(context.Background(), pods, true, pids, true)
	if e.h.State.Exists("psi-memory-thrash") {
		t.Fatal("latch not cleared after the thrash subsides")
	}
}

// TestCheckPSIThrashNeedsBothSignals: PSI stall alone (free memory
// still > 8%) and low memory alone (no stall) both mean NO thrash —
// a cache-heavy node with PSI headroom is healthy.
func TestCheckPSIThrashNeedsBothSignals(t *testing.T) {
	e := fixture(t)
	// Stall high, memory fine.
	writeThrashFiles(t, e, 40.0, 500000, 1000000)
	for i := 0; i < 3; i++ {
		e.h.checkPSIThrash(context.Background(), nil, true, pidsOf(), true)
	}
	if e.h.State.Exists("psi-memory-thrash") {
		t.Fatal("latched on PSI alone — free memory is fine")
	}
	// Memory low, no stall.
	writeThrashFiles(t, e, 3.0, 50000, 1000000)
	for i := 0; i < 3; i++ {
		e.h.checkPSIThrash(context.Background(), nil, true, pidsOf(), true)
	}
	if e.h.State.Exists("psi-memory-thrash") {
		t.Fatal("latched on low memory alone — no PSI stall")
	}
}

// TestCheckPSIThrashSystemPodsSafe: the eviction ranking never
// picks kube-system/node-ops pods even when they hold the most RSS.
func TestCheckPSIThrashSystemPodsSafe(t *testing.T) {
	e := fixture(t)
	writeThrashFiles(t, e, 30.0, 50000, 1000000)
	syspod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "kube-proxy-x1", Namespace: "kube-system", UID: types.UID(uidA)},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	work := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "workload", Namespace: "app", UID: types.UID(uidB)},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	pods := []corev1.Pod{*syspod, *work}
	for pid, uid := range map[int]string{5001: uidA, 5002: uidB} {
		d := filepath.Join(e.proc, strconv.Itoa(pid))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		underscored := strings.ReplaceAll(uid, "-", "_")
		writeFile(t, filepath.Join(d, "cgroup"),
			"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod"+underscored+".slice\n")
		rss := 900000 // the SYSTEM pod holds the most RSS
		if pid == 5002 {
			// Above the 512MiB victim floor (524288 kB) but
			// below the system pod — still the only eligible
			// victim.
			rss = 600000
		}
		writeFile(t, filepath.Join(d, "status"),
			fmt.Sprintf("Name:\tc\nVmRSS:\t%d kB\n", rss))
	}
	for i := 0; i < 2; i++ {
		e.h.checkPSIThrash(context.Background(), pods, true, pidsOf(5001, 5002), true)
	}
	evs := evictActions(e.cs)
	if len(evs) != 1 || evs[0] != "workload" {
		t.Fatalf("evictions = %v, want workload (system pods protected)", evs)
	}
}
