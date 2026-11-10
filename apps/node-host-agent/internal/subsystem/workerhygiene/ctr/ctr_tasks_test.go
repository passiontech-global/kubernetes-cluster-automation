// ctr_tasks_test.go — check 6 ctr-tasks (wedged dirs + orphan-shim
// reaper), check 37 ctr-image-healer (corrupted image rm + CRI name
// normalization), and the A3 ingest-dir GC sweep.
package ctr_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// --- check 6: ctr-tasks (31) ---

// TestCtrTasksUmountsRootfsBeforeRemove: a wedged task
// bundle whose rootfs is still a mount must be lazily unmounted in
// the HOST mount namespace BEFORE the dir removal — RemoveAll would
// hit EBUSY and leak the mountpoint into the mountinfo table.
func TestCtrTasksUmountsRootfsBeforeRemove(t *testing.T) {
	e := fixture(t)
	dir := filepath.Join(e.CtrDir, "ef0ce17"+strings.Repeat("f", 57))
	wdepstest.WriteFile(t, filepath.Join(dir, "init.pid"), "77777")
	wdepstest.WriteFile(t, filepath.Join(dir, "config.json"), `{"annotations":{}}`)
	wdepstest.WriteFile(t, filepath.Join(dir, "log.json"), "{}\n")
	// The still-mounted rootfs — contents on the leaked mount.
	wdepstest.WriteFile(t, filepath.Join(dir, "rootfs", "bin", "sh"), "#!/bin/sh\n")
	e.SDReply["umount"] = ""

	e.H.Cycle(context.Background()) // marker only
	if e.SDRan("umount") {
		t.Fatal("umount ran before the wedged-dir confirmation window")
	}
	e.Now = e.Now.Add(6 * time.Minute)
	e.H.Cycle(context.Background()) // confirm + clean
	if !e.SDRan("umount -l " + filepath.Join(dir, "rootfs")) {
		t.Fatalf("no lazy umount of the task rootfs; sdcmds=%v", e.SDCmds)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("wedged dir not removed after umount")
	}
	if !strings.Contains(e.LogLines(t), "umount -l rootfs of task") {
		t.Fatalf("missing umount ACTION line:\n%s", e.LogLines(t))
	}

	// A task dir WITHOUT a rootfs subtree (already unmounted) must
	// not fire a umount.
	dir2 := filepath.Join(e.CtrDir, "deadc0d"+strings.Repeat("0", 57))
	wdepstest.WriteFile(t, filepath.Join(dir2, "init.pid"), "77778")
	wdepstest.WriteFile(t, filepath.Join(dir2, "config.json"), `{"annotations":{}}`)
	wdepstest.WriteFile(t, filepath.Join(dir2, "log.json"), "{}\n")
	e.H.Cycle(context.Background())
	e.Now = e.Now.Add(6 * time.Minute)
	n := 0
	for _, c := range e.SDCmds {
		joined := strings.Join(c, " ")
		if strings.Contains(joined, "umount") && strings.Contains(joined, dir2) {
			n++
		}
	}
	if n != 0 {
		t.Fatalf("umount fired for a dir without rootfs: %d", n)
	}
}

func TestCtrTasksWedgedDirTwoPhase(t *testing.T) {
	e := fixture(t)
	// Dead-init task dir (init.pid points at nothing live).
	dir := filepath.Join(e.CtrDir, "deadbeef"+strings.Repeat("a", 56))
	wdepstest.WriteFile(t, filepath.Join(dir, "init.pid"), "77777")
	wdepstest.WriteFile(t, filepath.Join(dir, "config.json"), `{"annotations":{}}`)
	wdepstest.WriteFile(t, filepath.Join(dir, "log.json"), "{}\n")

	e.H.Cycle(context.Background())
	// First sighting: marker only — no cleanup yet.
	if _, err := os.Stat(dir); err != nil {
		t.Fatal("dir removed before marker confirmation")
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "wedged-seen-"+filepath.Base(dir))); err != nil {
		t.Fatalf("marker not written: %v", err)
	}
	// Advance past the 5m confirm window → cleanup.
	e.Now = e.Now.Add(6 * time.Minute)
	e.H.Cycle(context.Background())
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("wedged dir not removed after 5m marker")
	}
	if _, err := os.Stat(filepath.Join(e.StateDir,
		"wedged-seen-"+filepath.Base(dir))); !os.IsNotExist(err) {
		t.Fatal("marker not consumed by cleanup")
	}
	if !strings.Contains(e.LogLines(t), "rm wedged task dir") {
		t.Fatalf("missing rm-dir log:\n%s", e.LogLines(t))
	}
}

func TestCtrTasksLiveAndSandboxSkipped(t *testing.T) {
	e := fixture(t)
	// Live init, log.json present → healthy task, marker cleared.
	liveDir := filepath.Join(e.CtrDir, "livetask"+strings.Repeat("b", 57))
	wdepstest.WriteFile(t, filepath.Join(liveDir, "init.pid"), "9100")
	wdepstest.WriteFile(t, filepath.Join(liveDir, "config.json"), `{"annotations":{}}`)
	wdepstest.WriteFile(t, filepath.Join(liveDir, "log.json"), "{}\n")
	e.MkProc(t, 9100, "S", "", "")
	// Sandbox (pause) missing log.json → legitimately skipped.
	sbDir := filepath.Join(e.CtrDir, "sandboxx"+strings.Repeat("c", 57))
	wdepstest.WriteFile(t, filepath.Join(sbDir, "init.pid"), "9101")
	wdepstest.WriteFile(t, filepath.Join(sbDir, "config.json"),
		`{"annotations":{"cri.container-type":"sandbox"}}`)
	e.MkProc(t, 9101, "S", "", "")
	for i := 0; i < 3; i++ {
		e.H.Cycle(context.Background())
		e.Now = e.Now.Add(6 * time.Minute)
	}
	if _, err := os.Stat(liveDir); err != nil {
		t.Fatal("live task dir removed")
	}
	if _, err := os.Stat(sbDir); err != nil {
		t.Fatal("sandbox dir removed (log.json missing is normal)")
	}
}

func TestCtrTasksMissingLogJSONKillsInit(t *testing.T) {
	e := fixture(t)
	dir := filepath.Join(e.CtrDir, "0fa11ce"+strings.Repeat("d", 57))
	wdepstest.WriteFile(t, filepath.Join(dir, "init.pid"), "9102")
	wdepstest.WriteFile(t, filepath.Join(dir, "config.json"), `{"annotations":{}}`)
	// No log.json + LIVE init on a container task → dead wedge.
	e.MkProc(t, 9102, "S", "", "")
	e.H.Cycle(context.Background()) // marker
	e.Now = e.Now.Add(6 * time.Minute)
	e.H.Cycle(context.Background()) // confirm + clean
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("dir with missing log.json not removed")
	}
	if len(e.Kills) == 0 || e.Kills[0].PID != 9102 {
		t.Fatalf("init not SIGKILLed, kills=%v", e.Kills)
	}
}

func TestCtrTasksOrphanShim(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("e", 64)
	// Orphan shim: cmdline holds -id <sid> but no task dir anywhere.
	// -address pins it to the k0s containerd socket (host-side path —
	// ContainerdSocket's /host mount prefix is stripped for the
	// comparison).
	e.MkProc(t, 9200, "S",
		"containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-id\x00"+sid+
			"\x00-address\x00/run/k0s/containerd.sock\x00", "")
	// Fresh proc mtime — must survive the 5m orphan window.
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatal("fresh shim killed before 5m window")
	}
	// Age the /proc entry past 5m.
	old := e.Now.Add(-6 * time.Minute)
	if err := os.Chtimes(filepath.Join(e.ProcDir, "9200"), old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 1 || e.Kills[0].PID != 9200 || e.Kills[0].Sig != syscall.SIGKILL {
		t.Fatalf("orphan shim not killed, kills=%v", e.Kills)
	}
}

func TestCtrTasksHealthyShimKept(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("f", 64)
	e.MkProc(t, 9201, "S",
		"containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-id\x00"+sid+
			"\x00-address\x00/run/k0s/containerd.sock\x00", "")
	// The task dir exists → shim is not an orphan.
	if err := os.MkdirAll(filepath.Join(e.CtrDir, sid), 0o755); err != nil {
		t.Fatal(err)
	}
	old := e.Now.Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(e.ProcDir, "9201"), old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("healthy shim killed, kills=%v", e.Kills)
	}
}

// TestCtrTasksForeignShimNotKilled is the NodeOverloaded-incident
// regression: a host dockerd shim (namespace moby, socket
// /run/containerd/containerd.sock — a DIFFERENT containerd root) has
// no task dir under the k0s k8s.io root, so the pre-fix reaper
// SIGKILLed every docker shim each sweep. It must now read as
// out-of-scope and survive even past the 5m age window.
func TestCtrTasksForeignShimNotKilled(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("a", 64)
	e.MkProc(t, 9300, "S",
		"containerd-shim-runc-v2\x00-namespace\x00moby\x00-id\x00"+sid+
			"\x00-address\x00/run/containerd/containerd.sock\x00", "")
	old := e.Now.Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(e.ProcDir, "9300"), old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("docker/moby shim killed by orphan reaper, kills=%v", e.Kills)
	}
}

// TestCtrTasksK8sNsForeignAddressNotKilled: namespace alone is not
// scope — a foreign containerd can also serve a k8s.io-looking
// namespace (a second CRI daemon, a concourse worker's containerd).
// The -address flag is the instance identity.
func TestCtrTasksK8sNsForeignAddressNotKilled(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("b", 64)
	e.MkProc(t, 9301, "S",
		"containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-id\x00"+sid+
			"\x00-address\x00/run/containerd/containerd.sock\x00", "")
	old := e.Now.Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(e.ProcDir, "9301"), old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("k8s.io shim of foreign containerd killed, kills=%v", e.Kills)
	}
}

// TestCtrTasksShimMissingFlagsNotKilled: a shim that can't be tied to
// our containerd (no -address at all) is skipped — fail closed, the
// instance is unverifiable.
func TestCtrTasksShimMissingFlagsNotKilled(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("c", 64)
	e.MkProc(t, 9302, "S",
		"containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-id\x00"+sid+"\x00", "")
	old := e.Now.Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(e.ProcDir, "9302"), old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("unverifiable shim (no -address) killed, kills=%v", e.Kills)
	}
}

// TestCtrTasksForeignNsSameSocketKept: a non-k8s.io namespace on OUR
// containerd resolves its task dir under the sibling namespace root —
// a live task must not read as orphan.
func TestCtrTasksForeignNsSameSocketKept(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("d", 64)
	e.MkProc(t, 9303, "S",
		"containerd-shim-runc-v2\x00-namespace\x00buildkit\x00-id\x00"+sid+
			"\x00-address\x00/run/k0s/containerd.sock\x00", "")
	// Task dir exists under the buildkit namespace root: sibling of
	// the k8s.io root (filepath.Dir(e.CtrDir)/<ns>/<id>).
	if err := os.MkdirAll(
		filepath.Join(filepath.Dir(e.CtrDir), "buildkit", sid), 0o755); err != nil {
		t.Fatal(err)
	}
	old := e.Now.Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(e.ProcDir, "9303"), old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("live foreign-namespace shim on k0s containerd killed, kills=%v", e.Kills)
	}
}

// TestCtrTasksForeignNsSameSocketOrphanKilled: same socket + a
// foreign namespace whose task dir is genuinely gone IS our
// containerd's orphan — reap it like a k8s.io orphan.
func TestCtrTasksForeignNsSameSocketOrphanKilled(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("9", 64)
	e.MkProc(t, 9304, "S",
		"containerd-shim-runc-v2\x00-namespace\x00buildkit\x00-id\x00"+sid+
			"\x00-address\x00/run/k0s/containerd.sock\x00", "")
	old := e.Now.Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(e.ProcDir, "9304"), old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 1 || e.Kills[0].PID != 9304 || e.Kills[0].Sig != syscall.SIGKILL {
		t.Fatalf("orphan same-socket foreign-ns shim not killed, kills=%v", e.Kills)
	}
}

// TestCtrTasksOverCapKeepsMarker: dirs dropped by the per-cycle cap
// must KEEP their confirmed wedged-seen marker — removing it on the
// capped pass forced over-cap dirs to re-confirm for 5m forever.
func TestCtrTasksOverCapKeepsMarker(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Ctr.MaxTaskClean = 2
	// 4 confirmed-wedged dirs (dead init: no init.pid at all), each
	// with a marker already past the 5m confirm window. Hex64 ids —
	// the wedge scan gates on CRI id shape before pid-scanning.
	for i := range 4 {
		id := fmt.Sprintf("%02x%s", i, strings.Repeat("d", 62))
		if err := os.MkdirAll(filepath.Join(e.CtrDir, id), 0o755); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, filepath.Join(e.StateDir, "wedged-seen-"+id),
			fmt.Sprintf("%d\n", e.Now.Add(-10*time.Minute).Unix()))
	}
	e.H.Cycle(context.Background())
	// First two (ReadDir order) cleaned, markers consumed.
	for i := range 2 {
		id := fmt.Sprintf("%02x%s", i, strings.Repeat("d", 62))
		if _, err := os.Stat(filepath.Join(e.CtrDir, id)); !os.IsNotExist(err) {
			t.Fatalf("in-cap wedged dir %s not removed", id)
		}
	}
	// The capped two keep BOTH dir and marker — confirmed state
	// survives so next cycle cleans them without a new 5m wait.
	for i := 2; i < 4; i++ {
		id := fmt.Sprintf("%02x%s", i, strings.Repeat("d", 62))
		if _, err := os.Stat(filepath.Join(e.StateDir, "wedged-seen-"+id)); err != nil {
			t.Fatalf("over-cap marker %s dropped — dir would re-confirm forever", id)
		}
	}
}

// --- check: ctr-image-healer (37) ---

// recordImageRm points the single Seams.Ctr.Exec seam at a recorder
// for `images rm --sync <ref>` calls (the argv the RmImage method
// builds — the ref is the last element). Other ctr execs pass
// through quietly.
func recordImageRm(e *env, removed *[]string) {
	e.H.Cfg.Seams.Ctr.Exec = func(_ context.Context, argv ...string) error {
		if slices.Contains(argv, "--sync") {
			*removed = append(*removed, argv[len(argv)-1])
		}
		return nil
	}
}

// waitingPod builds a Pending pod on node-a whose single container is
// stuck Waiting with the given reason/message/image — 37 evidence.
// imageID is the CRI repoDigest record (e.g.
// docker.io/library/nginx@sha256:…) kubelet reports alongside Image —
// the healer removes both records.
func waitingPod(name, ns, uid, image, imageID, reason, msg string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns, UID: types.UID(uid),
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:    "app",
				Image:   image,
				ImageID: imageID,
				State: corev1.ContainerState{
					Waiting: &corev1.ContainerStateWaiting{Reason: reason, Message: msg},
				},
			}},
		},
	}
}

func TestCtrImageHealerRemovesCorruptedImage(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	p := waitingPod("stuck-pull", "default", wdepstest.UIDA, "registry.local/app:v1",
		"registry.local/app@sha256:f00dcafe",
		"ImagePullBackOff",
		`rpc error: code = Unknown desc = failed to pull and unpack image: `+
			`content digest sha256:abc123def456: not found`)
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	// One corrupted container → two store records (tag + repoDigest).
	want := []string{"registry.local/app:v1", "registry.local/app@sha256:f00dcafe"}
	if !slices.Equal(removed, want) {
		t.Fatalf("removed=%v want %v", removed, want)
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "last-ctr-image-rm")); err != nil {
		t.Fatal("last-ctr-image-rm budget not spent")
	}
	if !strings.Contains(e.LogLines(t),
		"ACTION: removed corrupted image registry.local/app:v1") {
		t.Fatalf("missing NPD ACTION contract line:\n%s", e.LogLines(t))
	}
}

func TestCtrImageHealerReasonAndMessageFilter(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	mk := func(name, uid, image, imageID, reason, msg string) {
		p := waitingPod(name, "default", uid, image, imageID, reason, msg)
		if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	// Wrong reason — a plain CrashLoopBackOff with the corrupt text is
	// a runtime crash, not a store-corruption signal.
	mk("crashloop", wdepstest.UIDA, "registry.local/app:v1", "registry.local/app@sha256:f00d",
		"CrashLoopBackOff", "content digest sha256:abc123: not found")
	// Right reason, unrelated message — a quota deny is not a
	// corrupted layer.
	mk("quota-deny", wdepstest.UIDB, "registry.local/app:v1", "registry.local/app@sha256:f00d",
		"ErrImagePull", "pull rate limit exceeded")
	// Right reason + matching message but no image recorded — nothing
	// to remove.
	mk("no-image", wdepstest.UIDC, "", "",
		"ImagePullBackOff", "content digest sha256:abc123: not found")
	// A pod on another node must be ignored entirely.
	other := waitingPod("other-node", "default", wdepstest.UIDD, "registry.local/app:v1",
		"registry.local/app@sha256:f00d",
		"CreateContainerError", "failed to extract layer")
	other.Spec.NodeName = "node-b"
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), other, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(removed) != 0 {
		t.Fatalf("removed=%v want none (reason/message/node filters)", removed)
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "last-ctr-image-rm")); !os.IsNotExist(err) {
		t.Fatal("budget spent with nothing to remove")
	}
}

func TestCtrImageHealerAllSignatures(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	mk := func(name, uid, image, imageID, reason, msg string) {
		p := waitingPod(name, "default", uid, image, imageID, reason, msg)
		if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	mk("extract", wdepstest.UIDA, "img/extract:1", "docker.io/img/extract@sha256:e1e1",
		"CreateContainerError", "failed to extract layer sha256:abc: unexpected EOF")
	mk("snapshot", wdepstest.UIDB, "img/snapshot:2", "docker.io/img/snapshot@sha256:52",
		"ErrImagePull", "parent snapshot sha256:def456 does not exist")
	mk("digest", wdepstest.UIDC, "img/digest:3", "docker.io/img/digest@sha256:d363",
		"CreateContainerError", "content digest sha256:789abc: not found")
	e.H.Cycle(context.Background())
	// Each corrupted container removes its tag record AND its
	// repoDigest record → 2 refs per pod.
	want := []string{
		"docker.io/img/digest:3", "docker.io/img/digest@sha256:d363",
		"docker.io/img/extract:1", "docker.io/img/extract@sha256:e1e1",
		"docker.io/img/snapshot:2", "docker.io/img/snapshot@sha256:52",
	}
	if !slices.Equal(removed, want) {
		t.Fatalf("removed=%v want %v (tag+digest per corrupted image)", removed, want)
	}
}

func TestCtrImageHealerDedupesAndRateLimits(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	msg := "content digest sha256:aaa111: not found"
	for i, uid := range []string{wdepstest.UIDA, wdepstest.UIDB} {
		p := waitingPod(fmt.Sprintf("dup-%d", i), "default", uid,
			"registry.local/app:v1", "registry.local/app@sha256:aaa111",
			"ImagePullBackOff", msg)
		if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	e.H.Cycle(context.Background())
	if len(removed) != 2 {
		t.Fatalf("removed=%v want 2 (tag+digest deduped across pods)", removed)
	}
	// Second cycle: evidence unchanged but the 15m budget is spent.
	e.H.Cycle(context.Background())
	if len(removed) != 2 {
		t.Fatalf("removed=%v want 2 (15m cooldown blocks the repeat)", removed)
	}
	if !strings.Contains(e.LogLines(t), "in rm cooldown (<15m)") {
		t.Fatalf("missing cooldown suspect line:\n%s", e.LogLines(t))
	}
	// Budget aged out → the next cycle may rm again.
	e.Now = e.Now.Add(16 * time.Minute)
	e.H.Cycle(context.Background())
	if len(removed) != 4 {
		t.Fatalf("removed=%v want 4 after cooldown expired", removed)
	}
}

func TestCtrImageHealerRmErrorKeepsGoing(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Seams.Ctr.Exec = func(_ context.Context, argv ...string) error {
		if slices.Contains(argv, "--sync") &&
			argv[len(argv)-1] == "docker.io/library/bad:1" {
			return errors.New("ctr exploded")
		}
		return nil
	}
	mk := func(name, uid, image, imageID string) {
		p := waitingPod(name, "default", uid, image, imageID, "CreateContainerError",
			"failed to extract layer sha256:x")
		if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	mk("a", wdepstest.UIDA, "bad:1", "docker.io/library/bad@sha256:b1")
	mk("b", wdepstest.UIDB, "good:2", "docker.io/library/good@sha256:62")
	e.H.Cycle(context.Background())
	if !strings.Contains(e.LogLines(t),
		"ctr image rm docker.io/library/bad:1 failed: ctr exploded") {
		t.Fatalf("missing rm-failure log:\n%s", e.LogLines(t))
	}
	if !strings.Contains(e.LogLines(t),
		"ACTION: removed corrupted image docker.io/library/good:2") {
		t.Fatalf("one rm failure must not block the next image:\n%s", e.LogLines(t))
	}
}

func TestCtrImageHealerDefaultSeamUsesSystemdExec(t *testing.T) {
	e := fixture(t)
	// Bind stubs Seams.Ctr.Exec — restore the production default's
	// shape (a full-argv passthrough onto Systemd.Exec) so the rm
	// argv lands on the systemd fake, which answers any `ctr
	// images rm` with success.
	e.H.Cfg.Seams.Ctr.Exec = func(ctx context.Context, argv ...string) error {
		_, err := e.H.Cfg.Systemd.Exec(ctx, argv[0], argv[1:]...)
		return err
	}
	e.SDReply["images rm"] = ""
	p := waitingPod("stuck", "default", wdepstest.UIDA, "registry.local/app:v1",
		"registry.local/app@sha256:feed",
		"ImagePullBackOff", "content digest sha256:abc123: not found")
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if !e.SDRan("k0s ctr --namespace k8s.io images rm --sync registry.local/app:v1") {
		t.Fatalf("RmImage did not exec ctr images rm, cmds=%v", e.SDCmds)
	}
	if !e.SDRan("k0s ctr --namespace k8s.io images rm --sync registry.local/app@sha256:feed") {
		t.Fatalf("RmImage did not exec ctr images rm on the repoDigest, cmds=%v", e.SDCmds)
	}
}

func TestCtrImageHealerAPIFailNoAction(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	e.CS.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver flake")
	})
	e.H.Cycle(context.Background())
	if len(removed) != 0 {
		t.Fatal("image rm fired on an inconclusive (API-failed) cycle")
	}
	if got := e.H.Cycles.WithLabelValues(wdeps.CheckCtrImages, "abort"); testutil.ToFloat64(got) != 1 {
		t.Fatalf("abort=%v want 1", testutil.ToFloat64(got))
	}
}

// TestNormalizeCRIImageName pins the docker reference convention the
// CRI plugin applies at pull time — `ctr images rm` matches store
// names verbatim, so every spec must be canonicalized first.
func TestNormalizeCRIImageName(t *testing.T) {
	cases := []struct{ in, want string }{
		// Short dockerhub names → docker.io/library/.
		{"nginx:1.25", "docker.io/library/nginx:1.25"},
		{"nginx", "docker.io/library/nginx"},
		{"docker.io/nginx:1.25", "docker.io/library/nginx:1.25"},
		// Org path → docker.io/org/, no library insertion.
		{"org/app:1.0", "docker.io/org/app:1.0"},
		{"docker.io/org/app:1.0", "docker.io/org/app:1.0"},
		// Private registries pass through untouched — '.'/':'/
		// "localhost" mark the first segment as a domain, and
		// library/ is a docker.io-only convention.
		{"registry.local/app:v1", "registry.local/app:v1"},
		{"registry.local:5000/team/app:v2", "registry.local:5000/team/app:v2"},
		{"localhost/app:1", "localhost/app:1"},
		{"localhost:5000/app:1", "localhost:5000/app:1"},
		// Digest refs canonicalize to name@sha256:… — the tag is
		// dropped, a registry port is not.
		{"nginx:1.25@sha256:abc", "docker.io/library/nginx@sha256:abc"},
		{"nginx@sha256:abc", "docker.io/library/nginx@sha256:abc"},
		{"registry.local/app:v1@sha256:abc", "registry.local/app@sha256:abc"},
		{"localhost:5000/app@sha256:abc", "localhost:5000/app@sha256:abc"},
		// Already-canonical refs are idempotent.
		{"docker.io/library/nginx:1.25", "docker.io/library/nginx:1.25"},
		{"docker.io/library/nginx@sha256:abc", "docker.io/library/nginx@sha256:abc"},
	}
	for _, c := range cases {
		if got := ctr.NormalizeCRIImageName(c.in); got != c.want {
			t.Errorf("ctr.NormalizeCRIImageName(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

// The whole point of the fix: a short dockerhub spec must reach
// Ctr.RmImage as the canonical docker.io/library/… ref, and the
// repoDigest record goes with it.
func TestCtrImageHealerNormalizesDockerHubShortName(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	p := waitingPod("stuck-pull", "default", wdepstest.UIDA, "nginx:1.25",
		"docker.io/library/nginx@sha256:beef",
		"ImagePullBackOff", "content digest sha256:abc123: not found")
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	want := []string{"docker.io/library/nginx:1.25", "docker.io/library/nginx@sha256:beef"}
	if !slices.Equal(removed, want) {
		t.Fatalf("removed=%v want %v", removed, want)
	}
}

// Spec and ImageID naming the same canonical digest ref must produce
// ONE rm — the image store holds a single record for it.
func TestCtrImageHealerDigestRefDedupes(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	p := waitingPod("stuck-pull", "default", wdepstest.UIDA, "nginx@sha256:beef",
		"docker.io/library/nginx@sha256:beef",
		"CreateContainerError", "failed to extract layer sha256:abc")
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	want := []string{"docker.io/library/nginx@sha256:beef"}
	if !slices.Equal(removed, want) {
		t.Fatalf("removed=%v want %v (spec+ImageID same ref → single rm)", removed, want)
	}
}

// name:tag@digest spec → the tag is stripped, digest wins.
func TestCtrImageHealerTagPlusDigestStripsTag(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	p := waitingPod("stuck-pull", "default", wdepstest.UIDA, "nginx:1.25@sha256:beef",
		"docker.io/library/nginx@sha256:beef",
		"ImagePullBackOff", "content digest sha256:abc123: not found")
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	want := []string{"docker.io/library/nginx@sha256:beef"}
	if !slices.Equal(removed, want) {
		t.Fatalf("removed=%v want %v (tag+digest → digest only)", removed, want)
	}
}

// Private-registry refs (with port, multi-segment path) must reach
// Ctr.RmImage byte-for-byte unchanged — no docker.io/library rewrite.
func TestCtrImageHealerPrivateRegistryUntouched(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	p := waitingPod("stuck-pull", "default", wdepstest.UIDA,
		"registry.local:5000/team/app:v2", "registry.local:5000/team/app@sha256:cafe",
		"ErrImagePull", "parent snapshot sha256:def456 does not exist")
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	want := []string{
		"registry.local:5000/team/app:v2",
		"registry.local:5000/team/app@sha256:cafe",
	}
	if !slices.Equal(removed, want) {
		t.Fatalf("removed=%v want %v", removed, want)
	}
}

// Corrupted-on-disk-layer signatures at run/start time — the
// waiting reasons kubelet reports for a container that started and
// then died on the corrupt layer (RunContainerError/StartError).
func TestCtrImageHealerCorruptLayerSignatures(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	for i, tc := range []struct {
		reason, msg string
	}{
		{"RunContainerError", "failed to mount /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/9/fs: structure needs cleaning"},
		{"StartError", "failed to create shim task: OCI runtime create failed: input/output error"},
		{"RunContainerError", "error while loading shared libraries: libc.so.6: file too short"},
	} {
		p := waitingPod("stuck-"+strconv.Itoa(i), "default", wdepstest.UIDA[:8]+strconv.Itoa(i),
			"registry.local/app:v"+strconv.Itoa(i), "",
			tc.reason, tc.msg)
		if _, err := e.CS.CoreV1().Pods("default").Create(
			context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	e.H.Cycle(context.Background())
	if len(removed) != 3 {
		t.Fatalf("removed=%v want 3 (all on-disk-corrupt signatures)", removed)
	}
}

// The exec-format class is once-per-image: a 0-byte truncated
// binary heals on repull, but a wrong-arch image repulls the same
// un-runnable ref — the ref may be deleted at most ONCE, even after
// the 15m rm budget ages out. Other signatures stay unlimited.
func TestCtrImageHealerExecFormatOncePerImage(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	p := waitingPod("wrongarch", "default", wdepstest.UIDA, "app:v1",
		"registry.local/app@sha256:beef",
		"StartError", "exec /bin/app: exec format error")
	if _, err := e.CS.CoreV1().Pods("default").Create(
		context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(removed) != 2 {
		t.Fatalf("removed=%v want 2 (tag + digest refs once)", removed)
	}
	// Budget ages out but the refs are healed — a persistent
	// wrong-arch image must never loop-delete.
	e.Now = e.Now.Add(16 * time.Minute)
	e.H.Cycle(context.Background())
	if len(removed) != 2 {
		t.Fatalf("removed=%v want 2 (exec-format refs deleted at most once)", removed)
	}
	e.Now = e.Now.Add(16 * time.Minute)
	e.H.Cycle(context.Background())
	if len(removed) != 2 {
		t.Fatalf("removed=%v want 2 (still healed)", removed)
	}
}

// A DIFFERENT image with an exec-format failure still gets its own
// single heal — the ledger is per-ref.
func TestCtrImageHealerExecFormatPerRef(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	for i, img := range []string{"bad-a:1", "bad-b:2"} {
		p := waitingPod("w"+strconv.Itoa(i), "default",
			wdepstest.UIDA[:8]+strconv.Itoa(i), img, "",
			"StartError", "exec format error")
		if _, err := e.CS.CoreV1().Pods("default").Create(
			context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	e.H.Cycle(context.Background())
	if len(removed) != 2 {
		t.Fatalf("removed=%v want 2 (each ref healed once)", removed)
	}
	// A pod reporting exec-format AND a different corrupt signature
	// on the same cycle keeps the once-guard on the exec refs while
	// the other signature still re-deletes after cooldown.
	e.Now = e.Now.Add(16 * time.Minute)
	p := waitingPod("mixed", "default", wdepstest.UIDC, "dirty:3", "",
		"CreateContainerError", "failed to extract layer sha256:zz")
	if _, err := e.CS.CoreV1().Pods("default").Create(
		context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	want := []string{"bad-a:1", "bad-b:2", "docker.io/library/dirty:3"}
	if len(removed) != 3 {
		t.Fatalf("removed=%v want %v (only the new non-exec ref re-deleted)", removed, want)
	}
}

// --- A3: ingest GC ---

func TestCtrIngestGCCleansStaleDirs(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.DiskUsed = 0.90 // above the 75% watermark
	stale := filepath.Join(e.IngestDir, "deadbeefref")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-4 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale ingest dir should be removed, stat err=%v", err)
	}
	if !e.SDRan("content ingest rm deadbeefref") {
		t.Fatal("ctr ingest rm should run for the stale ref")
	}
	got, err := counterValue(e.H.CtrIngestsCleaned)
	if err != nil || got != 1 {
		t.Fatalf("ctr_ingests_cleaned_total=%v err=%v want 1", got, err)
	}
}

func TestCtrIngestGCSkipsFreshDirsWhenDiskLow(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.DiskUsed = 0.10
	// first cycle marks lastIngestScan (due on start); make a fresh
	// dir and verify a second cycle under low disk skips it.
	e.H.Cycle(context.Background())
	fresh := filepath.Join(e.IngestDir, "stillpulling")
	if err := os.MkdirAll(fresh, 0o755); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("fresh ingest dir must not be removed")
	}
}

// TestCtrIngestGCFailedScanRetriesNextCycle: a transient ReadDir
// failure must NOT stamp lastIngestScan — stamping would defer the
// retry by a full 6h CtrIngestScanInterval. The next cycle after
// the dir recovers must still scan (disk below the watermark, so
// only the unstamped due-check lets it in).
func TestCtrIngestGCFailedScanRetriesNextCycle(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.DiskUsed = 0.10 // below watermark — only `due` triggers a scan
	// Break the ingest dir: a plain FILE where a dir is expected →
	// ReadDir errors (ENOTDIR, not IsNotExist) → abort, no stamp.
	if err := os.RemoveAll(e.IngestDir); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, e.IngestDir, "not a dir")
	e.H.Cycle(context.Background())
	// Repair the dir with one stale ingest — if the failed scan
	// had stamped lastIngestScan this cycle would be not-due and
	// skip the cleanup.
	if err := os.Remove(e.IngestDir); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(e.IngestDir, "deadbeefref")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-4 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("failed scan must not defer retry — stale dir should be removed, stat err=%v", err)
	}
}

// TestCtrIngestGCBavailOverBlocksSaturates: btrfs/XFS can report
// Bavail > Blocks — the uint64 subtraction wraps to ~2^64 and
// diskHigh sticks true, sweeping the GC every cycle. The saturation
// guard must keep it low (concourse fsPressure parity).
func TestCtrIngestGCBavailOverBlocksSaturates(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.H.Cfg.Seams.Host.StatfsFn = func(_ string, st *unix.Statfs_t) error {
		st.Blocks, st.Bavail = 100, 120 // free > total
		return nil
	}
	// First cycle stamps lastIngestScan so the second is not `due`.
	e.H.Cycle(context.Background())
	stale := filepath.Join(e.IngestDir, "deadbeefref")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-4 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if _, err := os.Stat(stale); err != nil {
		t.Fatal("stale ingest dir swept under wrapped-free disk pressure")
	}
}

// counterValue reads a prometheus.Counter for tests.
func counterValue(c prometheus.Counter) (float64, error) {
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		return 0, err
	}
	return m.GetCounter().GetValue(), nil
}

// --- cri-sandbox-reaper: orphan CRI sandbox reaper ---

// TestCtrTasksOrphanSandboxTwoPhase: a SandboxCtlRoot dir with no
// task dir and no shim gets the sandbox-orphan-seen marker on first
// observation and is removed only once the marker AND the dir
// ModTime are >=30m old — never on the first sighting.
func TestCtrTasksOrphanSandboxTwoPhase(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("7", 64)
	sbDir := filepath.Join(e.SbDir, sid)
	if err := os.MkdirAll(sbDir, 0o755); err != nil {
		t.Fatal(err)
	}
	old := e.Now.Add(-31 * time.Minute)
	if err := os.Chtimes(sbDir, old, old); err != nil {
		t.Fatal(err)
	}

	e.H.Cycle(context.Background())
	// First sighting: marker only — no cleanup yet.
	if _, err := os.Stat(sbDir); err != nil {
		t.Fatal("orphan sandbox removed before marker confirmation")
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "sandbox-orphan-seen-"+sid)); err != nil {
		t.Fatalf("orphan-sandbox marker not written: %v", err)
	}
	// Advance past the 30m confirm window → cleanup + metric.
	e.Now = e.Now.Add(31 * time.Minute)
	e.H.Cycle(context.Background())
	if _, err := os.Stat(sbDir); !os.IsNotExist(err) {
		t.Fatal("orphan sandbox dir not removed after 30m marker")
	}
	if _, err := os.Stat(filepath.Join(e.StateDir,
		"sandbox-orphan-seen-"+sid)); !os.IsNotExist(err) {
		t.Fatal("orphan-sandbox marker not consumed by cleanup")
	}
	if got := testutil.ToFloat64(
		e.H.Deps.Actions.WithLabelValues(wdeps.CheckCtrTasks, "rm_orphan_sandbox")); got != 1 {
		t.Fatalf("rm_orphan_sandbox=%v want 1", got)
	}
	if !strings.Contains(e.LogLines(t), "rm orphan sandbox dir") {
		t.Fatalf("missing orphan-sandbox ACTION line:\n%s", e.LogLines(t))
	}
}

// TestCtrTasksOrphanSandboxFreshDirKept: a sandbox dir whose ModTime
// is fresh (mid-creation) must stay regardless of any stale marker.
func TestCtrTasksOrphanSandboxFreshDirKept(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("8", 64)
	sbDir := filepath.Join(e.SbDir, sid)
	if err := os.MkdirAll(sbDir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	e.Now = e.Now.Add(31 * time.Minute)
	e.H.Cycle(context.Background())
	if _, err := os.Stat(sbDir); err != nil {
		t.Fatal("fresh-ModTime sandbox dir removed before its age window")
	}
}

// TestCtrTasksSandboxWithShimOrTaskKept: a sandbox dir that a live
// shim holds, or that still has a task dir under CtrTaskRoot, is
// never an orphan — even at ancient ages.
func TestCtrTasksSandboxWithShimOrTaskKept(t *testing.T) {
	e := fixture(t)
	shimSID := strings.Repeat("c", 64)
	taskSID := strings.Repeat("d", 64)
	shimDir := filepath.Join(e.SbDir, shimSID)
	taskDir := filepath.Join(e.SbDir, taskSID)
	for _, d := range []string{shimDir, taskDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		old := e.Now.Add(-2 * time.Hour)
		if err := os.Chtimes(d, old, old); err != nil {
			t.Fatal(err)
		}
	}
	// Live shim scoped to OUR containerd holding shimSID.
	e.MkProc(t, 9400, "S",
		"containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-id\x00"+shimSID+
			"\x00-address\x00/run/k0s/containerd.sock\x00", "")
	// taskSID still has a task dir under CtrTaskRoot.
	if err := os.MkdirAll(filepath.Join(e.CtrDir, taskSID), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		e.H.Cycle(context.Background())
		e.Now = e.Now.Add(31 * time.Minute)
	}
	if _, err := os.Stat(shimDir); err != nil {
		t.Fatal("sandbox dir with a live shim removed")
	}
	if _, err := os.Stat(taskDir); err != nil {
		t.Fatal("sandbox dir with a live task dir removed")
	}
}

// A non-hex64 dir name is not a CRI task id: the wedge scan must
// neither create a confirm marker for it nor pid-scan/SIGKILL on its
// name (the cleanup is pkill -f shaped — a dir named "kubelet" would
// otherwise spear the kubelet).
func TestCtrTasksNonHexIDNeverScanned(t *testing.T) {
	e := fixture(t)
	dir := filepath.Join(e.CtrDir, "kubelet")
	wdepstest.WriteFile(t, filepath.Join(dir, "garbage"), "")
	wdepstest.WriteFile(t, filepath.Join(e.StateDir, "wedged-seen-kubelet"),
		fmt.Sprintf("%d\n", e.Now.Add(-10*time.Minute).Unix()))
	e.H.Cycle(context.Background())
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("non-hex dir removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "wedged-seen-kubelet")); err != nil {
		t.Fatal("marker for non-hex id consumed")
	}
	if len(e.Kills) != 0 {
		t.Fatalf("SIGKILL fired for the non-hex id: %+v", e.Kills)
	}
}

// --- reaper failure tails and fail-closed gates ---

// wedgedTaskDir builds a hex-id task dir whose init is dead; when
// withRootfs is set the bundle rootfs subtree exists (a live mount).
func wedgedTaskDir(t *testing.T, e *env, id string, withRootfs bool) string {
	t.Helper()
	dir := filepath.Join(e.CtrDir, id)
	wdepstest.WriteFile(t, filepath.Join(dir, "init.pid"), "77888")
	wdepstest.WriteFile(t, filepath.Join(dir, "config.json"), `{"annotations":{}}`)
	if withRootfs {
		wdepstest.WriteFile(t, filepath.Join(dir, "rootfs", "bin", "sh"), "#!/bin/sh\n")
	}
	return dir
}

// TestCtrTasksUmountFailureStillRemoves: a failed lazy umount is
// logged and the removal is still attempted (best effort).
func TestCtrTasksUmountFailureStillRemoves(t *testing.T) {
	e := fixture(t)
	// No SDReply["umount"] → the exec fails.
	dir := wedgedTaskDir(t, e, strings.Repeat("4", 64), true)
	e.H.Cycle(context.Background()) // marker only
	e.Now = e.Now.Add(6 * time.Minute)
	e.H.Cycle(context.Background()) // confirm → umount fails → rm anyway
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("wedged dir kept after the failed umount — removal must still run")
	}
	if !strings.Contains(e.LogLines(t), "umount -l "+filepath.Join(dir, "rootfs")+" failed") {
		t.Fatalf("missing umount-failure line:\n%s", e.LogLines(t))
	}
}

// TestCtrTasksRmFailureLogged: an undeletable dir logs the suspect
// instead of silently losing the task.
func TestCtrTasksRmFailureLogged(t *testing.T) {
	e := fixture(t)
	dir := wedgedTaskDir(t, e, strings.Repeat("5", 64), false)
	e.H.Cycle(context.Background())
	e.Now = e.Now.Add(6 * time.Minute)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	e.H.Cycle(context.Background())
	if !strings.Contains(e.LogLines(t), "rm task dir ") {
		t.Fatalf("missing rm-failure suspect line:\n%s", e.LogLines(t))
	}
}

// TestCtrTasksOrphanShimKillFailureLogged: a failing signal delivery
// must not read as a successful reap.
func TestCtrTasksOrphanShimKillFailureLogged(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("8", 64)
	e.MkProc(t, 9350, "S",
		"containerd-shim-runc-v2\x00-id\x00"+sid+
			"\x00-namespace\x00k8s.io\x00-address\x00/run/k0s/containerd.sock\x00", "")
	old := e.Now.Add(-10 * time.Minute)
	if err := os.Chtimes(filepath.Join(e.ProcDir, "9350"), old, old); err != nil {
		t.Fatal(err)
	}
	orig := e.H.Cfg.Seams.Host.KillFn
	e.H.Cfg.Seams.Host.KillFn = func(pid int, sig syscall.Signal) error {
		if sig == syscall.SIGKILL {
			return errors.New("permission denied")
		}
		return orig(pid, sig)
	}
	e.H.Cycle(context.Background())
	if !strings.Contains(e.LogLines(t), "kill orphan shim pid=9350 failed") {
		t.Fatalf("missing shim-kill failure line:\n%s", e.LogLines(t))
	}
	if !e.H.State.Exists(latchdefs.LatchPodTeardownWedged) &&
		strings.Contains(e.LogLines(t), "escalated") {
		t.Fatal("unexpected escalation on a kill-shaped failure")
	}
}

// TestCtrTasksOrphanShimDStateEscalates: an orphan shim wedged in D
// cannot be SIGKILLed away — the wedge escalates into the shared
// pod-teardown latch instead of a doomed kill.
func TestCtrTasksOrphanShimDStateEscalates(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("6", 64)
	e.MkProc(t, 9360, "D",
		"containerd-shim-runc-v2\x00-id\x00"+sid+
			"\x00-namespace\x00k8s.io\x00-address\x00/run/k0s/containerd.sock\x00", "")
	old := e.Now.Add(-10 * time.Minute)
	if err := os.Chtimes(filepath.Join(e.ProcDir, "9360"), old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if !e.H.State.Exists(latchdefs.LatchPodTeardownWedged) {
		t.Fatal("D-state orphan shim not escalated to pod-teardown-wedged")
	}
	if !strings.Contains(e.LogLines(t), "escalated to pod-teardown-wedged") {
		t.Fatalf("missing escalation line:\n%s", e.LogLines(t))
	}
	for _, k := range e.Kills {
		if k.PID == 9360 {
			t.Fatal("D-state shim SIGKILLed anyway — the signal pends forever")
		}
	}
}

// TestCtrTasksInitKillFailureLogged: the live-init kill failing is
// evidence, not silence.
func TestCtrTasksInitKillFailureLogged(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 77777, "S", "", "")
	dir := filepath.Join(e.CtrDir, strings.Repeat("7", 64))
	wdepstest.WriteFile(t, filepath.Join(dir, "init.pid"), "77777")
	wdepstest.WriteFile(t, filepath.Join(dir, "config.json"), `{"annotations":{}}`)
	e.H.Cycle(context.Background()) // marker
	e.Now = e.Now.Add(6 * time.Minute)
	orig := e.H.Cfg.Seams.Host.KillFn
	e.H.Cfg.Seams.Host.KillFn = func(pid int, sig syscall.Signal) error {
		if sig == syscall.SIGKILL {
			return errors.New("permission denied")
		}
		return orig(pid, sig)
	}
	e.H.Cycle(context.Background())
	if !strings.Contains(e.LogLines(t), "kill init 77777 of ") {
		t.Fatalf("missing init-kill failure line:\n%s", e.LogLines(t))
	}
}

// TestCtrTasksOrphanSandboxCapLine: a zero clean budget logs the
// pending-cap suspect instead of touching sandbox dirs.
func TestCtrTasksOrphanSandboxCapLine(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Ctr.MaxTaskClean = 0
	sid := strings.Repeat("2", 64)
	sbDir := filepath.Join(e.SbDir, sid)
	wdepstest.WriteFile(t, filepath.Join(sbDir, "junk"), "x")
	old := e.Now.Add(-45 * time.Minute)
	if err := os.Chtimes(sbDir, old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background()) // marker
	e.Now = e.Now.Add(31 * time.Minute)
	e.H.Cycle(context.Background()) // confirmed → cap 0
	if !strings.Contains(e.LogLines(t), "orphan sandbox dir still pending cap=0") {
		t.Fatalf("missing sandbox cap line:\n%s", e.LogLines(t))
	}
	if _, err := os.Stat(sbDir); err != nil {
		t.Fatal("sandbox dir removed despite the zero budget")
	}
}

// TestCtrTasksSandboxMarkerPruned: sandbox markers whose dir
// disappeared are swept between runs.
func TestCtrTasksSandboxMarkerPruned(t *testing.T) {
	e := fixture(t)
	gone := "sandbox-orphan-seen-" + strings.Repeat("3", 64)
	wdepstest.WriteFile(t, filepath.Join(e.StateDir, gone), "stale")
	e.H.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.StateDir, gone)); !os.IsNotExist(err) {
		t.Fatal("stale sandbox marker survived the sweep")
	}
}

// TestCtrImagesAPIFailAborts: no apiserver verdict → the healer never
// removes an image; a clean round initializes its ledger.
func TestCtrImagesAPIFailAborts(t *testing.T) {
	e := fixture(t)
	var removed []string
	e.H.Cfg.Seams.Ctr.Exec = func(_ context.Context, argv ...string) error {
		if slices.Contains(argv, "rm") {
			removed = append(removed, strings.Join(argv, " "))
		}
		return nil
	}
	c := wdepstest.Check[*ctr.CtrImagesCheck](e.H, wdeps.CheckCtrImages)
	c.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
	if len(removed) != 0 {
		t.Fatalf("images removed with the API down: %v", removed)
	}
	c.Run(context.Background(), &wdeps.CycleEnv{APIOK: true, WorkerActive: true})
}

// TestCtrTasksGatesAndPrunes: the worker gate stands the reaper down;
// an unreadable task root aborts; markers and non-dir entries on the
// task root are handled without touching processes.
func TestCtrTasksGatesAndPrunes(t *testing.T) {
	// Worker gate down → no task-root walk at all.
	e := fixture(t)
	e.H.Cfg.Seams.Host.KillFn = func(int, syscall.Signal) error {
		t.Error("kill ran with the worker gate down")
		return nil
	}
	wdepstest.Check[*ctr.CtrTasksCheck](e.H, wdeps.CheckCtrTasks).
		Run(context.Background(), &wdeps.CycleEnv{})

	// Unreadable task root → skip, never verdict.
	e = fixture(t)
	e.H.Cfg.CtrTaskRoot = filepath.Join(e.CtrDir, "gone")
	wdepstest.Check[*ctr.CtrTasksCheck](e.H, wdeps.CheckCtrTasks).
		Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
	if !strings.Contains(e.LogLines(t), "ctr-tasks check skipped") {
		t.Fatalf("missing unreadable-root line:\n%s", e.LogLines(t))
	}

	// A non-dir entry on the task root is not a task.
	e = fixture(t)
	wdepstest.WriteFile(t, filepath.Join(e.CtrDir, "not-a-task"), "x")
	// A wedged-seen marker whose dir disappeared is swept.
	wdepstest.WriteFile(t, filepath.Join(e.StateDir,
		"wedged-seen-"+strings.Repeat("0", 64)), "gone")
	// A fresh (<5m) wedge marker defers the confirmation: the first
	// Cycle arms it, the immediate second Cycle must not confirm.
	freshID := strings.Repeat("f", 64)
	wedgedTaskDir(t, e, freshID, false)
	e.H.Cycle(context.Background()) // arm
	e.H.Cycle(context.Background()) // sub-5m → deferred
	if strings.Contains(e.LogLines(t), "ACTION: rm wedged task dir") {
		t.Fatal("confirmed on a sub-5m marker")
	}
}

// TestCtrTasksShimKillCap: MaxShimKill bounds the orphan sweep — the
// unexamined tail keeps the incomplete-scan flag instead of a verdict.
func TestCtrTasksShimKillCap(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Ctr.MaxShimKill = 2
	old := e.Now.Add(-10 * time.Minute)
	for i := range 4 {
		pid := 9370 + i
		sid := fmt.Sprintf("%064x", i+10)
		e.MkProc(t, pid, "S",
			"containerd-shim-runc-v2\x00-id\x00"+sid+
				"\x00-namespace\x00k8s.io\x00-address\x00/run/k0s/containerd.sock\x00", "")
		if err := os.Chtimes(filepath.Join(e.ProcDir, strconv.Itoa(pid)), old, old); err != nil {
			t.Fatal(err)
		}
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 2 {
		t.Fatalf("kills=%d want exactly MaxShimKill=2", len(e.Kills))
	}
}

// TestCtrTasksLeftoverHolderKilled: a live process holding the wedged
// task id on its cmdline is SIGKILLed before the dir removal — the
// pkill -9 -f parity.
func TestCtrTasksLeftoverHolderKilled(t *testing.T) {
	e := fixture(t)
	id := strings.Repeat("d", 64)
	dir := wedgedTaskDir(t, e, id, false)
	// A shim leftover still holding the task id.
	e.MkProc(t, 9399, "S",
		"containerd-shim-runc-v2\x00-id\x00"+id+
			"\x00-namespace\x00k8s.io\x00-address\x00/run/k0s/containerd.sock\x00", "")
	e.H.Cycle(context.Background()) // marker
	e.Now = e.Now.Add(6 * time.Minute)
	e.H.Cycle(context.Background()) // confirm → kill holder + rm
	killed := false
	for _, k := range e.Kills {
		if k.PID == 9399 && k.Sig == syscall.SIGKILL {
			killed = true
		}
	}
	if !killed {
		t.Fatalf("leftover holder not killed: kills=%v", e.Kills)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("wedged dir kept after the holder kill")
	}
}

// TestCtrTasksSandboxGatesAndFailures: a young confirmation marker
// defers the removal; an undeletable sandbox dir logs the failure.
func TestCtrTasksSandboxGatesAndFailures(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("1", 64)
	sbDir := filepath.Join(e.SbDir, sid)
	wdepstest.WriteFile(t, filepath.Join(sbDir, "junk"), "x")
	old := e.Now.Add(-45 * time.Minute)
	if err := os.Chtimes(sbDir, old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background()) // marker
	e.Now = e.Now.Add(10 * time.Minute)
	e.H.Cycle(context.Background()) // marker only 10m old → defer
	if strings.Contains(e.LogLines(t), "rm orphan sandbox dir") {
		t.Fatal("sandbox dir removed on a sub-30m marker")
	}
	e.Now = e.Now.Add(25 * time.Minute) // marker 35m → confirm
	if err := os.Chmod(sbDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sbDir, 0o755) })
	e.H.Cycle(context.Background())
	if !strings.Contains(e.LogLines(t), "rm orphan sandbox dir ") {
		t.Fatalf("missing sandbox rm-failure line:\n%s", e.LogLines(t))
	}
	if _, err := os.Stat(sbDir); err != nil {
		t.Fatal("sandbox dir vanished despite the failing removal")
	}
}

// TestCtrImagesGatedAndLedgerInit: the worker gate stands the healer
// down; a bare check round initializes the exec-format ledger.
func TestCtrImagesGatedAndLedgerInit(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Seams.Ctr.Exec = func(context.Context, ...string) error {
		t.Error("image rm ran with the worker gate down")
		return nil
	}
	wdepstest.Check[*ctr.CtrImagesCheck](e.H, wdeps.CheckCtrImages).
		Run(context.Background(), &wdeps.CycleEnv{})
}
