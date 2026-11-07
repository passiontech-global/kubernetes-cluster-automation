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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// --- check 6: ctr-tasks (31) ---

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
	dir := filepath.Join(e.CtrDir, "nologger"+strings.Repeat("d", 57))
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
	// with a marker already past the 5m confirm window.
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("wedged%02d%s", i, strings.Repeat("d", 55))
		if err := os.MkdirAll(filepath.Join(e.CtrDir, id), 0o755); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, filepath.Join(e.StateDir, "wedged-seen-"+id),
			fmt.Sprintf("%d\n", e.Now.Add(-10*time.Minute).Unix()))
	}
	e.H.Cycle(context.Background())
	// First two (ReadDir order) cleaned, markers consumed.
	for i := 0; i < 2; i++ {
		id := fmt.Sprintf("wedged%02d%s", i, strings.Repeat("d", 55))
		if _, err := os.Stat(filepath.Join(e.CtrDir, id)); !os.IsNotExist(err) {
			t.Fatalf("in-cap wedged dir %s not removed", id)
		}
	}
	// The capped two keep BOTH dir and marker — confirmed state
	// survives so next cycle cleans them without a new 5m wait.
	for i := 2; i < 4; i++ {
		id := fmt.Sprintf("wedged%02d%s", i, strings.Repeat("d", 55))
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
