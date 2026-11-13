// builders.go — the Fixture's file/pod builders: fake /proc entries
// (MkProc/MkStatProc/MkCiliumTask/MkTask), the canned pod shapes
// (TerminatingPod/DNSPod/AssignedPod) and the comm-mirroring rules
// that keep proc fixtures faithful to the kernel contract. Split out
// of fixture.go so the fixture core stays under the ~500-LOC bar.
package wdepstest

import (
	"fmt"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// MkTask creates a containerd task dir for pod uid; pid goes into
// init.pid — register it in Live first for a "live" task.
func (f *Fixture) MkTask(t *testing.T, uid, containerName string, pid int) {
	t.Helper()
	dir := filepath.Join(f.CtrDir, "task-"+containerName+"-"+uid[:8])
	cfg := fmt.Sprintf(`{"annotations":{"io.kubernetes.pod.uid":"%s",`+
		`"io.kubernetes.container.name":"%s"}}`, uid, containerName)
	WriteFile(t, filepath.Join(dir, "config.json"), cfg)
	WriteFile(t, filepath.Join(dir, "init.pid"), strconv.Itoa(pid))
}

// MkProc puts a fake process under ProcDir: stat with the given
// state char + optional cmdline/environ content. When a cmdline is
// given the comm field mirrors the kernel contract — argv[0]'s
// basename truncated to TASK_COMM_LEN-1 (15 chars) — so comm-gated
// checks (ctr_tasks' runtime-kill allowlist) see the same comm a
// real process would expose; procs without a cmdline keep the
// "fakeproc" placeholder.
func (f *Fixture) MkProc(t *testing.T, pid int, state, cmdline, environ string) {
	t.Helper()
	comm := "fakeproc"
	if cmdline != "" {
		if argv0 := strings.SplitN(cmdline, "\x00", 2)[0]; argv0 != "" {
			comm = path.Base(argv0)
			if len(comm) > 15 {
				comm = comm[:15]
			}
		}
	}
	WriteFile(t, filepath.Join(f.ProcDir, strconv.Itoa(pid), "stat"),
		fmt.Sprintf("%d (%s) %s 0 0 0", pid, comm, state))
	f.Live[pid] = state != "Z"
	if cmdline != "" {
		WriteFile(t, filepath.Join(f.ProcDir, strconv.Itoa(pid), "cmdline"), cmdline)
	}
	if environ != "" {
		WriteFile(t, filepath.Join(f.ProcDir, strconv.Itoa(pid), "environ"), environ)
	}
}

// MkStatProc writes a /proc entry with a custom comm + state and an
// optional wchan — MkProc only ever writes comm "fakeproc", but the
// d-state check classifies by comm (runc/jbd2/...).
func (f *Fixture) MkStatProc(t *testing.T, pid int, comm, state, wchan string) {
	t.Helper()
	WriteFile(t, filepath.Join(f.ProcDir, strconv.Itoa(pid), "stat"),
		fmt.Sprintf("%d (%s) %s 1 0 0", pid, comm, state))
	f.Live[pid] = state != "Z"
	if wchan != "" {
		WriteFile(t, filepath.Join(f.ProcDir, strconv.Itoa(pid), "wchan"), wchan+"\n")
	}
}

// MkCiliumTask creates a cilium-agent containerd task dir with a live
// init pid.
func (f *Fixture) MkCiliumTask(t *testing.T, pid int) {
	t.Helper()
	dir := filepath.Join(f.CtrDir, "ciliumagent"+strings.Repeat("0", 54))
	cfg := `{"annotations":{"io.kubernetes.pod.uid":"` + UIDE +
		`","io.kubernetes.container.name":"cilium-agent"}}`
	WriteFile(t, filepath.Join(dir, "config.json"), cfg)
	WriteFile(t, filepath.Join(dir, "init.pid"), strconv.Itoa(pid))
	WriteFile(t, filepath.Join(dir, "log.json"), "{}\n")
	f.MkProc(t, pid, "S", "", "")
}

// TerminatingPod builds a pod on node-a whose deletion started ago.
func (f *Fixture) TerminatingPod(name, ns, uid string, ago time.Duration) *corev1.Pod {
	ts := metav1.NewTime(f.Now.Add(-ago))
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns, UID: types.UID(uid),
			DeletionTimestamp: &ts,
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
	}
}

// DNSPod builds a Running kube-system dns-named pod on node-a — the
// dns-resolv check's target shape.
func (f *Fixture) DNSPod(name, uid string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "kube-system", UID: types.UID(uid),
		},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// AssignedPod is an old non-terminating pod on node-a with no kubelet
// pod dir — watch-wedge evidence.
func (f *Fixture) AssignedPod(name, uid string, age time.Duration) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "default", UID: types.UID(uid),
			CreationTimestamp: metav1.NewTime(f.Now.Add(-age)),
		},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}
