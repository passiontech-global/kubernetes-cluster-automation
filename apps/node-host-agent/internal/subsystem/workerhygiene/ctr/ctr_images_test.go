// ctr_images_test.go — unit tests for CtrImagesCheck.execFormatHealed pruning.
package ctr_test

import (
	"context"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestCtrImagesExecFormatHealedPrunedWhenPodGone(t *testing.T) {
	e := fixture(t)
	var removed []string
	e.H.Cfg.Seams.Ctr.Exec = func(_ context.Context, argv ...string) error {
		if slices.Contains(argv, "--sync") {
			removed = append(removed, argv[len(argv)-1])
		}
		return nil
	}
	chk := wdepstest.Check[*ctr.CtrImagesCheck](e.H, wdeps.CheckCtrImages)
	ctx := context.Background()

	mkExecFmtPod := func(name, uid string) corev1.Pod {
		return corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", UID: types.UID(uid)},
			Spec: corev1.PodSpec{
				NodeName:   "node-a",
				Containers: []corev1.Container{{Name: "app", Image: "registry.local/wrong-arch:v1"}},
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodPending,
				ContainerStatuses: []corev1.ContainerStatus{{
					Name:  "app",
					Image: "registry.local/wrong-arch:v1",
					State: corev1.ContainerState{
						Waiting: &corev1.ContainerStateWaiting{
							Reason:  "StartError",
							Message: "exec /app: exec format error",
						},
					},
				}},
			},
		}
	}

	pod1 := mkExecFmtPod("bad-arch-1", wdepstest.UIDA)
	// Cycle 1: removes once and records execFormatHealed["registry.local/wrong-arch:v1"].
	chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{pod1}})
	if len(removed) != 1 || removed[0] != "registry.local/wrong-arch:v1" {
		t.Fatalf("cycle 1 removed=%v want [registry.local/wrong-arch:v1]", removed)
	}

	// Cycle 2 (past cooldown): APIOK=false must NOT prune or remove.
	e.Now = e.Now.Add(wdeps.CtrImageRmInterval + time.Minute)
	chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true, APIOK: false, Pods: nil})
	if len(removed) != 1 {
		t.Fatalf("APIOK=false triggered unexpected rm: %v", removed)
	}

	// Cycle 3: same pod still present -> execFormatHealed suppresses repeat removal.
	chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{pod1}})
	if len(removed) != 1 {
		t.Fatalf("execFormatHealed did not suppress repeat rm while pod present: %v", removed)
	}

	// Cycle 4: pod disappeared (len(seen)==0) with APIOK=true -> prunes execFormatHealed.
	chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: nil})

	// Cycle 5: a brand-new pod references the same image with exec format error -> allowed once again.
	pod2 := mkExecFmtPod("bad-arch-2", wdepstest.UIDB)
	chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{pod2}})
	if len(removed) != 2 {
		t.Fatalf("expected re-heal after pod exit pruned execFormatHealed, removed=%v", removed)
	}
}
