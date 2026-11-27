// calico_ip_drift_test.go — coverage for calico-hygiene IPv4Address vs
// Node InternalIP drift detection and calico-node pod bounce.
package guards_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/guards"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestCalicoNodeIPDriftDeletesPodAfterStreak(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "w1",
			Annotations: map[string]string{
				"projectcalico.org/IPv4Address": "172.29.0.11/24",
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "169.58.175.45"},
			},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system",
			Name:      "calico-node-abc12",
			UID:       types.UID("calico-uid-1"),
		},
		Spec:   corev1.PodSpec{NodeName: "w1"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	e := fixture(t, node, pod)
	e.H.Deps.Cfg.NodeName = "w1"
	e.H.Deps.Cfg.ConsecNeeded = 2
	e.H.Deps.Cfg.Calico.FelixReadyURL = "http://127.0.0.1:9099/readiness"
	e.Status["http://127.0.0.1:9099/readiness"] = http.StatusOK
	if err := os.MkdirAll(filepath.Join(e.SysNet, "cali1234"), 0o755); err != nil {
		t.Fatal(err)
	}

	chk := wdepstest.Check[*guards.CalicoCheck](e.H, wdeps.CheckCalico)
	cycleEnv := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}

	// Cycle 1: pending streak — pod still present.
	chk.Run(context.Background(), cycleEnv)
	if _, err := e.CS.CoreV1().Pods("kube-system").Get(context.Background(), pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("pod deleted on first cycle (before streak): %v", err)
	}

	// Cycle 2: streak reached — pod deleted.
	chk.Run(context.Background(), cycleEnv)
	if _, err := e.CS.CoreV1().Pods("kube-system").Get(context.Background(), pod.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("calico-node pod was not deleted after consecutive IP drift cycles")
	}
}

func TestCalicoNodeIPMatchedNoAction(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "w1",
			Annotations: map[string]string{
				"projectcalico.org/IPv4Address": "169.58.175.45/17",
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "169.58.175.45"},
			},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system",
			Name:      "calico-node-abc12",
			UID:       types.UID("calico-uid-2"),
		},
		Spec:   corev1.PodSpec{NodeName: "w1"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	e := fixture(t, node, pod)
	e.H.Deps.Cfg.NodeName = "w1"
	e.H.Deps.Cfg.ConsecNeeded = 1
	e.H.Deps.Cfg.Calico.FelixReadyURL = "http://127.0.0.1:9099/readiness"
	e.Status["http://127.0.0.1:9099/readiness"] = http.StatusOK
	if err := os.MkdirAll(filepath.Join(e.SysNet, "cali1234"), 0o755); err != nil {
		t.Fatal(err)
	}

	chk := wdepstest.Check[*guards.CalicoCheck](e.H, wdeps.CheckCalico)
	cycleEnv := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
	chk.Run(context.Background(), cycleEnv)
	if _, err := e.CS.CoreV1().Pods("kube-system").Get(context.Background(), pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("matching IP calico-node pod should not be deleted: %v", err)
	}
}
