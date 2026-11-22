package failedjobsjanitor

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func stReadyNode(name string, conds ...corev1.NodeCondition) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     corev1.NodeStatus{Conditions: conds},
	}
}

func stClaimPod(ns, name, nodeName string, phase corev1.PodPhase, vols ...corev1.Volume) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
			Volumes:  vols,
		},
		Status: corev1.PodStatus{Phase: phase},
	}
}

func stPVC(ns, name, pvName string) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: pvName},
	}
}

func TestPVCMountThreatenable(t *testing.T) {
	now := metav1.Now()
	pvTarget := "pv-target"
	pvOther := "pv-other"

	tests := []struct {
		name           string
		objs           []runtime.Object
		pvcNS          string
		pvcName        string
		prep           func(cs *fake.Clientset, vaLists, nodeLists, podLists *atomic.Int32)
		want           bool
		wantErrorDelta float64
		wantVALists    int32
		wantNodeLists  int32
		wantPodLists   int32
	}{
		{
			name:    "claim already gone (NotFound) returns false with zero scans",
			pvcNS:   "apps",
			pvcName: "gone-pvc",
			want:    false,
		},
		{
			name:    "full PVC Get API error fails closed and IncErrors once",
			pvcNS:   "apps",
			pvcName: "err-pvc",
			prep: func(cs *fake.Clientset, _, _, _ *atomic.Int32) {
				cs.PrependReactor("get", "persistentvolumeclaims",
					func(ktesting.Action) (bool, runtime.Object, error) {
						return true, nil, errors.New("apiserver timeout")
					})
			},
			want:           true,
			wantErrorDelta: 1,
		},
		{
			name:    "unbound PVC (VolumeName empty) with no dead-node pods skips VA list and returns false",
			pvcNS:   "apps",
			pvcName: "unbound-clean",
			objs: []runtime.Object{
				stPVC("apps", "unbound-clean", ""),
				stReadyNode("n-ready", corev1.NodeCondition{Type: corev1.NodeReady, Status: corev1.ConditionTrue}),
			},
			want:          false,
			wantVALists:   0,
			wantNodeLists: 1,
			wantPodLists:  1,
		},
		{
			name:    "unbound PVC (VolumeName empty) with failed pod on dead node returns true",
			pvcNS:   "apps",
			pvcName: "unbound-dead",
			objs: []runtime.Object{
				stPVC("apps", "unbound-dead", ""),
				stReadyNode("n-dead", corev1.NodeCondition{Type: corev1.NodeReady, Status: corev1.ConditionFalse}),
				stClaimPod("apps", "job-pod", "n-dead", corev1.PodFailed, corev1.Volume{
					Name: "data",
					VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "unbound-dead"},
					},
				}),
			},
			want:          true,
			wantVALists:   0,
			wantNodeLists: 1,
			wantPodLists:  1,
		},
		{
			name:    "bound PV with attached VolumeAttachment short-circuits node and pod scans",
			pvcNS:   "apps",
			pvcName: "attached-pvc",
			objs: []runtime.Object{
				stPVC("apps", "attached-pvc", pvTarget),
				&storagev1.VolumeAttachment{
					ObjectMeta: metav1.ObjectMeta{Name: "va-attached"},
					Spec:       storagev1.VolumeAttachmentSpec{Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: &pvTarget}},
					Status:     storagev1.VolumeAttachmentStatus{Attached: true},
				},
			},
			want:          true,
			wantVALists:   1,
			wantNodeLists: 0,
			wantPodLists:  0,
		},
		{
			name:    "bound PV with live VA Attached=false and DeletionTimestamp==nil fails closed",
			pvcNS:   "apps",
			pvcName: "live-unconfirmed-va",
			objs: []runtime.Object{
				stPVC("apps", "live-unconfirmed-va", pvTarget),
				&storagev1.VolumeAttachment{
					ObjectMeta: metav1.ObjectMeta{Name: "va-live"},
					Spec:       storagev1.VolumeAttachmentSpec{Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: &pvTarget}},
					Status:     storagev1.VolumeAttachmentStatus{Attached: false},
				},
			},
			want:          true,
			wantVALists:   1,
			wantNodeLists: 0,
			wantPodLists:  0,
		},
		{
			name:    "terminating detached VA, nil-PV VA, other-PV attached VA, and live-node failed pod returns false",
			pvcNS:   "apps",
			pvcName: "clean-pvc",
			objs: []runtime.Object{
				stPVC("apps", "clean-pvc", pvTarget),
				&storagev1.VolumeAttachment{
					ObjectMeta: metav1.ObjectMeta{Name: "va-nil-pv"},
					Spec:       storagev1.VolumeAttachmentSpec{Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: nil}},
					Status:     storagev1.VolumeAttachmentStatus{Attached: true},
				},
				&storagev1.VolumeAttachment{
					ObjectMeta: metav1.ObjectMeta{Name: "va-other-pv"},
					Spec:       storagev1.VolumeAttachmentSpec{Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: &pvOther}},
					Status:     storagev1.VolumeAttachmentStatus{Attached: true},
				},
				&storagev1.VolumeAttachment{
					ObjectMeta: metav1.ObjectMeta{Name: "va-term-detached", DeletionTimestamp: &now},
					Spec:       storagev1.VolumeAttachmentSpec{Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: &pvTarget}},
					Status:     storagev1.VolumeAttachmentStatus{Attached: false},
				},
				stReadyNode("n-ready", corev1.NodeCondition{Type: corev1.NodeReady, Status: corev1.ConditionTrue}),
				stClaimPod("apps", "finished-pod", "n-ready", corev1.PodFailed, corev1.Volume{
					Name: "data",
					VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "clean-pvc"},
					},
				}),
			},
			want:          false,
			wantVALists:   1,
			wantNodeLists: 1,
			wantPodLists:  1,
		},
		{
			name:    "pod list error in failedPodOnDeadNode fails closed and IncErrors once",
			pvcNS:   "apps",
			pvcName: "pod-list-err",
			objs: []runtime.Object{
				stPVC("apps", "pod-list-err", ""),
				stReadyNode("n-ready", corev1.NodeCondition{Type: corev1.NodeReady, Status: corev1.ConditionTrue}),
			},
			prep: func(cs *fake.Clientset, _, _, _ *atomic.Int32) {
				cs.PrependReactor("list", "pods",
					func(ktesting.Action) (bool, runtime.Object, error) {
						return true, nil, errors.New("pod list boom")
					})
			},
			want:           true,
			wantErrorDelta: 1,
			wantNodeLists:  1,
			wantPodLists:   1,
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(tc.objs...)
			var vaLists, nodeLists, podLists atomic.Int32
			if tc.prep != nil {
				tc.prep(cs, &vaLists, &nodeLists, &podLists)
			}
			// Prepend the counter after tc.prep so it observes calls even when
			// tc.prep short-circuits with a simulated error.
			cs.PrependReactor("list", "*", func(a ktesting.Action) (bool, runtime.Object, error) {
				switch a.GetResource().Resource {
				case "volumeattachments":
					vaLists.Add(1)
				case "nodes":
					nodeLists.Add(1)
				case "pods":
					podLists.Add(1)
				}
				return false, nil, nil
			})

			queue := fmt.Sprintf("fjj-threatenable-case-%d", i)
			j := &failedJobsJanitor{cs: cs, queue: queue}
			before := hookRunErrorCount(t, queue)
			got := j.pvcMountThreatenable(ctx, &metav1.PartialObjectMetadata{
				ObjectMeta: metav1.ObjectMeta{Namespace: tc.pvcNS, Name: tc.pvcName},
			})
			after := hookRunErrorCount(t, queue)

			if got != tc.want {
				t.Fatalf("pvcMountThreatenable() = %v, want %v", got, tc.want)
			}
			if gotDelta := after - before; gotDelta != tc.wantErrorDelta {
				t.Fatalf("IncError delta = %v, want %v", gotDelta, tc.wantErrorDelta)
			}
			if got := vaLists.Load(); got != tc.wantVALists {
				t.Fatalf("VA list calls = %d, want %d", got, tc.wantVALists)
			}
			if got := nodeLists.Load(); got != tc.wantNodeLists {
				t.Fatalf("Node list calls = %d, want %d", got, tc.wantNodeLists)
			}
			if got := podLists.Load(); got != tc.wantPodLists {
				t.Fatalf("Pod list calls = %d, want %d", got, tc.wantPodLists)
			}
		})
	}

	t.Run("cached VA list error IncErrors once across two claims sharing pvcCensus", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			stPVC("apps", "pvc-1", pvTarget),
			stPVC("apps", "pvc-2", pvTarget),
		)
		var vaLists atomic.Int32
		cs.PrependReactor("list", "volumeattachments",
			func(ktesting.Action) (bool, runtime.Object, error) {
				vaLists.Add(1)
				return true, nil, errors.New("va list failed")
			})
		queue := "fjj-va-cached-err"
		j := &failedJobsJanitor{cs: cs, queue: queue}
		census := &pvcCensus{}
		before := hookRunErrorCount(t, queue)

		if !j.pvcMountThreatenableWithCensus(ctx, &metav1.PartialObjectMetadata{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "pvc-1"},
		}, census) {
			t.Fatal("first call must fail closed")
		}
		if delta := hookRunErrorCount(t, queue) - before; delta != 1 {
			t.Fatalf("first call IncError delta = %v, want 1", delta)
		}
		if !j.pvcMountThreatenableWithCensus(ctx, &metav1.PartialObjectMetadata{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "pvc-2"},
		}, census) {
			t.Fatal("second cached call must fail closed")
		}
		if delta := hookRunErrorCount(t, queue) - before; delta != 1 {
			t.Fatalf("second cached call IncError delta = %v, want still 1", delta)
		}
		if got := vaLists.Load(); got != 1 {
			t.Fatalf("VA list calls = %d, want 1", got)
		}
	})

	t.Run("cached Node list error IncErrors once across two claims sharing pvcCensus", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			stPVC("apps", "pvc-1", ""),
			stPVC("apps", "pvc-2", ""),
		)
		var nodeLists atomic.Int32
		cs.PrependReactor("list", "nodes",
			func(ktesting.Action) (bool, runtime.Object, error) {
				nodeLists.Add(1)
				return true, nil, errors.New("node list failed")
			})
		queue := "fjj-node-cached-err"
		j := &failedJobsJanitor{cs: cs, queue: queue}
		census := &pvcCensus{}
		before := hookRunErrorCount(t, queue)

		if !j.pvcMountThreatenableWithCensus(ctx, &metav1.PartialObjectMetadata{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "pvc-1"},
		}, census) {
			t.Fatal("first call must fail closed")
		}
		if delta := hookRunErrorCount(t, queue) - before; delta != 1 {
			t.Fatalf("first call IncError delta = %v, want 1", delta)
		}
		if !j.pvcMountThreatenableWithCensus(ctx, &metav1.PartialObjectMetadata{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "pvc-2"},
		}, census) {
			t.Fatal("second cached call must fail closed")
		}
		if delta := hookRunErrorCount(t, queue) - before; delta != 1 {
			t.Fatalf("second cached call IncError delta = %v, want still 1", delta)
		}
		if got := nodeLists.Load(); got != 1 {
			t.Fatalf("Node list calls = %d, want 1", got)
		}
	})
}

func TestFailedPodOnDeadNode(t *testing.T) {
	pvcVol := func(claim string) corev1.Volume {
		return corev1.Volume{
			Name: "data",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim},
			},
		}
	}
	ephVol := func(volName string) corev1.Volume {
		return corev1.Volume{
			Name: volName,
			VolumeSource: corev1.VolumeSource{
				Ephemeral: &corev1.EphemeralVolumeSource{},
			},
		}
	}

	tests := []struct {
		name    string
		objs    []runtime.Object
		prep    func(cs *fake.Clientset)
		ns      string
		pvcName string
		wantPod string
		wantErr bool
	}{
		{
			name:    "non-Failed phases on dead node return empty",
			ns:      "apps",
			pvcName: "target-pvc",
			objs: []runtime.Object{
				stReadyNode("n-dead", corev1.NodeCondition{Type: corev1.NodeReady, Status: corev1.ConditionFalse}),
				stClaimPod("apps", "p-run", "n-dead", corev1.PodRunning, pvcVol("target-pvc")),
				stClaimPod("apps", "p-pend", "n-dead", corev1.PodPending, pvcVol("target-pvc")),
				stClaimPod("apps", "p-succ", "n-dead", corev1.PodSucceeded, pvcVol("target-pvc")),
				stClaimPod("apps", "p-unk", "n-dead", corev1.PodUnknown, pvcVol("target-pvc")),
			},
			wantPod: "",
		},
		{
			name:    "Failed pod with empty Spec.NodeName returns empty",
			ns:      "apps",
			pvcName: "target-pvc",
			objs: []runtime.Object{
				stClaimPod("apps", "p-unscheduled", "", corev1.PodFailed, pvcVol("target-pvc")),
			},
			wantPod: "",
		},
		{
			name:    "Failed pod on Ready=True node returns empty",
			ns:      "apps",
			pvcName: "target-pvc",
			objs: []runtime.Object{
				stReadyNode("n-ready", corev1.NodeCondition{Type: corev1.NodeReady, Status: corev1.ConditionTrue}),
				stClaimPod("apps", "p-live", "n-ready", corev1.PodFailed, pvcVol("target-pvc")),
			},
			wantPod: "",
		},
		{
			name:    "Failed pod on NotReady (ConditionFalse) node returns pod name",
			ns:      "apps",
			pvcName: "target-pvc",
			objs: []runtime.Object{
				stReadyNode("n-false", corev1.NodeCondition{Type: corev1.NodeReady, Status: corev1.ConditionFalse}),
				stClaimPod("apps", "p-dead", "n-false", corev1.PodFailed, pvcVol("target-pvc")),
			},
			wantPod: "p-dead",
		},
		{
			name:    "Failed pod on Unknown (ConditionUnknown) node returns pod name",
			ns:      "apps",
			pvcName: "target-pvc",
			objs: []runtime.Object{
				stReadyNode("n-unk", corev1.NodeCondition{Type: corev1.NodeReady, Status: corev1.ConditionUnknown}),
				stClaimPod("apps", "p-unk-node", "n-unk", corev1.PodFailed, pvcVol("target-pvc")),
			},
			wantPod: "p-unk-node",
		},
		{
			name:    "Failed pod on node missing NodeReady condition returns pod name",
			ns:      "apps",
			pvcName: "target-pvc",
			objs: []runtime.Object{
				stReadyNode("n-nocond"),
				stClaimPod("apps", "p-nocond", "n-nocond", corev1.PodFailed, pvcVol("target-pvc")),
			},
			wantPod: "p-nocond",
		},
		{
			name:    "Failed pod on deleted/missing node returns pod name",
			ns:      "apps",
			pvcName: "target-pvc",
			objs: []runtime.Object{
				stReadyNode("n-other", corev1.NodeCondition{Type: corev1.NodeReady, Status: corev1.ConditionTrue}),
				stClaimPod("apps", "p-missing-node", "n-deleted", corev1.PodFailed, pvcVol("target-pvc")),
			},
			wantPod: "p-missing-node",
		},
		{
			name:    "Failed pod on dead node claiming generic Ephemeral volume (<pod>-<vol>) matches pvcName",
			ns:      "apps",
			pvcName: "p-eph-scratch",
			objs: []runtime.Object{
				stReadyNode("n-dead", corev1.NodeCondition{Type: corev1.NodeReady, Status: corev1.ConditionFalse}),
				stClaimPod("apps", "p-eph", "n-dead", corev1.PodFailed, ephVol("scratch")),
			},
			wantPod: "p-eph",
		},
		{
			name:    "Failed pod on dead node claiming different PVC or no volumes returns empty",
			ns:      "apps",
			pvcName: "target-pvc",
			objs: []runtime.Object{
				stReadyNode("n-dead", corev1.NodeCondition{Type: corev1.NodeReady, Status: corev1.ConditionFalse}),
				stClaimPod("apps", "p-other", "n-dead", corev1.PodFailed, pvcVol("other-pvc")),
				stClaimPod("apps", "p-novol", "n-dead", corev1.PodFailed),
			},
			wantPod: "",
		},
		{
			name:    "Failed pod in different namespace claiming same pvcName is isolated",
			ns:      "apps",
			pvcName: "target-pvc",
			objs: []runtime.Object{
				stReadyNode("n-dead", corev1.NodeCondition{Type: corev1.NodeReady, Status: corev1.ConditionFalse}),
				stClaimPod("other-ns", "p-foreign", "n-dead", corev1.PodFailed, pvcVol("target-pvc")),
			},
			wantPod: "",
		},
		{
			name:    "Node list error returns error",
			ns:      "apps",
			pvcName: "target-pvc",
			prep: func(cs *fake.Clientset) {
				cs.PrependReactor("list", "nodes",
					func(ktesting.Action) (bool, runtime.Object, error) {
						return true, nil, errors.New("nodes list failed")
					})
			},
			wantErr: true,
		},
		{
			name:    "Pod list error returns error",
			ns:      "apps",
			pvcName: "target-pvc",
			prep: func(cs *fake.Clientset) {
				cs.PrependReactor("list", "pods",
					func(ktesting.Action) (bool, runtime.Object, error) {
						return true, nil, errors.New("pods list failed")
					})
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(tc.objs...)
			if tc.prep != nil {
				tc.prep(cs)
			}
			j := &failedJobsJanitor{cs: cs}
			got, err := j.failedPodOnDeadNode(ctx, tc.ns, tc.pvcName)
			if (err != nil) != tc.wantErr {
				t.Fatalf("failedPodOnDeadNode() err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.wantPod {
				t.Fatalf("failedPodOnDeadNode() = %q, want %q", got, tc.wantPod)
			}
		})
	}
}
