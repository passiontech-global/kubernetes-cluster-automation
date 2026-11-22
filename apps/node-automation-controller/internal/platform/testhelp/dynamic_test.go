package testhelp

import (
	"testing"

	resourcev1 "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

func testDynObj(apiVersion, kind, ns, name string) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
	}}
	o.SetNamespace(ns)
	o.SetName(name)
	return o
}

func TestNewDynamicClientWave5GVRs(t *testing.T) {
	tests := []struct {
		name       string
		apiVersion string
		kind       string
		gvr        schema.GroupVersionResource
		ns         string
		objName    string
	}{
		{
			name:       "velero Restore v1",
			apiVersion: "velero.io/v1",
			kind:       "Restore",
			gvr:        kube.GVVeleroRestore,
			ns:         "apps",
			objName:    "restore-1",
		},
		{
			name:       "gateway TLSRoute v1",
			apiVersion: "gateway.networking.k8s.io/v1",
			kind:       "TLSRoute",
			gvr:        kube.GVRTLSRouteV1,
			ns:         "apps",
			objName:    "tls-v1",
		},
		{
			name:       "gateway TLSRoute v1alpha3",
			apiVersion: "gateway.networking.k8s.io/v1alpha3",
			kind:       "TLSRoute",
			gvr:        kube.GVRTLSRouteV1Alpha3,
			ns:         "apps",
			objName:    "tls-v1alpha3",
		},
		{
			name:       "gateway TLSRoute v1alpha2",
			apiVersion: "gateway.networking.k8s.io/v1alpha2",
			kind:       "TLSRoute",
			gvr:        kube.GVRTLSRouteV1Alpha2,
			ns:         "apps",
			objName:    "tls-v1alpha2",
		},
		{
			name:       "gateway ReferenceGrant v1",
			apiVersion: "gateway.networking.k8s.io/v1",
			kind:       "ReferenceGrant",
			gvr:        kube.GVRReferenceGrantV1,
			ns:         "apps",
			objName:    "rg-v1",
		},
		{
			name:       "gateway ReferenceGrant v1beta1",
			apiVersion: "gateway.networking.k8s.io/v1beta1",
			kind:       "ReferenceGrant",
			gvr:        kube.GVRReferenceGrantV1Beta1,
			ns:         "apps",
			objName:    "rg-v1beta1",
		},
		{
			name:       "gateway ReferenceGrant v1alpha2",
			apiVersion: "gateway.networking.k8s.io/v1alpha2",
			kind:       "ReferenceGrant",
			gvr:        kube.GVRReferenceGrantV1Alpha2,
			ns:         "apps",
			objName:    "rg-v1alpha2",
		},
		{
			name:       "snapshot VolumeSnapshot v1",
			apiVersion: "snapshot.storage.k8s.io/v1",
			kind:       "VolumeSnapshot",
			gvr:        kube.GVRVolumeSnapshot,
			ns:         "apps",
			objName:    "snap-1",
		},
		{
			name:       "snapshot VolumeSnapshotContent v1",
			apiVersion: "snapshot.storage.k8s.io/v1",
			kind:       "VolumeSnapshotContent",
			gvr:        kube.GVRVolumeSnapshotContent,
			objName:    "snapcontent-1",
		},
		{
			name:       "DRA ResourceClaim v1 unstructured",
			apiVersion: "resource.k8s.io/v1",
			kind:       "ResourceClaim",
			gvr:        kube.GVRResourceClaim,
			ns:         "apps",
			objName:    "claim-unstructured",
		},
	}

	ctx := t.Context()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			seed := testDynObj(tc.apiVersion, tc.kind, tc.ns, tc.objName)
			dyn := NewDynamicClient(seed)
			var res dynamic.ResourceInterface = dyn.Resource(tc.gvr)
			if tc.ns != "" {
				res = dyn.Resource(tc.gvr).Namespace(tc.ns)
			}

			list, err := res.List(ctx, metav1.ListOptions{})
			if err != nil {
				t.Fatalf("List(%v): %v", tc.gvr, err)
			}
			if len(list.Items) != 1 || list.Items[0].GetName() != tc.objName {
				t.Fatalf("List(%v) = %v, want [%s]", tc.gvr, list.Items, tc.objName)
			}

			created := testDynObj(tc.apiVersion, tc.kind, tc.ns, tc.objName+"-new")
			if _, err := res.Create(ctx, created, metav1.CreateOptions{}); err != nil {
				t.Fatalf("Create(%v): %v", tc.gvr, err)
			}
			got, err := res.Get(ctx, tc.objName+"-new", metav1.GetOptions{})
			if err != nil {
				t.Fatalf("Get(%v): %v", tc.gvr, err)
			}
			if got.GetName() != tc.objName+"-new" {
				t.Fatalf("Get(%v) name = %q, want %q", tc.gvr, got.GetName(), tc.objName+"-new")
			}
		})
	}

	t.Run("DRA ResourceClaim v1 typed seed", func(t *testing.T) {
		claim := &resourcev1.ResourceClaim{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "claim-typed"},
		}
		dyn := NewDynamicClient(claim)
		list, err := dyn.Resource(kube.GVRResourceClaim).Namespace("apps").List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatalf("List(%v) with typed seed: %v", kube.GVRResourceClaim, err)
		}
		if len(list.Items) != 1 || list.Items[0].GetName() != "claim-typed" {
			t.Fatalf("List(%v) = %v, want [claim-typed]", kube.GVRResourceClaim, list.Items)
		}
	})
}

func TestDynListKindsWave5(t *testing.T) {
	kinds := DynListKinds()
	want := map[schema.GroupVersionResource]string{
		kube.GVVeleroRestore:           "RestoreList",
		kube.GVRTLSRouteV1:             "TLSRouteList",
		kube.GVRTLSRouteV1Alpha3:       "TLSRouteList",
		kube.GVRTLSRouteV1Alpha2:       "TLSRouteList",
		kube.GVRReferenceGrantV1:       "ReferenceGrantList",
		kube.GVRReferenceGrantV1Beta1:  "ReferenceGrantList",
		kube.GVRReferenceGrantV1Alpha2: "ReferenceGrantList",
		kube.GVRVolumeSnapshot:         "VolumeSnapshotList",
		kube.GVRVolumeSnapshotContent:  "VolumeSnapshotContentList",
		kube.GVRResourceClaim:          "ResourceClaimList",
	}
	for gvr, wantKind := range want {
		if got := kinds[gvr]; got != wantKind {
			t.Fatalf("DynListKinds[%v] = %q, want %q", gvr, got, wantKind)
		}
	}

	// Verify NewFakeDyn(DynListKinds()) can list every Wave 5 GVR including ResourceClaim.
	dyn := NewFakeDyn(kinds)
	ctx := t.Context()
	for gvr := range want {
		if _, err := dyn.Resource(gvr).List(ctx, metav1.ListOptions{}); err != nil {
			t.Fatalf("NewFakeDyn.Resource(%v).List: %v", gvr, err)
		}
	}
}
