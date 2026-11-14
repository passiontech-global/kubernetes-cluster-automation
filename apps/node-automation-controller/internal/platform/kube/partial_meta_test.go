// partial_meta_test.go — unit tests for ListPartialOrFallback, its
// metaUnsupported / dynamic / typed fallback chain, and partialFromUnstructured.
package kube

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	metadatafake "k8s.io/client-go/metadata/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

func TestListPartialOrFallback_MetaSuccessAndErrors(t *testing.T) {
	t.Parallel()

	gvr := corev1.SchemeGroupVersion.WithResource("pods")

	// 1. Meta succeeds.
	meta := testhelp.NewMetaClient(
		testhelp.MetaObj("v1", "Pod", metav1.ObjectMeta{Namespace: "ns1", Name: "p1"}),
		testhelp.MetaObj("v1", "Pod", metav1.ObjectMeta{Namespace: "ns1", Name: "p2"}),
	)
	cs := fake.NewClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "from-typed"}})
	items, err := ListPartialOrFallback(context.Background(), meta, cs, nil, gvr, "ns1", metav1.ListOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items from meta, got %+v", items)
	}

	// 2. Non-unsupported meta error (403 Forbidden) must NOT fall back to typed/dynamic.
	metaForbidden := testhelp.NewMetaClient()
	metaForbidden.(*metadatafake.FakeMetadataClient).PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, &apierrors.StatusError{ErrStatus: metav1.Status{
			Status: metav1.StatusFailure,
			Code:   http.StatusForbidden,
			Reason: metav1.StatusReasonForbidden,
		}}
	})
	if _, err := ListPartialOrFallback(context.Background(), metaForbidden, cs, nil, gvr, "ns1", metav1.ListOptions{}); !apierrors.IsForbidden(err) {
		t.Fatalf("expected Forbidden without fallback, got %v", err)
	}

	// 3. 406 NotAcceptable degrades to typed fallback.
	meta406 := testhelp.NewMetaClient()
	meta406.(*metadatafake.FakeMetadataClient).PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, &apierrors.StatusError{ErrStatus: metav1.Status{
			Status: metav1.StatusFailure,
			Code:   http.StatusNotAcceptable,
			Reason: metav1.StatusReasonNotAcceptable,
		}}
	})
	items, err = ListPartialOrFallback(context.Background(), meta406, cs, nil, gvr, "ns1", metav1.ListOptions{})
	if err != nil || len(items) != 1 || items[0].Name != "from-typed" {
		t.Fatalf("expected fallback to typed [from-typed], got items=%+v err=%v", items, err)
	}

	// 4. Unregistered scheme error degrades to fallback.
	metaUnreg := testhelp.NewMetaClient()
	metaUnreg.(*metadatafake.FakeMetadataClient).PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, runtime.NewNotRegisteredErrForType("meta", reflect.TypeOf(corev1.Pod{}))
	})
	items, err = ListPartialOrFallback(context.Background(), metaUnreg, cs, nil, gvr, "ns1", metav1.ListOptions{})
	if err != nil || len(items) != 1 || items[0].Name != "from-typed" {
		t.Fatalf("expected fallback on NotRegisteredErr, got items=%+v err=%v", items, err)
	}

	// 5. All clients nil returns clear error.
	if _, err := ListPartialOrFallback(context.Background(), nil, nil, nil, gvr, "ns1", metav1.ListOptions{}); err == nil {
		t.Fatal("expected error when all clients are nil")
	}
}

func TestListPartialOrFallback_DynamicFallbackAndUnstructured(t *testing.T) {
	t.Parallel()

	crdGVR := schema.GroupVersionResource{Group: "example.io", Version: "v1", Resource: "widgets"}
	scheme := runtime.NewScheme()
	u1 := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "example.io/v1",
		"kind":       "Widget",
		"metadata":   map[string]interface{}{"namespace": "ns1", "name": "w1"},
	}}
	u2 := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "example.io/v1",
		"kind":       "Widget",
		// malformed/missing metadata yields empty ObjectMeta
	}}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
		crdGVR: "WidgetList",
	}, u1)
	dynCalls := 0
	dyn.PrependReactor("list", "widgets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		dynCalls++
		if dynCalls == 1 {
			return true, &unstructured.UnstructuredList{
				Object: map[string]interface{}{"metadata": map[string]interface{}{"continue": "c2"}},
				Items:  []unstructured.Unstructured{*u1},
			}, nil
		}
		return true, &unstructured.UnstructuredList{
			Items: []unstructured.Unstructured{*u2},
		}, nil
	})

	items, err := ListPartialOrFallback(context.Background(), nil, fake.NewClientset(), dyn, crdGVR, "ns1", metav1.ListOptions{Limit: 500})
	if err != nil {
		t.Fatalf("unexpected dynamic fallback error: %v", err)
	}
	if len(items) != 2 || items[0].Name != "w1" || items[1].Kind != "Widget" {
		t.Fatalf("unexpected dynamic items: %+v", items)
	}

	// Unregistered GVR on bare dynamic fake panics internally -> recovered as error.
	bareDyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	unknownGVR := schema.GroupVersionResource{Group: "unknown.io", Version: "v1", Resource: "things"}
	if _, err := ListPartialOrFallback(context.Background(), nil, nil, bareDyn, unknownGVR, "", metav1.ListOptions{}); err == nil {
		t.Fatal("expected recovered error for unregistered GVR on dynamic fake")
	}

	// Core GVR with Limit=0 on dynamic fallback (unregistered in empty scheme -> recovered error).
	coreGVR := corev1.SchemeGroupVersion.WithResource("configmaps")
	dynCore := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	if _, err := listPartialViaDynamic(context.Background(), dynCore, coreGVR, "", metav1.ListOptions{}); err == nil {
		t.Fatal("expected recovered error for unregistered core GVR on dynamic fake")
	}
}

func TestTypedFallbackCoversAndListPartialViaTyped(t *testing.T) {
	t.Parallel()

	cs := fake.NewClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "svc"}},
		//nolint:staticcheck // SA1019: exercise deprecated Endpoints fallback
		&corev1.Endpoints{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ep"}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "cm"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "sec"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "sa"}},
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pvc"}},
		&corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "pv"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}},
		&corev1.Event{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ev"}},
		&corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rq"}},
		&corev1.LimitRange{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "lr"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "dep"}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rs"}},
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "sts"}},
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ds"}},
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "job"}},
		&batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "cj"}},
		&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pdb"}},
		&discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "es"}},
		&storagev1.VolumeAttachment{ObjectMeta: metav1.ObjectMeta{Name: "va"}},
		&coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "lease"}},
		&certificatesv1.CertificateSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: "csr"}},
		&admissionv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "mwc"}},
		&admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "vwc"}},
	)

	covered := []struct {
		gvr schema.GroupVersionResource
		ns  string
	}{
		{corev1.SchemeGroupVersion.WithResource("pods"), "ns"},
		{corev1.SchemeGroupVersion.WithResource("services"), "ns"},
		{corev1.SchemeGroupVersion.WithResource("endpoints"), "ns"},
		{corev1.SchemeGroupVersion.WithResource("configmaps"), "ns"},
		{corev1.SchemeGroupVersion.WithResource("secrets"), "ns"},
		{corev1.SchemeGroupVersion.WithResource("serviceaccounts"), "ns"},
		{corev1.SchemeGroupVersion.WithResource("persistentvolumeclaims"), "ns"},
		{corev1.SchemeGroupVersion.WithResource("persistentvolumes"), ""},
		{corev1.SchemeGroupVersion.WithResource("namespaces"), ""},
		{corev1.SchemeGroupVersion.WithResource("nodes"), ""},
		{corev1.SchemeGroupVersion.WithResource("events"), "ns"},
		{corev1.SchemeGroupVersion.WithResource("resourcequotas"), "ns"},
		{corev1.SchemeGroupVersion.WithResource("limitranges"), "ns"},
		{appsv1.SchemeGroupVersion.WithResource("deployments"), "ns"},
		{appsv1.SchemeGroupVersion.WithResource("replicasets"), "ns"},
		{appsv1.SchemeGroupVersion.WithResource("statefulsets"), "ns"},
		{appsv1.SchemeGroupVersion.WithResource("daemonsets"), "ns"},
		{batchv1.SchemeGroupVersion.WithResource("jobs"), "ns"},
		{batchv1.SchemeGroupVersion.WithResource("cronjobs"), "ns"},
		{policyv1.SchemeGroupVersion.WithResource("poddisruptionbudgets"), "ns"},
		{discoveryv1.SchemeGroupVersion.WithResource("endpointslices"), "ns"},
		{storagev1.SchemeGroupVersion.WithResource("volumeattachments"), ""},
		{coordinationv1.SchemeGroupVersion.WithResource("leases"), "ns"},
		{certificatesv1.SchemeGroupVersion.WithResource("certificatesigningrequests"), ""},
		{admissionv1.SchemeGroupVersion.WithResource("mutatingwebhookconfigurations"), ""},
		{admissionv1.SchemeGroupVersion.WithResource("validatingwebhookconfigurations"), ""},
	}
	for _, tc := range covered {
		items, err := listPartialViaTyped(context.Background(), cs, tc.gvr, tc.ns, metav1.ListOptions{})
		if err != nil {
			t.Errorf("%s: unexpected error: %v", tc.gvr, err)
			continue
		}
		if len(items) != 1 {
			t.Errorf("%s: expected 1 item, got %d", tc.gvr, len(items))
		}
	}

	uncovered := []schema.GroupVersionResource{
		{Group: "", Version: "v2", Resource: "pods"},
		{Group: "", Version: "v1", Resource: "unknown"},
		{Group: "custom.io", Version: "v1", Resource: "widgets"},
	}
	for _, gvr := range uncovered {
		if typedFallbackCovers(gvr) {
			t.Errorf("expected typedFallbackCovers(%s)=false", gvr)
		}
		if _, err := listPartialViaTyped(context.Background(), cs, gvr, "", metav1.ListOptions{}); err == nil {
			t.Errorf("expected error for uncovered %s", gvr)
		}
	}

	// Propagates typed list error.
	csErr := fake.NewClientset()
	csErr.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("typed list failed")
	})
	if _, err := listPartialViaTyped(context.Background(), csErr, corev1.SchemeGroupVersion.WithResource("pods"), "ns", metav1.ListOptions{}); err == nil {
		t.Fatal("expected typed list error")
	}
}
