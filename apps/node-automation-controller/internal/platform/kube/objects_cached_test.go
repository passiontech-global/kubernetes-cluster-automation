// objects_cached_test.go — coverage for the GetXCached helpers:
// the nil-reader fallback must hit the direct clientset, a wired
// reader serves the cache path (and propagates its error), for all
// three object types.
package kube

import (
	"context"
	"errors"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// cacheGetReader is a minimal CachedObjectReader fake: it records the
// requested key and either fills the object (marking it cache-served)
// or returns err.
type cacheGetReader struct {
	key client.ObjectKey
	err error
}

func (r *cacheGetReader) Get(_ context.Context, key client.ObjectKey,
	obj client.Object, _ ...client.GetOption) error {

	r.key = key
	if r.err != nil {
		return r.err
	}
	obj.(metav1.Object).SetName(key.Name)
	obj.(metav1.Object).SetNamespace(key.Namespace)
	return nil
}

func TestGetDeploymentCached(t *testing.T) {
	ctx := t.Context()
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Namespace: "apps", Name: "web"}}
	cs := fake.NewSimpleClientset(dep)

	// nil reader → direct clientset Get.
	got, err := GetDeploymentCached(ctx, nil, cs, "apps", "web")
	if err != nil || got.Name != "web" {
		t.Fatalf("nil-reader GetDeploymentCached = (%v,%v)", got, err)
	}

	// wired reader → cache path, keyed read.
	r := &cacheGetReader{}
	got, err = GetDeploymentCached(ctx, r, cs, "apps", "web")
	if err != nil || got.Name != "web" {
		t.Fatalf("cached GetDeploymentCached = (%v,%v)", got, err)
	}
	if r.key != (client.ObjectKey{Namespace: "apps", Name: "web"}) {
		t.Fatalf("cache read key = %v", r.key)
	}

	// cache error propagates (a NotFound-from-cache stays NotFound).
	r = &cacheGetReader{err: errors.New("cache miss")}
	if _, err := GetDeploymentCached(ctx, r, cs, "apps", "web"); err == nil {
		t.Fatal("cache error swallowed")
	}
}

func TestGetDaemonSetCached(t *testing.T) {
	ctx := t.Context()
	ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "kube-system", Name: "konnectivity-agent"}}
	cs := fake.NewSimpleClientset(ds)

	got, err := GetDaemonSetCached(ctx, nil, cs, "kube-system", "konnectivity-agent")
	if err != nil || got.Name != "konnectivity-agent" {
		t.Fatalf("nil-reader GetDaemonSetCached = (%v,%v)", got, err)
	}

	r := &cacheGetReader{}
	got, err = GetDaemonSetCached(ctx, r, cs, "kube-system", "konnectivity-agent")
	if err != nil || got.Name != "konnectivity-agent" {
		t.Fatalf("cached GetDaemonSetCached = (%v,%v)", got, err)
	}
	if r.key.Name != "konnectivity-agent" {
		t.Fatalf("cache read key = %v", r.key)
	}
}

func TestGetSecretCached(t *testing.T) {
	ctx := t.Context()
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Namespace: "passiontech-pipeline", Name: "creds"}}
	cs := fake.NewSimpleClientset(sec)

	got, err := GetSecretCached(ctx, nil, cs, "passiontech-pipeline", "creds")
	if err != nil || got.Name != "creds" {
		t.Fatalf("nil-reader GetSecretCached = (%v,%v)", got, err)
	}

	r := &cacheGetReader{}
	got, err = GetSecretCached(ctx, r, cs, "passiontech-pipeline", "creds")
	if err != nil || got.Name != "creds" {
		t.Fatalf("cached GetSecretCached = (%v,%v)", got, err)
	}
	if r.key != (client.ObjectKey{Namespace: "passiontech-pipeline", Name: "creds"}) {
		t.Fatalf("cache read key = %v", r.key)
	}
}
