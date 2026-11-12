// metafake.go — the metadata-client fake for tests that exercise
// the metadata path of kube.ListPartialOrFallback. client-go ships
// metadata/fake.NewSimpleMetadataClient; this file wraps it with
// the seeding shape the module tests need: objects are
// *metav1.PartialObjectMetadata carrying the REAL apiVersion/kind
// (the fake resolves the requested GVR through each object's own
// GVK), exactly what the apiserver's meta.k8s.io endpoint returns.
package testhelp

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/metadata"
	metadatafake "k8s.io/client-go/metadata/fake"
)

// NewMetaClient returns a fake metadata.Interface seeded with objs.
// Pass MetaObj-built PartialObjectMetadata values (or hand-built
// ones) — a bare typed object (e.g. *corev1.Pod) is NOT understood
// by this fake; project it first.
//
// The scheme is a fresh NewTestScheme per call (never a shared
// runtime.NewScheme — scheme mutation is global state and parallel
// tests would race it) with the meta types registered: without
// metav1.AddMetaToScheme the fake's tracker cannot resolve
// PartialObjectMetadataList on LIST and panics on the first read.
func NewMetaClient(objs ...runtime.Object) metadata.Interface {
	scheme := metadatafake.NewTestScheme()
	if err := metav1.AddMetaToScheme(scheme); err != nil {
		panic(err)
	}
	return metadatafake.NewSimpleMetadataClient(scheme, objs...)
}

// MetaObj builds one seed object for NewMetaClient: the ObjectMeta
// the caller already has (labels, annotations, ownerRefs, UID,
// timestamps) under the apiVersion/kind the GVR resolves to —
// e.g. MetaObj("apps/v1", "ReplicaSet", om).
func MetaObj(apiVersion, kind string, om metav1.ObjectMeta) *metav1.PartialObjectMetadata {
	return &metav1.PartialObjectMetadata{
		TypeMeta:   metav1.TypeMeta{APIVersion: apiVersion, Kind: kind},
		ObjectMeta: om,
	}
}
