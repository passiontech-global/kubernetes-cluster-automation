// Package testutil holds the shared fakes and fixture builders the
// internal/... subsystem tests use — one home for the construction
// lines each suite would otherwise copy into its own fixture.
package testutil

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

// FakeKube returns a fake clientset seeded with objects — the
// fake.NewSimpleClientset line every subsystem fixture rewrites. It
// returns the concrete *fake.Clientset (which satisfies
// kubernetes.Interface) so tests keep access to the Actions and
// PrependReactor seams.
func FakeKube(objects ...runtime.Object) *fake.Clientset {
	return fake.NewSimpleClientset(objects...)
}
