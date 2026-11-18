// namespace_terminating_wedged_phase_d_test.go — Phase-D finalizer
// sweep contracts: the metadata-only object is sufficient to strip,
// 409/404 patch races are quiet skips, and "attempted" is set on any
// sent patch so a failed write does not get its grant refunded.
package nodehealth

import (
	"errors"
	"testing"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// The sweep's LIST is metadata-only now: every field this strip path
// reads (finalizers, ownerRefs, RV, name/ns, deletion timestamp)
// lives in ObjectMeta, so a PartialObjectMetadata must be enough.
func TestMaybeStripFinalizersFromPartialMetadata(t *testing.T) {
	foo := sweepFoo("dead-ns", "foo-pom",
		[]string{"gone-deploy.example.com/finalizer", "kubernetes.io/pvc-protection"},
		"Deployment", "gone-deploy")
	kinds := testutil.DynListKinds()
	kinds[fooGVR] = "FooList"
	dyn := testutil.NewFakeDyn(kinds, foo)
	p := probetest.MustCheck[*namespaceTerminatingWedgedCheck](t,
		testProberDyn(fake.NewSimpleClientset(), dyn))

	pom := &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{
			APIVersion: foo.GetAPIVersion(),
			Kind:       foo.GetKind(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         foo.GetNamespace(),
			Name:              foo.GetName(),
			ResourceVersion:   foo.GetResourceVersion(),
			Finalizers:        foo.GetFinalizers(),
			OwnerReferences:   foo.GetOwnerReferences(),
			DeletionTimestamp: foo.GetDeletionTimestamp(),
		},
	}
	stripped, attempted := p.maybeStripFinalizers(ctx, logr.Discard(), fooGVR, pom)
	if !stripped || !attempted {
		t.Fatalf("partial-metadata strip = (%v,%v), want (true,true)", stripped, attempted)
	}
	got, err := dyn.Resource(fooGVR).Namespace("dead-ns").
		Get(ctx, "foo-pom", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if fins := got.GetFinalizers(); len(fins) != 1 ||
		fins[0] != "kubernetes.io/pvc-protection" {
		t.Fatalf("finalizers after strip = %v, want only the protected one", fins)
	}
}

// A patch racing with another writer (409) or with the object's own
// deletion (404) is a quiet skip: no run error is counted, but the
// patch WAS attempted, so the heal grant must not be refunded.
func TestMaybeStripFinalizersRaceResponsesKeepGrant(t *testing.T) {
	gr := schema.GroupResource{Group: "example.com", Resource: "foos"}
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"conflict", apierrors.NewConflict(gr, "foo-race", errors.New("changed"))},
		{"notfound", apierrors.NewNotFound(gr, "foo-race")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			foo := sweepFoo("dead-ns", "foo-race",
				[]string{"gone-deploy.example.com/finalizer"},
				"Deployment", "gone-deploy")
			kinds := testutil.DynListKinds()
			kinds[fooGVR] = "FooList"
			dyn := testutil.NewFakeDyn(kinds, foo)
			dyn.PrependReactor("patch", "foos",
				func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, tc.err
				})
			p := probetest.MustCheck[*namespaceTerminatingWedgedCheck](t,
				testProberDyn(fake.NewSimpleClientset(), dyn))
			before := testutil.QueueErrorCount(t, p.Name)

			stripped, attempted := p.maybeStripFinalizers(ctx, logr.Discard(), fooGVR, foo)
			if stripped || !attempted {
				t.Fatalf("race patch = (%v,%v), want (false,true)", stripped, attempted)
			}
			if got := testutil.QueueErrorCount(t, p.Name) - before; got != 0 {
				t.Fatalf("race response metered %v run errors, want 0", got)
			}
		})
	}
}

// No strippable finalizer means no patch is ever sent — the sweep's
// grant is refunded in that case (attempted=false).
func TestMaybeStripFinalizersNoCandidateNotAttempted(t *testing.T) {
	foo := sweepFoo("dead-ns", "foo-clean",
		[]string{"kubernetes.io/pvc-protection"}, "Deployment", "gone-deploy")
	kinds := testutil.DynListKinds()
	kinds[fooGVR] = "FooList"
	dyn := testutil.NewFakeDyn(kinds, foo)
	p := probetest.MustCheck[*namespaceTerminatingWedgedCheck](t,
		testProberDyn(fake.NewSimpleClientset(), dyn))

	stripped, attempted := p.maybeStripFinalizers(ctx, logr.Discard(), fooGVR, foo)
	if stripped || attempted {
		t.Fatalf("protected-only object = (%v,%v), want (false,false)", stripped, attempted)
	}
}
