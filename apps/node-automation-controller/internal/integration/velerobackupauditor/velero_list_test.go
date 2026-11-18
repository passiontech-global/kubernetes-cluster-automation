// velero_list_test.go — the shared paged dynamic read: kube.ListEach
// must visit EVERY PAGE in the callback (no whole-list accumulation),
// a 410 Gone restart re-walks from a fresh first page, and a fetch
// failure must surface as an error (the callers' CRD-absent path).
package velerobackupauditor

import (
	"errors"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func TestVeleroListEachVisitsEveryPage(t *testing.T) {
	dyn := newDynFake()
	calls := 0
	dyn.PrependReactor("list", "schedules",
		func(ktesting.Action) (bool, runtime.Object, error) {
			calls++
			list := &unstructured.UnstructuredList{}
			switch calls {
			case 1:
				list.Items = []unstructured.Unstructured{
					*veleroSchedule("velero", "page-one", false, 0)}
				list.SetContinue("next-page")
			case 2:
				list.Items = []unstructured.Unstructured{
					*veleroSchedule("velero", "page-two", false, 0)}
			default:
				t.Fatalf("unexpected list call #%d — pagination did not stop", calls)
			}
			return true, list, nil
		})
	a := newVeleroAuditor(dyn, time.Now())

	// The callback sees each page as it lands; nothing outside it
	// retains the page bodies.
	var visited []string
	pages := 0
	err := a.veleroListEach(ctx, veleroScheduleGVR,
		func(page []unstructured.Unstructured) error {
			pages++
			for i := range page {
				visited = append(visited, page[i].GetName())
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("list calls = %d, want 2 (one per page)", calls)
	}
	if pages != 2 {
		t.Fatalf("callback pages = %d, want 2", pages)
	}
	if len(visited) != 2 || visited[0] != "page-one" || visited[1] != "page-two" {
		t.Fatalf("page order lost: %q", visited)
	}
}

func TestVeleroListEachResourceExpiredRestartsOnce(t *testing.T) {
	dyn := newDynFake()
	calls := 0
	dyn.PrependReactor("list", "schedules",
		func(ktesting.Action) (bool, runtime.Object, error) {
			calls++
			list := &unstructured.UnstructuredList{
				Items: []unstructured.Unstructured{
					*veleroSchedule("velero", "page-one", false, 0)},
			}
			switch calls {
			case 1:
				list.SetContinue("next-page")
			case 2:
				// The continue token's RV was compacted mid-walk.
				return true, nil, apierrors.NewResourceExpired("token gone")
			}
			return true, list, nil
		})
	a := newVeleroAuditor(dyn, time.Now())

	visits := 0
	if err := a.veleroListEach(ctx, veleroScheduleGVR,
		func([]unstructured.Unstructured) error {
			visits++
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if calls != 3 || visits != 2 {
		t.Fatalf("calls = %d, visits = %d, want 3/2 (one-shot restart)", calls, visits)
	}
}

func TestVeleroListFetchError(t *testing.T) {
	dyn := newDynFake()
	dyn.PrependReactor("list", "schedules",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	a := newVeleroAuditor(dyn, time.Now())

	called := false
	err := a.veleroListEach(ctx, veleroScheduleGVR,
		func([]unstructured.Unstructured) error {
			called = true
			return nil
		})
	if err == nil {
		t.Fatal("fetch error swallowed")
	}
	if called {
		t.Fatal("callback ran on a failed list")
	}
}
