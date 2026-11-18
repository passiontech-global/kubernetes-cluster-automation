// crd_conversion_sweep_test.go — the conversion-backend existence
// check must read the snapshot's targeted Service census (no per-CRD
// GET fan-out), memoize both verdicts per sweep, and fail closed when
// the census itself was unreadable.
package circuitbreaker

import (
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
)

func crdSweepFixture(snap *guardstate.Snapshot) (*crdConversionSweep, *int) {
	cs := kfake.NewSimpleClientset()
	gets := new(int)
	cs.PrependReactor("get", "services",
		func(ktesting.Action) (bool, runtime.Object, error) {
			*gets = *gets + 1
			return true, nil, errors.New("svcExists must not GET per CRD")
		})
	return &crdConversionSweep{
		g:           &guardstate.Guard{CS: cs},
		snap:        snap,
		svcVerdicts: map[string]bool{},
		svcMissing:  map[string]bool{},
	}, gets
}

func TestCRDSweepSvcExistsFromSnapshot(t *testing.T) {
	snap := &guardstate.Snapshot{Services: []corev1.Service{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "backend", Name: "conv"}},
	}}
	s, gets := crdSweepFixture(snap)

	missing, exists, err := s.svcExists("backend/conv", "backend", "conv")
	if err != nil || missing || !exists {
		t.Fatalf("present service = (%v,%v,%v), want (false,true,nil)", missing, exists, err)
	}
	// Memoized present: mutating the census afterwards must not
	// change this sweep's verdict for the same key.
	snap.Services = nil
	if missing, exists, err := s.svcExists("backend/conv", "backend", "conv"); err != nil || missing || !exists {
		t.Fatalf("memoized present = (%v,%v,%v)", missing, exists, err)
	}

	// Absent service reads as missing — the normal orphansweep case.
	missing, exists, err = s.svcExists("backend/gone", "backend", "gone")
	if err != nil || !missing || exists {
		t.Fatalf("absent service = (%v,%v,%v), want (true,false,nil)", missing, exists, err)
	}
	snap.Services = []corev1.Service{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "backend", Name: "gone"}},
	}
	if missing, exists, err := s.svcExists("backend/gone", "backend", "gone"); err != nil || !missing || exists {
		t.Fatalf("memoized missing = (%v,%v,%v)", missing, exists, err)
	}

	if *gets != 0 {
		t.Fatalf("svcExists issued %d Service GETs, want 0 (snapshot only)", *gets)
	}
}

func TestCRDSweepSvcExistsCensusFailureIsUnverifiable(t *testing.T) {
	snap := &guardstate.Snapshot{
		Services:    []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Namespace: "backend", Name: "conv"}}},
		ServicesErr: errors.New("census flap"),
	}
	s, gets := crdSweepFixture(snap)

	missing, exists, err := s.svcExists("backend/conv", "backend", "conv")
	if err == nil || missing || exists {
		t.Fatalf("unreadable census = (%v,%v,%v), want error and no verdict", missing, exists, err)
	}
	if *gets != 0 {
		t.Fatalf("svcExists issued %d Service GETs, want 0", *gets)
	}
}
