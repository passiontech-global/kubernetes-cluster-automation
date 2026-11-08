// allowed_persisted_test.go — AllowedVPersisted's gate folding: the
// persisted stamp defers before the mutex is ever read (a nil dyn
// client would make the mutex unverifiable, so (false,false) proves
// the early exit), the nil-object fold collapses to plain AllowedV
// verdicts, and the clear path reaches the mutex and proceeds.
package heal

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

func allowedPersistedObj() *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name: "target", Annotations: map[string]string{
			"passiontech.dev/last-heal": time.Now().
				Add(-time.Minute).UTC().Format(time.RFC3339),
		}},
		Data: map[string]string{"k": "v"},
	}
}

// A fresh persisted stamp defers the heal WITHOUT evaluating the
// maintenance mutex — dyn stays nil on purpose: reaching AllowedV's
// mutex would return unverifiable=true, so (false,false) is only
// reachable through the early exit.
func TestAllowedVPersistedStampDefersBeforeMutex(t *testing.T) {
	now := time.Now()
	obj := allowedPersistedObj()
	var ledger state.CooldownSet

	proceed, unverifiable := AllowedVPersisted(context.Background(),
		logr.Discard(), nil, fake.NewSimpleClientset(), nil,
		&ledger, obj, "passiontech.dev/last-heal", "k", time.Hour, now)
	if proceed || unverifiable {
		t.Fatalf("AllowedVPersisted = (%v,%v), want (false,false)",
			proceed, unverifiable)
	}
}

// The in-RAM half still defers on its own (the wider-of-two contract
// carries through): warm ledger, expired annotation.
func TestAllowedVPersistedLedgerHalfDefers(t *testing.T) {
	now := time.Now()
	obj := allowedPersistedObj()
	obj.Annotations["passiontech.dev/last-heal"] =
		now.Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	var ledger state.CooldownSet
	ledger.Stamp("k", now.Add(-time.Minute))

	proceed, unverifiable := AllowedVPersisted(context.Background(),
		logr.Discard(), nil, fake.NewSimpleClientset(), nil,
		&ledger, obj, "passiontech.dev/last-heal", "k", time.Hour, now)
	if proceed || unverifiable {
		t.Fatalf("AllowedVPersisted = (%v,%v), want (false,false)",
			proceed, unverifiable)
	}
}

// A nil obj collapses to plain AllowedV: the ledger-only cooldown
// defers exactly like AllowedV's cooled path, and with a clear
// ledger the mutex evaluates — here nil dyn makes it unverifiable,
// AllowedV's documented fail-closed verdict.
func TestAllowedVPersistedNilObjFoldsToAllowedV(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset()

	var cooled state.CooldownSet
	cooled.Stamp("k", now.Add(-time.Minute))
	if proceed, unver := AllowedVPersisted(context.Background(),
		logr.Discard(), nil, cs, nil, &cooled, nil,
		"passiontech.dev/last-heal", "k", time.Hour, now); proceed || unver {
		t.Fatalf("cooled ledger via nil obj = (%v,%v), want (false,false)",
			proceed, unver)
	}
	// An empty annoKey is the same fold — nothing to read off the
	// object — even with the object present.
	if proceed, unver := AllowedVPersisted(context.Background(),
		logr.Discard(), nil, cs, nil, &cooled, allowedPersistedObj(),
		"", "k", time.Hour, now); proceed || unver {
		t.Fatalf("empty annoKey = (%v,%v), want (false,false)",
			proceed, unver)
	}
	// Clear ledger: the gate falls through to the mutex, whose nil
	// dyn evaluation is unverifiable — the AllowedV verdict pair.
	var fresh state.CooldownSet
	if proceed, unver := AllowedVPersisted(context.Background(),
		logr.Discard(), nil, cs, nil, &fresh, nil,
		"passiontech.dev/last-heal", "k", time.Hour, now); proceed || !unver {
		t.Fatalf("clear ledger via nil obj = (%v,%v), want (false,true)",
			proceed, unver)
	}
}

// All gates clear (fresh stamp long expired, no maintenance signals
// in the fakes) — the heal proceeds and the verdict memoizes like
// AllowedV's.
func TestAllowedVPersistedClearGateProceeds(t *testing.T) {
	now := time.Now()
	obj := allowedPersistedObj()
	obj.Annotations["passiontech.dev/last-heal"] =
		now.Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	var ledger state.CooldownSet

	proceed, unverifiable := AllowedVPersisted(context.Background(),
		logr.Discard(), &kube.Verdict{}, fake.NewSimpleClientset(),
		testhelp.NewDynamicClient(), &ledger, obj,
		"passiontech.dev/last-heal", "k", time.Hour, now)
	if !proceed || unverifiable {
		t.Fatalf("AllowedVPersisted = (%v,%v), want (true,false)",
			proceed, unverifiable)
	}
}
