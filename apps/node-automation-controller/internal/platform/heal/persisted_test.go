package heal

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// The wider-of-both verdict: a warm stamp on EITHER clock cools the
// key — the in-RAM ledger covers a stamp whose patch never landed,
// the annotation survives the restart that wiped the ledger.
func TestPersistedCooledDownWiderOfBoth(t *testing.T) {
	now := time.Now()
	recent := now.Add(-time.Minute)

	var ledger state.CooldownSet
	ledger.Stamp("ledgered", recent)
	obj := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Annotations: map[string]string{
			"passiontech.dev/last-heal": recent.UTC().Format(time.RFC3339),
		},
	}}
	cool := time.Hour

	for _, tc := range []struct {
		name      string
		ledger    *state.CooldownSet
		obj       metav1.Object
		ledgerKey string
		want      bool
	}{
		{"ledger warm", &ledger, &corev1.Pod{}, "ledgered", true},
		{"anno warm", nil, obj, "k", true},
		{"neither", &state.CooldownSet{}, &corev1.Pod{}, "k", false},
		{"nil ledger + bare obj", nil, &corev1.Pod{}, "k", false},
		{"nil obj", &ledger, nil, "ledgered", true},
		{"expired anno", nil, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"passiontech.dev/last-heal": now.Add(-2 * time.Hour).
					UTC().Format(time.RFC3339)}}}, "k", false},
		// Legacy unix-seconds stamps still read through AnnoTime.
		{"unix anno", nil, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"passiontech.dev/last-heal": "1762871400"}}},
			"k", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			when := now
			if tc.name == "unix anno" {
				// The fixed unix stamp is inside the window only
				// relative to a matching now.
				when = time.Unix(1762871400, 0).Add(time.Minute)
			}
			got := PersistedCooledDown(tc.ledger, tc.obj,
				"passiontech.dev/last-heal", tc.ledgerKey, cool, when)
			if got != tc.want {
				t.Fatalf("PersistedCooledDown = %v, want %v", got, tc.want)
			}
		})
	}
}

// The delivered-only contract: the ledger stamps ONLY when the patch
// lands — a failed patch must not sit the heal out for the window.
func TestStampPersistedStampsOnlyOnDelivery(t *testing.T) {
	now := time.Now()

	var ledger state.CooldownSet
	err := StampPersisted(ctx,
		func(context.Context, []byte) error { return errors.New("patch rejected") },
		"passiontech.dev/last-heal", &ledger, "k", now)
	if err == nil {
		t.Fatal("patch error not propagated")
	}
	if ledger.CooledDown("k", time.Hour, now) {
		t.Fatal("failed patch stamped the ledger")
	}

	var payload []byte
	err = StampPersisted(ctx,
		func(_ context.Context, data []byte) error {
			payload = data
			return nil
		},
		"passiontech.dev/last-heal", &ledger, "k", now)
	if err != nil {
		t.Fatal(err)
	}
	if !ledger.CooledDown("k", time.Hour, now) {
		t.Fatal("delivered patch did not stamp the ledger")
	}
	// The patch doc is the metadata.annotations merge patch with an
	// RFC3339 stamp — what every hand-rolled site marshaled.
	want := `{"metadata":{"annotations":{"passiontech.dev/last-heal":"` +
		now.UTC().Format(time.RFC3339) + `"}}}`
	if string(payload) != want {
		t.Fatalf("payload = %s, want %s", payload, want)
	}
}

// A nil ledger skips the in-RAM half — the annotation alone persists.
func TestStampPersistedNilLedger(t *testing.T) {
	if err := StampPersisted(ctx,
		func(context.Context, []byte) error { return nil },
		"passiontech.dev/last-heal", nil, "k", time.Now()); err != nil {
		t.Fatal(err)
	}
}
