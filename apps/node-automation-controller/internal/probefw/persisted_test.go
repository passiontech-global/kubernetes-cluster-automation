// persisted_test.go — the first-seen→min-age window contract of
// Persisted: a fresh key stamps and stays inside the window, a
// tracked key counts only once now-first >= minAge, and keys track
// independently.
package probefw

import (
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

func TestPersistedWindow(t *testing.T) {
	var fs state.FirstSeenLedger
	now := time.Now()
	const minAge = 5 * time.Minute
	log := logr.Discard()

	// First sight: stamps the key and reports inside the window.
	if Persisted(&fs, "sig/one", now, minAge, log) {
		t.Fatal("first sight reported persisted")
	}
	// Tracked but younger than minAge — still inside the window.
	if Persisted(&fs, "sig/one", now.Add(minAge-time.Second), minAge, log) {
		t.Fatal("in-window observation reported persisted")
	}
	// age == minAge counts.
	if !Persisted(&fs, "sig/one", now.Add(minAge), minAge, log) {
		t.Fatal("age >= minAge did not report persisted")
	}
	// A different key tracks independently — first sight even now.
	if Persisted(&fs, "sig/two", now.Add(2*minAge), minAge, log) {
		t.Fatal("fresh second key reported persisted")
	}
}
