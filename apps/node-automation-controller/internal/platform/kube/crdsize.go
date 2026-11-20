// crdsize.go — the informer-fed CRD size side table for the
// api-object-sprawl kine large-object census: the manager cache's
// CustomResourceDefinition transform records each CRD's full
// serialized size HERE, before stripping .spec.versions[*].schema off
// the cached object, so the census reads (name, RV) → size from this
// table instead of re-listing multi-MB CRD bodies every cycle (the
// watch-cache re-serialization of full schemas across the
// apiserver/Kine path was ~1.5–2 GiB/hour of datastore churn).
//
// The table lives in the platform leaf because the producer
// (cmd/manager's cache transform) and the consumer
// (health/watchdogs/sprawl) share no other package: the check side is
// a probefw.CheckReg row whose constructor is typed
// `func(*probefw.Deps) probefw.Check`, so the NodeReader-style
// Deps threading has no seam to flow through. A process-wide instance
// is exact here — there is one manager cache per process, and the
// empty-table miss path degrades to the legacy full-object measure
// (tests and pre-sync windows measure live, byte-identical output).
package kube

import (
	"sync"
	"sync/atomic"
)

var crdInformerDisabled atomic.Bool

// SetCRDInformerEnabled records whether the CRD watch informer was enabled
// after the startup SSAR check.
func SetCRDInformerEnabled(enabled bool) {
	crdInformerDisabled.Store(!enabled)
}

// CRDInformerEnabled reports whether cached CRD reads are allowed to invoke
// the manager informer without lazily opening a forbidden CRD watch.
func CRDInformerEnabled() bool {
	return !crdInformerDisabled.Load()
}

// crdSizeTableCap bounds the table. A cluster carries tens of CRDs
// that update a handful of times a day, so the steady state is a few
// hundred (name, RV) entries; the cap only exists so a pathological
// update storm (CRD churn loops) cannot grow the map unbounded.
const crdSizeTableCap = 1024

// crdSizeEntry stores the latest observed resourceVersion and JSON
// byte size for one CRD name so updates overwrite in O(1).
type crdSizeEntry struct {
	rv   string
	size int64
}

// CRDSizeTable is the bounded name → (resourceVersion, full-object
// JSON size) map the CRD cache transform writes and the kine census
// reads.
type CRDSizeTable struct {
	mu       sync.RWMutex
	m        map[string]crdSizeEntry
	capacity int
}

// CRDSizeIndex is the process-wide table — cmd/manager's CRD cache
// transform is the writer, the sprawl kine census the reader. Never
// nil: an unwired (empty) table simply misses, and the consumer's
// miss path keeps the legacy measurement.
var CRDSizeIndex = NewCRDSizeTable(crdSizeTableCap)

// NewCRDSizeTable builds a table with the given entry capacity.
func NewCRDSizeTable(capacity int) *CRDSizeTable {
	return &CRDSizeTable{m: map[string]crdSizeEntry{}, capacity: capacity}
}

// Record stamps one CRD's full serialized size. Called from the
// informer transform (watch goroutine) before the object is stripped;
// the size is the json.Marshal-equivalent byte count of the UNSTRIPPED
// object — exactly the number the pre-table census measured.
func (t *CRDSizeTable) Record(name, rv string, size int64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[string]crdSizeEntry{}
	}
	// Only a NEW CRD name can grow the map — an RV update overwrites
	// in place in O(1) without leaving stale RV entries behind. Past
	// capacity, drop roughly half the entries (map iteration order —
	// the survivors are repopulated by the next informer pass/lookup
	// fallback, and a miss costs one live read, never a wrong number).
	if _, ok := t.m[name]; !ok && len(t.m) >= t.capacity {
		target := t.capacity / 2
		for k := range t.m {
			if len(t.m) <= target {
				break
			}
			delete(t.m, k)
		}
	}
	t.m[name] = crdSizeEntry{rv: rv, size: size}
}

// Lookup returns the recorded full-object size for name at the given
// resourceVersion — ok=false when the informer has not seen that
// (name, RV) pair yet (fresh CRD inside the watch-latency window, or
// an unwired table): the consumer then measures live.
func (t *CRDSizeTable) Lookup(name, rv string) (int64, bool) {
	if t == nil {
		return 0, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.m[name]
	if !ok || e.rv != rv {
		return 0, false
	}
	return e.size, true
}
