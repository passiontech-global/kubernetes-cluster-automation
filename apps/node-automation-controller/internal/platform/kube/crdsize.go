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

import "sync"

// crdSizeTableCap bounds the table. A cluster carries tens of CRDs
// that update a handful of times a day, so the steady state is a few
// hundred (name, RV) entries; the cap only exists so a pathological
// update storm (CRD churn loops) cannot grow the map unbounded.
const crdSizeTableCap = 1024

// crdSizeKey is name+RV: the RV half makes a re-created CRD's fresh
// object miss the old entry instead of inheriting its size.
type crdSizeKey struct{ name, rv string }

// CRDSizeTable is the bounded (name, resourceVersion) →
// full-object JSON size map the CRD cache transform writes and the
// kine census reads.
type CRDSizeTable struct {
	mu       sync.RWMutex
	m        map[crdSizeKey]int64
	capacity int
}

// CRDSizeIndex is the process-wide table — cmd/manager's CRD cache
// transform is the writer, the sprawl kine census the reader. Never
// nil: an unwired (empty) table simply misses, and the consumer's
// miss path keeps the legacy measurement.
var CRDSizeIndex = NewCRDSizeTable(crdSizeTableCap)

// NewCRDSizeTable builds a table with the given entry capacity.
func NewCRDSizeTable(capacity int) *CRDSizeTable {
	return &CRDSizeTable{m: map[crdSizeKey]int64{}, capacity: capacity}
}

// Record stamps one CRD's full serialized size. Called from the
// informer transform (watch goroutine) before the object is stripped;
// the size is the json.Marshal-equivalent byte count of the UNSTRIPPED
// object — exactly the number the pre-table census measured.
func (t *CRDSizeTable) Record(name, rv string, size int64) {
	k := crdSizeKey{name, rv}
	t.mu.Lock()
	defer t.mu.Unlock()
	// Only a NEW key can grow the map — an update overwrites in
	// place. Past capacity, drop roughly half the entries (map
	// iteration order — the survivors are repopulated by the next
	// informer pass/lookup fallback, and a miss costs one live read,
	// never a wrong number).
	if _, ok := t.m[k]; !ok && len(t.m) >= t.capacity {
		target := t.capacity / 2
		for k := range t.m {
			if len(t.m) <= target {
				break
			}
			delete(t.m, k)
		}
	}
	t.m[k] = size
}

// Lookup returns the recorded full-object size for name at the given
// resourceVersion — ok=false when the informer has not seen that
// (name, RV) pair yet (fresh CRD inside the watch-latency window, or
// an unwired table): the consumer then measures live.
func (t *CRDSizeTable) Lookup(name, rv string) (int64, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	size, ok := t.m[crdSizeKey{name, rv}]
	return size, ok
}
