// memo.go — generic per-sweep memoization primitives usable across
// packages (including leaf and domain packages that do not pull in
// probefw.Snapshot). Zero values are ready to use without constructors.
package state

import "sync"

// SweepMemo caches one sweep-scoped value under a mutex so concurrent
// or repeated callers inside a sweep invoke load at most once.
type SweepMemo[T any] struct {
	mu     sync.Mutex
	val    T
	err    error
	loaded bool
}

// Get returns the memoized (val, err), calling load on the first call
// (including memoizing errors for uniform per-sweep failure behavior).
func (m *SweepMemo[T]) Get(load func() (T, error)) (T, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.loaded {
		m.val, m.err = load()
		m.loaded = true
	}
	return m.val, m.err
}

// GetSuccess returns the cached value or invokes load until a call
// succeeds (err == nil); failed loads are not cached.
func (m *SweepMemo[T]) GetSuccess(load func() (T, error)) (T, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.loaded {
		v, err := load()
		if err != nil {
			return v, err
		}
		m.val = v
		m.loaded = true
	}
	return m.val, nil
}

// Reset clears any memoized result so the next Get re-runs load.
func (m *SweepMemo[T]) Reset() {
	m.mu.Lock()
	var zero T
	m.val, m.err, m.loaded = zero, nil, false
	m.mu.Unlock()
}

// KeyedSweepMemo caches per-key sweep results under a shared mutex,
// memoizing both values and errors per key so repeated lookups for the
// same GroupVersion/resource within one sweep execute load once.
type KeyedSweepMemo[K comparable, T any] struct {
	mu      sync.Mutex
	entries map[K]keyedMemoEntry[T]
}

type keyedMemoEntry[T any] struct {
	val T
	err error
}

// Get returns the memoized result for key, running load on first access.
func (m *KeyedSweepMemo[K, T]) Get(key K, load func() (T, error)) (T, error) {
	m.mu.Lock()
	if e, ok := m.entries[key]; ok {
		m.mu.Unlock()
		return e.val, e.err
	}
	m.mu.Unlock()

	v, err := load()

	m.mu.Lock()
	if m.entries == nil {
		m.entries = map[K]keyedMemoEntry[T]{}
	}
	if e, ok := m.entries[key]; ok {
		m.mu.Unlock()
		return e.val, e.err
	}
	m.entries[key] = keyedMemoEntry[T]{val: v, err: err}
	m.mu.Unlock()
	return v, err
}

// Reset drops all cached entries.
func (m *KeyedSweepMemo[K, T]) Reset() {
	m.mu.Lock()
	m.entries = nil
	m.mu.Unlock()
}
