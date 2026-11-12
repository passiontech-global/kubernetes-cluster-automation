// cache.go — render-time memoization: the compiled template AST and
// compiled regex patterns.
//
// THREAD-SAFETY OF THE AST CACHE: the node tree is shared across
// concurrent renders by design, which is only sound because rendering
// provably never mutates the AST.
//
//   - Every tnode.render / expr.eval implementation reads its own
//     struct fields and writes only render-local state: scope.vars
//     (a fresh map per Render call) and the output strings.Builder.
//     setNode assigns into scope.vars, forNode.bind likewise — the
//     nodes themselves are never assigned after parsing.
//   - The parser allocates a fresh tree per parse; the closures it
//     builds (cur/pushFrame/pop) capture parser state but are not
//     stored in nodes, and are dead once parsing returns.
//   - Values flowing through a render (List/OMap) are created during
//     evaluation, not during parsing; {% set %} rebinding swaps
//     pointers in the scope, never in the tree.
//
// Given an immutable tree, the only shared mutable state is the cache
// bookkeeping itself, which the mutexes below guard. A cache hit hands
// the SAME []tnode slice to any number of goroutines concurrently —
// safe per the argument above (exercised by TestTemplateCache with
// -race). Renders of distinct sources parse OUTSIDE the lock so one
// slow parse never serializes unrelated renders.
//
// Both caches are CLOCK (second-chance) rings behind sync.RWMutex:
// a hit takes only RLock, reads the payload, and sets the slot's
// atomic used-bit — no shared-memory write when the bit is already
// 1, no list.Element allocation, and a full cache still evicts (the
// clock hand sweeps) instead of degrading to never-cache like the
// old regex map did at its cap.
package jinja

import (
	"regexp"
	"sync"
	"sync/atomic"
)

// templateCacheCap bounds the AST cache. Callers re-render the same
// vendored .j2 sources many times (vars resolution re-renders one var
// per read; converge loops re-render unit templates per node), so a
// small fixed set covers the working set; 128 sources of template
// text are far below any real repo's template count while capping
// memory if a caller renders dynamic strings.
const templateCacheCap = 128

// clockEntry is one second-chance slot: the payload plus the used
// bit the clock hand inspects. used is atomic because the HIT path
// sets it under RLock (a read lock cannot write shared state
// non-atomically); only ever 0 or 1.
type clockEntry[V any] struct {
	key  string
	val  V
	used atomic.Uint32
}

// clockCache is a fixed-capacity cache using the CLOCK replacement
// policy: each slot carries a used-bit set on every hit; when the
// cache is full the hand sweeps the ring clearing bits (a second
// chance for hot entries) and evicts the first slot whose bit was
// already 0 — an approximation of LRU that needs no list and no
// per-hit write-lock.
type clockCache[V any] struct {
	mu    sync.RWMutex
	slots []clockEntry[V]
	byKey map[string]int // key -> slot index
	free  []int          // never-yet-used slot indices (LIFO)
	hand  int            // clock hand — next slot to inspect
}

func newClockCache[V any](cap int) *clockCache[V] {
	if cap < 1 {
		cap = 1
	}
	c := &clockCache[V]{
		slots: make([]clockEntry[V], cap),
		byKey: make(map[string]int, cap),
		// free must be EMPTY with room for cap — make([]int, cap)
		// would leave cap zero-valued entries that append turns
		// into 2*cap slots, every post-cap insert reusing slot 0
		// without evicting its byKey entry (cache leak + wrong
		// payload served for the displaced keys).
		free: make([]int, 0, cap),
	}
	for i := cap - 1; i >= 0; i-- {
		c.free = append(c.free, i)
	}
	return c
}

// get returns the cached value for key. A hit marks the slot used
// (its second chance): the CompareAndSwap writes NOTHING when the
// bit is already 1, so the hot path is RLock + map lookup + slice
// read + one atomic RMW — no allocation, no exclusive lock.
func (c *clockCache[V]) get(key string) (V, bool) {
	c.mu.RLock()
	idx, ok := c.byKey[key]
	if !ok {
		var zero V
		c.mu.RUnlock()
		return zero, false
	}
	e := &c.slots[idx]
	v := e.val
	e.used.CompareAndSwap(0, 1)
	c.mu.RUnlock()
	return v, true
}

// putIfAbsent inserts key→val when absent and returns the value now
// cached for key — the freshly inserted val, or the ALREADY-cached
// winner when a racer inserted while we worked outside the lock.
// First-wins keeps "one AST / one compiled regexp per key" without
// a second lookup.
func (c *clockCache[V]) putIfAbsent(key string, val V) V {
	c.mu.Lock()
	defer c.mu.Unlock()
	if idx, ok := c.byKey[key]; ok {
		e := &c.slots[idx]
		e.used.Store(1)
		return e.val
	}
	idx := c.allocLocked()
	e := &c.slots[idx]
	e.key = key
	e.val = val
	e.used.Store(1)
	c.byKey[key] = idx
	return val
}

// allocLocked picks a victim slot: a never-used one while any
// remain, else one clock sweep. Caller holds c.mu (write) — readers
// need RLock, so used-bits cannot change mid-sweep and the sweep
// terminates within cap bit-clears plus one eviction.
func (c *clockCache[V]) allocLocked() int {
	if n := len(c.free); n > 0 {
		idx := c.free[n-1]
		c.free = c.free[:n-1]
		return idx
	}
	for {
		i := c.hand
		c.hand = (c.hand + 1) % len(c.slots)
		e := &c.slots[i]
		if e.used.CompareAndSwap(1, 0) {
			continue // bit was set — second chance, hand moves on
		}
		// Bit already 0 — this slot is the eviction victim.
		delete(c.byKey, e.key)
		return i
	}
}

var templateCache = newClockCache[[]tnode](templateCacheCap)

// parsedTemplate returns the compiled node tree for src, memoized in
// the bounded clock cache. Parse errors are NOT cached — an
// unparseable source re-errors identically on every render, and
// skipping the error path keeps the cache entries immutable success
// values.
func parsedTemplate(src string) ([]tnode, error) {
	if nodes, ok := templateCache.get(src); ok {
		return nodes, nil
	}

	nodes, err := parseTemplate(src)
	if err != nil {
		return nil, err
	}

	// A concurrent render of the same source may have parsed and
	// inserted while we parsed outside the lock — putIfAbsent keeps
	// ONE tree per source (the winner's; either is correct since the
	// trees are immutable) and returns it.
	return templateCache.putIfAbsent(src, nodes), nil
}

// regexCache memoizes compiled patterns for the regex_* filters and
// the `is search` test — templates reuse a handful of fixed patterns
// and regexp.Compile parsed and NFA-built per call. Patterns
// normally originate in vendored template files (a bounded set), but
// a template can build a pattern from data (regex_replace on a
// user-controlled string), so the cache is capped like logx's logger
// cache: past the cap the clock hand evicts the coldest pattern —
// caching continues instead of degrading to compile-per-call.
var regexCache = newClockCache[*regexp.Regexp](regexCacheCap)

// regexCacheCap bounds regexCache's live entries.
const regexCacheCap = 512

func cachedRegexp(pattern string) (*regexp.Regexp, error) {
	if re, ok := regexCache.get(pattern); ok {
		return re, nil
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	// Compile failures stay uncached (they re-error identically);
	// putIfAbsent keeps the first of any racing duplicates.
	return regexCache.putIfAbsent(pattern, compiled), nil
}
