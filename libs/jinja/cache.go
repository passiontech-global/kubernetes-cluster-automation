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
// Given an immutable tree, the only shared mutable state is the LRU
// bookkeeping itself, which the mutex below guards. A cache hit hands
// the SAME []tnode slice to any number of goroutines concurrently —
// safe per the argument above (exercised by TestTemplateCache with
// -race). Renders of distinct sources parse OUTSIDE the lock so one
// slow parse never serializes unrelated renders.
package jinja

import (
	"container/list"
	"regexp"
	"sync"
)

// templateCacheCap bounds the AST cache. Callers re-render the same
// vendored .j2 sources many times (vars resolution re-renders one var
// per read; converge loops re-render unit templates per node), so a
// small fixed set covers the working set; 128 sources of template
// text are far below any real repo's template count while capping
// memory if a caller renders dynamic strings.
const templateCacheCap = 128

type templateCacheEntry struct {
	src   string
	nodes []tnode
}

var templateCache = struct {
	mu    sync.Mutex
	lru   *list.List // front = most recently used
	elems map[string]*list.Element
}{
	lru:   list.New(),
	elems: make(map[string]*list.Element, templateCacheCap),
}

// parsedTemplate returns the compiled node tree for src, memoized in
// the bounded LRU. Parse errors are NOT cached — an unparseable
// source re-errors identically on every render, and skipping the
// error path keeps the cache entries immutable success values.
func parsedTemplate(src string) ([]tnode, error) {
	templateCache.mu.Lock()
	if el, ok := templateCache.elems[src]; ok {
		templateCache.lru.MoveToFront(el)
		nodes := el.Value.(*templateCacheEntry).nodes
		templateCache.mu.Unlock()
		return nodes, nil
	}
	templateCache.mu.Unlock()

	nodes, err := parseTemplate(src)
	if err != nil {
		return nil, err
	}

	templateCache.mu.Lock()
	defer templateCache.mu.Unlock()
	// A concurrent render of the same source may have parsed and
	// inserted while we parsed outside the lock — keep ONE tree per
	// source (either is correct; sharing the winner keeps the LRU
	// bookkeeping and the "parse once per source" property).
	if el, ok := templateCache.elems[src]; ok {
		templateCache.lru.MoveToFront(el)
		return el.Value.(*templateCacheEntry).nodes, nil
	}
	templateCache.elems[src] = templateCache.lru.PushFront(&templateCacheEntry{src: src, nodes: nodes})
	if templateCache.lru.Len() > templateCacheCap {
		if back := templateCache.lru.Back(); back != nil {
			delete(templateCache.elems, back.Value.(*templateCacheEntry).src)
			templateCache.lru.Remove(back)
		}
	}
	return nodes, nil
}

// regexCache memoizes compiled patterns for the regex_* filters and
// the `is search` test — templates reuse a handful of fixed patterns
// and regexp.Compile parsed and NFA-built per call. Patterns
// normally originate in vendored template files (a bounded set), but
// a template can build a pattern from data (regex_replace on a
// user-controlled string), so the map is capped like logx's logger
// cache: past the cap new patterns compile per call — correct,
// just slower — rather than the map leaking.
var regexCache = struct {
	sync.RWMutex
	m map[string]*regexp.Regexp
}{m: make(map[string]*regexp.Regexp)}

// regexCacheCap bounds regexCache's live entries.
const regexCacheCap = 512

func cachedRegexp(pattern string) (*regexp.Regexp, error) {
	regexCache.RLock()
	re, ok := regexCache.m[pattern]
	regexCache.RUnlock()
	if ok {
		return re, nil
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	regexCache.Lock()
	defer regexCache.Unlock()
	// A racer may have cached the same pattern while we compiled —
	// keep the first (identical) result.
	if re, ok := regexCache.m[pattern]; ok {
		return re, nil
	}
	// At cap the pattern compiles fresh every call — correct,
	// uncached — rather than the map leaking.
	if len(regexCache.m) < regexCacheCap {
		regexCache.m[pattern] = compiled
	}
	return compiled, nil
}
