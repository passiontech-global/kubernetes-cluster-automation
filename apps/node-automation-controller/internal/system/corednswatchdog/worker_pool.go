// worker_pool.go — the bounded per-pod fan-out the layer-2 DNS probe
// runs through. Every dnsFn call dials UDP+TCP :53 against one
// CoreDNS pod with multi-second timeouts; one goroutine per pod would
// let the sweep's wall-clock and socket count grow with the fleet,
// so the pool caps the in-flight probes and the verdicts still land
// in one deterministic sequential pass afterwards.
package corednswatchdog

import "sync"

// boundedForEach runs visit(i) for every index in [0, len(n)) with at
// most probePoolSize goroutines in flight, blocking until all of them
// finish. Each index runs exactly once; visit must only touch its own
// index (results slots) plus goroutine-safe seams — shared state
// (streak ledgers, maps) stays in the caller's sequential pass.
func boundedForEach(n []string, visit func(i int)) {
	if len(n) == 0 {
		return
	}
	sem := make(chan struct{}, probePoolSize)
	var wg sync.WaitGroup
	for i := range n {
		sem <- struct{}{} // blocks while probePoolSize probes are in flight
		wg.Go(func() {
			defer func() { <-sem }()
			visit(i)
		})
	}
	wg.Wait()
}
