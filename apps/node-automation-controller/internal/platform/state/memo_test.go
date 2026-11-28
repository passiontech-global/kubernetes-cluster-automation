// memo_test.go — unit tests for SweepMemo and KeyedSweepMemo.
package state

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestSweepMemoGetAndReset(t *testing.T) {
	var m SweepMemo[int]
	var calls atomic.Int32

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			v, err := m.Get(func() (int, error) {
				calls.Add(1)
				return 42, nil
			})
			if err != nil || v != 42 {
				t.Errorf("Get() = (%d, %v), want (42, nil)", v, err)
			}
		})
	}
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("load calls = %d, want 1", got)
	}

	m.Reset()
	v, err := m.Get(func() (int, error) {
		calls.Add(1)
		return 99, nil
	})
	if err != nil || v != 99 || calls.Load() != 2 {
		t.Fatalf("post-Reset Get() = (%d, %v) calls=%d, want (99, nil) calls=2", v, err, calls.Load())
	}
}

func TestSweepMemoGetSuccessRetriesErrors(t *testing.T) {
	var m SweepMemo[string]
	calls := 0
	_, err := m.GetSuccess(func() (string, error) {
		calls++
		return "", errors.New("boom")
	})
	if err == nil || calls != 1 {
		t.Fatalf("first GetSuccess err=%v calls=%d, want non-nil err, calls=1", err, calls)
	}
	v, err := m.GetSuccess(func() (string, error) {
		calls++
		return "ok", nil
	})
	if err != nil || v != "ok" || calls != 2 {
		t.Fatalf("second GetSuccess = (%q, %v) calls=%d, want (ok, nil) calls=2", v, err, calls)
	}
	v, err = m.GetSuccess(func() (string, error) {
		calls++
		return "stale", nil
	})
	if err != nil || v != "ok" || calls != 2 {
		t.Fatalf("cached GetSuccess = (%q, %v) calls=%d, want (ok, nil) calls=2", v, err, calls)
	}
}

func TestKeyedSweepMemo(t *testing.T) {
	var km KeyedSweepMemo[string, int]
	var calls atomic.Int32

	var wg sync.WaitGroup
	for i := range 8 {
		key := "v1"
		if i%2 == 1 {
			key = "v2"
		}
		wg.Go(func() {
			v, err := km.Get(key, func() (int, error) {
				calls.Add(1)
				return len(key), nil
			})
			if err != nil || v != 2 {
				t.Errorf("Get(%q) = (%d, %v), want (2, nil)", key, v, err)
			}
		})
	}
	wg.Wait()
	if got := calls.Load(); got != 2 {
		t.Fatalf("keyed load calls = %d, want 2", got)
	}
	km.Reset()
	_, _ = km.Get("v1", func() (int, error) {
		calls.Add(1)
		return 1, nil
	})
	if got := calls.Load(); got != 3 {
		t.Fatalf("post-Reset calls = %d, want 3", got)
	}
}
