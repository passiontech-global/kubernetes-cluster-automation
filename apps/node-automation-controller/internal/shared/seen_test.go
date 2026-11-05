package shared

import "testing"

func TestSeenSetAddOnce(t *testing.T) {
	var s SeenSet
	if !s.Add("a") {
		t.Fatal("first Add should report new")
	}
	if s.Add("a") {
		t.Fatal("second Add of the same key should not report new")
	}
	if !s.Has("a") {
		t.Fatal("Has should see the added key")
	}
	if s.Has("b") {
		t.Fatal("Has should not see an unknown key")
	}
}

func TestSeenSetPrune(t *testing.T) {
	var s SeenSet
	s.Add("a")
	s.Add("b")
	s.Add("c")
	if n := s.Prune(func(k string) bool { return k != "b" }); n != 1 {
		t.Fatalf("Prune dropped %d keys, want 1", n)
	}
	if s.Has("b") || !s.Has("a") || !s.Has("c") {
		t.Fatal("Prune kept the wrong keys")
	}
	// A re-added pruned key reads as new again (re-arms the once-action).
	if !s.Add("b") {
		t.Fatal("re-Add of a pruned key should report new")
	}
}
