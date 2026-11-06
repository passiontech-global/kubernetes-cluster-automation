package shared

import (
	"errors"
	"testing"
)

func TestSetupWithConfigParsesBeforeGate(t *testing.T) {
	parsed, registered := false, false
	err := SetupWithConfig(Deps{Disabled: true},
		func() int { parsed = true; return 42 },
		func(int) error { registered = true; return nil })
	if err != nil {
		t.Fatalf("disabled module should return nil, got %v", err)
	}
	if !parsed {
		t.Fatal("parse must run even for a disabled module — its warnings fire")
	}
	if registered {
		t.Fatal("register must not run for a disabled module")
	}
}

func TestSetupWithConfigRegisters(t *testing.T) {
	var got int
	err := SetupWithConfig(Deps{}, // zero value = gate on
		func() int { return 7 },
		func(c int) error { got = c; return nil })
	if err != nil {
		t.Fatalf("register returned %v", err)
	}
	if got != 7 {
		t.Fatalf("register got config %d, want the parsed 7", got)
	}
}

func TestSetupWithConfigPropagatesError(t *testing.T) {
	want := errors.New("manager Add failed")
	err := SetupWithConfig(Deps{},
		func() int { return 1 },
		func(int) error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

// SetupNoConfig is the same gate without the parse step: Disabled
// skips register entirely, enabled runs it, and its error propagates.
func TestSetupNoConfigGate(t *testing.T) {
	registered := false
	err := SetupNoConfig(Deps{Disabled: true},
		func() error { registered = true; return nil })
	if err != nil {
		t.Fatalf("disabled module should return nil, got %v", err)
	}
	if registered {
		t.Fatal("register must not run for a disabled module")
	}

	registered = false
	if err := SetupNoConfig(Deps{}, // zero value = gate on
		func() error { registered = true; return nil }); err != nil {
		t.Fatalf("enabled module should return nil, got %v", err)
	}
	if !registered {
		t.Fatal("register must run for an enabled module")
	}
}

func TestSetupNoConfigPropagatesError(t *testing.T) {
	want := errors.New("manager Add failed")
	err := SetupNoConfig(Deps{}, func() error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}
