//go:build linux

// dbus_linux_test.go — unit tests for the D-Bus backend's pure
// helpers: the unit-name normalizer, the fatal-dial classifier
// behind the disabled latch, the signal table, the property-value
// decoders and the not-found error matcher. The conn itself needs a
// real /run/systemd/private — untestable here by design (the CLI
// fallback is what systemd_test.go exercises through RunCmd fakes).
package systemd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestNormalizeUnit(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"k0sworker", "k0sworker.service"},
		{"k0sworker.service", "k0sworker.service"},
		{"nebula@interdc", "nebula@interdc.service"},
		{"foo.timer", "foo.timer"},
		{"foo.scope", "foo.scope"},
		{"foo.path", "foo.path"},
		{"foo.slice", "foo.slice"},
	} {
		if got := normalizeUnit(tc.in); got != tc.want {
			t.Fatalf("normalizeUnit(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsFatalDialErr(t *testing.T) {
	if !isFatalDialErr(os.ErrPermission) {
		t.Fatal("os.ErrPermission must latch disabled")
	}
	if !isFatalDialErr(os.ErrNotExist) {
		t.Fatal("os.ErrNotExist must latch disabled")
	}
	if !isFatalDialErr(fmt.Errorf("wrap: %w", syscall.EACCES)) {
		t.Fatal("EACCES must latch disabled")
	}
	if isFatalDialErr(errors.New("connection refused")) {
		t.Fatal("transient dial error must NOT latch disabled")
	}
	if isFatalDialErr(nil) {
		t.Fatal("nil must not latch")
	}
}

func TestDisabledLatchSkipsRedial(t *testing.T) {
	b := newDBusBackend(t.TempDir())
	b.disabled.Store(true)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := b.systemConn(ctx); err == nil {
		t.Fatal("disabled backend must report unavailable, not dial")
	} else if !errors.Is(err, errDBusUnavailable) {
		t.Fatalf("err=%v want errDBusUnavailable", err)
	}
}

func TestPropDecoders(t *testing.T) {
	if got := propString("active"); got != "active" {
		t.Fatalf("propString=%q", got)
	}
	if got := propString(uint64(3)); got != "" {
		t.Fatalf("propString(uint64)=%q want empty", got)
	}
	if v, ok := propUint64(uint64(42)); !ok || v != 42 {
		t.Fatalf("propUint64(uint64)=%d,%v", v, ok)
	}
	if v, ok := propUint64("12345"); !ok || v != 12345 {
		t.Fatalf("propUint64(string)=%d,%v", v, ok)
	}
	if _, ok := propUint64("n/a"); ok {
		t.Fatal("propUint64 must reject non-numeric")
	}
}

func TestIsNotFoundErr(t *testing.T) {
	for _, msg := range []string{
		"org.freedesktop.systemd1.NoSuchUnit",
		"load-state not-found",
		"UnknownObject",
	} {
		if !isNotFoundErr(errors.New(msg)) {
			t.Fatalf("isNotFoundErr(%q)=false", msg)
		}
	}
	if isNotFoundErr(errors.New("connection reset")) || isNotFoundErr(nil) {
		t.Fatal("non-not-found errors must not match")
	}
}

func TestSignalNumber(t *testing.T) {
	for sig, want := range map[string]int32{
		"TERM": 15, "SIGTERM": 15, "term": 15, "KILL": 9,
		"SIGUSR1": 10, "HUP": 1, "USR2": 12, "CONT": 18,
	} {
		if n, ok := signalNumber(sig); !ok || n != want {
			t.Fatalf("signalNumber(%q)=%d,%v want %d", sig, n, ok, want)
		}
	}
	if _, ok := signalNumber("SIGBOGUS"); ok {
		t.Fatal("unknown signal must not resolve")
	}
}
