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
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	sdbus "github.com/coreos/go-systemd/v22/dbus"
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
	if isFatalDialErr(os.ErrNotExist) {
		t.Fatal("os.ErrNotExist must NOT latch disabled (transient during daemon-reexec)")
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

func TestDBusHelpersAndDisabledPaths(t *testing.T) {
	if _, _, err := dialSystemdPrivate(filepath.Join(t.TempDir(), "missing.sock")); err == nil {
		t.Fatal("expected dialSystemdPrivate on missing socket to fail")
	}

	if !isTransportDead(io.EOF) || !isTransportDead(net.ErrClosed) || !isTransportDead(errors.New("connection reset by peer")) {
		t.Fatal("isTransportDead missed transport error")
	}
	if isTransportDead(errors.New("other")) {
		t.Fatal("isTransportDead matched unrelated error")
	}

	ctx, cancel := opCtx(context.Background())
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		t.Fatal("opCtx did not set deadline")
	}

	if v, ok := propUint32(uint32(7)); !ok || v != 7 {
		t.Fatalf("propUint32(7) = (%d,%v)", v, ok)
	}
	if v, ok := propUint32("9"); !ok || v != 9 {
		t.Fatalf("propUint32('9') = (%d,%v)", v, ok)
	}
	if _, ok := propUint32("bad"); ok {
		t.Fatal("propUint32('bad') returned ok")
	}

	b := newDBusBackend(t.TempDir())
	b.maybeDisable(errors.New("transient"))
	if b.disabled.Load() {
		t.Fatal("transient error disabled backend")
	}
	b.maybeDisable(os.ErrNotExist)
	if b.disabled.Load() {
		t.Fatal("ErrNotExist must not permanently disable backend")
	}
	b.maybeDisable(os.ErrPermission)
	if !b.disabled.Load() {
		t.Fatal("ErrPermission did not disable backend")
	}
	b.close()
	b.dropConn(&sdbus.Conn{})

	// Exercise all dbus* entry points against the disabled backend (returns errDBusUnavailable cleanly).
	if err := b.dbusJob(ctx, "restart", "foo.service"); !errors.Is(err, errDBusUnavailable) {
		t.Fatalf("dbusJob = %v", err)
	}
	if err := b.dbusSignal(ctx, "foo.service", "SIGTERM"); !errors.Is(err, errDBusUnavailable) {
		t.Fatalf("dbusSignal = %v", err)
	}
	if err := b.dbusDaemonReload(ctx); !errors.Is(err, errDBusUnavailable) {
		t.Fatalf("dbusDaemonReload = %v", err)
	}
	if err := b.dbusResetFailed(ctx, "foo.service"); !errors.Is(err, errDBusUnavailable) {
		t.Fatalf("dbusResetFailed = %v", err)
	}
	if _, err := b.unitProp(ctx, "foo.service", "ActiveState"); !errors.Is(err, errDBusUnavailable) {
		t.Fatalf("unitProp = %v", err)
	}
	if _, err := b.dbusActive(ctx, "foo.service"); !errors.Is(err, errDBusUnavailable) {
		t.Fatalf("dbusActive = %v", err)
	}
	if _, err := b.dbusExists(ctx, "foo.service"); !errors.Is(err, errDBusUnavailable) {
		t.Fatalf("dbusExists = %v", err)
	}
	if _, err := b.dbusActiveAge(ctx, "foo.service", "/proc/uptime"); !errors.Is(err, errDBusUnavailable) {
		t.Fatalf("dbusActiveAge = %v", err)
	}
	if _, err := b.dbusActiveEnterUSec(ctx, "foo.service"); !errors.Is(err, errDBusUnavailable) {
		t.Fatalf("dbusActiveEnterUSec = %v", err)
	}
	if _, err := b.dbusMainPID(ctx, "foo.service"); !errors.Is(err, errDBusUnavailable) {
		t.Fatalf("dbusMainPID = %v", err)
	}
	if _, err := b.dbusListUnitsByPatterns(ctx, []string{"*.service"}); !errors.Is(err, errDBusUnavailable) {
		t.Fatalf("dbusListUnitsByPatterns = %v", err)
	}
	if _, err := b.dbusEnabled(ctx, "foo.service"); !errors.Is(err, errDBusUnavailable) {
		t.Fatalf("dbusEnabled = %v", err)
	}
	if _, err := b.dbusSystemState(ctx); !errors.Is(err, errDBusUnavailable) {
		t.Fatalf("dbusSystemState = %v", err)
	}
}
