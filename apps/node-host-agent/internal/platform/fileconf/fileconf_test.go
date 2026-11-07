// fileconf_test.go — the reloader contract both consumers share:
// re-read per Get, absent file parses as empty content, keep-
// last-good on unreadable, the warn edge-latch vs WarnEveryGet,
// and the BlankPathHolds early return.
package fileconf

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// kv is the minimal conf type: parse fails on a "BAD" line, empty
// content yields the "defaults" marker — the watchdogconf/guard
// pattern of "absent file = defaults".
type kv struct{ v string }

func parse(data []byte) (kv, error) {
	s := strings.TrimSpace(string(data))
	if s == "" {
		return kv{v: "defaults"}, nil
	}
	if strings.HasPrefix(s, "BAD") {
		return kv{}, errors.New("bad conf")
	}
	return kv{v: s}, nil
}

// recordSink counts Warn/Info records so the latch assertions don't
// scrape log text.
type recordSink struct {
	warns, infos int
}

func (s *recordSink) Enabled(context.Context, slog.Level) bool { return true }
func (s *recordSink) Handle(_ context.Context, r slog.Record) error {
	switch r.Level {
	case slog.LevelWarn:
		s.warns++
	case slog.LevelInfo:
		s.infos++
	}
	return nil
}
func (s *recordSink) WithAttrs([]slog.Attr) slog.Handler { return s }
func (s *recordSink) WithGroup(string) slog.Handler      { return s }

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestGetRereadsAndAbsentParsesEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "conf")
	r := New(p, parse, kv{v: "seed"}, Options{})
	// Missing file → the empty-content parse, not the seed.
	if got := r.Get(); got.v != "defaults" {
		t.Fatalf("absent conf Get=%+v want defaults", got)
	}
	write(t, p, "v1")
	if got := r.Get(); got.v != "v1" {
		t.Fatalf("Get=%+v want v1", got)
	}
	// A rewrite lands on the very next Get.
	write(t, p, "v2")
	if got := r.Get(); got.v != "v2" {
		t.Fatalf("rewrite not picked up: %+v", got)
	}
	// Removing the file reverts to defaults again (shell `source`
	// parity: absent = defaults, not last-good).
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if got := r.Get(); got.v != "defaults" {
		t.Fatalf("removed conf Get=%+v want defaults", got)
	}
}

func TestKeepsLastGoodAndLatchesWarn(t *testing.T) {
	p := filepath.Join(t.TempDir(), "conf")
	sink := &recordSink{}
	r := New(p, parse, kv{v: "seed"}, Options{
		Log:          slog.New(sink),
		WarnMsg:      "test: conf unreadable",
		RecoveredMsg: "test: conf readable again",
	})
	write(t, p, "good")
	if got := r.Get(); got.v != "good" {
		t.Fatalf("Get=%+v want good", got)
	}
	// Unreadable path (a directory replaces the file) → the last
	// good value is kept and the warn fires ONCE per episode.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if got := r.Get(); got.v != "good" {
			t.Fatalf("unreadable conf must keep last good, got %+v", got)
		}
	}
	if sink.warns != 1 {
		t.Fatalf("warns=%d want 1 (edge-latched per episode)", sink.warns)
	}
	// A parse failure counts the same way: keep last good, stay
	// latched (the episode never recovered).
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	write(t, p, "BAD")
	if got := r.Get(); got.v != "good" {
		t.Fatalf("parse error must keep last good, got %+v", got)
	}
	if sink.warns != 1 {
		t.Fatalf("warns=%d want still 1 (same episode)", sink.warns)
	}
	// Recovery logs the readable-again info once.
	write(t, p, "back")
	if got := r.Get(); got.v != "back" {
		t.Fatalf("recovery Get=%+v want back", got)
	}
	if sink.infos != 1 {
		t.Fatalf("infos=%d want 1 (recovery logged once)", sink.infos)
	}
}

func TestWarnEveryGet(t *testing.T) {
	p := filepath.Join(t.TempDir(), "conf")
	sink := &recordSink{}
	r := New(p, parse, kv{v: "seed"}, Options{
		Log:          slog.New(sink),
		WarnMsg:      "test: reload failed",
		WarnEveryGet: true,
	})
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		r.Get()
	}
	if sink.warns != 3 {
		t.Fatalf("warns=%d want 3 (WarnEveryGet disables the latch)", sink.warns)
	}
	// No RecoveredMsg configured → recovery is silent.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	write(t, p, "ok")
	r.Get()
	if sink.infos != 0 {
		t.Fatalf("infos=%d want 0 (no RecoveredMsg configured)", sink.infos)
	}
}

func TestBlankPathHolds(t *testing.T) {
	// BlankPathHolds: an empty Path returns the current value
	// untouched — the guard conf's early return.
	r := New("", parse, kv{v: "keep"}, Options{BlankPathHolds: true})
	if got := r.Get(); got.v != "keep" {
		t.Fatalf("blank path Get=%+v want keep", got)
	}
	// Unset, an empty path opens ENOENT and parses as absent.
	r = New("", parse, kv{v: "keep"}, Options{})
	if got := r.Get(); got.v != "defaults" {
		t.Fatalf("blank path without hold Get=%+v want defaults", got)
	}
}

func TestLoadSharedFileContract(t *testing.T) {
	// The one-shot Load shares the reloader's file contract.
	v, err := Load(filepath.Join(t.TempDir(), "absent"), parse)
	if err != nil || v.v != "defaults" {
		t.Fatalf("Load(absent)=%+v err=%v want defaults,nil", v, err)
	}
	if _, err = Load(t.TempDir(), parse); err == nil ||
		!strings.Contains(err.Error(), "read ") {
		t.Fatalf("Load(dir) err=%v want wrapped read error", err)
	}
}
