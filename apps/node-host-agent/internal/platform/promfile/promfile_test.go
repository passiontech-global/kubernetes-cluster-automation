package promfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuilderGaugeFamilies(t *testing.T) {
	var b Builder
	b.Gauge("m_one", "first metric", 1)
	b.GaugeLabels("m_two", "second metric", `check="x"`, 2.5)
	// Same family twice: header must appear exactly once.
	b.GaugeLabels("m_two", "second metric", `check="y"`, 0)
	want := "# HELP m_one first metric\n" +
		"# TYPE m_one gauge\n" +
		"m_one 1\n" +
		"# HELP m_two second metric\n" +
		"# TYPE m_two gauge\n" +
		"m_two{check=\"x\"} 2.5\n" +
		"m_two{check=\"y\"} 0\n"
	if got := b.String(); got != want {
		t.Fatalf("output mismatch:\n got %q\nwant %q", got, want)
	}
}

func TestBuilderHeaderOnly(t *testing.T) {
	var b Builder
	b.Header("m_absent", "headers only")
	b.Header("m_absent", "headers only")
	want := "# HELP m_absent headers only\n" +
		"# TYPE m_absent gauge\n"
	if got := b.String(); got != want {
		t.Fatalf("output mismatch:\n got %q\nwant %q", got, want)
	}
}

func TestBuilderHeaderTypeAndLine(t *testing.T) {
	var b Builder
	b.HeaderType("m_ctr", "counter family", "counter")
	b.Line("m_ctr 7")
	want := "# HELP m_ctr counter family\n" +
		"# TYPE m_ctr counter\n" +
		"m_ctr 7\n"
	if got := b.String(); got != want {
		t.Fatalf("output mismatch:\n got %q\nwant %q", got, want)
	}
}

func TestEscapeLabelValue(t *testing.T) {
	got := EscapeLabelValue("a\\b\"c\nd")
	if want := `a\\b\"c\nd`; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, "kine-db.prom", []byte("m 1\n")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "kine-db.prom"))
	if err != nil || string(data) != "m 1\n" {
		t.Fatalf("content=%q err=%v", data, err)
	}
	// No staging leftovers.
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("leftovers: %v", ents)
	}
	// Second write replaces.
	if err := Write(dir, "kine-db.prom", []byte("m 2\n")); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(dir, "kine-db.prom"))
	if string(data) != "m 2\n" {
		t.Fatalf("content=%q", data)
	}
}

func TestWriteCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "textfile")
	if err := Write(dir, "x.prom", []byte("m 1\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "x.prom")); err != nil {
		t.Fatal(err)
	}
}

// TestWriteLogged: the one logged writer every textfile emitter
// routes through — success stays quiet, a failure reports exactly
// once through the caller's channel AND still returns the error, and
// a nil onFail degrades to plain Write.
func TestWriteLogged(t *testing.T) {
	dir := t.TempDir()
	var fails []string
	onFail := func(d, name string, err error) {
		fails = append(fails, d+"/"+name+": "+err.Error())
	}

	if err := WriteLogged(dir, "kine-db.prom", []byte("m 1\n"), onFail); err != nil {
		t.Fatal(err)
	}
	if len(fails) != 0 {
		t.Fatalf("successful install must stay quiet: %v", fails)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "kine-db.prom")); err != nil ||
		string(data) != "m 1\n" {
		t.Fatalf("content=%q err=%v", data, err)
	}

	// A dir that is an existing FILE → MkdirAll fails → one report +
	// the error propagates.
	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := WriteLogged(notADir, "y.prom", []byte("m 2\n"), onFail)
	if err == nil {
		t.Fatal("unwritable dir want error")
	}
	if len(fails) != 1 || !strings.Contains(fails[0], notADir+"/y.prom") {
		t.Fatalf("failure not reported exactly once: %v", fails)
	}
	if !strings.Contains(fails[0], err.Error()) {
		t.Fatalf("reported failure %q must carry the returned error %v", fails[0], err)
	}

	// nil onFail degrades to plain Write (same error, no panic).
	if err := WriteLogged(notADir, "z.prom", []byte("m 3\n"), nil); err == nil {
		t.Fatal("nil onFail must still return the error")
	}
}

func TestStagingNameEscapesPromGlob(t *testing.T) {
	// node_exporter ingests every file matching *.prom — the
	// staging name must never match, or a partially-written file
	// could be scraped (and ".tmp-x.prom" DOES match: glob *
	// swallows the leading dot).
	dir := t.TempDir()
	f, err := os.CreateTemp(dir, stagingPattern("node-watchdog.prom"))
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Base(f.Name())
	_ = f.Close()
	if ok, _ := filepath.Match("*.prom", base); ok {
		t.Fatalf("staging name %q matches the *.prom glob", base)
	}
	if ok, _ := filepath.Match("*.prom", ".tmp-node-watchdog.prom"); !ok {
		t.Fatal("sanity: the .tmp- prefix really does match *.prom")
	}
	if ok, _ := filepath.Match("*.prom", "node-watchdog.prom"); !ok {
		t.Fatal("sanity: the final name must match the *.prom glob")
	}
	if !strings.HasPrefix(base, ".node-watchdog.prom.") {
		t.Fatalf("staging name %q lost the leading-dot convention", base)
	}
}
