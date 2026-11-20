// util_test.go — the parse/quote/state-file helpers' edge cases the
// parent-package integration tests never reach in-package: pair and
// triple first-field parse failures, .env quoting/comment corners and
// the WriteIntFile write-failure warn path.
package kdeps

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParsePairHappyPath(t *testing.T) {
	a, b, err := ParsePair(" 10 | 20 \nignored second line\n")
	if err != nil || a != 10 || b != 20 {
		t.Fatalf("ParsePair = %d,%d,%v want 10,20,nil", a, b, err)
	}
	if _, _, err := ParsePair("x|2\n"); err == nil {
		t.Fatal("bad first field must error")
	}
}

func TestParseTripleFirstFieldError(t *testing.T) {
	// Field-1 and field-3 parse failures are already covered —
	// field 2 is the remaining gap.
	if _, _, _, err := ParseTriple("x|2|3\n"); err == nil {
		t.Fatal("bad first field must error")
	}
}

func TestEnvValueQuotingAndComments(t *testing.T) {
	data := "DOUBLE=\"a b\"\n" +
		"SINGLE='x y'\n" +
		"UNCLOSED=\"rest\n" +
		"COMMENTED=value # note\n" +
		"HASHY=a#b\n" + // '#' mid-token is NOT a comment — ` #` only
		"EMPTY=\n" +
		"export EXPORTED=ok\n"
	cases := map[string]string{
		"DOUBLE":    "a b",
		"SINGLE":    "x y",
		"UNCLOSED":  "rest", // unmatched opener: quote dropped, rest kept
		"COMMENTED": "value",
		"HASHY":     "a#b",
		"EMPTY":     "",
		"EXPORTED":  "ok",
		"MISSING":   "",
	}
	for key, want := range cases {
		if got := EnvValue(data, key); got != want {
			t.Errorf("EnvValue(%s) = %q want %q", key, got, want)
		}
	}
}

// The write failure path warns rather than panics or dying — the
// guard loops keep running even when the state dir goes bad. A
// target path that IS a directory makes the atomic rename fail after
// a successful stage+write.
func TestWriteIntFileFailureIsQuiet(t *testing.T) {
	target := filepath.Join(t.TempDir(), "is-a-dir")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	WriteIntFile(target, 42) // must not panic
	if fi, err := os.Stat(target); err != nil || !fi.IsDir() {
		t.Fatal("the directory target was clobbered")
	}
}

func TestCooldownActive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "last-test")
	now := time.Unix(1700000000, 0)
	window := 22 * time.Hour

	if CooldownActive(path, now, window, false) {
		t.Fatal("missing epoch file must not be active")
	}

	WriteIntFile(path, now.Add(-1*time.Hour).Unix())
	if !CooldownActive(path, now, window, false) {
		t.Fatal("1h ago must be active inside 22h window")
	}

	WriteIntFile(path, now.Add(-23*time.Hour).Unix())
	if CooldownActive(path, now, window, false) {
		t.Fatal("23h ago must be expired outside 22h window")
	}

	// Sub-minute future skew (-30s): active, no rewrite.
	skew30 := now.Add(30 * time.Second).Unix()
	WriteIntFile(path, skew30)
	if !CooldownActive(path, now, window, false) {
		t.Fatal("sub-minute future skew should stay active")
	}
	if got, _ := ReadIntFile(path); got != skew30 {
		t.Fatalf("sub-minute skew rewrote file: got %d want %d", got, skew30)
	}

	// Large future skew (+5h) in readOnly: active, no file rewrite.
	skew5h := now.Add(5 * time.Hour).Unix()
	WriteIntFile(path, skew5h)
	if !CooldownActive(path, now, window, true) {
		t.Fatal("large future skew in readOnly should stay active")
	}
	if got, _ := ReadIntFile(path); got != skew5h {
		t.Fatalf("readOnly rewrote epoch file: got %d want %d", got, skew5h)
	}

	// Large future skew (+5h) writable: active and self-healed to now.
	if !CooldownActive(path, now, window, false) {
		t.Fatal("large future skew should stay active while healing")
	}
	if got, _ := ReadIntFile(path); got != now.Unix() {
		t.Fatalf("future skew not self-healed to now: got %d want %d", got, now.Unix())
	}
	if CooldownActive(path, now.Add(window+time.Second), window, false) {
		t.Fatal("self-healed cooldown must expire after one window")
	}
}
