// util_test.go — the parse/quote/state-file helpers' edge cases the
// parent-package integration tests never reach in-package: pair and
// triple first-field parse failures, .env quoting/comment corners and
// the WriteIntFile write-failure warn path.
package kdeps

import (
	"os"
	"path/filepath"
	"testing"
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
