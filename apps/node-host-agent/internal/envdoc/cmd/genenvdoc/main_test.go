// main_test.go — emit's markdown row rendering: empty cells become
// "—", populated cells get backtick-quoted.
package main

import (
	"io"
	"os"
	"testing"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestEmit(t *testing.T) {
	for name, tc := range map[string]struct {
		envFlag, subsystem, def, want string
	}{
		"full row": {
			envFlag:   "NODE_HOST_AGENT_ENABLE_SWEEPER",
			subsystem: "sweeper", def: "auto",
			want: "| `NODE_HOST_AGENT_ENABLE_SWEEPER` | sweeper | `auto` |\n",
		},
		"all empty": {
			want: "| — | — | — |\n",
		},
		"unwired gate (no subsystem/default)": {
			envFlag: "NODE_HOST_AGENT_ENABLE_FEEDER",
			want:    "| `NODE_HOST_AGENT_ENABLE_FEEDER` | — | — |\n",
		},
		"hubsync (no env gate)": {
			subsystem: "hubsync",
			want:      "| — | hubsync | — |\n",
		},
	} {
		got := captureStdout(t, func() {
			emit(tc.envFlag, tc.subsystem, tc.def)
		})
		if got != tc.want {
			t.Fatalf("%s: emit row = %q want %q", name, got, tc.want)
		}
	}
}
