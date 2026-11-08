// logx_test.go — For must bind the CURRENT slog.Default() per call.
package logx

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// For resolves slog.With at call time so a handler installed later by
// main() (the JSON handler) still sees the "logger" attribute — a
// package-level cache would freeze the pre-main default instead.
func TestForTagsLoggerAttribute(t *testing.T) {
	old := slog.Default()
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)

	For("probe").Info("hello")
	line := buf.String()
	if !strings.Contains(line, "logger=probe") {
		t.Fatalf("For output missing logger=probe: %q", line)
	}
	if !strings.Contains(line, "msg=hello") {
		t.Fatalf("For output missing msg=hello: %q", line)
	}
}
