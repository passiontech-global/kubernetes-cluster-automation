package promfile

import (
	"errors"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
)

func TestTextfileDirAndScanLinesWithPrefixes(t *testing.T) {
	t.Setenv(envnames.EnvTextfileDir, "")
	if got := TextfileDir("/host"); got != "/host/var/lib/node-exporter/textfile" {
		t.Fatalf("default TextfileDir = %q", got)
	}
	t.Setenv(envnames.EnvTextfileDir, "/custom/dir")
	if got := TextfileDir("/host"); got != "/custom/dir" {
		t.Fatalf("env TextfileDir = %q", got)
	}

	input := "foo_metric 1\nbar_metric 2\nbaz_metric 3\nbar_other 4\n"
	got, err := ScanLinesWithPrefixes(strings.NewReader(input), [][]byte{[]byte("bar_")}, 0)
	if err != nil {
		t.Fatalf("ScanLinesWithPrefixes: %v", err)
	}
	if got != "bar_metric 2\nbar_other 4" {
		t.Fatalf("ScanLinesWithPrefixes = %q", got)
	}

	// maxBytes cap stops early.
	capped, err := ScanLinesWithPrefixes(strings.NewReader(input), [][]byte{[]byte("bar_")}, 5)
	if err != nil || capped != "bar_metric 2" {
		t.Fatalf("capped ScanLinesWithPrefixes = (%q,%v)", capped, err)
	}

	// Reader error propagates.
	if _, err := ScanLinesWithPrefixes(errReader{}, [][]byte{[]byte("a")}, 0); err == nil {
		t.Fatal("expected reader error")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }
