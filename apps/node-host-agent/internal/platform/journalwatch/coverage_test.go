package journalwatch

import (
	"errors"
	"slices"
	"testing"
)

func TestArgvBuildersAndClassifyRead(t *testing.T) {
	if got := UnitWindowArgv("kubelet.service", "5m ago"); !slices.Equal(got, []string{"journalctl", "-u", "kubelet.service", "--since", "5m ago", "--no-pager"}) {
		t.Fatalf("UnitWindowArgv = %v", got)
	}
	if got := UnitWindowGrepArgv("etcd.service", "-10m", "ERR|WARN"); !slices.Equal(got, []string{"journalctl", "-u", "etcd.service", "--since", "-10m", "--grep=ERR|WARN", "--no-pager"}) {
		t.Fatalf("UnitWindowGrepArgv = %v", got)
	}
	if got := AnyLineArgv(); !slices.Equal(got, []string{"journalctl", "-n", "1", "--no-pager"}) {
		t.Fatalf("AnyLineArgv = %v", got)
	}

	if cls, detail := ClassifyRead("out", errors.New("boom")); cls != ClassFailed || detail == "" {
		t.Fatalf("ClassifyRead(err) = (%v,%q)", cls, detail)
	}
	if cls, detail := ClassifyRead("No journal files were found.", nil); cls != ClassFilesGone || detail == "" {
		t.Fatalf("ClassifyRead(files gone) = (%v,%q)", cls, detail)
	}
	if cls, _ := ClassifyRead("   \n\t ", nil); cls != ClassEmpty {
		t.Fatalf("ClassifyRead(empty) = %v, want ClassEmpty", cls)
	}
	if cls, _ := ClassifyRead("May 01 00:00:00 host unit: ok", nil); cls != ClassOK {
		t.Fatalf("ClassifyRead(ok) = %v, want ClassOK", cls)
	}
}
