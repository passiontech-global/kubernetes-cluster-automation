package checkkit

import "testing"

func TestProgress(t *testing.T) {
	if got := Progress(1, 3); got != " (check 1/3)" {
		t.Fatalf("Progress(1,3) = %q", got)
	}
}

func TestPendingBelowNeededLogsAndReportsPending(t *testing.T) {
	n := 0
	var logged []string
	if !Pending(3, &n, "suspect: thing bad", func(s string) {
		logged = append(logged, s)
	}) {
		t.Fatal("Pending reported confirmed below needed")
	}
	if n != 1 {
		t.Fatalf("streak = %d, want 1", n)
	}
	if len(logged) != 1 || logged[0] != "suspect: thing bad (check 1/3)" {
		t.Fatalf("logged = %v", logged)
	}
}

func TestPendingAtNeededConfirmsWithoutLogging(t *testing.T) {
	n := 1
	logged := false
	if Pending(2, &n, "suspect: thing bad", func(string) { logged = true }) {
		t.Fatal("Pending reported pending at needed")
	}
	if n != 2 {
		t.Fatalf("streak = %d, want 2", n)
	}
	if logged {
		t.Fatal("Pending logged on the confirmed cycle")
	}
}

func TestPendingNeededOneConfirmsFirstFailure(t *testing.T) {
	n := 0
	if Pending(1, &n, "x", nil) {
		t.Fatal("needed=1 must confirm on the first failure")
	}
}

func TestPendingNilLogfCountsSilently(t *testing.T) {
	n := 0
	if !Pending(2, &n, "x", nil) {
		t.Fatal("Pending reported confirmed below needed")
	}
}
