// kernel_close_test.go — coverage for the closeKmsg seam: the
// read-error path drops the kmsg handle and the next sync reopens
// it lazily (no data loss, partial-line carry survives in the
// tailer).
package npd

import (
	"context"
	"testing"
)

func TestCloseKmsgReopensOnNextSync(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()

	if err := e.m.SyncKernelMonitor(ctx, e.sink); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	// The sync opened the kmsg tailer — drop the handle the way the
	// read-error path does.
	e.m.closeKmsg()

	// A later sync must still work (lazy reopen) and classify lines.
	e.appendKmsg(t, "6,1,3599000000,-;INFO: task rm:123 blocked for more than 120 seconds.")
	if err := e.m.SyncKernelMonitor(ctx, e.sink); err != nil {
		t.Fatalf("sync after closeKmsg: %v", err)
	}
	if got := e.sink.counter("TaskHung"); got != 1 {
		t.Fatalf("problem_counter{TaskHung}=%d want 1 after reopen", got)
	}
}
