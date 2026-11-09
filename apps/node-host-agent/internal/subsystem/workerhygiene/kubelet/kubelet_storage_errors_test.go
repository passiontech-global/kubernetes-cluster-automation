// kubelet_storage_errors_test.go — disk-slow-io coverage: the
// kubelet-syncloop :10250/metrics scrape now also parses
// storage_operation_errors_total into the
// node_kubelet_storage_operation_errors_total textfile series —
// summed across the volume_plugin/operation labels, exported even
// when the PLEG family is absent from the scrape.
package kubelet_test

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestStorageOperationErrorsExported: every labelled sample of
// storage_operation_errors_total sums into the node-level
// counter — the scrape already runs for the PLEG series, so the
// export costs no extra call.
func TestStorageOperationErrorsExported(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.MetricsBody = fmt.Sprintf(`# HELP storage_operation_errors_total x
storage_operation_errors_total{operation_name="volume_attach",volume_plugin="kubernetes.io/csi"} 3
storage_operation_errors_total{operation_name="volume_mount",volume_plugin="kubernetes.io/csi"} 2
kubelet_pleg_last_seen_seconds %d
`, time.Now().Unix())
	e.H.Cycle(context.Background())
	if e.H.KubeletStorageOperationErrors != 5 {
		t.Fatalf("storage errors=%d want 5 (3 attach + 2 mount)",
			e.H.KubeletStorageOperationErrors)
	}
}

// TestStorageOperationErrorsWithoutPLEGFamily: a scrape that
// carries the storage series but no PLEG family must still export
// — the counter is independent of PLEG health.
func TestStorageOperationErrorsWithoutPLEGFamily(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.MetricsBody = `storage_operation_errors_total{operation_name="volume_detach"} 7
`
	e.H.Cycle(context.Background())
	if e.H.KubeletStorageOperationErrors != 7 {
		t.Fatalf("storage errors=%d want 7 (PLEG-absent scrape still exports)",
			e.H.KubeletStorageOperationErrors)
	}
}
