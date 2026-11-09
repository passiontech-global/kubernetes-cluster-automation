package velerobackupauditor

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

var ctx = context.Background()

// newDynFake seeds the Velero types the auditor lists — schedules,
// backups, and the velero-bsl-audit backupstoragelocations — plus the backup-posture-audit
// Everest DatabaseCluster/DatabaseClusterBackup GVRs and the
// autopilot Plan GVR the maintenance mutex reads inside
// heal.AllowedV (the fake PANICS on a List for an unregistered GVR,
// so every type the audit touches must be mapped even when a test
// seeds none).
func newDynFake(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return testutil.NewDynamicClient(objs...)
}
