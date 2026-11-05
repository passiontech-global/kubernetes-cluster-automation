package velerobackupauditor

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

var ctx = context.Background()

// newDynFake seeds the Velero types the auditor lists — schedules,
// backups, and the W8-ST1 backupstoragelocations — plus the W9-ST3
// Everest DatabaseCluster/DatabaseClusterBackup GVRs (the fake
// PANICS on a List for an unregistered GVR, so every type the audit
// touches must be mapped even when a test seeds none).
func newDynFake(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return testutil.NewFakeDyn(map[schema.GroupVersionResource]string{
		veleroScheduleGVR:   "ScheduleList",
		veleroBackupGVR:     "BackupList",
		veleroBSLGVR:        "BackupStorageLocationList",
		veleroPVBGVR:        "PodVolumeBackupList",
		everestDBClusterGVR: "DatabaseClusterList",
		everestDBBackupGVR:  "DatabaseClusterBackupList",
	}, objs...)
}
