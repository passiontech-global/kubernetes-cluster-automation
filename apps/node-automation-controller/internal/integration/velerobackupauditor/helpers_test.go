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
// backups, and the W8-ST1 backupstoragelocations.
func newDynFake(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return testutil.NewFakeDyn(map[schema.GroupVersionResource]string{
		veleroScheduleGVR: "ScheduleList",
		veleroBackupGVR:   "BackupList",
		veleroBSLGVR:      "BackupStorageLocationList",
	}, objs...)
}
