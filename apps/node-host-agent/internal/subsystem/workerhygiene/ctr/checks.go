// checks.go — the containerd-domain check constructors (ctr-tasks,
// ctr-image-healer, ctr-ingest-gc, containerd-meta). The parent
// workerhygiene package wires them into its ordered dispatch list.
package ctr

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// NewCtrTasks returns the 31 wedged-task-dir + orphan-shim check.
func NewCtrTasks(d *wdeps.Deps) *CtrTasksCheck {
	return &CtrTasksCheck{d: d}
}

// NewCtrImages returns the 37 corrupted-layer image healer.
func NewCtrImages(d *wdeps.Deps) *CtrImagesCheck {
	return &CtrImagesCheck{d: d, execFormatHealed: map[string]bool{}}
}

// NewIngestGC returns the 39/A3 stale-ingest + content-prune GC.
func NewIngestGC(d *wdeps.Deps) *IngestGCCheck {
	return &IngestGCCheck{d: d}
}

// NewCtrMeta returns the W10-KR3 containerd meta.db corruption guard.
func NewCtrMeta(d *wdeps.Deps) *CtrMetaCheck {
	return &CtrMetaCheck{d: d}
}
