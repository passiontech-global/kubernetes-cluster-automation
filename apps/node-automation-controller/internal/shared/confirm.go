// confirm.go — ConfirmAbsent: the "live re-confirm before delete"
// verdict every janitor/reaper hand-rolls as a switch on a Get
// error. A List snapshot can lag the apiserver, so before a delete
// fires on "the snapshot says the resource is gone" the module
// Gets it live — apiserviceguard's namespace confirm,
// orphanendpointslicecleaner's Service Get — and only proceeds
// when the apiserver itself answers NotFound (fail closed on any
// other error).
package shared

import apierrors "k8s.io/apimachinery/pkg/api/errors"

// ConfirmAbsent classifies the error from a caller's
// resource-specific live Get into the three-way re-confirm
// verdict:
//
//	gone=true, err=nil   — the apiserver confirmed NotFound; the
//	                       snapshot's absence verdict stands and the
//	                       UID-preconditioned delete may proceed.
//	gone=false, err!=nil — the confirm itself failed (API flap,
//	                       timeout). The caller must keep the object
//	                       (fail closed) and may IncError — a
//	                       tolerated failure, retried next sweep.
//	gone=false, err=nil  — the Get succeeded: the object still
//	                       exists and the snapshot was stale.
func ConfirmAbsent(getErr error) (gone bool, err error) {
	switch {
	case apierrors.IsNotFound(getErr):
		return true, nil
	case getErr != nil:
		return false, getErr
	default:
		return false, nil
	}
}
