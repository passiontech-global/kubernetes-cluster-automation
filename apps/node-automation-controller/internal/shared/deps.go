package shared

import (
	"github.com/go-logr/logr"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// Deps bundles the process-wide dependencies every module's Setup
// receives. Modules take `Setup(d Deps) error` so main.go can wire
// the whole fleet from one registry entry per module — no per-module
// parameter plumbing, and a module that needs nothing beyond the
// standard clients still gets a uniform signature.
//
//   - Mgr is the controller-runtime manager (Add/runables, builder
//     watches, cached client).
//   - CS is the direct (uncached) clientset — RBAC intentionally
//     grants no watch on most types, so module reads go through it.
//   - Dyn is the dynamic client for CRD types (helmreleases,
//     cert-manager, externalsecrets, ...).
//   - Log is the manager logger, for Setup-time registration lines.
type Deps struct {
	Mgr manager.Manager
	CS  kubernetes.Interface
	Dyn dynamic.Interface
	Log logr.Logger
}
