// envx.go — rebinds libs/hostkit/envx.Warnf into the
// controller-runtime log stream so env-knob parse warnings keep
// their zap JSON shape in the manager's records.
package shared

import (
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// envx warnings belong in the controller-runtime log stream, not on
// the default slog text handler: the Getenv* getters' "invalid env
// value — using default" diagnostics used to log through
// logf.Log.WithName("env").Info from the retired
// internal/platform/envx, and operators must keep seeing them in the
// same zap JSON records as the rest of the manager. Rebinding
// envx.Warnf here is safe on ordering — every envx call in this app
// runs inside module Setup (invoked from main() well after
// ctrl.SetLogger); no envx getter executes in a package-var
// initializer.
//
// The rebind goes through envx.SetWarnf, the atomic-hook path: the
// rebind is still this init()-time, before-the-first-getter ordering
// as before, but the swap no longer races getter traffic (a plain
// `envx.Warnf = f` assignment is a racy var write — and it orphans
// the hook, so SetWarnf would silently stop routing until the var is
// reassigned again).
func init() {
	envx.SetWarnf(func(msg string, kv ...any) {
		logf.Log.WithName("env").Info(msg, kv...)
	})
}
