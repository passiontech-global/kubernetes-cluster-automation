package shared

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
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
func init() {
	envx.Warnf = func(msg string, kv ...any) {
		logf.Log.WithName("env").Info(msg, kv...)
	}
}
