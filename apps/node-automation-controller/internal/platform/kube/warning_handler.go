// warning_handler.go — the "v1 Endpoints is deprecated" warning filter
// shared by apiserver-endpoint-guard. core/v1 Endpoints is deprecated
// since v1.33 and the apiserver returns a 299 Warning header on every
// get/update, yet the guard writes the deprecated object deliberately
// wherever the kubernetes slice is a mirror projection — the filter
// drops exactly that one warning while every other still delegates to
// the default WarningLogger. main attaches it to the shared
// rest.Config before the clientsets are built; the guard's dedicated
// dynamic client reuses the shared client when it already carries the
// filter.
package kube

import (
	"context"
	"strings"

	"k8s.io/client-go/rest"
)

// NewWarningHandler returns the WarningHandler that drops
// only the apiserver's "v1 Endpoints is deprecated" header — exported
// so main can attach it to the shared rest.Config before the first
// clientset is built. The guard then recognizes its own filter on the
// manager config and reuses that clientset instead of paying for a
// second http.Transport and TLS connection pool.
func NewWarningHandler() rest.WarningHandler {
	return EndpointGuardWarnings{Delegate: rest.WarningLogger{}}
}

// EndpointGuardWarnings suppresses exactly one warning: "v1 Endpoints
// is deprecated" (the deprecated object is written by design wherever
// the kubernetes slice is a mirror projection). Everything else still
// reaches the default WarningLogger. Exported so the guard's client
// wiring can recognize the filter on an incoming rest.Config and so
// tests can inject a recording delegate.
type EndpointGuardWarnings struct {
	Delegate rest.WarningHandlerWithContext
}

func (w EndpointGuardWarnings) HandleWarningHeader(code int, agent, message string) {
	w.HandleWarningHeaderWithContext(context.Background(), code, agent, message)
}

func (w EndpointGuardWarnings) HandleWarningHeaderWithContext(ctx context.Context, code int, agent, message string) {
	if code == 299 && strings.Contains(message, "v1 Endpoints is deprecated") {
		return
	}
	w.Delegate.HandleWarningHeaderWithContext(ctx, code, agent, message)
}

var _ rest.WarningHandlerWithContext = EndpointGuardWarnings{}
