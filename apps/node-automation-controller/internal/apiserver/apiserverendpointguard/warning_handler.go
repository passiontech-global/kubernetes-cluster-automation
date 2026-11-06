// warning_handler.go — the "v1 Endpoints is deprecated" warning filter
// of apiserver-endpoint-guard. core/v1 Endpoints is deprecated since
// v1.33 and the apiserver returns a 299 Warning header on every
// get/update, yet the guard writes the deprecated object deliberately
// wherever the kubernetes slice is a mirror projection — the filter
// drops exactly that one warning while every other still delegates to
// the default WarningLogger. main attaches it to the shared
// rest.Config before the clientsets are built; Setup's dedicated
// dynamic client reuses the shared client when it already carries the
// filter.
package apiserverendpointguard

import (
	"context"
	"strings"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// NewWarningHandler returns the WarningHandler that drops
// only the apiserver's "v1 Endpoints is deprecated" header — exported
// so main can attach it to the shared rest.Config before the first
// clientset is built. The guard then recognizes its own filter on the
// manager config and reuses that clientset instead of paying for a
// second http.Transport and TLS connection pool.
func NewWarningHandler() rest.WarningHandler {
	return endpointGuardWarnings{delegate: rest.WarningLogger{}}
}

// endpointsWarningClient returns a dynamic client whose WarningHandler
// drops only the apiserver's Endpoints deprecation header — the
// guard's Endpoints reads/writes are intentional. When cfg already
// carries the guard's filter (main wires it onto the shared config
// before building dyn), the incoming client is reused: cloning cfg
// into a second client would duplicate the http.Transport and its
// connection pool for zero behavioral gain.
func endpointsWarningClient(cfg *rest.Config, dyn dynamic.Interface) (dynamic.Interface, error) {
	if dyn != nil {
		if _, ok := cfg.WarningHandler.(endpointGuardWarnings); ok {
			return dyn, nil
		}
	}
	cfg = rest.CopyConfig(cfg)
	cfg.WarningHandler = NewWarningHandler()
	return dynamic.NewForConfig(cfg)
}

// endpointGuardWarnings suppresses exactly one warning: "v1 Endpoints
// is deprecated" (the deprecated object is written by design wherever
// the kubernetes slice is a mirror projection). Everything else still
// reaches the default WarningLogger.
type endpointGuardWarnings struct {
	delegate rest.WarningHandlerWithContext
}

func (w endpointGuardWarnings) HandleWarningHeader(code int, agent, message string) {
	w.HandleWarningHeaderWithContext(context.Background(), code, agent, message)
}

func (w endpointGuardWarnings) HandleWarningHeaderWithContext(ctx context.Context, code int, agent, message string) {
	if code == 299 && strings.Contains(message, "v1 Endpoints is deprecated") {
		return
	}
	w.delegate.HandleWarningHeaderWithContext(ctx, code, agent, message)
}

var _ rest.WarningHandlerWithContext = endpointGuardWarnings{}
