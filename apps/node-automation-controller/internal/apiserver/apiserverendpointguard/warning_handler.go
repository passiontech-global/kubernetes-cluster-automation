// warning_handler.go — the guard's wiring around the shared
// "v1 Endpoints is deprecated" warning filter (kube.NewWarningHandler):
// a dedicated dynamic client whose WarningHandler drops only that one
// header — the guard's Endpoints reads/writes are intentional. When
// cfg already carries the filter (main wires it onto the shared config
// before building dyn), the incoming client is reused: cloning cfg
// into a second client would duplicate the http.Transport and its
// connection pool for zero behavioral gain.
package apiserverendpointguard

import (
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// endpointsWarningClient returns a dynamic client whose WarningHandler
// drops only the apiserver's Endpoints deprecation header.
func endpointsWarningClient(cfg *rest.Config, dyn dynamic.Interface) (dynamic.Interface, error) {
	if dyn != nil {
		if _, ok := cfg.WarningHandler.(kube.EndpointGuardWarnings); ok {
			return dyn, nil
		}
	}
	cfg = rest.CopyConfig(cfg)
	cfg.WarningHandler = kube.NewWarningHandler()
	return dynamic.NewForConfig(cfg)
}
