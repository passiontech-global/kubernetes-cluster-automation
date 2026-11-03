// Package apiserviceguard is the apiservice-guard module: prunes
// aggregated-API APIService objects whose backend Service namespace no
// longer exists (they would wedge namespace deletion and GC), and
// surfaces long-unavailable APIServices as a gauge.
package apiserviceguard
