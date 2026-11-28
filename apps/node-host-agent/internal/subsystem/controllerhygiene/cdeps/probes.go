// probes.go — the network liveness probes behind the Config seams:
// the pg-wire StartupMessage check behind PgWireFn (lib.sh
// pg_wire_ok) and the presented-cert TLS dial behind TLSCertFn. The
// HTTP probes (the old probeClient + probeAnyCode and the CP-freeze
// probeHTTP2xx/httpGetInsecure) live in platform/probee — same
// shared insecure client, same semantics.
package cdeps

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/probee"
)

// PGWireOK is the pg-wire StartupMessage probe behind PgWireFn —
// the implementation lives in platform/probee (PGWireProbe) so
// every subsystem shares the one wire-format port of lib.sh
// pg_wire_ok.
func PGWireOK(ctx context.Context, hostport string) bool {
	return probee.PGWireProbe(ctx, hostport)
}

// tlsDialCert returns the leaf certificate addr presents — delegates
// to probee.TLSPeerCert.
func tlsDialCert(ctx context.Context, addr string) (*x509.Certificate, error) {
	return probee.TLSPeerCert(ctx, addr, 8*time.Second)
}
