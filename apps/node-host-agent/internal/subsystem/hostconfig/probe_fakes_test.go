// probe_fakes_test.go — Config seam fakes for the in-process
// replacements of the old forked probes (bash /dev/tcp, dig,
// ss -lntu): TCPProbe/DNSProbe/ListenAddrsFn driven by plain maps
// so tests never touch the network or netlink.
package hostconfig

import (
	"context"
	"errors"
	"time"
)

// tcpProbeFake answers TCPProbe from a reachable "host:port" set —
// the addr form is net.JoinHostPort ("10.0.0.1:6443",
// "[::1]:6443"). Missing entries refuse like a closed port.
func tcpProbeFake(reachable map[string]bool) func(context.Context, string, time.Duration) error {
	return func(_ context.Context, addr string, _ time.Duration) error {
		if reachable[addr] {
			return nil
		}
		return errors.New("dial " + addr + ": connection refused")
	}
}

// dnsProbeFake answers DNSProbe from a name → addresses map;
// unlisted names fail like an unresolvable stub.
func dnsProbeFake(answered map[string][]string) func(context.Context, string) ([]string, error) {
	return func(ctx context.Context, name string) ([]string, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if a, ok := answered[name]; ok {
			return a, nil
		}
		return nil, errors.New("lookup " + name + ": no such host")
	}
}

// listenAddrsFake serves a fixed bound-endpoint set — the keys are
// the "ip:port"/"[v6]:port" strings the ss -lntu rows used to show.
func listenAddrsFake(addrs ...string) func(int) (map[string]struct{}, error) {
	return func(int) (map[string]struct{}, error) {
		m := make(map[string]struct{}, len(addrs))
		for _, a := range addrs {
			m[a] = struct{}{}
		}
		return m, nil
	}
}

// listenAddrsErr fakes a failed listener census (the old
// `ss -lntu` non-zero exit).
func listenAddrsErr(err error) func(int) (map[string]struct{}, error) {
	return func(int) (map[string]struct{}, error) { return nil, err }
}

// tcpProbeAllOK — every addr accepts; the common fixture default
// for tests that don't exercise a dead backend.
func tcpProbeAllOK() func(context.Context, string, time.Duration) error {
	return func(context.Context, string, time.Duration) error { return nil }
}

// dnsProbeAnyOK — every name resolves to one address; the common
// fixture default for tests that only need "the stub answers".
func dnsProbeAnyOK() func(context.Context, string) ([]string, error) {
	return func(ctx context.Context, _ string) ([]string, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return []string{"10.0.1.10"}, nil
	}
}

// dnsProbeErr fakes a dead stub resolver (the old dig non-zero exit).
func dnsProbeErr(err error) func(context.Context, string) ([]string, error) {
	return func(ctx context.Context, _ string) ([]string, error) {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, err
	}
}
