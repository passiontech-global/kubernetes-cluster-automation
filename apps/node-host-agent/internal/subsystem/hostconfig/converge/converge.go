// Package converge holds the generic host-convergence primitives
// extracted from subsystem/hostconfig — this IS that subsystem's
// subtree now, hostconfig being the package's single production
// consumer: the Runner exec contract
// (nsenter into host PID 1 namespaces, or direct when standalone),
// managed-file writes (sha256-compare + atomic tmp+rename + mode
// preservation), candidate-staged validated deploys (a bad render
// never reaches the live path), systemd unit state verbs, shell
// -interpolation safety gates, and bounded downloads + tar-member
// installs.
//
// The package is a leaf: it returns errors instead of
// counting them — the caller owns metrics and per-cycle error
// attribution (hostconfig routes Deploy/NftUnit through its Ops
// adapter so write/action failures still land on the active cycle).
package converge
