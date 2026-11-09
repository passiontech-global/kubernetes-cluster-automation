// seams.go — the Seams test-seam surface, grouped by concern. The
// flat ~24-func list outgrew readability, so the fields now live in
// the four embedded groups below: Probe (evidence reads over
// HTTP/DNS/unix/kubelet-metrics/pod-log), Host (signals, clock,
// fs/scheduling/journal/proc primitives), Ctr (the one containerd
// exec) and Cilium (the one agent unix-API GET). Field names are
// unchanged inside each group and every default is the same nil →
// production impl the flat applyDefaults filled — only the
// organization moved.
//
// DERIVED reads are not seams: a (low-level seam + fixed argv +
// parsing) composition adds no test coverage a stub of the
// low-level seam doesn't already give, so those live as named
// methods on their group instead of func fields — Ctr.RmImage /
// RmIngest / PruneContent build argv over the single Ctr.Exec seam,
// and Cilium.WGAllowedIPs / EncryptPeers / ServiceBackends compose
// Cilium.UnixGet (or Config.Systemd for `wg`) with the parsers.
package wdeps

// Seams groups the unexported test-seam funcs. Every one has a
// production default filled by applyDefaults; tests re-stub them on
// the live Hygiene after New.
//
// The four concern groups are EMBEDDED rather than named fields, so
// both access paths resolve to the same storage: the explicit
// d.Cfg.Seams.<Group>.<name> the checks use, and the promoted
// d.Cfg.Seams.<name> the wdepstest fixture and workerhygiene.go
// still write. Field names are unique across the groups, so
// promotion stays unambiguous.
type Seams struct {
	// Probe — HTTP/DNS/unix/kubelet-metrics/pod-log evidence reads.
	Probe
	// Host — signals, clock, fs/scheduling/journal/proc primitives.
	Host
	// Ctr — the containerd exec behind the named rm/prune methods.
	Ctr
	// Cilium — the agent unix-API GET behind the derived reads.
	Cilium
}

// applyDefaults fills the production implementations of every test
// seam. cfg carries the already-defaulted knob groups — the systemd
// exec default captures c.Systemd. The group calls are independent
// nil-checks, so their order is unobservable.
func (s *Seams) applyDefaults(c *Config) {
	s.Probe.applyDefaults(c)
	s.Host.applyDefaults(c)
	s.Ctr.applyDefaults(c)
	s.Cilium.applyDefaults(c)
}

// applyDefaults fills the Probe group's production implementations —
// same nil → default logic and order the flat pass had.
