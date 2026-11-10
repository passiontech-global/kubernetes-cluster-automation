// binary_install.go — installManagedBinary, the shared
// version-probe → staged-sha256-check → download → install flow for
// the sha256-pinned managed artifacts the converge groups install:
// the nebula/etcdctl/coredns tarballs, the kine raw binary and the
// haproxy/node_exporter debs. Each group used to carry its own copy
// of the staged-verify/download dance; the spec struct below pins
// the shapes where they legitimately diverge.
package hostconfig

import (
	"context"
	"os"
)

// managedBinarySpec pins one downloaded artifact for
// installManagedBinary: how to detect the wanted version already in
// place, where the staged/downloaded file lives and its sha256 pin,
// and how the verified artifact installs (untar member vs raw
// dest-file vs external installer).
//
// Zero-value fields mean the common shape: r.download as transport,
// the uniform url/file/error download-failure line, no untar, no
// hooks. Every counted/log line emitted here keeps the exact keys
// and wording the copied-out originals carried.
type managedBinarySpec struct {
	// name is the group tag the shared-flow error lines carry
	// ("T5b", "etcdctl", "T9", ...).
	name string

	// artifact is the noun the staged-mismatch line names
	// ("nebula tarball", "tgz", "coredns tgz").
	artifact string

	// probe is the version probe: true = the destination already
	// carries the pinned version, nothing to stage/download/install.
	// The tarball groups run `<bin> -version`; kine probes the dest
	// file's sha256; the deb groups compare dpkg versions.
	probe func(c *cyc) bool

	// url + sum pin the artifact: download source and its sha256.
	// download verifies the hash as it streams; a staged copy is
	// verified by sha256FileOK below.
	url, sum string

	// staged is the artifact's staged/downloaded path — the
	// DownloadDir tarball path for the binary groups, hp()-joined
	// host paths where the consumer runs on the host (kine binary,
	// the debs the runner apt-installs).
	staged string

	// refuseBadStaged marks the tarball contract: a STAGED copy with
	// a wrong sha256 aborts with a counted error instead of
	// re-downloading (operator-provided staging, ansible
	// sha256sum -c parity). Deb/raw artifacts re-download instead.
	refuseBadStaged bool

	// download overrides the transport (nexpDownload's slow-egress
	// timeout floor); nil = r.download (Config.HTTPTimeout).
	download func(ctx context.Context, url, dst, wantSHA256 string) error

	// downloadLine is the counted download-failure line, logged with
	// the uniform (url, file, error) args. Sites whose line carries
	// other keys set downloadErr instead.
	downloadLine string

	// downloadErr overrides the download-failure report for lines
	// that do not fit the uniform (url, file, error) shape.
	downloadErr func(c *cyc, err error)

	// prepare runs between verify and install (etcdctl's k0s bin dir
	// — untarInstall does not mkdir parents). false aborts the
	// install; the failure was already logged/counted inside.
	prepare func(c *cyc) bool

	// member/dest/mode install a .tar.gz member: untarInstall
	// extracts member from the staged tarball to hp(dest) with mode.
	// member == "" skips the untar — either the staged file IS the
	// dest (kine) or install below drives an external installer.
	member string
	dest   string
	mode   os.FileMode

	// installErr reports a failed member extraction with the
	// per-site (byte-identical) line.
	installErr func(c *cyc, local string, err error)

	// install is the external-installer hook (the deb groups'
	// apt-get install of the verified staged deb). It replaces the
	// untar path; a returned error is reported via installErr (the
	// per-site counted line) and fails the flow (ok=false) — callers
	// gating daemon restarts on ok must never proceed past a failed
	// apt install onto a stale daemon.
	install func(c *cyc, local string) error

	// companion installs a second, best-effort member from the same
	// tarball (nebula-cert): its failure only warns, never counts —
	// a missing key errors at the keygen call site instead.
	companionMember   string
	companionDest     string
	companionFailLine string

	// onInstalled fires after the main member untar succeeds — the
	// "binary file was actually replaced this cycle" signal. `changed`
	// only covers the fresh-download path: a staged tarball already
	// matching the pin installs without a download (changed=false)
	// yet still swaps the binary, so callers whose daemon must
	// restart on a new binary (nebula, coredns — unlike kine whose
	// staged path IS the dest, where changed is exact) hook this
	// instead of reading `changed`.
	onInstalled func(c *cyc, local string)
}

// installManagedBinary runs the shared sha256-pinned artifact flow:
// version probe → staged sha256 check → download → install. A staged
// copy matching the pin skips the download entirely; whether a bad
// staged copy refuses (tarballs) or re-downloads (debs/raw) is the
// spec's refuseBadStaged contract.
//
// Returns (changed, ok): changed=true when a fresh download happened
// this call (kine restarts the unit on a new binary); ok=false when
// the flow aborted on a refused staged copy, a failed prepare or a
// failed download — the failure is already counted/logged, the
// caller just stops.
func (c *cyc) installManagedBinary(sp managedBinarySpec) (changed, ok bool) {
	if sp.probe != nil && sp.probe(c) {
		return false, true
	}
	local := sp.staged
	stagedOK := fileExistsNoRoot(local) && sha256FileOK(local, sp.sum)
	if !stagedOK && sp.refuseBadStaged && fileExistsNoRoot(local) {
		c.err(sp.name+": staged "+sp.artifact+" sha256 mismatch — not installing",
			"file", local, "sha256", sp.sum)
		return false, false
	}
	if !stagedOK {
		dl := sp.download
		if dl == nil {
			dl = c.r.download
		}
		if err := dl(c.ctx, sp.url, local, sp.sum); err != nil {
			if sp.downloadErr != nil {
				sp.downloadErr(c, err)
			} else {
				c.err(sp.downloadLine, "url", sp.url, "file", local, "error", err)
			}
			return false, false
		}
		changed = true
	}
	if sp.prepare != nil && !sp.prepare(c) {
		return false, false
	}
	switch {
	case sp.install != nil:
		if err := sp.install(c, local); err != nil {
			// Same contract as the untar path's installErr: the
			// per-site counted line reports the failure — and the
			// flow fails (ok=false) so restart gating never treats
			// a stale daemon as freshly installed.
			if sp.installErr != nil {
				sp.installErr(c, local, err)
			} else {
				c.err(sp.name+": "+sp.artifact+" install failed", "file", local, "error", err)
			}
			return changed, false
		}
	case sp.member != "":
		mainErr := untarInstall(local, sp.member, c.r.hp(sp.dest), sp.mode)
		if mainErr != nil {
			sp.installErr(c, local, mainErr)
		}
		// The companion only runs when the main member landed — the
		// pre-extraction nebula flow returned after a failed main
		// extraction instead of trying nebula-cert from a bad tarball.
		if mainErr == nil && sp.companionMember != "" {
			if err := untarInstall(local, sp.companionMember,
				c.r.hp(sp.companionDest), sp.mode); err != nil {
				// Best-effort companion binary — the main binary is
				// already installed; a missing key only errors when
				// keygen is actually needed (counted at the keygen
				// call site).
				logger().Warn(sp.companionFailLine, "file", local, "error", err)
			}
		}
		if mainErr == nil && sp.onInstalled != nil {
			sp.onInstalled(c, local)
		}
	}
	return changed, true
}
