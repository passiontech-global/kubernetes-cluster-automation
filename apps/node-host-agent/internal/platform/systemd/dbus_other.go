//go:build !linux

// dbus_other.go — non-linux stub: the D-Bus backend only exists on
// linux (the agent's deployment target); elsewhere newDBusBackend
// returns nil and every Client method keeps the systemctl path.
package systemd

// dbusBackend is a nil marker off-linux — Client.dbus stays nil so
// the dispatch in systemd.go never reaches the dbus* methods.
type dbusBackend struct{}

func newDBusBackend(hostRoot string) *dbusBackend { return nil }

// close satisfies Client.Close's call on the (always-nil here)
// backend — kept for signature parity with the linux build.
func (b *dbusBackend) close() {}
