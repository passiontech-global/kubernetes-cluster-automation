//go:build !linux

// udp_destroy_other.go — non-Linux stubs for connected UDP dump/destroy.
package netlinkx

// DumpConnectedUDP refuses off Linux.
func DumpConnectedUDP(int) ([]ConnectedUDPSocket, error) {
	return nil, errNotLinux
}

// DestroyUDPSocket refuses off Linux.
func DestroyUDPSocket(int, uint8, [48]byte) error {
	return errNotLinux
}
