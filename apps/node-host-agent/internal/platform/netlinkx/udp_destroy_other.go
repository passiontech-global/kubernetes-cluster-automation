//go:build !linux

// udp_destroy_other.go — non-Linux stubs for connected UDP dump/destroy.
package netlinkx

// DumpConnectedUDP refuses off Linux.
func DumpConnectedUDP(int) ([]ConnectedUDPSocket, error) {
	return nil, errNotLinux
}

// DestroyUDPSocket refuses off Linux. destroyed is always false.
func DestroyUDPSocket(int, uint8, [48]byte) (bool, error) {
	return false, errNotLinux
}

// UDPBoundPorts refuses off Linux.
func UDPBoundPorts(int) (map[uint16]bool, error) { return nil, errNotLinux }
