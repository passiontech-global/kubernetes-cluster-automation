// bind_test.go — the route-guard socket seam: bindRouteSocket must
// come up with a subscribed NETLINK_ROUTE socket (route+rule groups)
// and leave it closeable.
package routewatch

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestBindRouteSocket(t *testing.T) {
	fd, err := bindRouteSocket()
	if err != nil {
		t.Fatalf("bindRouteSocket: %v", err)
	}
	if fd < 0 {
		t.Fatalf("fd=%d want >= 0", fd)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatalf("close: %v", err)
	}
}
