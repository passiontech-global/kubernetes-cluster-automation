// bind_test.go — the route-guard socket seam: bindRouteSocket must
// come up with a subscribed NETLINK_ROUTE socket (route+rule groups)
// and leave it closeable.
package routewatch

import (
	"path/filepath"
	"strings"
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

// An unopenable netns path (no such file) fails BindInNetns before
// any thread is locked — the error names the path.
func TestBindInNetnsUnopenableNetns(t *testing.T) {
	_, err := BindInNetns(filepath.Join(t.TempDir(), "no-such-ns"))
	if err == nil {
		t.Fatal("BindInNetns succeeded on a missing netns path")
	}
	if !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("unexpected error: %v", err)
	}
}
