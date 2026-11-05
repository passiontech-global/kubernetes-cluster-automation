package hubsync

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/sshclient"
)

// dlConn is a net.Conn that only records SetDeadline calls — the
// seam for asserting the per-op bound behaviour (sshclient.BoundOp)
// without a real socket, and for emulating the x/crypto chanConn
// jump.Dial returns whose SetDeadline always errors ("deadline not
// supported").
type dlConn struct {
	dls []time.Time
	err error
}

func (c *dlConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *dlConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *dlConn) Close() error                { return nil }
func (c *dlConn) LocalAddr() net.Addr         { return nil }
func (c *dlConn) RemoteAddr() net.Addr        { return nil }
func (c *dlConn) SetDeadline(t time.Time) error {
	c.dls = append(c.dls, t)
	return c.err
}
func (c *dlConn) SetReadDeadline(time.Time) error  { return nil }
func (c *dlConn) SetWriteDeadline(time.Time) error { return nil }

// TestBoundOpSetsAndClearsDeadline: the per-op bound is applied then
// cleared — steady-state session I/O stays governed by ctx +
// Session.Close, not a stale conn deadline.
func TestBoundOpSetsAndClearsDeadline(t *testing.T) {
	nc := &dlConn{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clear := sshclient.BoundOp(context.Background(), log, nc, time.Minute)
	if len(nc.dls) != 1 || nc.dls[0].IsZero() {
		t.Fatalf("deadline not applied: %v", nc.dls)
	}
	clear()
	if len(nc.dls) != 2 || !nc.dls[1].IsZero() {
		t.Fatalf("deadline not cleared: %v", nc.dls)
	}
}

// TestBoundOpUnsupportedIsLoud: a conn rejecting SetDeadline leaves
// the op unbounded — the warning must say so instead of letting a
// wedged-target hang look identical to a bounded op.
func TestBoundOpUnsupportedIsLoud(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	nc := &dlConn{err: errors.New("deadline not supported")}
	clear := sshclient.BoundOp(context.Background(), log, nc, time.Minute)
	clear()
	if !strings.Contains(buf.String(), "unbounded") {
		t.Fatalf("rejected SetDeadline not warned:\n%s", buf.String())
	}
}

// TestSSHConnBindsSessionsOnLink: sshConn wires its per-op bound to
// the link's deadline conn — the selection itself (chanConn vs the
// jump's TCP conn) is sshclient.Link's job, covered in its own
// package tests.
func TestSSHConnBindsSessionsOnLink(t *testing.T) {
	direct, jump := &dlConn{}, &dlConn{}
	if got := (&sshclient.Link{Net: direct}).DeadlineConn(); got != direct {
		t.Fatal("direct conn must be its own deadline handle")
	}
	if got := (&sshclient.Link{Net: direct, JumpNet: jump}).DeadlineConn(); got != jump {
		t.Fatal("bastion conn must bound on the jump's TCP conn")
	}
}
