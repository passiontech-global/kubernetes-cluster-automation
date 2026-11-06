// probes.go — the production defaults behind the newer Seams probe
// funcs that have no platform/probee twin: the deleted-fd stat used
// by the unlinked-open-files guard, the TCP half of the :53 DNS
// datapath probe, and the bearer-authenticated kubelet /metrics GET.
// probee is untouched — its helpers deliberately carry no bearer and
// the deleted-fd stat is procfs semantics, not a network probe.
package wdeps

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

// deletedFDStat is the DeletedFDStatFn default: stat() the
// /proc/<pid>/fd magic symlink — the kernel resolves it to the
// still-open inode even when readlink reports "<path> (deleted)":
// the fd pins the inode, so dev/ino/size stay readable until the
// last holder closes. ok=false on a raced close or a non-regular
// target (sockets/pipes never pin filesystem blocks anyway).
func deletedFDStat(path string) (dev, ino uint64, size int64, ok bool) {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return 0, 0, 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, false
	}
	return uint64(st.Dev), st.Ino, st.Size, true
}

// tcpDNSQuery is the DNSProbeTCP default — the same minimal A-record
// query probee.DNSQuery sends over UDP, but on the TCP transport:
// RFC 1035 length-prefixed query/response. Any reply matching the
// query id with the QR bit set proves the :53 listener answers on
// TCP; silence means the TCP datapath is wedged.
func tcpDNSQuery(addr, name string, timeout time.Duration) bool {
	id := uint16(time.Now().UnixNano())
	// Header: ID, flags 0x0100 (RD), QDCOUNT=1, AN/NS/AR=0.
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1) // root label + QTYPE A + QCLASS IN
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	frame := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(frame, uint16(len(q)))
	copy(frame[2:], q)
	if _, err := conn.Write(frame); err != nil {
		return false
	}
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return false
	}
	rlen := int(binary.BigEndian.Uint16(hdr[:]))
	if rlen < 4 {
		return false
	}
	buf := make([]byte, rlen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false
	}
	// ID echo + QR bit set — NXDOMAIN/SERVFAIL still count as alive.
	return buf[0] == q[0] && buf[1] == q[1] && buf[2]&0x80 != 0
}

// kubeletMetricsClient backs kubeletMetricsGet — insecure TLS like
// the other :10250 probes (kubelet serves a cert whose SANs never
// cover the loopback; curl -ks parity) with the shared keep-alive
// transport settings probee uses.
var kubeletMetricsClient = func() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // curl -ks parity
	tr.IdleConnTimeout = 90 * time.Second
	return &http.Client{Transport: tr}
}()

// kubeletMetricsGet is the KubeletMetricsFn default — GET url with
// the SA bearer, return the body (4MiB cap — kubelet /metrics is a
// few hundred KiB; a blowout body is discarded, never slurped).
// Non-200 is an error: the scrape verdict is unreadable, not "zero".
func kubeletMetricsGet(ctx context.Context, url, bearer string,
	timeout time.Duration) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := kubeletMetricsClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return "", fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}
