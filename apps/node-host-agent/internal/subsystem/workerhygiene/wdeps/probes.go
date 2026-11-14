// probes.go — the production defaults behind the newer Seams probe
// funcs that have no platform/probee twin: the deleted-fd stat used
// by the unlinked-open-files guard and the bearer-authenticated
// kubelet /metrics GET. (The TCP :53 DNS probe lives in
// platform/probee as DNSQueryTCP — the seam default points there.)
// probee is untouched — its helpers deliberately carry no bearer and
// the deleted-fd stat is procfs semantics, not a network probe.
package wdeps

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
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
	return st.Dev, st.Ino, st.Size, true
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
// the SA bearer, return the body lines the syncloop check parses
// (kubelet_pleg_* + storage_operation_errors_total). Non-200 is an
// error: the scrape verdict is unreadable, not "zero".
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
	return scanKubeletMetrics(resp.Body)
}

// kubeletMetricPrefixes are the exposition families parsePLEGMetrics
// switches on — a multi-MiB /metrics scrape collapses to a few KiB
// before it becomes a string. The 4MiB kept-lines budget mirrors the
// old body cap.
var kubeletMetricPrefixes = [][]byte{
	[]byte("kubelet_pleg_"),
	[]byte("storage_operation_errors_total"),
}

// scanKubeletMetrics streams the /metrics body through a 64 KiB
// bufio.Scanner keeping only the parsed families — line-oriented
// filtering is exact: parsePLEGMetrics keys each line on the sample
// name before '{', and HELP/TYPE comment lines never match the
// prefixes.
func scanKubeletMetrics(r io.Reader) (string, error) {
	return promfile.ScanLinesWithPrefixes(r, kubeletMetricPrefixes, 4<<20)
}
