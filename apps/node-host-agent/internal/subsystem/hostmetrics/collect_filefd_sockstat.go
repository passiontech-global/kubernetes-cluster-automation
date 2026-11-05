// collect_filefd_sockstat.go — H6 fd + socket pressure:
// /proc/sys/fs/file-nr and /proc/1/net/sockstat. Split out of
// hostmetrics.go.
package hostmetrics

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// H6 fd/socket sources.
	defaultFileNRFile   = "/proc/sys/fs/file-nr"
	defaultSockstatFile = "/proc/1/net/sockstat"
)

// --- H6: FD + socket pressure (file-nr, sockstat) ---

// collectFileFD parses /proc/sys/fs/file-nr — "allocated unused
// max" (fields 0 and 2; the middle "unused" field is always ~0 on
// modern kernels). Absent/malformed → no series.
func (c *Collector) collectFileFD(ch chan<- prometheus.Metric) {
	data, err := os.ReadFile(c.cfg.FileNRFile)
	if err != nil {
		return
	}
	f := strings.Fields(string(data))
	if len(f) < 3 {
		return
	}
	alloc, errA := strconv.ParseFloat(f[0], 64)
	maxFD, errM := strconv.ParseFloat(f[2], 64)
	if errA != nil || errM != nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.descFileFDAlloc,
		prometheus.GaugeValue, alloc, c.cfg.NodeName)
	ch <- prometheus.MustNewConstMetric(c.descFileFDMax,
		prometheus.GaugeValue, maxFD, c.cfg.NodeName)
	if maxFD > 0 {
		ch <- prometheus.MustNewConstMetric(c.descFileFDRatio,
			prometheus.GaugeValue, alloc/maxFD, c.cfg.NodeName)
	}
}

// collectSockstat parses /proc/1/net/sockstat — section lines of
// "NAME: key N key N ..." pairs ("sockets: used 1847",
// "TCP: inuse 25 orphan 0 tw 4 alloc 1200 mem 456"). Each gauge
// emits only when its key parsed — a node missing a section keeps
// that series absent rather than 0.
func (c *Collector) collectSockstat(ch chan<- prometheus.Metric) {
	f, err := os.Open(c.cfg.SockstatFile)
	if err != nil {
		return
	}
	defer f.Close()
	var tcpInuse, tcpOrphan, tcpTW, tcpCW, sockUsed float64
	var tcpInuseOK, tcpOrphanOK, tcpTWOK, tcpCWOK, sockUsedOK bool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// "NAME:" + an even number of key/value fields → odd total.
		if len(fields) < 3 || len(fields)%2 == 0 {
			continue
		}
		kv := make(map[string]float64, len(fields)/2)
		good := true
		for i := 1; i+1 < len(fields); i += 2 {
			v, err := strconv.ParseFloat(fields[i+1], 64)
			if err != nil {
				good = false
				break
			}
			kv[fields[i]] = v
		}
		if !good {
			continue // malformed line — never emit junk
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "TCP":
			if v, ok := kv["inuse"]; ok {
				tcpInuse, tcpInuseOK = v, true
			}
			if v, ok := kv["orphan"]; ok {
				tcpOrphan, tcpOrphanOK = v, true
			}
			if v, ok := kv["tw"]; ok {
				tcpTW, tcpTWOK = v, true
			}
			// close_wait/cw — kernels that report it carry hung
			// half-closed sockets here (W8-KR3 companion metric).
			if v, ok := kv["close_wait"]; ok {
				tcpCW, tcpCWOK = v, true
			} else if v, ok := kv["cw"]; ok {
				tcpCW, tcpCWOK = v, true
			}
		case "sockets":
			if v, ok := kv["used"]; ok {
				sockUsed, sockUsedOK = v, true
			}
		}
	}
	if sockUsedOK {
		ch <- prometheus.MustNewConstMetric(c.descSockUsed,
			prometheus.GaugeValue, sockUsed, c.cfg.NodeName)
	}
	if tcpInuseOK {
		ch <- prometheus.MustNewConstMetric(c.descSockTCPInuse,
			prometheus.GaugeValue, tcpInuse, c.cfg.NodeName)
	}
	if tcpOrphanOK {
		ch <- prometheus.MustNewConstMetric(c.descSockTCPOrphan,
			prometheus.GaugeValue, tcpOrphan, c.cfg.NodeName)
	}
	if tcpTWOK {
		ch <- prometheus.MustNewConstMetric(c.descSockTCPTW,
			prometheus.GaugeValue, tcpTW, c.cfg.NodeName)
	}
	if tcpCWOK {
		ch <- prometheus.MustNewConstMetric(c.descSockTCPCW,
			prometheus.GaugeValue, tcpCW, c.cfg.NodeName)
	}
}
