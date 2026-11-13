//go:build linux

// sockstat_linux.go — the cheap aggregate reader:
// /proc/<pid>/net/sockstat{,6} answers "how many sockets, how many
// TIME_WAIT" without a single syscall (the file is already
// namespaced by the target pid — no setns needed for the
// file-based half). The NETLINK_SOCK_DIAG census + listener-destroy
// half lives in sockdiag_linux.go.
package netlinkx

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Sockstat reads both sockstat files for pid's netns view
// (/proc/<pid>/net is already namespaced by the target pid — no
// setns needed for the file-based half).
func Sockstat(pid int) (SockstatV4, SockstatV6, error) {
	v4raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/sockstat", pid))
	if err != nil {
		return SockstatV4{}, SockstatV6{}, fmt.Errorf("read sockstat: %w", err)
	}
	v6raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/sockstat6", pid))
	if err != nil {
		return SockstatV4{}, SockstatV6{}, fmt.Errorf("read sockstat6: %w", err)
	}
	v4, err := parseSockstatV4(string(v4raw))
	if err != nil {
		return SockstatV4{}, SockstatV6{}, err
	}
	v6, err := parseSockstatV6(string(v6raw))
	if err != nil {
		return SockstatV4{}, SockstatV6{}, err
	}
	return v4, v6, nil
}

// parseKVLine splits "LABEL: k v k v ..." into its label and a
// k->v map. Malformed pairs are skipped — the kernel format is
// stable but a partial read must not zero the whole table.
func parseKVLine(line string) (string, map[string]int) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", nil
	}
	label := strings.TrimSuffix(fields[0], ":")
	kv := map[string]int{}
	for i := 1; i+1 < len(fields); i += 2 {
		n, err := strconv.Atoi(fields[i+1])
		if err != nil {
			continue
		}
		kv[fields[i]] = n
	}
	return label, kv
}

func parseSockstatV4(raw string) (SockstatV4, error) {
	var s SockstatV4
	for line := range strings.SplitSeq(raw, "\n") {
		label, kv := parseKVLine(line)
		switch label {
		case "sockets":
			s.SocketsUsed = kv["used"]
		case "TCP":
			s.TCP = ProtoCounters{Inuse: kv["inuse"], Orphan: kv["orphan"], TimeWait: kv["tw"], Alloc: kv["alloc"], Mem: kv["mem"]}
		case "UDP":
			s.UDP = ProtoCounters{Inuse: kv["inuse"], Mem: kv["mem"]}
		case "RAW":
			s.RawInuse = kv["inuse"]
		case "FRAG":
			s.FragInuse = kv["inuse"]
			s.FragMem = kv["memory"]
		}
	}
	return s, nil
}

func parseSockstatV6(raw string) (SockstatV6, error) {
	var s SockstatV6
	for line := range strings.SplitSeq(raw, "\n") {
		label, kv := parseKVLine(line)
		switch label {
		case "TCP6":
			s.TCPInuse = kv["inuse"]
		case "UDP6":
			s.UDPInuse = kv["inuse"]
		case "RAW6":
			s.RawInuse = kv["inuse"]
		case "FRAG6":
			s.FragInuse = kv["inuse"]
			s.FragMem = kv["memory"]
		}
	}
	return s, nil
}
