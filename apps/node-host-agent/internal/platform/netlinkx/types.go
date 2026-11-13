// types.go — the sockstat aggregate shapes shared by the linux
// reader and the !linux stub (netlinkx_other.go).
package netlinkx

// ProtoCounters is one /proc/net/sockstat protocol row. Absent
// key/value pairs stay 0 — same convention as procfs.ConntrackStat
// (the kernel omits fields it does not count).
type ProtoCounters struct {
	Inuse    int
	Orphan   int
	TimeWait int // `tw` — the only per-state count sockstat carries
	Alloc    int
	Mem      int
}

// SockstatV4 is /proc/<pid>/net/sockstat — IPv4 socket aggregates.
type SockstatV4 struct {
	SocketsUsed int
	TCP         ProtoCounters
	UDP         ProtoCounters
	RawInuse    int
	FragInuse   int
	FragMem     int
}

// SockstatV6 is /proc/<pid>/net/sockstat6 — the v6 file carries
// only `inuse` per protocol, no timewait/orphan detail.
type SockstatV6 struct {
	TCPInuse  int
	UDPInuse  int
	RawInuse  int
	FragInuse int
	FragMem   int
}

// TCPCensus is one 1-pass NETLINK_SOCK_DIAG read — both halves the
// per-cycle connection-table evidence used to pull from separate
// transports (the per-family state dumps + the /proc/net/tcp{,6}
// text scan):
//
//   - States: idiag_state → socket count across IPv4+IPv6 (the
//     kernel ids 1=ESTABLISHED .. 12=TIME_WAIT, tcp_states.h).
//   - PerTuple: daddr+BE-dport (raw bytes) → socket count — the
//     per-remote-endpoint hot-spot table; DiagEndpoint renders a
//     key for emission.
//
// An error return leaves both maps zeroed: inconclusive, never a
// fabricated zero census.
type TCPCensus struct {
	States   map[uint8]int
	PerTuple map[string]int
}
