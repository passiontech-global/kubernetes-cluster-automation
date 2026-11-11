// kinepool_internal_test.go — the /proc/net/tcp(6) row parser behind
// the kine pool probe: classifyConnLine's column/branch table and
// the tcpRemotePort hex-port reader. Internal test package: both are
// unexported package funcs.
package storelocal

import "testing"

// The st-column spellings classifyConnLine byte-compares: LISTEN
// "0A" is excluded from the connection count; FIN_WAIT2 "05" and
// CLOSE_WAIT "08" are the stuck orphans.
const (
	tcpStateListen    = "0A"
	tcpStateFinWait2  = "05"
	tcpStateCloseWait = "08"
)

// kineTCPRow builds one /proc/net/tcp(6) data row:
//
//	sl local rem st tx:rx tr:tm retrnsmt uid timeout inode ...
func kineTCPRow(st, rem, retrnsmt, inode string) string {
	return "   1: 0100007F:1234 " + rem + " " + st +
		" 00000000:00000000 00:00000000 " + retrnsmt +
		" 0 0 " + inode + " 1 0000000000000000"
}

func TestClassifyConnLine(t *testing.T) {
	// rem port 0x1920 = 6432, the default DB port in the rows below.
	inodes := map[uint64]bool{900: true}
	const dbPort = 6432

	tests := []struct {
		name            string
		line            string
		wantConn, stuck bool
	}{
		{
			name: "short row is ignored",
			line: "   1: 0100007F:1234 0A0000FF:1920 01",
		},
		{
			name: "LISTEN socket is not a connection",
			line: kineTCPRow(tcpStateListen, "0A0000FF:1920", "00000000", "900"),
		},
		{
			name:     "established conn to db port",
			line:     kineTCPRow("01", "0A0000FF:1920", "00000000", "900"),
			wantConn: true,
		},
		{
			name: "foreign remote port",
			line: kineTCPRow("01", "0A0000FF:1F90", "00000000", "900"),
		},
		{
			name: "inode not owned by the watched pid",
			line: kineTCPRow("01", "0A0000FF:1920", "00000000", "901"),
		},
		{
			name: "rem address without a port colon",
			line: kineTCPRow("01", "0A0000FF", "00000000", "900"),
		},
		{
			name:     "FIN_WAIT2 orphan is stuck",
			line:     kineTCPRow(tcpStateFinWait2, "0A0000FF:1920", "00000000", "900"),
			wantConn: true, stuck: true,
		},
		{
			name:     "CLOSE_WAIT orphan is stuck",
			line:     kineTCPRow(tcpStateCloseWait, "0A0000FF:1920", "00000000", "900"),
			wantConn: true, stuck: true,
		},
		{
			name:     "retransmit past the floor is stuck (hex parse)",
			line:     kineTCPRow("01", "0A0000FF:1920", "0000000A", "900"),
			wantConn: true, stuck: true,
		},
		{
			name:     "retransmit at the floor is not stuck",
			line:     kineTCPRow("01", "0A0000FF:1920", "00000003", "900"),
			wantConn: true,
		},
		{
			name:     "non-hex retrnsmt degrades to not stuck",
			line:     kineTCPRow("01", "0A0000FF:1920", "0000000G", "900"),
			wantConn: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isConn, isStuck := classifyConnLine([]byte(tc.line), dbPort, inodes)
			if isConn != tc.wantConn || isStuck != tc.stuck {
				t.Fatalf("classifyConnLine(%q) = %v,%v want %v,%v",
					tc.line, isConn, isStuck, tc.wantConn, tc.stuck)
			}
		})
	}

	// tcp6 rows go through the same parser.
	isConn, isStuck := classifyConnLine(
		[]byte(kineTCPRow("01", "00645E0A647D:1920", "00000004", "900")), dbPort, inodes)
	if !isConn || !isStuck {
		t.Fatalf("tcp6 retransmitting conn = %v,%v want true,true", isConn, isStuck)
	}
}

func TestTCPRemotePort(t *testing.T) {
	tests := []struct {
		rem      string
		wantPort int
		wantOK   bool
	}{
		{"0A0000FF:1920", 6432, true},
		{"00645E0A647D:1538", 5432, true},
		{"0100007F", 0, false},       // no colon — not an address:port
		{"0A0000FF:XYZW", 0, false},  // not hex
		{"0A0000FF:10000", 0, false}, // overflows 16 bits
		{"0A0000FF:", 0, false},      // empty port
	}
	for _, tc := range tests {
		port, ok := tcpRemotePort([]byte(tc.rem))
		if ok != tc.wantOK || port != tc.wantPort {
			t.Fatalf("tcpRemotePort(%q) = %d,%v want %d,%v",
				tc.rem, port, ok, tc.wantPort, tc.wantOK)
		}
	}
}
