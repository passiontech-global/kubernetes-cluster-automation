package kinedb

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"net"
	"os"
	"strings"
	"testing"
)

func TestPGStartupMessage(t *testing.T) {
	pkt := pgStartupMessage("postgres", "postgres")
	// Length prefix covers itself + the whole packet.
	if got := binary.BigEndian.Uint32(pkt[:4]); int(got) != len(pkt) {
		t.Fatalf("length prefix=%d packet=%d", got, len(pkt))
	}
	// Protocol 3.0 = 196608 = \x00\x03\x00\x00.
	if got := binary.BigEndian.Uint32(pkt[4:8]); got != 196608 {
		t.Fatalf("protocol=%d", got)
	}
	want := "user\x00postgres\x00database\x00postgres\x00\x00"
	if string(pkt[8:]) != want {
		t.Fatalf("params=%q", pkt[8:])
	}
}

func TestPGFirstByteOK(t *testing.T) {
	for _, b := range []byte{'R', 'S', 'N', 'K'} {
		if !pgFirstByteOK(b) {
			t.Fatalf("byte %c should be ok", b)
		}
	}
	for _, b := range []byte{'E', 'F', 0} {
		if pgFirstByteOK(b) {
			t.Fatalf("byte %c should fail", b)
		}
	}
}

// wireListener answers every conn with resp after reading one write.
func wireListener(t *testing.T, resp byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback")
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte{resp})
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestPGWireProbe(t *testing.T) {
	if !pgWireProbe(context.Background(), wireListener(t, 'R'), 2*testWireTO) {
		t.Fatal("rejected an R response")
	}
	if pgWireProbe(context.Background(), wireListener(t, 'E'), 2*testWireTO) {
		t.Fatal("accepted an E response")
	}
	// Closed port → dial refused → fail.
	if pgWireProbe(context.Background(), "127.0.0.1:1", testWireTO) {
		t.Fatal("accepted a refused connection")
	}
}

const testWireTO = 2 * 1e9 // 2s in ns — time.Duration

const showPoolsOut = `database|user|cl_active|cl_waiting|sv_active|sv_idle|sv_used|sv_tested|sv_login|maxwait|maxwait_us|pool_mode
postgres|postgres|4|0|3|7|0|0|0|0|0|transaction
pgbouncer|pgbouncer|1|0|0|0|0|0|0|0|0|transaction
`

func TestParseShowPools(t *testing.T) {
	st, ok := parseShowPools(showPoolsOut, "postgres")
	if !ok {
		t.Fatal("postgres row not found")
	}
	if st.svActive != 3 || st.svIdle != 7 {
		t.Fatalf("sv_active=%d sv_idle=%d", st.svActive, st.svIdle)
	}
	if st.serverConns != 10 {
		t.Fatalf("serverConns=%d", st.serverConns)
	}
	if st.clWaiting != 0 {
		t.Fatalf("clWaiting=%d", st.clWaiting)
	}
	// Column order independence — cl_waiting moved to the end.
	shuffled := "database|cl_waiting|sv_active|sv_idle\npostgres|9|1|2\n"
	st, ok = parseShowPools(shuffled, "postgres")
	if !ok || st.clWaiting != 9 || st.serverConns != 3 {
		t.Fatalf("shuffled=%+v ok=%v", st, ok)
	}
	if _, ok := parseShowPools("ERROR: boom\n", "postgres"); ok {
		t.Fatal("parsed garbage")
	}
	// SHOW POOLS emits one row per (database,user) — sv_* sum and
	// cl_waiting takes the max across the postgres pool's rows.
	multi := "database|user|sv_active|sv_idle|cl_waiting\n" +
		"postgres|postgres|3|7|2\n" +
		"postgres|kine|1|4|9\n" +
		"pgbouncer|pgbouncer|0|0|50\n"
	st, ok = parseShowPools(multi, "postgres")
	if !ok || st.svActive != 4 || st.svIdle != 11 ||
		st.serverConns != 15 || st.clWaiting != 9 {
		t.Fatalf("multi=%+v ok=%v", st, ok)
	}
	// A pool literally named "database" must not be eaten by the
	// header case — the header row carries sv_*/cl_* column names.
	named := "database|user|sv_active|cl_waiting\n" +
		"database|postgres|5|1\n"
	st, ok = parseShowPools(named, "database")
	if !ok || st.svActive != 5 || st.clWaiting != 1 {
		t.Fatalf("db-named pool=%+v ok=%v", st, ok)
	}
}

// probeOKRules is the full-success command set. The revision query
// answers head|compact_rev|live_tup — no COUNT(*) (the row count is
// the guard's job; a per-2min seq-scan bloats what it measures).
var probeOKRules = []testutil.ExecRule{
	{Substr: "inspect", Out: "true"},
	{Substr: "SHOW POOLS", Out: showPoolsOut},
	{Substr: "logs --since", Out: "all quiet"},
	{Substr: "MAX(id)", Out: "1000|200|290\n"},
	{Substr: "select 1", Out: "1\n"},
}

func TestProbeCycleAllOK(t *testing.T) {
	k, fr, dir := fixture(t, probeOKRules)
	res := k.probeCycle(context.Background())
	for _, c := range probeChecks {
		if res.checks[c] != 1 {
			t.Fatalf("check %s=%d notes=%v", c, res.checks[c], res.notes)
		}
	}
	if !res.succeeded {
		t.Fatalf("probe did not succeed: %v", res.notes)
	}
	j := fr.Joined()
	// e2e goes through the pooler from inside the postgres container
	// — in-container port 5432 on the podman network (6432 is only
	// the published host port).
	if !strings.Contains(j, "exec -e PGPASSWORD=secret kine-postgres psql -h kine-pgbouncer -p 5432") {
		t.Fatalf("e2e argv missing pooler path:\n%s", j)
	}
	// The pgbouncer log scan uses the bash's 301s window (5m plus
	// the boundary second).
	if !strings.Contains(j, "logs --since 301s") {
		t.Fatalf("log scan window wrong:\n%s", j)
	}
	// No COUNT(*) anywhere in the 2-minute probe — the row count
	// seq-scan belongs to the 10-min guard.
	if strings.Contains(j, "COUNT(*)") {
		t.Fatalf("probe ran a full COUNT(*):\n%s", j)
	}
	content := readText(t, dir, "kine-db.prom")
	for _, want := range []string{
		`kine_db_probe_ok{check="containers"} 1`,
		`kine_db_probe_ok{check="wire"} 1`,
		`kine_db_probe_ok{check="e2e_auth"} 1`,
		`kine_db_probe_ok{check="pools"} 1`,
		`kine_db_probe_ok{check="backend_env"} 1`,
		`kine_db_probe_ok{check="log_errors"} 1`,
		`kine_db_probe_ok{check="revision_horizon"} 1`,
		`kine_db_pgbouncer_server_conns{state="active"} 3`,
		`kine_db_pgbouncer_server_conns{state="idle"} 7`,
		`kine_db_pgbouncer_clients_waiting 0`,
		`kine_db_head_revision 1000`,
		`kine_db_compact_revision 200`,
		`kine_db_retained_revisions 800`,
		`kine_db_probe_last_run_timestamp_seconds 1700000000`,
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("textfile missing %q:\n%s", want, content)
		}
	}
	// kine_db_rows must NOT be in the probe textfile — the guard
	// owns that series in kine-compact-guard.prom (duplicate series
	// across textfiles fail the scrape).
	if strings.Contains(content, "kine_db_rows") {
		t.Fatalf("probe textfile must not carry kine_db_rows:\n%s", content)
	}
	for _, fam := range []string{"kine_db_probe_ok", "kine_db_pgbouncer_server_conns"} {
		if n := strings.Count(content, "# HELP "+fam+" "); n != 1 {
			t.Fatalf("duplicate HELP for %s (count=%d):\n%s", fam, n, content)
		}
		if n := strings.Count(content, "# TYPE "+fam+" "); n != 1 {
			t.Fatalf("duplicate TYPE for %s (count=%d):\n%s", fam, n, content)
		}
	}
}

func TestProbeCycleFailures(t *testing.T) {
	k, _, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "SHOW POOLS", Out: "database|sv_active|sv_idle|cl_waiting\npostgres|0|0|300\n"},
		{Substr: "logs --since", Out: "server_login_retry\npassword authentication failed\n"},
		{Substr: "MAX(id)", Out: "1000|200|290\n"},
		{Substr: "select 1", Out: "1\n"},
	})
	k.cfg.wireFn = func(context.Context, string) bool { return false }
	res := k.probeCycle(context.Background())
	if res.checks[checkWire] != 0 {
		t.Fatal("wire should fail")
	}
	if res.checks[checkPools] != 0 {
		t.Fatal("pools should fail (no server conns + deep queue)")
	}
	if res.checks[checkLogErrors] != 0 {
		t.Fatal("log_errors should fail")
	}
	if res.succeeded {
		t.Fatal("probe reported success")
	}
	if res.pool.clWaiting != 300 {
		t.Fatalf("clWaiting=%d", res.pool.clWaiting)
	}
	content := readText(t, dir, "kine-db.prom")
	if !strings.Contains(content, `kine_db_probe_ok{check="wire"} 0`) ||
		!strings.Contains(content, `kine_db_pgbouncer_clients_waiting 300`) {
		t.Fatalf("textfile:\n%s", content)
	}
}

// The pgbouncer log scan needs no .env creds — the bash ran it at
// containers==1. With the env file missing, log_errors must still
// evaluate while every cred-needing check stays 0.
func TestProbeCycleLogScanWithoutCreds(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "logs --since", Out: "all quiet"},
	})
	if err := os.Remove(k.cfg.EnvFile); err != nil {
		t.Fatal(err)
	}
	res := k.probeCycle(context.Background())
	if res.checks[checkLogErrors] != 1 {
		t.Fatalf("log_errors must run without .env creds: %+v", res.checks)
	}
	for _, c := range []string{checkE2EAuth, checkPools, checkBackendEnv, checkRevision} {
		if res.checks[c] != 0 {
			t.Fatalf("check %s must stay 0 without creds", c)
		}
	}
	if !strings.Contains(fr.Joined(), "logs --since 301s") {
		t.Fatalf("log scan did not run:\n%s", fr.Joined())
	}
}

func TestProbeCycleContainersDown(t *testing.T) {
	k, _, _ := fixture(t, []testutil.ExecRule{
		// inspect of the named containers fails AND no match in ps →
		// discovery keeps the preferred names, then -f inspect fails.
		{Substr: "inspect", Err: errors.New("down")},
		{Substr: "ps --format", Out: ""},
	})
	res := k.probeCycle(context.Background())
	if res.checks[checkContainers] != 0 {
		t.Fatal("containers should fail")
	}
	// Wire still runs unconditionally.
	if res.checks[checkWire] != 1 {
		t.Fatal("wire check must run even with containers down")
	}
	if res.checks[checkE2EAuth] != 0 {
		t.Fatal("e2e must stay 0 with containers down")
	}
}

// TestProbeLogScanQuoting: the log scan is the one place a configured
// name reaches a `sh -c` STRING — the runtime and container words
// must be single-quoted so a space/metachar cannot split or glob.
func TestProbeLogScanQuoting(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "logs --since", Out: "all quiet"},
	})
	k.probeCycle(context.Background())
	if !strings.Contains(fr.Joined(),
		"'podman' logs --since 301s 'kine-pgbouncer' 2>&1") {
		t.Fatalf("log scan argv unquoted:\n%s", fr.Joined())
	}
}
