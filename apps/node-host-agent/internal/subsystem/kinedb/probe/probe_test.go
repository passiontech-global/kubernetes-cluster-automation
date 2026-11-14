package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/probee"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func TestPGStartupMessage(t *testing.T) {
	pkt := probee.PGStartupMessage("postgres", "postgres")
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
		if !probee.PGFirstByteOK(b) {
			t.Fatalf("byte %c should be ok", b)
		}
	}
	for _, b := range []byte{'E', 'F', 0} {
		if probee.PGFirstByteOK(b) {
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

func TestParseShowPools(t *testing.T) {
	st, ok := parseShowPools(kdepstest.ShowPoolsOut, "postgres")
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

func TestProbeCycleAllOK(t *testing.T) {
	k, fr, dir := fixture(t, kdepstest.ProbeOKRules)
	res := k.Cycle(context.Background())
	for _, c := range probeChecks {
		if res.Checks[c] != 1 {
			t.Fatalf("check %s=%d notes=%v", c, res.Checks[c], res.notes)
		}
	}
	if !res.succeeded {
		t.Fatalf("probe did not succeed: %v", res.notes)
	}
	j := fr.Joined()
	// e2e goes through the pooler from inside the postgres container
	// — in-container port 5432 on the podman network (6432 is only
	// the published host port).
	if !strings.Contains(j, "exec -e PGPASSWORD kine-postgres psql -h kine-pgbouncer -p 5432") {
		t.Fatalf("e2e argv missing pooler path:\n%s", j)
	}
	if strings.Contains(j, "PGPASSWORD=secret") {
		t.Fatalf("password leaked onto argv:\n%s", j)
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
	content := kdepstest.ReadText(t, dir, "kine-db.prom")
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
		{Substr: "inspect", Out: "true\ntrue\ntrue\ntrue\n"},
		{Substr: "SHOW POOLS", Out: "database|sv_active|sv_idle|cl_waiting\npostgres|0|0|300\n"},
		{Substr: "logs --since", Out: "server_login_retry\npassword authentication failed\n"},
		{Substr: "MAX(id)", Out: "1000|200|290\n"},
		{Substr: "select 1", Out: "1\n"},
	})
	k.d.Cfg.WireFn = func(context.Context, string) bool { return false }
	res := k.Cycle(context.Background())
	if res.Checks[CheckWire] != 0 {
		t.Fatal("wire should fail")
	}
	if res.Checks[CheckPools] != 0 {
		t.Fatal("pools should fail (no server conns + deep queue)")
	}
	if res.Checks[CheckLogErrors] != 0 {
		t.Fatal("log_errors should fail")
	}
	if res.succeeded {
		t.Fatal("probe reported success")
	}
	if res.pool.clWaiting != 300 {
		t.Fatalf("clWaiting=%d", res.pool.clWaiting)
	}
	content := kdepstest.ReadText(t, dir, "kine-db.prom")
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
		{Substr: "inspect", Out: "true\ntrue\ntrue\ntrue\n"},
		{Substr: "logs --since", Out: "all quiet"},
	})
	if err := os.Remove(k.d.Cfg.EnvFile); err != nil {
		t.Fatal(err)
	}
	res := k.Cycle(context.Background())
	if res.Checks[CheckLogErrors] != 1 {
		t.Fatalf("log_errors must run without .env creds: %+v", res.Checks)
	}
	for _, c := range []string{CheckE2EAuth, CheckPools, CheckBackendEnv, CheckRevision} {
		if res.Checks[c] != 0 {
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
	res := k.Cycle(context.Background())
	if res.Checks[CheckContainers] != 0 {
		t.Fatal("containers should fail")
	}
	// Wire still runs unconditionally.
	if res.Checks[CheckWire] != 1 {
		t.Fatal("wire check must run even with containers down")
	}
	if res.Checks[CheckE2EAuth] != 0 {
		t.Fatal("e2e must stay 0 with containers down")
	}
}

// TestProbeLogScanArgv: the log scan runs `logs` argv-direct through
// the combined seam — no sh -c means the configured runtime and
// container names reach the exec verbatim, metachars and all (the
// quoting hazard the old shell string carried is gone by
// construction).
func TestProbeLogScanArgv(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true\ntrue\ntrue\ntrue\n"},
		{Substr: "logs --since", Out: "all quiet"},
	})
	k.Cycle(context.Background())
	if !strings.Contains(fr.Joined(),
		"podman logs --since 301s kine-pgbouncer") {
		t.Fatalf("log scan argv not direct:\n%s", fr.Joined())
	}
	if strings.Contains(fr.Joined(), "2>&1") ||
		strings.Contains(fr.Joined(), "sh -c") {
		t.Fatalf("log scan still shells out:\n%s", fr.Joined())
	}
}

// A failed `logs` read is inconclusive: log_errors stays 0, the
// check is excluded from the success verdict (logScanned false), and
// the failure is noted — a scan failure must not read as a clean log.
func TestProbeLogScanFailure(t *testing.T) {
	k, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true\ntrue\ntrue\ntrue\n"},
		{Substr: "logs --since", Err: errors.New("container gone")},
	})
	res := k.Cycle(context.Background())
	if res.logScanned {
		t.Fatal("failed scan must not read scanned")
	}
	if res.Checks[CheckLogErrors] != 0 {
		t.Fatalf("log errors=%d want 0", res.Checks[CheckLogErrors])
	}
	found := false
	for _, n := range res.notes {
		if strings.Contains(n, "log-scan-fail") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no log-scan-fail note: %v", res.notes)
	}
}

// New fills the wire seam with the real Go v3 StartupMessage probe
// when the config left it unset — and the default seam answers false
// on a refused dial.
func TestProbeNewDefaultsWireFn(t *testing.T) {
	cfg, _, _ := kdepstest.Config(t, nil)
	cfg.WireFn = nil
	p := New(kdepstest.Deps(t, cfg))
	if p.d.Cfg.WireFn == nil {
		t.Fatal("New did not install the default wire seam")
	}
	if p.d.Cfg.WireFn(context.Background(), "127.0.0.1:1") {
		t.Fatal("refused dial reported alive")
	}
}

// A pooler that takes the StartupMessage and hangs up without a
// reply is broken — the probe's one-byte read must fail.
func TestPGWireProbeReadFail(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		// Drain the exact StartupMessage (41 bytes for
		// postgres/postgres), then close with no answer.
		buf := make([]byte, len(probee.PGStartupMessage("postgres", "postgres")))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
	}()
	if pgWireProbe(context.Background(), ln.Addr().String(), 2*time.Second) {
		t.Fatal("connection closed without a reply reported alive")
	}
	<-done
}

// A pooler that resets right after the dial (RST before the write)
// must also read as broken. The exact failure point is racy — write
// error vs read error — so only the false verdict is asserted.
func TestPGWireProbeReset(t *testing.T) {
	for range 3 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if tc, ok := conn.(*net.TCPConn); ok {
				_ = tc.SetLinger(0) // close → RST, no FIN
			}
			_ = conn.Close()
		}()
		alive := pgWireProbe(context.Background(), ln.Addr().String(), 2*time.Second)
		_ = ln.Close()
		if alive {
			t.Fatal("RST connection reported alive")
		}
	}
}

// A failed SHOW POOLS read (primary AND in-container fallback) and
// a failed revision query each note their own inconclusive shape and
// zero their checks — the probe reads failed, not clean.
func TestProbeCyclePoolAndRevisionQueryFail(t *testing.T) {
	k, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true\ntrue\ntrue\ntrue\n"},
		{Substr: "SHOW POOLS", Err: errors.New("console unreachable")},
		// The fallback psql (stats_users from pgbouncer.ini) fails too.
		{Substr: "userlist.txt", Err: errors.New("no such file")},
		{Substr: "COALESCE((SELECT n_live_tup", Err: errors.New("connection reset")},
		{Substr: "select 1", Out: "1\n"},
	})
	res := k.Cycle(context.Background())
	if res.Checks[CheckPools] != 0 || res.Checks[CheckRevision] != 0 {
		t.Fatalf("checks=%v want pools+revision zeroed", res.Checks)
	}
	if res.succeeded {
		t.Fatal("probe must fail with pools+revision inconclusive")
	}
	joined := strings.Join(res.notes, "\n")
	if !strings.Contains(joined, "show-pools-fail") {
		t.Fatalf("notes=%v want show-pools-fail", res.notes)
	}
	if !strings.Contains(joined, "revision-query-fail") {
		t.Fatalf("notes=%v want revision-query-fail", res.notes)
	}
}

// parseShowPools skips malformed rows (too few fields for the
// header, non-numeric cells) but still aggregates the good ones.
func TestParseShowPoolsSkipsMalformedRows(t *testing.T) {
	out := "database|user|cl_active|cl_waiting|sv_active|sv_idle|sv_used|sv_tested|sv_login|maxwait|maxwait_us|pool_mode\n" +
		"postgres|truncated|3\n" + // short row → skipped
		"postgres|postgres|x|0|1|1|0|0|0|0|0|transaction\n" + // bad int → cell skipped
		"postgres|postgres|4|0|1|2|0|0|0|0|0|transaction\n"
	st, ok := parseShowPools(out, "postgres")
	if !ok {
		t.Fatal("a valid row among malformed ones must parse")
	}
	if st.serverConns != 5 { // 1+1 from row 2, 1+2 from row 3
		t.Fatalf("serverConns=%d want 5", st.serverConns)
	}
}

func TestUserlistPassword(t *testing.T) {
	ul := "\"postgres_extra\" \"wrong\"\r\n" +
		"\"postgres\" \"md5abc123\"\r\n" +
		"\"noquote\" bare\n" +
		"\"unterminated\" \"tailval\n"

	if got := userlistPassword(ul, "postgres"); got != "md5abc123" {
		t.Fatalf("postgres=%q want md5abc123", got)
	}
	if got := userlistPassword(ul, "noquote"); got != "" {
		t.Fatalf("noquote=%q want empty", got)
	}
	if got := userlistPassword(ul, "unterminated"); got != "tailval" {
		t.Fatalf("unterminated=%q want tailval", got)
	}
	if got := userlistPassword(ul, "absent"); got != "" {
		t.Fatalf("absent=%q want empty", got)
	}
}
