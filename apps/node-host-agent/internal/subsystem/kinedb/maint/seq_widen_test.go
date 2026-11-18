package maint

import (
	"context"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func TestSeqWidenAutoWidensInt8ColumnWithInt4Sequence(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
		{Substr: "pg_sequences", Out: "20|kine_id_seq\n1500000000|2147483647|integer\n"},
	})
	var stdins []string
	origRun := k.d.Cfg.Run
	k.d.Cfg.Run = func(ctx context.Context, env, argv []string, stdin string) (string, error) {
		if stdin != "" {
			stdins = append(stdins, stdin)
		}
		return origRun(ctx, env, argv, stdin)
	}

	res := k.Cycle(context.Background())
	if !res.seqWidened {
		t.Fatalf("expected seqWidened=true, notes=%v", res.notes)
	}
	allStdin := strings.Join(stdins, "\n")
	if !strings.Contains(allStdin, `ALTER SEQUENCE "kine_id_seq" AS bigint MAXVALUE 9223372036854775807;`) ||
		!strings.Contains(allStdin, "pg_try_advisory_lock") {
		t.Fatalf("missing advisory-locked ALTER SEQUENCE in stdins:\n%s\ncmds:\n%s", allStdin, fr.Joined())
	}
	// The ACCESS EXCLUSIVE lock must be bounded or it blocks apiserver nextval.
	lockTO := strings.Index(allStdin, "SET lock_timeout = '2s'")
	stmtTO := strings.Index(allStdin, "SET statement_timeout = '5s'")
	alter := strings.Index(allStdin, "ALTER SEQUENCE")
	if lockTO < 0 || stmtTO < 0 || alter < 0 || lockTO > stmtTO || stmtTO > alter {
		t.Fatalf("want lock_timeout then statement_timeout then ALTER, got:\n%s", allStdin)
	}
}

// A quoted sequence identifier from pg_get_serial_sequence must be
// unquoted once and re-quoted safely in the DDL (no double-escaping).
// A kine.id without an OWNED BY link makes pg_get_serial_sequence() NULL.
// The generated pg_sequences WHERE must COALESCE to the same fallback name
// the SELECT reports; otherwise it matches zero rows and MAX(max_value)
// parses as 0 — silently disabling the widen guard.
func TestSeqWidenFallbackSeqUsedInWhere(t *testing.T) {
	k, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
		{Substr: "pg_sequences", Out: "20|kine_id_seq\n1500000000|2147483647|integer\n"},
	})
	var seqSQL string
	origRun := k.d.Cfg.Run
	k.d.Cfg.Run = func(ctx context.Context, env, argv []string, stdin string) (string, error) {
		for i := range argv {
			if strings.Contains(argv[i], "pg_sequences") {
				seqSQL = argv[i]
			}
		}
		return origRun(ctx, env, argv, stdin)
	}
	res := k.Cycle(context.Background())
	if !res.seqWidened {
		t.Fatalf("expected widen with fallback seq, notes=%v", res.notes)
	}
	wantWhere := "WHERE schemaname = current_schema() AND sequencename = COALESCE("
	if !strings.Contains(seqSQL, wantWhere) || !strings.Contains(seqSQL, ", 'kine_id_seq')") {
		t.Fatalf("pg_sequences WHERE lacks the fallback COALESCE:\n%s", seqSQL)
	}
	if !strings.Contains(seqSQL, "COALESCE(MAX(max_value),0)") {
		t.Fatalf("single-row MAX shape changed:\n%s", seqSQL)
	}
}

func TestSeqWidenQuotedSequenceName(t *testing.T) {
	k, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
		{Substr: "pg_sequences", Out: "20|\"my\"\"seq\"\n1500000000|2147483647|integer\n"},
	})
	var stdins []string
	origRun := k.d.Cfg.Run
	k.d.Cfg.Run = func(ctx context.Context, env, argv []string, stdin string) (string, error) {
		if stdin != "" {
			stdins = append(stdins, stdin)
		}
		return origRun(ctx, env, argv, stdin)
	}
	res := k.Cycle(context.Background())
	if !res.seqWidened {
		t.Fatalf("expected seqWidened=true for quoted name, notes=%v", res.notes)
	}
	if !strings.Contains(strings.Join(stdins, "\n"), `ALTER SEQUENCE "my""seq" AS bigint`) {
		t.Fatalf("quoted name not re-quoted correctly:\n%s", strings.Join(stdins, "\n"))
	}
}

func TestSeqWidenSkipsLockBusyAndReadOnlyAndDisabled(t *testing.T) {
	// Lock busy skips without failing.
	k, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
		{Substr: "pg_sequences", Out: "20|kine_id_seq\n1500000000|2147483647|integer\n"},
		{Substr: "ON_ERROR_STOP", Out: kdeps.LockBusyMarker + "\n"},
	})
	res := k.Cycle(context.Background())
	if res.seqWidened {
		t.Fatal("expected seqWidened=false when advisory lock busy")
	}

	// ReadOnly skips probe & DDL completely.
	kRO, frRO, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
		{Substr: "pg_sequences", Out: "20|kine_id_seq\n1500000000|2147483647|integer\n"},
	})
	kRO.d.Cfg.ReadOnly = true
	resRO := kRO.Cycle(context.Background())
	if resRO.seqWidened || strings.Contains(frRO.Joined(), "pg_sequences") {
		t.Fatal("ReadOnly must not probe or widen sequence")
	}

	// SeqWidenEnabled=false skips completely.
	kDis, frDis, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
		{Substr: "pg_sequences", Out: "20|kine_id_seq\n1500000000|2147483647|integer\n"},
	})
	kDis.d.Cfg.SeqWidenEnabled = false
	resDis := kDis.Cycle(context.Background())
	if resDis.seqWidened || strings.Contains(frDis.Joined(), "pg_sequences") {
		t.Fatal("SeqWidenEnabled=false must not probe or widen sequence")
	}
}

func TestSeqWidenInt4ColumnWarnsP0WithoutAlterTable(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
		{Substr: "pg_sequences", Out: "23|kine_id_seq\n1200000000|2147483647|integer\n"},
	})
	var stdins []string
	origRun := k.d.Cfg.Run
	k.d.Cfg.Run = func(ctx context.Context, env, argv []string, stdin string) (string, error) {
		if stdin != "" {
			stdins = append(stdins, stdin)
		}
		return origRun(ctx, env, argv, stdin)
	}

	res := k.Cycle(context.Background())
	if res.seqWidened {
		t.Fatal("int4 column must not trigger ALTER SEQUENCE or ALTER TABLE")
	}
	allStdin := strings.Join(stdins, "\n")
	if strings.Contains(allStdin, "ALTER TABLE") || strings.Contains(allStdin, "ALTER SEQUENCE") || strings.Contains(fr.Joined(), "ALTER ") {
		t.Fatalf("int4 column must not run ALTER DDL:\n%s\n%s", allStdin, fr.Joined())
	}
	foundP0 := false
	for _, n := range res.notes {
		if strings.Contains(n, "P0 CRITICAL") && strings.Contains(n, "int4") {
			foundP0 = true
		}
	}
	if !foundP0 {
		t.Fatalf("expected P0 CRITICAL note for int4 >= 50%%, got: %v", res.notes)
	}
}
