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
