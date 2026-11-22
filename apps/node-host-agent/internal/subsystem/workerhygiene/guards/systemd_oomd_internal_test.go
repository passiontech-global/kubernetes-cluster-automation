// systemd_oomd_internal_test.go — internal table-driven tests for
// SystemdOOMDCheck.pruneSeenKills.
package guards

import (
	"fmt"
	"testing"
	"time"
)

func TestPruneSeenKills(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()

	cases := []struct {
		name  string
		seed  func(c *SystemdOOMDCheck)
		check func(t *testing.T, c *SystemdOOMDCheck)
	}{
		{
			name: "cutoff_lt_evicted_eq_and_gt_retained",
			seed: func(c *SystemdOOMDCheck) {
				c.seenKills["lt"] = base.Add(-time.Nanosecond)
				c.seenKills["eq"] = base
				c.seenKills["gt"] = base.Add(time.Second)
			},
			check: func(t *testing.T, c *SystemdOOMDCheck) {
				if len(c.seenKills) != 2 {
					t.Fatalf("len(seenKills)=%d want 2: %v", len(c.seenKills), c.seenKills)
				}
				if _, ok := c.seenKills["lt"]; ok {
					t.Fatal("entry strictly before cutoff must be evicted")
				}
				if _, ok := c.seenKills["eq"]; !ok {
					t.Fatal("entry equal to cutoff must be retained")
				}
				if _, ok := c.seenKills["gt"]; !ok {
					t.Fatal("entry after cutoff must be retained")
				}
			},
		},
		{
			name: "all_stale_cleared",
			seed: func(c *SystemdOOMDCheck) {
				c.seenKills["a"] = base.Add(-time.Minute)
				c.seenKills["b"] = base.Add(-time.Second)
			},
			check: func(t *testing.T, c *SystemdOOMDCheck) {
				if len(c.seenKills) != 0 {
					t.Fatalf("len(seenKills)=%d want 0", len(c.seenKills))
				}
			},
		},
		{
			name: "over_maxSeenOOMDKills_evicts_oldest",
			seed: func(c *SystemdOOMDCheck) {
				for i := range maxSeenOOMDKills + 5 {
					c.seenKills[fmt.Sprintf("k-%04d", i)] = base.Add(time.Duration(i) * time.Second)
				}
			},
			check: func(t *testing.T, c *SystemdOOMDCheck) {
				if len(c.seenKills) != maxSeenOOMDKills {
					t.Fatalf("len(seenKills)=%d want %d", len(c.seenKills), maxSeenOOMDKills)
				}
				for i := range 5 {
					k := fmt.Sprintf("k-%04d", i)
					if _, ok := c.seenKills[k]; ok {
						t.Fatalf("expected oldest key %s to be evicted", k)
					}
				}
				for i := 5; i < maxSeenOOMDKills+5; i++ {
					k := fmt.Sprintf("k-%04d", i)
					if _, ok := c.seenKills[k]; !ok {
						t.Fatalf("expected newer key %s to be retained", k)
					}
				}
			},
		},
		{
			name: "stale_pruned_before_cap_check",
			seed: func(c *SystemdOOMDCheck) {
				for i := range 10 {
					c.seenKills[fmt.Sprintf("stale-%d", i)] = base.Add(-time.Duration(i+1) * time.Second)
				}
				for i := range maxSeenOOMDKills {
					c.seenKills[fmt.Sprintf("fresh-%04d", i)] = base.Add(time.Duration(i) * time.Second)
				}
			},
			check: func(t *testing.T, c *SystemdOOMDCheck) {
				if len(c.seenKills) != maxSeenOOMDKills {
					t.Fatalf("len(seenKills)=%d want %d", len(c.seenKills), maxSeenOOMDKills)
				}
				for i := range maxSeenOOMDKills {
					k := fmt.Sprintf("fresh-%04d", i)
					if _, ok := c.seenKills[k]; !ok {
						t.Fatalf("expected fresh key %s retained after stale eviction", k)
					}
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, _ := gDeps(t)
			c := newSystemdOOMD(d)
			tc.seed(c)
			c.pruneSeenKills(base)
			tc.check(t, c)
		})
	}
}
