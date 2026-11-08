// deps_test.go — the Deps decision helpers: the spof-streak
// single-controller rule (TotalControllers override vs the PeerAPI
// heuristic) and the doubled restart-gate streak.
package cdeps_test

import (
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

func TestSingleController(t *testing.T) {
	cases := []struct {
		name  string
		total int
		peer  string
		want  bool
	}{
		{"explicit single", 1, "10.0.0.2:6443", true},
		{"explicit multi", 3, "", false},
		{"auto no peer", 0, "", true},
		{"auto with peer", 0, "10.0.0.2:6443", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := &cdeps.Deps{Cfg: cdeps.Config{
				TotalControllers: c.total,
				Hub:              cdeps.HubConfig{PeerAPI: c.peer},
			}}
			if got := d.SingleController(); got != c.want {
				t.Fatalf("SingleController=%v want %v", got, c.want)
			}
		})
	}
}

func TestStreakCycles(t *testing.T) {
	d := &cdeps.Deps{Cfg: cdeps.Config{TotalControllers: 3}}
	if got := d.StreakCycles(4); got != 4 {
		t.Fatalf("multi-controller streak=%d want 4", got)
	}
	d.Cfg.TotalControllers = 1
	if got := d.StreakCycles(4); got != 8 {
		t.Fatalf("single-controller streak=%d want 8 (doubled)", got)
	}
}
