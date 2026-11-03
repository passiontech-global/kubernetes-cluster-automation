package hubsync

import (
	"testing"
)

// TestLoadTargetsAggregation covers the three inventory sources,
// by-IP dedup and the ssh_user resolution chain against the fixture
// vars dir.
func TestLoadTargetsAggregation(t *testing.T) {
	targets, err := loadTargets("testdata/vars")
	if err != nil {
		t.Fatalf("loadTargets: %v", err)
	}

	byName := map[string]Target{}
	for _, tg := range targets {
		if _, dup := byName[tg.Name]; dup {
			t.Fatalf("duplicate target %q", tg.Name)
		}
		byName[tg.Name] = tg
	}
	if len(targets) != 5 {
		t.Fatalf("got %d targets, want 5: %+v", len(targets), targets)
	}

	// a. interdc agent:false nodes — controllers/hubs.
	hub := byName["hub-controller-01"]
	if !hub.InterDC || !hub.Hub {
		t.Fatalf("hub-controller-01 flags: %+v", hub)
	}
	if hub.IP != "10.0.0.25" {
		t.Fatalf("hub-controller-01 ip %q", hub.IP)
	}
	if hub.ProxyJump != "root@10.0.0.15" {
		t.Fatalf("hub-controller-01 proxyjump %q", hub.ProxyJump)
	}
	// site=datahub not in by_site map → interdc_ssh_default_user.
	if hub.SSHUser != "root" {
		t.Fatalf("hub-controller-01 user %q", hub.SSHUser)
	}

	// site=lanit resolves via interdc_ssh_user_by_site → ubuntu.
	lh := byName["lanit-hub-01"]
	if !lh.InterDC || lh.SSHUser != "ubuntu" {
		t.Fatalf("lanit-hub-01: %+v", lh)
	}

	// An explicit ssh_user beats the site map (lanit would be ubuntu).
	lh2 := byName["lanit-hub-02"]
	if !lh2.InterDC || lh2.Hub {
		t.Fatalf("lanit-hub-02 flags: %+v", lh2)
	}
	if lh2.SSHUser != "converge" {
		t.Fatalf("lanit-hub-02 user %q, want explicit converge", lh2.SSHUser)
	}

	// b+c. api-lb-vm is in node_exporter_extra_hosts AND
	// api_lb_guard_vms — deduped to one target carrying APILB.
	alb := byName["api-lb-vm"]
	if !alb.APILB || alb.IP != "10.0.0.14" {
		t.Fatalf("api-lb-vm: %+v", alb)
	}
	if alb.InterDC || alb.KineDB {
		t.Fatalf("api-lb-vm picked up wrong flags: %+v", alb)
	}

	// db-vm carries kine_db from extra_hosts.
	db := byName["db-vm"]
	if !db.KineDB || db.APILB || db.InterDC {
		t.Fatalf("db-vm flags: %+v", db)
	}
	// extra_hosts has no site-map step → default user.
	if db.SSHUser != "root" {
		t.Fatalf("db-vm user %q", db.SSHUser)
	}

	// Excluded: lanit-worker-01 (agent defaulted true) and
	// lanit-worker-02 (agent: true).
	for _, n := range []string{"lanit-worker-01", "lanit-worker-02"} {
		if _, ok := byName[n]; ok {
			t.Fatalf("worker %s must not be a target", n)
		}
	}
}
