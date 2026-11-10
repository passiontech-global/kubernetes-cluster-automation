// group_verify_extra_test.go — the informational tail group: failing
// probes warn without counting, succeeding ones log.
package hostconfig

import (
	"testing"
)

// TestVerifyProbesAreInformational — both probes failing must leave
// the cycle clean (ansible debug parity: log, never count).
func TestVerifyProbesAreInformational(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	sr.FailOn("getent ahosts", nil)
	sr.FailOn("sysctl -n", nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupVerify()
	if c.errs != 0 {
		t.Fatalf("errs = %d — the verify group is informational only", c.errs)
	}
	if len(sr.CallsMatching("getent ahosts api.test.internal")) == 0 {
		t.Fatal("cp_endpoint probe not issued")
	}

	// The healthy path issues both probes and stays clean too.
	sr.ClearFails()
	sr.On("getent ahosts api.test.internal", "203.0.113.14 STREAM api.test.internal\n")
	sr.On("sysctl -n", "bbr\nfq\n")
	c.groupVerify()
	if c.errs != 0 {
		t.Fatalf("healthy verify counted errors: %d", c.errs)
	}
}
