package converge

import "testing"

func TestSHExecTokenAndCfgEnvVal(t *testing.T) {
	for _, good := range []string{"127.0.0.1", "[::1]", "/run/kine.sock", "10.0.0.1:2379"} {
		if !SHExecToken(good) {
			t.Fatalf("SHExecToken(%q) = false, want true", good)
		}
	}
	for _, bad := range []string{"", "a;b", "a b", "$(id)", "a\nb"} {
		if SHExecToken(bad) {
			t.Fatalf("SHExecToken(%q) = true, want false", bad)
		}
	}

	for _, good := range []string{"postgres://u:p@127.0.0.1:5432/db?sslmode=disable", "simple"} {
		if !CfgEnvVal(good) {
			t.Fatalf("CfgEnvVal(%q) = false, want true", good)
		}
	}
	for _, bad := range []string{"", `has"quote`, "line1\nline2", "tab\there"} {
		if CfgEnvVal(bad) {
			t.Fatalf("CfgEnvVal(%q) = true, want false", bad)
		}
	}
}
