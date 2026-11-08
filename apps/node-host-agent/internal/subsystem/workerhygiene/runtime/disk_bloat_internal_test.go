// disk_bloat_internal_test.go — package-internal coverage for the
// podLogDirUID parser (the external runtime tests reach the check
// only through full Cycles).
package runtime

import "testing"

func TestPodLogDirUID(t *testing.T) {
	for base, want := range map[string]string{
		"default_web_11111111-2222-3333-4444-555555555555": "11111111-2222-3333-4444-555555555555",
		"kube-system_coredns-abc_abcd1234":                 "abcd1234",
		"no-underscores":                                   "",
		"trailing-underscore_":                             "",
		"bare_":                                            "",
		"":                                                 "",
	} {
		if got := podLogDirUID(base); got != want {
			t.Fatalf("podLogDirUID(%q)=%q want %q", base, got, want)
		}
	}
}
