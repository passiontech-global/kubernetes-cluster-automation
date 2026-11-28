package releaseglob

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestRepoRoot(t *testing.T) {
	root := RepoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "go.work")); err != nil {
		t.Fatalf("RepoRoot(%q) missing go.work: %v", root, err)
	}
}

func TestParseConsumerArmsAndLookup(t *testing.T) {
	sample := `
            def consumers($p):
              if ($p | startswith("apps/")) then [] else [] end
              elif ($p | startswith("libs/jinja/")) then ["node-host-agent"]
              elif ($p | startswith("libs/hostkit/envx/")) or $p == "libs/hostkit/go.mod" then ["node-host-agent","webhook-dispatcher"]
              elif $p == "mise.toml" then ["node-host-agent","node-automation-controller","webhook-dispatcher"]
              else [] end;
`
	arms, errMsg := parseConsumerArms(sample)
	if errMsg != "" {
		t.Fatalf("parseConsumerArms error: %s", errMsg)
	}
	if len(arms) != 3 {
		t.Fatalf("len(arms) = %d, want 3", len(arms))
	}
	if got := consumersFor(arms, "libs/jinja/jinja.go"); !slices.Equal(got, []string{"node-host-agent"}) {
		t.Fatalf("consumersFor(jinja) = %v", got)
	}
	if got := consumersFor(arms, "libs/hostkit/go.mod"); !slices.Equal(got, []string{"node-host-agent", "webhook-dispatcher"}) {
		t.Fatalf("consumersFor(go.mod) = %v", got)
	}
	if got := consumersFor(arms, "libs/hostkit/envdoc/envdoc.go"); got != nil {
		t.Fatalf("consumersFor(envdoc) = %v, want nil", got)
	}
}

func TestParseKoDetectArmsAndLookup(t *testing.T) {
	sample := `
      - name: Detect affected ko apps
        id: ko-detect
        run: |
          case "$p" in
            ""|*.md|*_test.go) continue ;;
            apps/node-automation-controller/*|libs/hostkit/ledger/*)
              nac=true ;;
            apps/webhook-dispatcher/*)
              wd=true ;;
            libs/hostkit/envx/*|mise.toml)
              nac=true; wd=true ;;
          esac
`
	arms, errMsg := parseKoDetectArms(sample)
	if errMsg != "" {
		t.Fatalf("parseKoDetectArms error: %s", errMsg)
	}
	cases := []struct {
		path    string
		wantNAC bool
		wantWD  bool
	}{
		{"", false, false},
		{"README.md", false, false},
		{"libs/hostkit/envx/envx_test.go", false, false},
		{"libs/hostkit/ledger/ledger.go", true, false},
		{"apps/webhook-dispatcher/cmd/dispatcher/main.go", false, true},
		{"libs/hostkit/envx/knobs.go", true, true},
		{"mise.toml", true, true},
		{"libs/hostkit/releaseglob/releaseglob.go", false, false},
	}
	for _, tc := range cases {
		gotNAC, gotWD := koDetectFor(arms, tc.path)
		if gotNAC != tc.wantNAC || gotWD != tc.wantWD {
			t.Errorf("koDetectFor(%q) = (%v, %v), want (%v, %v)",
				tc.path, gotNAC, gotWD, tc.wantNAC, tc.wantWD)
		}
	}
}

func TestDiffSets(t *testing.T) {
	want := map[string]bool{"a": true, "b": true}
	got := map[string]bool{"b": true, "c": true}
	missing, stale := diffSets(want, got)
	if !slices.Equal(missing, []string{"a"}) {
		t.Fatalf("missing = %v, want [a]", missing)
	}
	if !slices.Equal(stale, []string{"c"}) {
		t.Fatalf("stale = %v, want [c]", stale)
	}
}
