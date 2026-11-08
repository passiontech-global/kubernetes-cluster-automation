package opsx

import (
	"bytes"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
)

// TestFlagSet: the shared FlagSet is ContinueOnError (parse failures
// come back as errors the caller maps onto the exit-code contract)
// with usage going to a writable output — not os.Exit inside flag.
func TestFlagSet(t *testing.T) {
	fs := FlagSet("probe")
	if fs.Name() != "probe" {
		t.Fatalf("name=%q want probe", fs.Name())
	}
	if fs.Output() == nil {
		t.Fatal("output nil — usage would go nowhere")
	}
	if err := fs.Parse([]string{"-nope"}); err == nil {
		t.Fatal("unknown flag accepted — ContinueOnError not set")
	}
}

// TestParse: ok path, -h/--help is a clean exit (ExitOK), any other
// parse failure is a usage error (ExitUsage).
func TestParse(t *testing.T) {
	fs := FlagSet("probe")
	v := fs.String("x", "", "")
	if code, ok := Parse(fs, []string{"-x", "1"}); !ok || code != ExitOK {
		t.Fatalf("ok path code=%d ok=%v", code, ok)
	}
	if *v != "1" {
		t.Fatalf("x=%q want 1", *v)
	}
	// Silence stderr for the error paths.
	devnull := bytes.NewBuffer(nil)
	fs.SetOutput(devnull)

	if code, ok := Parse(fs, []string{"-h"}); ok || code != ExitOK {
		t.Fatalf("-h code=%d ok=%v want ExitOK/no-continue", code, ok)
	}
	if code, ok := Parse(fs, []string{"--bogus"}); ok || code != ExitUsage {
		t.Fatalf("bad flag code=%d ok=%v want ExitUsage/no-continue", code, ok)
	}
}

// TestVarsDirFlag: default falls back through the env knob, the env
// overrides the path default, and the flag overrides both — the
// pointer is only meaningful after Parse.
func TestVarsDirFlag(t *testing.T) {
	fs := FlagSet("probe")
	v := VarsDirFlag(fs)
	if *v != "/etc/node-host-agent/vars" {
		t.Fatalf("default=%q", *v)
	}
	t.Setenv(envnames.EnvHostconfigVarsDir, "/tmp/vars-env")
	fs = FlagSet("probe")
	v = VarsDirFlag(fs)
	if *v != "/tmp/vars-env" {
		t.Fatalf("env=%q want /tmp/vars-env", *v)
	}
	if code, ok := Parse(fs, []string{"--vars-dir", "/tmp/vars-flag"}); !ok {
		t.Fatalf("parse failed code=%d", code)
	}
	if *v != "/tmp/vars-flag" {
		t.Fatalf("flag=%q want /tmp/vars-flag", *v)
	}
}

// TestNebulaCertsDirFlag: same default chain as VarsDirFlag.
func TestNebulaCertsDirFlag(t *testing.T) {
	fs := FlagSet("probe")
	v := NebulaCertsDirFlag(fs)
	if *v != "/etc/node-host-agent/nebula-certs" {
		t.Fatalf("default=%q", *v)
	}
	t.Setenv(envnames.EnvNebulaCertsDir, "/tmp/certs-env")
	fs = FlagSet("probe")
	v = NebulaCertsDirFlag(fs)
	if *v != "/tmp/certs-env" {
		t.Fatalf("env=%q want /tmp/certs-env", *v)
	}
	if code, ok := Parse(fs, []string{"--nebula-certs-dir", "/tmp/certs-flag"}); !ok {
		t.Fatalf("parse failed code=%d", code)
	}
	if *v != "/tmp/certs-flag" {
		t.Fatalf("flag=%q want /tmp/certs-flag", *v)
	}
	if !strings.Contains(fs.Lookup("nebula-certs-dir").Usage,
		"nebula cert dir") {
		t.Fatalf("usage=%q", fs.Lookup("nebula-certs-dir").Usage)
	}
}
