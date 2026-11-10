package concourseinit

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// execCall records what the exec seam was invoked with.
type execCall struct {
	path string
	argv []string
	env  []string
}

// recordingExec returns an execFunc that captures the call and
// returns err (nil → the wrapper reports 0).
func recordingExec(calls *[]execCall, err error) execFunc {
	return func(path string, argv, envv []string) error {
		*calls = append(*calls, execCall{path, argv, envv})
		return err
	}
}

// writeSpec drops a config.json into a fresh bundle dir.
func writeSpec(t *testing.T, body string) string {
	t.Helper()
	bundle := t.TempDir()
	if err := os.WriteFile(filepath.Join(bundle, "config.json"),
		[]byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return bundle
}

// qualifyingSpec is an unprivileged task container spec: uidMappings
// hostID 4294967294 + a /scratch mount, no /shared-cache yet.
const qualifyingSpec = `{
  "ociVersion": "1.0.2",
  "process": {"args": ["/bin/sh"]},
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/scratch", "type": "bind", "source": "/vol/scratch", "options": ["bind", "rw"]},
    {"destination": "/dev/shm", "type": "tmpfs", "source": "shm"}
  ],
  "linux": {
    "uidMappings": [{"containerID": 0, "hostID": 4294967294, "size": 1}],
    "gidMappings": [{"containerID": 0, "hostID": 4294967294, "size": 1}],
    "namespaces": [{"type": "user"}]
  }
}`

func readMounts(t *testing.T, configPath string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]json.RawMessage
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatalf("rewritten config is not JSON: %v", err)
	}
	var mounts []map[string]any
	if err := json.Unmarshal(spec["mounts"], &mounts); err != nil {
		t.Fatal(err)
	}
	return mounts
}

// Every non-create invocation is a pure passthrough — exec runc.real
// with the original args, never touching a config.json.
func TestWrapperFastPathNonCreate(t *testing.T) {
	for _, args := range [][]string{
		{"state", "abc"},
		{"start", "abc"},
		{"kill", "abc", "TERM"},
		{"delete", "abc"},
		{"--bundle", "/nonexistent", "start", "abc"},
	} {
		var calls []execCall
		code := runRuncWrapper(append([]string{"runc"}, args...),
			[]string{"A=1"}, "/runc.real",
			recordingExec(&calls, nil))
		if code != 0 || len(calls) != 1 {
			t.Fatalf("args=%v code=%d calls=%v", args, code, calls)
		}
		wantArgv := append([]string{"/runc.real"}, args...)
		if calls[0].path != "/runc.real" ||
			!slices.Equal(calls[0].argv, wantArgv) ||
			!slices.Equal(calls[0].env, []string{"A=1"}) {
			t.Fatalf("args=%v call=%+v", args, calls[0])
		}
	}
}

// The happy path: create + --bundle + all three conditions → the
// /shared-cache bind mount lands directly before /scratch, the rest
// of the spec is preserved, the tmp file is gone, and runc.real is
// still exec'd.
func TestWrapperCreateInjectsSharedCache(t *testing.T) {
	bundle := writeSpec(t, qualifyingSpec)
	configPath := filepath.Join(bundle, "config.json")

	var calls []execCall
	code := runRuncWrapper(
		[]string{"runc", "--bundle", bundle, "create", "task-1"},
		[]string{"PATH=/bin"}, "/concourse-runc/runc.real",
		recordingExec(&calls, nil))

	if code != 0 || len(calls) != 1 {
		t.Fatalf("code=%d calls=%v", code, calls)
	}

	mounts := readMounts(t, configPath)
	if len(mounts) != 4 {
		t.Fatalf("mounts=%v", mounts)
	}
	inj := mounts[1] // inserted before /scratch (was index 1)
	if inj["destination"] != "/shared-cache" ||
		inj["type"] != "bind" ||
		inj["source"] != "/concourse-work-dir/shared-cache" {
		t.Fatalf("injected mount=%v", inj)
	}
	opts, ok := inj["options"].([]any)
	if !ok || len(opts) != 2 || opts[0] != "bind" || opts[1] != "rw" {
		t.Fatalf("options=%v", inj["options"])
	}
	if mounts[2]["destination"] != "/scratch" {
		t.Fatalf("scratch moved: %v", mounts)
	}
	// Untouched mount objects keep their original fields.
	if mounts[0]["destination"] != "/proc" ||
		mounts[3]["destination"] != "/dev/shm" {
		t.Fatalf("other mounts altered: %v", mounts)
	}
	// Other top-level fields survive.
	data, _ := os.ReadFile(configPath)
	var spec map[string]json.RawMessage
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"ociVersion", "process", "linux"} {
		if _, ok := spec[k]; !ok {
			t.Fatalf("key %s lost: %s", k, data)
		}
	}
	// Atomic write leaves no tmp litter.
	assertMissing(t, configPath+".tmp")
}

// The injected entry serializes exactly like the awk's literal JSON
// (destination,type,source,options key order).
func TestWrapperInjectedJSONShape(t *testing.T) {
	bundle := writeSpec(t, qualifyingSpec)
	configPath := filepath.Join(bundle, "config.json")

	injectSharedCacheMount(configPath, sharedCacheSource)

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"destination":"/shared-cache","type":"bind","source":"/concourse-work-dir/shared-cache","options":["bind","rw"]}`
	if !strings.Contains(string(data), want) {
		t.Fatalf("injected text missing\ngot:  %s\nwant: %s", data, want)
	}
}

// Injection requires ALL THREE conditions — every failing spec is
// passed through byte-identical.
func TestWrapperCreateConditions(t *testing.T) {
	cases := map[string]string{
		// Privileged container: root maps to real root, not 4294967294.
		"no unprivileged uidMapping": `{
		  "mounts": [{"destination":"/scratch","type":"bind","source":"/s","options":["bind","rw"]}],
		  "linux": {"uidMappings":[{"containerID":0,"hostID":0,"size":1}]}
		}`,
		// /shared-cache already mounted — no duplicate injection.
		"shared-cache already present": `{
		  "mounts": [
		    {"destination":"/shared-cache","type":"bind","source":"/sc","options":["bind","rw"]},
		    {"destination":"/scratch","type":"bind","source":"/s","options":["bind","rw"]}
		  ],
		  "linux": {"uidMappings":[{"containerID":0,"hostID":4294967294,"size":1}]}
		}`,
		// No /scratch mount — nothing to anchor the insertion to.
		"no scratch mount": `{
		  "mounts": [{"destination":"/proc","type":"proc","source":"proc"}],
		  "linux": {"uidMappings":[{"containerID":0,"hostID":4294967294,"size":1}]}
		}`,
		// No linux block at all.
		"no linux block": `{
		  "mounts": [{"destination":"/scratch","type":"bind","source":"/s","options":["bind","rw"]}]
		}`,
		// hostID present only in gidMappings does NOT qualify — the
		// script matched the substring anywhere, but the port keys on
		// uidMappings as the task spec prescribes.
		"hostID only in gidMappings": `{
		  "mounts": [{"destination":"/scratch","type":"bind","source":"/s","options":["bind","rw"]}],
		  "linux": {
		    "uidMappings":[{"containerID":0,"hostID":1000,"size":1}],
		    "gidMappings":[{"containerID":0,"hostID":4294967294,"size":1}]
		  }
		}`,
	}
	for name, specBody := range cases {
		t.Run(name, func(t *testing.T) {
			bundle := writeSpec(t, specBody)
			configPath := filepath.Join(bundle, "config.json")
			before, _ := os.ReadFile(configPath)

			var calls []execCall
			code := runRuncWrapper(
				[]string{"runc", "--bundle", bundle, "create", "id"},
				nil, "/runc.real", recordingExec(&calls, nil))

			if code != 0 || len(calls) != 1 {
				t.Fatalf("code=%d calls=%v — exec must still happen", code, calls)
			}
			after, _ := os.ReadFile(configPath)
			if !slices.Equal(before, after) {
				t.Fatalf("config was rewritten:\nbefore: %s\nafter:  %s", before, after)
			}
			assertMissing(t, configPath+".tmp")
		})
	}
}

// Fail-open on malformed JSON: unparseable config → passthrough,
// bytes unchanged, exec still runs.
func TestWrapperCreateMalformedJSON(t *testing.T) {
	bundle := writeSpec(t, `{"mounts": [{"destination": "/scratch"`)
	configPath := filepath.Join(bundle, "config.json")
	before, _ := os.ReadFile(configPath)

	var calls []execCall
	code := runRuncWrapper(
		[]string{"runc", "--bundle", bundle, "create", "id"},
		nil, "/runc.real", recordingExec(&calls, nil))

	if code != 0 || len(calls) != 1 {
		t.Fatalf("code=%d calls=%v", code, calls)
	}
	after, _ := os.ReadFile(configPath)
	if !slices.Equal(before, after) {
		t.Fatal("malformed config was modified")
	}
	assertMissing(t, configPath+".tmp")
}

// `create` without a bundle → no rewrite; bundle without config.json
// → no rewrite. Both still exec.
func TestWrapperCreateMissingInputs(t *testing.T) {
	var calls []execCall
	// No --bundle at all.
	if code := runRuncWrapper(
		[]string{"runc", "create", "id"}, nil, "/runc.real",
		recordingExec(&calls, nil)); code != 0 || len(calls) != 1 {
		t.Fatalf("no-bundle: code=%d calls=%v", code, calls)
	}
	// Bundle dir exists but holds no config.json.
	bundle := t.TempDir()
	if code := runRuncWrapper(
		[]string{"runc", "--bundle", bundle, "create", "id"},
		nil, "/runc.real", recordingExec(&calls, nil)); code != 0 || len(calls) != 2 {
		t.Fatalf("empty-bundle: code=%d calls=%v", code, calls)
	}
	// config.json is a DIRECTORY — `[ -f ]` false → passthrough.
	mustDir(t, filepath.Join(bundle, "config.json"))
	if code := runRuncWrapper(
		[]string{"runc", "--bundle", bundle, "create", "id"},
		nil, "/runc.real", recordingExec(&calls, nil)); code != 0 || len(calls) != 3 {
		t.Fatalf("dir-config: code=%d calls=%v", code, calls)
	}
}

// All three bundle flag forms from the script: --bundle <p>,
// --bundle=<p>, -b <p>, -b=<p>.
func TestWrapperBundleFlagForms(t *testing.T) {
	forms := map[string]func(bundle string) []string{
		"--bundle space": func(b string) []string { return []string{"--bundle", b} },
		"--bundle=":      func(b string) []string { return []string{"--bundle=" + b} },
		"-b space":       func(b string) []string { return []string{"-b", b} },
		"-b=":            func(b string) []string { return []string{"-b=" + b} },
	}
	for name, mk := range forms {
		t.Run(name, func(t *testing.T) {
			bundle := writeSpec(t, qualifyingSpec)
			var calls []execCall
			code := runRuncWrapper(
				append([]string{"runc"}, append(mk(bundle), "create", "id")...),
				nil, "/runc.real", recordingExec(&calls, nil))
			if code != 0 {
				t.Fatalf("code=%d", code)
			}
			if len(readMounts(t, filepath.Join(bundle, "config.json"))) != 4 {
				t.Fatal("no injection for bundle flag form")
			}
		})
	}
}

// The word "create" inside an arg passes the fast-path gate (the
// script's `" $* "` substring check) but the is_create flag requires
// an exact arg — no injection.
func TestWrapperCreateWordInsideArg(t *testing.T) {
	bundle := writeSpec(t, qualifyingSpec)
	configPath := filepath.Join(bundle, "config.json")
	before, _ := os.ReadFile(configPath)

	var calls []execCall
	code := runRuncWrapper(
		[]string{"runc", "--bundle", bundle, "--note", "please create now", "id"},
		nil, "/runc.real", recordingExec(&calls, nil))

	if code != 0 || len(calls) != 1 {
		t.Fatalf("code=%d calls=%v", code, calls)
	}
	after, _ := os.ReadFile(configPath)
	if !slices.Equal(before, after) {
		t.Fatal("create-as-substring triggered a rewrite")
	}
}

// A failing exec reports non-zero — the only path where the wrapper
// can fail a create at all.
func TestWrapperExecError(t *testing.T) {
	var calls []execCall
	code := runRuncWrapper([]string{"runc", "state", "id"},
		nil, "/runc.real", recordingExec(&calls, errors.New("gone")))
	if code != 1 {
		t.Fatalf("code=%d, want 1", code)
	}
}

// createBundle flag parsing edge cases: last --bundle wins; is_create
// needs the exact arg.
func TestCreateBundleParsing(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		wantBundle string
		wantOK     bool
	}{
		{"bundle after create", []string{"create", "--bundle", "/b", "id"}, "/b", true},
		{"last bundle wins", []string{"--bundle", "/a", "--bundle", "/b", "create"}, "/b", true},
		{"flag form overrides", []string{"--bundle=/a", "-b=/b", "create"}, "/b", true},
		{"no create", []string{"--bundle", "/b", "run"}, "/b", false},
		{"create substring arg", []string{"--bundle", "/b", "create-x"}, "/b", false},
		{"empty bundle value", []string{"--bundle=", "create"}, "", false},
		{"dangling bundle flag", []string{"create", "--bundle"}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := createBundle(tc.args)
			if got != tc.wantBundle || ok != tc.wantOK {
				t.Fatalf("bundle=%q ok=%v, want %q %v",
					got, ok, tc.wantBundle, tc.wantOK)
			}
		})
	}
}

// syncFile's open failure is the only error it can produce in the
// normal world (fsync on a just-written file is near-infallible).
func TestSyncFileMissing(t *testing.T) {
	if err := syncFile(filepath.Join(t.TempDir(), "gone")); err == nil {
		t.Fatal("expected open error")
	}
}

// A "mounts" field that is not an array fails its own unmarshal —
// passthrough, config untouched, exec still runs.
func TestWrapperCreateBadMountsShape(t *testing.T) {
	bundle := writeSpec(t, `{
	  "mounts": {"destination": "/scratch"},
	  "linux": {"uidMappings": [{"containerID":0,"hostID":4294967294,"size":1}]}
	}`)
	configPath := filepath.Join(bundle, "config.json")
	before, _ := os.ReadFile(configPath)

	var calls []execCall
	code := runRuncWrapper(
		[]string{"runc", "--bundle", bundle, "create", "id"},
		nil, "/runc.real", recordingExec(&calls, nil))
	if code != 0 || len(calls) != 1 {
		t.Fatalf("code=%d calls=%v — exec must still happen", code, calls)
	}
	after, _ := os.ReadFile(configPath)
	if !slices.Equal(before, after) {
		t.Fatal("bad-mounts config was modified")
	}
	assertMissing(t, configPath+".tmp")
}

// An unparseable mount ENTRY is skipped, not fatal — the /scratch
// anchor is still found and the injection lands.
func TestWrapperCreateSkipsBadMountEntry(t *testing.T) {
	bundle := writeSpec(t, `{
	  "mounts": [42, {"destination": "/scratch", "type": "bind", "source": "/s", "options": ["bind","rw"]}],
	  "linux": {"uidMappings": [{"containerID":0,"hostID":4294967294,"size":1}]}
	}`)
	injectSharedCacheMount(filepath.Join(bundle, "config.json"), sharedCacheSource)

	// The bad entry is preserved verbatim — decode loosely: mounts
	// is [42, injected, /scratch].
	data, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Mounts []any `json:"mounts"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Mounts) != 3 {
		t.Fatalf("mounts=%v want 3 entries", spec.Mounts)
	}
	inj, ok := spec.Mounts[1].(map[string]any)
	if !ok || inj["destination"] != "/shared-cache" {
		t.Fatalf("mounts=%v want injection before /scratch", spec.Mounts)
	}
}

// The atomic swap's first step: when <config>.tmp cannot be created
// (a directory squats at the staging path) the rewrite bails with the
// config untouched — fail-open, no litter.
func TestWrapperCreateTmpWriteFails(t *testing.T) {
	bundle := writeSpec(t, qualifyingSpec)
	configPath := filepath.Join(bundle, "config.json")
	before, _ := os.ReadFile(configPath)
	if err := os.Mkdir(configPath+".tmp", 0o755); err != nil {
		t.Fatal(err)
	}

	injectSharedCacheMount(configPath, sharedCacheSource)

	after, _ := os.ReadFile(configPath)
	if !slices.Equal(before, after) {
		t.Fatal("config modified despite tmp-write failure")
	}
}
