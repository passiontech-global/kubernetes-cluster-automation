// runc_wrapper.go — `concourse-runc-wrapper`: port of the shell
// wrapper the init installed at /concourse-runc/runc (mounted over
// /usr/local/concourse/bin/runc inside the worker container, so every
// runc invocation by containerd-shim passes through it).
//
// Semantics of the original script, kept 1:1:
//   - Fast path: any invocation whose argv does not contain the word
//     `create` execs runc.real immediately — no arg parsing, no
//     config.json read (state/start/kill/delete/ps/events stay cheap).
//   - On `create`, parse --bundle/-b (all three flag forms), and only
//     when <bundle>/config.json exists rewrite it: inject the
//     /shared-cache bind mount immediately before the /scratch mount,
//     but only when linux.uidMappings carries hostID 4294967294 (the
//     unprivileged-task-container userns marker), a /scratch mount
//     exists, and no /shared-cache mount exists yet.
//   - Fail-open ALWAYS: any parse/read/write error still execs
//     runc.real with the unmodified config — the wrapper never blocks
//     a container create.
//   - The rewrite is atomic: a <config>.tmp sibling is written, then
//     renamed over config.json; on any failure the tmp is removed and
//     the original file is untouched.
package concourseinit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// execFunc matches syscall.Exec — a seam so tests never replace the
// test process image.
type execFunc func(path string, argv []string, envv []string) error

// RuncWrapper is the subcommand entrypoint: wrap os.Args/os.Environ
// for RunRuncWrapper.
func RuncWrapper() int {
	return RunRuncWrapper(os.Args, os.Environ())
}

// RunRuncWrapper implements concourse-runc-wrapper. argv is the full
// process argv (argv[0] included — it is replaced by the runc.real
// path on exec, matching the script's `exec /concourse-runc/runc.real
// "$@"` which never propagates the wrapper's own name). The returned
// int is an exit code: the real syscall.Exec never returns, so a
// return only happens when the exec seam does — 0 on nil error
// (tests), 1 when exec itself failed.
func RunRuncWrapper(argv []string, env []string) int {
	return runRuncWrapper(argv, env, DefaultRuncReal, syscall.Exec)
}

func runRuncWrapper(argv []string, env []string, runcReal string,
	execFn execFunc) int {

	var args []string
	if len(argv) > 1 {
		args = argv[1:]
	}

	// Fast path — the script's `case " $* " in *" create "*)`: the
	// gate is a substring match on the space-joined args, so the word
	// `create` inside a single arg also enters the slow path (the
	// stricter is_create flag below still gates the rewrite).
	if strings.Contains(" "+strings.Join(args, " ")+" ", " create ") {
		if bundle, ok := createBundle(args); ok {
			injectSharedCacheMount(
				filepath.Join(bundle, "config.json"), sharedCacheSource)
		}
	}

	// exec argv = [runcReal] + original args — the script's
	// `exec runc.real "$@"` gives runc.real argv[0]=itself.
	execArgv := append([]string{runcReal}, args...)
	if err := execFn(runcReal, execArgv, env); err != nil {
		fmt.Fprintf(os.Stderr,
			"concourse-runc-wrapper: exec %s: %v\n", runcReal, err)
		return 1
	}
	return 0
}

// createBundle is the script's arg loop: last --bundle/-b (all three
// forms) wins, is_create requires an arg that IS exactly "create".
// The bool reports `is_create=1 && -n "$bundle"`.
func createBundle(args []string) (string, bool) {
	isCreate := false
	bundle := ""
	prev := ""
	for _, arg := range args {
		// A `-`-prefixed arg after -b/--bundle is another flag, not
		// the bundle path — treat it as "no bundle value" instead of
		// consuming it.
		if (prev == "--bundle" || prev == "-b") &&
			!strings.HasPrefix(arg, "-") {
			bundle = arg
		}
		switch {
		case strings.HasPrefix(arg, "--bundle="):
			bundle = arg[len("--bundle="):]
		case strings.HasPrefix(arg, "-b="):
			bundle = arg[len("-b="):]
		case arg == "create":
			isCreate = true
		}
		prev = arg
	}
	return bundle, isCreate && bundle != ""
}

// injectSharedCacheMount rewrites <bundle>/config.json in place,
// inserting the shared-cache bind mount directly before the /scratch
// mount — the mount object the awk emitted, verbatim:
//
//	{"destination":"/shared-cache","type":"bind","source":
//	 "/concourse-work-dir/shared-cache","options":["bind","rw"]}
//
// Injection requires ALL THREE conditions (the awk's
// `host && !dup && inj`):
//   - linux.uidMappings has an entry with hostID == 4294967294 — the
//     unprivileged task container userns marker; privileged
//     containers (oci-build-task) map root to real root and are
//     never touched.
//   - A mounts entry with destination "/scratch" exists — the
//     insertion point.
//   - No mounts entry with destination "/shared-cache" yet —
//     duplicate-injection guard.
//
// Every failure path is fail-open: a one-line note goes to stderr
// (the wrapper's only channel — the shim surfaces it in containerd
// logs) and the caller still execs runc.real against the untouched
// config.
func injectSharedCacheMount(configPath, source string) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"concourse-runc-wrapper: read %s: %v — passthrough\n",
			configPath, err)
		return // `[ -f "$bundle/config.json" ]` failed — passthrough
	}

	// RawMessage everywhere except the fields we inspect, so
	// untouched SUBTREES re-serialise verbatim (each mount object
	// keeps its member order). The top-level object is a map — its
	// key order re-sorts alphabetically on marshal and insignificant
	// whitespace is compacted; byte-parity of the whole file was
	// never the contract (the awk rewrite changed formatting too).
	var spec map[string]json.RawMessage
	if err := json.Unmarshal(data, &spec); err != nil {
		fmt.Fprintf(os.Stderr,
			"concourse-runc-wrapper: parse %s: %v — passthrough\n",
			configPath, err)
		return // malformed JSON — never block create
	}

	// Condition 1: hostID 4294967294 in linux.uidMappings.
	var linux struct {
		UIDMappings []struct {
			HostID int64 `json:"hostID"`
		} `json:"uidMappings"`
	}
	if raw, ok := spec["linux"]; ok {
		_ = json.Unmarshal(raw, &linux) // parse error → treated absent
	}
	host := false
	for _, m := range linux.UIDMappings {
		if m.HostID == cacheOwner {
			host = true
			break
		}
	}

	// Conditions 2+3: /scratch present, /shared-cache absent.
	var mounts []json.RawMessage
	if raw, ok := spec["mounts"]; ok {
		if err := json.Unmarshal(raw, &mounts); err != nil {
			fmt.Fprintf(os.Stderr,
				"concourse-runc-wrapper: parse mounts in %s: %v — passthrough\n",
				configPath, err)
			return
		}
	}
	scratch := -1
	dup := false
	for i, m := range mounts {
		var md struct {
			Destination string `json:"destination"`
		}
		if err := json.Unmarshal(m, &md); err != nil {
			continue // unparseable entry is not a mount we match
		}
		switch md.Destination {
		case "/shared-cache":
			dup = true
		case "/scratch":
			if scratch < 0 {
				scratch = i
			}
		}
	}
	if !host || dup || scratch < 0 {
		return
	}

	// Insert BEFORE the /scratch entry — the awk rewrote the line
	// holding {"destination":"/scratch" so the new object lands
	// immediately ahead of it.
	entry, err := json.Marshal(struct {
		Destination string   `json:"destination"`
		Type        string   `json:"type"`
		Source      string   `json:"source"`
		Options     []string `json:"options"`
	}{"/shared-cache", "bind", source, []string{"bind", "rw"}})
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"concourse-runc-wrapper: marshal injected mount: %v — passthrough\n",
			err)
		return
	}
	mounts = slices.Insert(mounts, scratch, json.RawMessage(entry))
	newMounts, err := json.Marshal(mounts)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"concourse-runc-wrapper: marshal mounts for %s: %v — passthrough\n",
			configPath, err)
		return
	}
	spec["mounts"] = newMounts
	out, err := json.Marshal(spec)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"concourse-runc-wrapper: marshal %s: %v — passthrough\n",
			configPath, err)
		return
	}

	// Atomic swap — the script's `> config.json.tmp && mv`; tmp is
	// removed on every failure so a crashed wrapper never leaves
	// litter runc could trip on.
	tmp := configPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr,
			"concourse-runc-wrapper: write %s: %v — passthrough\n",
			tmp, err)
		_ = os.Remove(tmp)
		return
	}
	if err := os.Rename(tmp, configPath); err != nil {
		fmt.Fprintf(os.Stderr,
			"concourse-runc-wrapper: rename %s -> %s: %v — passthrough\n",
			tmp, configPath, err)
		_ = os.Remove(tmp)
	}
}
