// tasks.go — the shared /proc + containerd task machinery the
// domain checks all reach through *Deps: the per-cycle task map
// (CtrTaskRoot + SandboxCtlRoot grouped by pod UID), pid liveness
// and age, cmdline sweeps, raw state-dir probes and the /proc stat
// parser the ctr and guards packages share. The /proc reads
// themselves live in platform/procfs (d.Proc); what is here is only
// the part that must read the live config seams (KillFn/Clock are
// re-stubbed by tests after New).
package wdeps

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Regexes shared by the CtrTask machinery and the snapshot→pod
// attribution — config.json annotation extraction, same pattern
// shape as the shell sed: key, junk up to the quote, 36-char uid
// value. The domain matchers live next to their checks.
var (
	PodUIDRe        = regexp.MustCompile(`"io\.kubernetes\.pod\.uid"[^0-9a-f-]*"([0-9a-f-]{36})"`)
	ContainerNameRe = regexp.MustCompile(`"io\.kubernetes\.container\.name"[^"]*"([^"]+)"`)
)

// MinUptimeSeconds mirrors the shell runner's WD_REQUIRES: uptime
// gate (MIN_UPTIME_S=1200) — no destructive checks in the first 20
// minutes after boot. Shared by the Cycle gate and the T15 feeder.
const MinUptimeSeconds = 1200

// ProbeAttempts / ProbeTimeout are the shared probe-series
// parameters — the shell's curl retry loops (a single blip must not
// trigger a restart).
const (
	ProbeAttempts = 3               // kubelet/cilium curl loops run 3x
	ProbeTimeout  = 3 * time.Second // curl -ksm3
)

// ProbeHTTPSeries runs up to `attempts` GET probes `gap` apart —
// the shell's curl retry loops (a single blip must not trigger a
// restart). Returns nil on the first success. Shared by the kubelet
// and cilium healthz probes.
func (d *Deps) ProbeHTTPSeries(ctx context.Context, url string,
	attempts int, timeout, gap time.Duration) error {
	var last error
	for i := 0; i < attempts; i++ {
		last = d.Cfg.Seams.Probe.ProbeHTTP(ctx, url, timeout)
		if last == nil {
			return nil
		}
		if i+1 < attempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(gap):
			}
		}
	}
	return last
}

// PidLive is procfs.FS.Live bound to this subsystem's KillFn seam —
// d.Cfg.Seams.Host.KillFn is read at call time because tests re-stub it
// after New returns.
func (d *Deps) PidLive(pid int) bool {
	return d.Proc.Live(pid, d.Cfg.Seams.Host.KillFn)
}

// ProcAge is procfs.FS.Age bound to the Clock seam (tests re-stub
// h.Cfg.Seams.Host.Clock via Set after New — the Deps field promotes
// through the Hygiene embed).
func (d *Deps) ProcAge(pid int) time.Duration {
	return d.Proc.Age(pid, d.Cfg.Seams.Host.Clock.Now())
}

// PidsWithCmdline returns pids whose joined cmdline contains sub —
// the pkill -f replacement (the agent can't rely on pkill being in
// the container image). The pid list is the caller's per-cycle
// snapshot.
func (d *Deps) PidsWithCmdline(sub string, pids []int) []int {
	var out []int
	for _, pid := range pids {
		if strings.Contains(strings.Join(d.Proc.Cmdline(pid), " "), sub) {
			out = append(out, pid)
		}
	}
	return out
}

// ProcStatStatePPID parses /proc/<pid>/stat for state + ppid — the
// fields right after the LAST ')' (comm can hold spaces/parens).
// Shared by the ctr and guards packages.
func (d *Deps) ProcStatStatePPID(pid int) (state string, ppid int, ok bool) {
	st, ok := d.Proc.Stat(pid)
	if !ok || len(st.Fields) < 2 { // Fields[0]=state, Fields[1]=ppid
		return "", 0, false
	}
	p, err := strconv.Atoi(st.Fields[1])
	if err != nil || p < 0 {
		return "", 0, false
	}
	return st.Fields[0], p, true
}

// StateFileExists reports whether a state-dir file exists — unlike
// State.Exists it checks RAW filenames (markers like wedged-seen-<id>
// are not state-* latches).
func (d *Deps) StateFileExists(name string) bool {
	_, err := os.Stat(filepath.Join(d.Cfg.WatchdogStateDir, name))
	return err == nil
}

// CtrTask is one containerd task dir (runtime-v2 task or sandbox
// controller shim) — the node-side ground truth for "are tasks of
// this pod still around", replacing `ctr tasks ls` so no ctr socket
// is needed inside the agent pod.
type CtrTask struct {
	UID  string // io.kubernetes.pod.uid annotation
	Name string // io.kubernetes.container.name annotation ("pause"/"POD" = sandbox infra)
	PID  int    // init.pid contents
	Live bool   // kill -0 ok and not zombie
}

// BuildTaskMap scans CtrTaskRoot/*/ and SandboxCtlRoot/*/ once per
// cycle and groups task dirs by pod UID — shared by the teardown and
// dns checks. Missing files are skipped, never fatal.
//
// complete=false when a task ROOT itself could not be listed — the
// map then only claims "no live tasks" for pods whose tasks it
// never saw, so force-delete callers must fail closed (checkCtrTasks
// abort parity): the runtime root must exist on a live worker (ANY
// error incl. ENOENT is suspect), while a genuinely-absent sandbox
// root is normal on layouts without a shim dir and stays complete.
// TaskMapBuilds counts invocations so tests can assert the lazy
// once-per-cycle behaviour directly.
func (d *Deps) BuildTaskMap() (map[string][]CtrTask, bool) {
	d.TaskMapBuilds++
	m := map[string][]CtrTask{}
	complete := true
	for i, root := range []string{d.Cfg.CtrTaskRoot, d.Cfg.SandboxCtlRoot} {
		entries, err := os.ReadDir(root)
		if err != nil {
			if i == 0 || !os.IsNotExist(err) {
				complete = false
			}
			// A permission/IO error silently degrades the task
			// map — surface it so force-delete decisions aren't
			// the only trace of running on incomplete data.
			if !os.IsNotExist(err) {
				d.State.AppendLog(fmt.Sprintf(
					"suspect: ctr task root %s unreadable: %v — task map incomplete",
					root, err))
			}
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			dir := filepath.Join(root, e.Name())
			cfgData, err := os.ReadFile(filepath.Join(dir, "config.json"))
			if err != nil {
				continue
			}
			um := PodUIDRe.FindSubmatch(cfgData)
			if um == nil {
				continue
			}
			t := CtrTask{UID: string(um[1])}
			if nm := ContainerNameRe.FindSubmatch(cfgData); nm != nil {
				t.Name = string(nm[1])
			}
			if pidData, err := os.ReadFile(filepath.Join(dir, "init.pid")); err == nil {
				if pid, err := strconv.Atoi(strings.TrimSpace(string(pidData))); err == nil {
					t.PID = pid
					t.Live = d.PidLive(pid)
				}
			}
			m[t.UID] = append(m[t.UID], t)
		}
	}
	return m, complete
}

// CountLive returns how many tasks of a UID still have a live init
// pid — the force-delete precondition (zero live tasks = verified
// container death, status.containerStatuses is only last-known).
func CountLive(tasks []CtrTask) int {
	n := 0
	for _, t := range tasks {
		if t.Live {
			n++
		}
	}
	return n
}
