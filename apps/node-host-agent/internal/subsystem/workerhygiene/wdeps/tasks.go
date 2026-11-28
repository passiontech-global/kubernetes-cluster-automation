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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
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
	return probeRetry(ctx, attempts, gap, func() (bool, error) {
		err := d.Cfg.Seams.Probe.ProbeHTTP(ctx, url, timeout)
		return err == nil, err
	})
}

// ProbeHTTPStatusSeries runs up to `attempts` authenticated GET status
// probes `gap` apart, delegating status interpretation to accept (which
// returns stop=true once a conclusive verdict or short-circuit condition is
// reached).
func (d *Deps) ProbeHTTPStatusSeries(ctx context.Context, url, bearer string,
	attempts int, timeout, gap time.Duration,
	accept func(code int) (stop bool, err error)) error {
	return probeRetry(ctx, attempts, gap, func() (bool, error) {
		code, err := d.Cfg.Seams.Probe.ProbeHTTPStatus(ctx, url, bearer, timeout)
		if err != nil {
			return false, err
		}
		return accept(code)
	})
}

func probeRetry(ctx context.Context, attempts int, gap time.Duration,
	attempt func() (stop bool, err error)) error {
	var last error
	for i := 0; i < attempts; i++ {
		var stop bool
		stop, last = attempt()
		if stop {
			return last
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
		st, ok := d.Proc.Stat(pid)
		if !ok || len(st.Fields) == 0 ||
			st.Fields[0] == "D" || st.Fields[0] == "Z" || st.Fields[0] == "X" || st.Fields[0] == "x" {
			continue
		}
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

// ReadMountinfo reads Cfg.MountinfoFile once per cycle via
// e.MountinfoOnce when set, falling back to an uncached os.ReadFile
// when e or MountinfoOnce is nil.
func (d *Deps) ReadMountinfo(e *CycleEnv) ([]byte, error) {
	if e != nil && e.MountinfoOnce != nil {
		return e.MountinfoOnce()
	}
	return os.ReadFile(d.Cfg.MountinfoFile)
}

// MountinfoEntries parses Cfg.MountinfoFile at most once per cycle
// onto CycleEnv, avoiding 4+ redundant line-splits and path unescapes
// across workerhygiene checks.
func (d *Deps) MountinfoEntries(e *CycleEnv) ([]MountEntry, int, error) {
	if e != nil && e.MountinfoOnce != nil && e.mountParsed {
		return e.mountEntries, e.mountLines, nil
	}
	data, err := d.ReadMountinfo(e)
	if err != nil {
		return nil, 0, err
	}
	entries, lines := ParseMountinfo(data)
	if e != nil && e.MountinfoOnce != nil {
		e.mountEntries = entries
		e.mountLines = lines
		e.mountParsed = true
	}
	return entries, lines, nil
}

// ParseMountinfo parses raw /proc/<pid>/mountinfo bytes into structured
// entries and returns the count of non-empty lines.
func ParseMountinfo(data []byte) ([]MountEntry, int) {
	var entries []MountEntry
	nonEmpty := 0
	for ln := range strings.SplitSeq(string(data), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		nonEmpty++
		pre := ln
		var post string
		hasSep := false
		if sep := strings.Index(ln, " - "); sep >= 0 {
			pre = ln[:sep]
			post = ln[sep+3:]
			hasSep = true
		}
		f := strings.Fields(pre)
		if len(f) < 5 && !hasSep {
			continue
		}
		var ent MountEntry
		if len(f) >= 5 {
			ent.HasMount = true
			ent.Mountpoint = procfs.UnescapeMountPath(f[4])
			if len(f) > 6 {
				for _, opt := range f[6:] {
					if grp, ok := strings.CutPrefix(opt, "shared:"); ok {
						ent.SharedGroups = append(ent.SharedGroups, grp)
					}
				}
			}
		}
		if hasSep {
			ent.HasSep = true
			pf := strings.Fields(post)
			if len(pf) >= 1 {
				ent.FSType = pf[0]
			}
			if len(pf) >= 2 {
				ent.Source = procfs.UnescapeMountPath(pf[1])
			}
			if len(pf) >= 3 {
				ent.SuperOpts = pf[2]
			}
		}
		entries = append(entries, ent)
	}
	return entries, nonEmpty
}

// CtrTask is one containerd task dir (runtime-v2 task or sandbox
// controller shim) — the node-side ground truth for "are tasks of
// this pod still around", replacing `ctr tasks ls` so no ctr socket
// is needed inside the agent pod.
type CtrTask struct {
	ID   string // task dir name — the containerd container/sandbox id cri-containerd-*.scope units are named after
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
				if !os.IsNotExist(err) {
					complete = false
					if d.State != nil {
						d.State.AppendLog(fmt.Sprintf(
							"suspect: ctr task %s/config.json unreadable: %v — task map incomplete",
							dir, err))
					}
				}
				continue
			}
			um := PodUIDRe.FindSubmatch(cfgData)
			if um == nil {
				continue
			}
			t := CtrTask{ID: e.Name(), UID: string(um[1])}
			if nm := ContainerNameRe.FindSubmatch(cfgData); nm != nil {
				t.Name = string(nm[1])
			}
			if pidData, err := os.ReadFile(filepath.Join(dir, "init.pid")); err == nil {
				if pid, err := strconv.Atoi(strings.TrimSpace(string(pidData))); err == nil {
					t.PID = pid
					t.Live = d.PidLive(pid)
				}
			} else if !os.IsNotExist(err) {
				complete = false
				if d.State != nil {
					d.State.AppendLog(fmt.Sprintf(
						"suspect: ctr task %s/init.pid unreadable: %v — task map incomplete",
						dir, err))
				}
			}
			m[t.UID] = append(m[t.UID], t)
		}
	}
	return m, complete
}

// CyclePIDs returns the cycle's /proc PID list via e.PidsOnce when
// wired, falling back to d.Proc.PIDs() for hand-built CycleEnvs.
// ok=false when the underlying Proc.PIDs() read failed (distinguished
// from a genuinely empty /proc via e.PidsOK when wired).
func (d *Deps) CyclePIDs(e *CycleEnv) ([]int, bool) {
	if e != nil && e.PidsOnce != nil {
		pids := e.PidsOnce()
		if e.PidsOK != nil && !e.PidsOK() {
			return nil, false
		}
		return pids, true
	}
	pids, err := d.Proc.PIDs()
	if err != nil {
		return nil, false
	}
	return pids, true
}

// CycleTasks returns the cycle's containerd task map via e.TasksOnce
// when wired, falling back to d.BuildTaskMap() for hand-built
// CycleEnvs. The second return is the root-reachability complete flag.
func (d *Deps) CycleTasks(e *CycleEnv) (map[string][]CtrTask, bool) {
	if e != nil && e.TasksOnce != nil {
		return e.TasksOnce()
	}
	return d.BuildTaskMap()
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
