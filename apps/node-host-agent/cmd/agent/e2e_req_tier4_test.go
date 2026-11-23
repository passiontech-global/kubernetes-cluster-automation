package main_test

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func runTier4Tests(t *testing.T, bin string) {
	t.Run("Scenario7_HostilePodModeSweep", func(t *testing.T) {
		t.Parallel()
		api := newFakeE2EAPIServer(t)
		api.setNode(makeNode("e2e-node-7", "10.244.0.0/24"))
		badPod := makePod("default", "bad-img-s7", "77777777-0000-0000-0000-000000000007", "e2e-node-7")
		badPod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name:  "app",
			Image: "registry.example.com/-bad:1",
			State: corev1.ContainerState{
				Waiting: &corev1.ContainerStateWaiting{
					Reason:  "ErrImagePull",
					Message: "content digest sha256:abcd: not found",
				},
			},
		}}
		api.setPod(badPod)

		evilBytes, evilSum := makeTarGz(t, []tarEntry{{name: "../../etc/pwned", body: []byte("PWN"), typeflag: tar.TypeReg}})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(evilBytes)
		}))
		defer srv.Close()

		sb := newReqSandbox(t, map[string]string{
			"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE":   "true",
			"NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL": "150ms",
			"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":        "true",
			"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL":      "400ms",
			"NODE_HOST_AGENT_ENABLE_HYGIENE":           "true",
			"NODE_HOST_AGENT_HYGIENE_INTERVAL":         "350ms",
			"NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE": "true",
			"NODE_HOST_AGENT_CONTROLLER_INTERVAL":      "400ms",
			"NODE_HOST_AGENT_ETCD_DB_SIZE_LIMIT":       "1000",
			"NODE_HOST_AGENT_ENABLE_KINEDB":            "true",
			"NODE_HOST_AGENT_NODE_NAME":                "e2e-node-7",
			"POD_NAME":                                 "agent-s7",
		})
		kc := filepath.Join(sb.root, "kubeconfig")
		api.writeKubeconfig(t, kc)
		sb.envMap["KUBECONFIG"] = kc

		// 1. Concourse shared-cache symlink TOCTOU + FIFO DoS.
		outside := filepath.Join(sb.root, "outside-s7")
		_ = os.MkdirAll(outside, 0o755)
		canary := filepath.Join(outside, "canary.txt")
		_ = os.WriteFile(canary, []byte("DO_NOT_TOUCH"), 0o644)
		old := time.Now().Add(-100 * time.Hour)
		_ = os.Chtimes(canary, old, old)

		sc := filepath.Join(sb.openebs, "pvc-77777777-1111-2222-3333-444444444444", "shared-cache")
		_ = os.MkdirAll(filepath.Join(sc, "build"), 0o755)
		_ = os.MkdirAll(filepath.Join(sc, "go-build", "00"), 0o755)
		_ = os.Symlink(outside, filepath.Join(sc, "build", "escape"))
		fifoPath := filepath.Join(sc, "go-build", "00", strings.Repeat("0", 64)+"-a")
		if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
			t.Fatal(err)
		}
		age5h := time.Now().Add(-5 * time.Hour)
		_ = os.Chtimes(fifoPath, age5h, age5h)

		// 2. Hostconfig + k0s controller + etcdguard + kinedb + spoofed kubepods shim.
		_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)
		_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
		_ = os.WriteFile(filepath.Join(sb.hostroot, "var", "lib", "k0s", "pki", "etcd", "ca.crt"), []byte("CA"), 0o644)
		_ = os.WriteFile(filepath.Join(sb.k0s, "pki", "etcd", "ca.crt"), []byte("CA"), 0o644)

		secret := "Scenario7TopSecretPass99"
		writeHostconfigVars(t, sb.vars, fmt.Sprintf(
			"kine_service_hosts:\n  - e2e-node-7\nkine_endpoint: 'postgres://u:%s@db/kine\"bad'\netcdctl_version: \"3.7.3\"\netcdctl_tgz_url: %q\netcdctl_tgz_sha256: %q\netcdctl_tgz_file: \"s7-evil.tgz\"\n",
			secret, srv.URL+"/s7-evil.tgz", evilSum,
		), "", "")

		_, spoofPID := spawnDummySleep(t, 60)
		sid := strings.Repeat("7", 64)
		writeProcTask(t, sb.proc, spoofPID, "containerd-shim", "S", 1000,
			"0::/kubepods.slice/kubepods-pod777.slice/cri-containerd-s7.scope\n",
			[]string{"containerd-shim-runc-v2", "-namespace", "k8s.io", "-id", sid, "-address", sb.envMap["NODE_HOST_AGENT_CONTAINERD_SOCKET"]},
			10*time.Minute)

		_ = os.WriteFile(filepath.Join(sb.hostroot, "opt", "apps", "postgres", ".env"),
			[]byte("POSTGRES_USER=postgres\nPOSTGRES_PASSWORD=pw\n"), 0o600)
		installFakeRuntimeForKinedb(t, sb, false, false, 0)

		etcdBackupDir := filepath.Join(sb.hostroot, "var", "backups", "etcd")
		_ = os.Chmod(etcdBackupDir, 0o755)
		installFakeTool(t, sb.k0s, filepath.Join("bin", "etcdctl"), fmt.Sprintf(`#!/bin/sh
echo "etcdctl $*" >> %q
case "$*" in
  *"endpoint status"*) echo '[{"Endpoint":"127.0.0.1:2379","Status":{"dbSize":2000,"dbSizeInUse":1500,"leader":1,"raftTerm":2,"version":"3.5.0"}}]' ;;
  *"alarm list"*) exit 0 ;;
  *"snapshot save "*)
    for last; do :; done
    printf "ETCD_S7" > "$last"
    ;;
  *"snapshot status "*) exit 0 ;;
esac
exit 0
`, sb.toolLog))

		ra := startReqAgent(t, bin, sb.envSlice())
		defer ra.stopAndWait(t)

		eventually(t, 10*time.Second, 150*time.Millisecond, "Scenario 7 hostile pod sweep completes all checks safely", func() error {
			if code, _ := reqHTTPGet(t, ra.healthzURL()); code != http.StatusOK {
				return fmt.Errorf("healthz=%d", code)
			}
			m := ra.scrapeMetrics(t)
			if v, ok := parseMetricValue(m, "node_host_agent_concourse_cache_cycles_total", `result="ok"`); !ok || v < 2 {
				return fmt.Errorf("concourse-cache ok=%v v=%v", ok, v)
			}
			if v, ok := parseMetricValue(m, "node_host_agent_hostconfig_cycles_total", `group="kine"`, `result="error"`); !ok || v < 1 {
				return fmt.Errorf("hostconfig kine ok=%v v=%v", ok, v)
			}
			if v, ok := parseMetricValue(m, "kine_db_backup_valid"); !ok || v != 1 {
				return fmt.Errorf("kinedb valid ok=%v v=%v", ok, v)
			}
			snaps, _ := filepath.Glob(filepath.Join(etcdBackupDir, "premaint-*.db"))
			if len(snaps) == 0 {
				return fmt.Errorf("missing etcd premaint snapshot")
			}
			toolBytes, _ := os.ReadFile(sb.toolLog)
			if !strings.Contains(string(toolBytes), "images rm --sync -- registry.example.com/-bad:1") {
				return fmt.Errorf("missing -- RmImage call in toolLog")
			}
			return nil
		})

		if b, err := os.ReadFile(canary); err != nil || string(b) != "DO_NOT_TOUCH" {
			t.Fatalf("canary altered by concoursecache symlink: err=%v data=%q", err, b)
		}
		if strings.Contains(ra.logsCombined(), secret) {
			t.Fatalf("kine_endpoint secret leaked in logs")
		}
		if !pidAlive(spoofPID) {
			t.Fatalf("spoofed kubepods PID %d was killed!", spoofPID)
		}
		assertNoCtrShimKill(t, ra)
		if fi, err := os.Stat(etcdBackupDir); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("etcd backup dir mode=%v want 0700 (err=%v)", fi.Mode().Perm(), err)
		}
	})

	t.Run("Scenario8_MemoryAndKMSv2Incident", func(t *testing.T) {
		t.Parallel()
		api := newFakeE2EAPIServer(t)
		uid := "22222222-3333-4444-5555-666666666666"
		api.setNode(makeNode("e2e-node-8", "10.244.0.0/16"))
		api.setPod(makePod("app", "mem-hog", uid, "e2e-node-8"))

		srv, certPEM, keyPEM, caPEM := newSelfSignedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasPrefix(r.URL.Path, "/healthz/kms-provider-"):
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("kms down"))
			case r.URL.Path == "/api/v1/namespaces/default/services":
				_, _ = w.Write([]byte(`{"metadata":{"resourceVersion":"200"},"items":[]}`))
			case r.URL.Path == "/api/v1/namespaces/default/endpoints/kubernetes":
				_, _ = w.Write([]byte(`{"subsets":[{"addresses":[{"ip":"127.0.0.1"}]}]}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))

		sb := newReqSandbox(t, map[string]string{
			"NODE_HOST_AGENT_ENABLE_HYGIENE":                   "true",
			"NODE_HOST_AGENT_ENABLE_HOSTMETRICS":               "true",
			"NODE_HOST_AGENT_ENABLE_REPORTER":                  "true",
			"NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE":         "true",
			"NODE_HOST_AGENT_ENABLE_JANITOR":                   "true",
			"NODE_HOST_AGENT_HYGIENE_INTERVAL":                 "300ms",
			"NODE_HOST_AGENT_HYGIENE_CONSEC_NEEDED":            "2",
			"NODE_HOST_AGENT_CONTROLLER_INTERVAL":              "350ms",
			"NODE_HOST_AGENT_LATCH_INTERVAL":                   "300ms",
			"NODE_HOST_AGENT_REPORTER_INTERVAL":                "300ms",
			"NODE_HOST_AGENT_JANITOR_INTERVAL":                 "300ms",
			"NODE_HOST_AGENT_NETFILTER_GUARD_INTERVAL_SECONDS": "1",
			"NODE_HOST_AGENT_CONTROLLER_INSECURE_TLS":          "true",
			"NODE_HOST_AGENT_API_SELF":                         strings.TrimPrefix(srv.URL, "https://"),
			"NODE_HOST_AGENT_NODE_NAME":                        "e2e-node-8",
		})
		sb.ensureShortHostRoot(t)
		kc := filepath.Join(sb.root, "kubeconfig")
		api.writeKubeconfig(t, kc)
		sb.envMap["KUBECONFIG"] = kc

		_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)
		_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
		_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_K0S_CONFIG"], []byte(legacyGateK0sYAML()), 0o644)
		writeKubeconfigFile(t, filepath.Join(sb.k0s, "pki", "admin.conf"), srv.URL, certPEM, keyPEM, caPEM)
		startHungUnixSocket(t, filepath.Join(sb.hostroot, "run", "k0s", "kms.sock"))

		// Mock Cilium Unix socket: reserved:init -> ready.
		var ciliumInitStuck atomic.Bool
		ciliumInitStuck.Store(true)
		taskDir := filepath.Join(sb.ctrTaskRoot, strings.Repeat("8", 64))
		_ = os.MkdirAll(taskDir, 0o755)
		_ = os.WriteFile(filepath.Join(taskDir, "config.json"),
			[]byte(`{"annotations":{"io.kubernetes.pod.uid":"88888888-8888-8888-8888-888888888888","io.kubernetes.container.name":"cilium-agent"}}`), 0o644)
		_ = os.WriteFile(filepath.Join(taskDir, "init.pid"), []byte("0\n"), 0o644)
		sb.envMap["NODE_HOST_AGENT_CILIUM_SOCKET"] = startMockCiliumUnixServer(t, sb.envMap["NODE_HOST_AGENT_CILIUM_SOCKET"], func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/endpoint" {
				if ciliumInitStuck.Load() {
					_, _ = w.Write([]byte(`[{"id":1,"status":{"identity":{"labels":["reserved:init"]}}}]`))
				} else {
					_, _ = w.Write([]byte(`[{"id":1,"status":{"identity":{"labels":["k8s:app=ok"]}}}]`))
				}
				return
			}
			_, _ = w.Write([]byte(`{}`))
		})

		// Cgroup CPU + Memory PSI + high/max.
		sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod22222222_3333_4444_5555_666666666666.slice")
		_ = os.MkdirAll(sliceDir, 0o755)
		_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"), []byte("nr_periods 100\nnr_throttled 0\n"), 0o644)
		_ = os.WriteFile(filepath.Join(sliceDir, "memory.pressure"),
			[]byte("some avg10=70.00 avg60=60.00 total=100\nfull avg10=70.00 avg60=60.00 total=100\n"), 0o644)
		_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"), []byte("high 10\nmax 10\n"), 0o644)

		// K3 EBUSY dead-pod mountinfo + systemd-oomd + netfilter lock.
		deadMount := filepath.Join(sb.kubeletPods, "dead-s8", "volumes", "kubernetes.io~empty-dir", "c")
		_ = os.MkdirAll(deadMount, 0o755)
		_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_MOUNTINFO_FILE"],
			[]byte(fmt.Sprintf("240 1 8:1 / %s rw - tmpfs tmpfs rw\n", deadMount)), 0o644)
		_, pinPID := spawnDummySleep(t, 60)
		writeProcTask(t, sb.proc, pinPID, "containerd-shim", "S", 0,
			"0::/system.slice/k0sworker.service\n",
			[]string{"containerd-shim-runc-v2", "-namespace", "k8s.io", "-id", strings.Repeat("a", 64), "-address", sb.envMap["NODE_HOST_AGENT_CONTAINERD_SOCKET"]},
			10*time.Minute)
		_ = os.WriteFile(filepath.Join(sb.proc, strconv.Itoa(pinPID), "mountinfo"),
			[]byte(fmt.Sprintf("240 1 8:1 / %s rw - tmpfs tmpfs rw\n", deadMount)), 0o644)
		_ = os.Symlink(deadMount, filepath.Join(sb.proc, strconv.Itoa(pinPID), "fd", "4"))

		lockPath := sb.envMap["NODE_HOST_AGENT_NETFILTER_GUARD_LOCK_PATH"]
		lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		lockClosed := false
		t.Cleanup(func() {
			if !lockClosed {
				_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
				_ = lf.Close()
			}
		})

		tsUs := time.Now().UnixMicro()
		jline, _ := json.Marshal(map[string]any{
			"__CURSOR":             "s8c1",
			"__REALTIME_TIMESTAMP": strconv.FormatInt(tsUs, 10),
			"_SYSTEMD_UNIT":        "systemd-oomd.service",
			"MESSAGE":              "Killed process 666 in kubepods-pods8.slice",
		})
		installFakeTool(t, sb.fakebin, "journalctl", fmt.Sprintf("#!/bin/sh\necho '%s'\nexit 0\n", string(jline)))

		ra := startReqAgent(t, bin, sb.envSlice())
		defer ra.stopAndWait(t)

		ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
		for i := 1; i <= 6; i++ {
			_ = os.WriteFile(filepath.Join(sb.proc, "stat"),
				[]byte(fmt.Sprintf("cpu  %d 0 100 %d 0 0 0 0\n", 100+i*10, 1000+i*100)), 0o644)
			_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"),
				[]byte(fmt.Sprintf("nr_periods %d\nnr_throttled %d\n", 100+i*100, i*80)), 0o644)
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"),
				[]byte(fmt.Sprintf("high %d\nmax %d\n", 10+i*10, 10+i*10)), 0o644)
			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
		}

		eventually(t, 10*time.Second, 150*time.Millisecond, "Scenario 8 active multi-incident assertions", func() error {
			if _, err := os.Stat(filepath.Join(sb.state, "last-suspect-cgroup-cfs-"+uid)); err != nil {
				return fmt.Errorf("missing slash-free CFS suspect file: %w", err)
			}
			var gotCPU, gotMem bool
			for _, ev := range api.getEvents() {
				if ev.Reason == "PodCPUCFSThrottled" {
					gotCPU = true
				}
				if ev.Reason == "PodMemoryHighThrottled" {
					gotMem = true
				}
			}
			if !gotCPU || !gotMem {
				return fmt.Errorf("events cpu=%v mem=%v", gotCPU, gotMem)
			}
			for _, st := range []string{"cilium-init-stuck", "netfilter-locked", "systemd-oomd-kill"} {
				if _, err := os.Stat(filepath.Join(sb.state, "state-"+st)); err != nil {
					return err
				}
			}
			m := ra.scrapeMetrics(t)
			for _, st := range []string{"cilium-init-stuck", "netfilter-locked", "systemd-oomd-kill"} {
				v, ok := parseMetricValue(m, "node_host_agent_watchdog_state", fmt.Sprintf(`state=%q`, st))
				if !ok || v != 1 {
					return fmt.Errorf("state %s ok=%v v=%v", st, ok, v)
				}
			}
			kmsLatches, _ := filepath.Glob(filepath.Join(sb.state, "state-*kms*"))
			if len(kmsLatches) == 0 {
				return fmt.Errorf("missing KMSv2 latch")
			}
			if !hasK5ReadinessSignal(m, sb) {
				return fmt.Errorf("missing K5 readiness series/latch")
			}
			if v, ok := parseMetricValue(m, "node_host_agent_workerhygiene_cycles_total", `check="udp-stale-socket"`, `result="ok"`); !ok || v < 1 {
				return fmt.Errorf("udp-stale-socket ok=%v v=%v", ok, v)
			}
			if api.countRequests(http.MethodPatch, "/api/v1/nodes/e2e-node-8/status") < 1 {
				return fmt.Errorf("missing node status condition PATCH")
			}
			return nil
		})

		// Recovery phase: clear Cilium stuck endpoints + release netfilter lock.
		ciliumInitStuck.Store(false)
		_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
		_ = lf.Close()
		lockClosed = true

		eventually(t, 12*time.Second, 150*time.Millisecond, "recovered cilium-init-stuck and netfilter-locked clear", func() error {
			for _, st := range []string{"cilium-init-stuck", "netfilter-locked"} {
				if _, err := os.Stat(filepath.Join(sb.state, "state-"+st)); !os.IsNotExist(err) {
					return fmt.Errorf("state-%s still on disk", st)
				}
			}
			m := ra.scrapeMetrics(t)
			v1, ok1 := parseMetricValue(m, "node_host_agent_watchdog_state", `state="cilium-init-stuck"`)
			v2, ok2 := parseMetricValue(m, "node_host_agent_watchdog_state", `state="netfilter-locked"`)
			if !ok1 || v1 != 0 || !ok2 || v2 != 0 {
				return fmt.Errorf("recovery cilium(%v,%v) nf(%v,%v)", ok1, v1, ok2, v2)
			}
			return nil
		})
	})
}
