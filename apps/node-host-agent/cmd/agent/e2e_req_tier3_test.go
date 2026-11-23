package main_test

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func runTier3Tests(t *testing.T, bin string) {
	t.Run("Pair01_F2xF3_ConcourseCacheAndHostconfig", func(t *testing.T) {
		t.Parallel()
		evilBytes, evilSum := makeTarGz(t, []tarEntry{{name: "../../escape", body: []byte("BAD"), typeflag: tar.TypeReg}})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(evilBytes)
		}))
		defer srv.Close()

		sb := newReqSandbox(t, map[string]string{
			"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE":   "true",
			"NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL": "100ms",
			"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":        "true",
			"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL":      "400ms",
			"NODE_HOST_AGENT_NODE_NAME":                "t3-p1-node",
		})
		outside := filepath.Join(sb.root, "outside-p1")
		_ = os.MkdirAll(outside, 0o755)
		canary := filepath.Join(outside, "canary.txt")
		_ = os.WriteFile(canary, []byte("KEEP"), 0o644)
		old := time.Now().Add(-100 * time.Hour)
		_ = os.Chtimes(canary, old, old)

		sc := filepath.Join(sb.openebs, "pvc-11111111-1111-1111-1111-111111111111", "shared-cache")
		_ = os.MkdirAll(filepath.Join(sc, "build"), 0o755)
		_ = os.Symlink(outside, filepath.Join(sc, "build", "esc"))

		_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
		_ = os.WriteFile(filepath.Join(sb.hostroot, "var", "lib", "k0s", "pki", "etcd", "ca.crt"), []byte("CA"), 0o644)
		writeHostconfigVars(t, sb.vars, fmt.Sprintf(
			"etcdctl_version: \"3.7.3\"\netcdctl_tgz_url: %q\netcdctl_tgz_sha256: %q\netcdctl_tgz_file: \"p1.tgz\"\n",
			srv.URL+"/p1.tgz", evilSum,
		), "", "")

		ra := startReqAgent(t, bin, sb.envSlice())
		defer ra.stopAndWait(t)

		eventually(t, 6*time.Second, 100*time.Millisecond, "concourse-cache and hostconfig run concurrently", func() error {
			m := ra.scrapeMetrics(t)
			v1, ok1 := parseMetricValue(m, "node_host_agent_concourse_cache_cycles_total", `result="ok"`)
			v2, ok2 := parseMetricValue(m, "node_host_agent_hostconfig_cycles_total", `group="etcdctl"`, `result="error"`)
			if !ok1 || v1 < 2 || !ok2 || v2 < 1 {
				return fmt.Errorf("cc(%v,%v) hc(%v,%v)", ok1, v1, ok2, v2)
			}
			return nil
		})
		if b, err := os.ReadFile(canary); err != nil || string(b) != "KEEP" {
			t.Fatalf("symlink escape corrupted outside canary: err=%v data=%q", err, b)
		}
	})

	t.Run("Pair02_F3xF9_HostconfigTarballAndKineRedact", func(t *testing.T) {
		t.Parallel()
		evilBytes, evilSum := makeTarGz(t, []tarEntry{{name: "../../pwn", body: []byte("BAD"), typeflag: tar.TypeReg}})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(evilBytes)
		}))
		defer srv.Close()

		sb := newReqSandbox(t, map[string]string{
			"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
			"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "400ms",
			"NODE_HOST_AGENT_NODE_NAME":           "t3-p2-node",
		})
		_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
		_ = os.WriteFile(filepath.Join(sb.hostroot, "var", "lib", "k0s", "pki", "etcd", "ca.crt"), []byte("CA"), 0o644)
		secret := "PAIR2_KINE_SECRET_999"
		writeHostconfigVars(t, sb.vars, fmt.Sprintf(
			"kine_service_hosts:\n  - t3-p2-node\nkine_endpoint: 'postgres://u:%s@db/kine\"bad'\netcdctl_version: \"3.7.3\"\netcdctl_tgz_url: %q\netcdctl_tgz_sha256: %q\netcdctl_tgz_file: \"p2.tgz\"\n",
			secret, srv.URL+"/p2.tgz", evilSum,
		), "", "")

		ra := startReqAgent(t, bin, sb.envSlice())
		defer ra.stopAndWait(t)

		eventually(t, 6*time.Second, 100*time.Millisecond, "both kine and etcdctl fail safely", func() error {
			m := ra.scrapeMetrics(t)
			v1, ok1 := parseMetricValue(m, "node_host_agent_hostconfig_cycles_total", `group="kine"`, `result="error"`)
			v2, ok2 := parseMetricValue(m, "node_host_agent_hostconfig_cycles_total", `group="etcdctl"`, `result="error"`)
			if !ok1 || v1 < 1 || !ok2 || v2 < 1 {
				return fmt.Errorf("kine(%v,%v) etcdctl(%v,%v)", ok1, v1, ok2, v2)
			}
			return nil
		})
		if strings.Contains(ra.logsCombined(), secret) {
			t.Fatalf("kine secret %q leaked in logs", secret)
		}
		if _, err := os.Stat(filepath.Join(sb.hostroot, "var", "lib", "k0s", "bin", "etcdctl")); !os.IsNotExist(err) {
			t.Fatalf("traversal tarball installed etcdctl")
		}
	})

	t.Run("Pair03_F8xF26_AntiSpoofAndStaleMount", func(t *testing.T) {
		t.Parallel()
		api := newFakeE2EAPIServer(t)
		api.setNode(makeNode("t3-p3-node", "10.244.0.0/24"))
		sb := newReqSandbox(t, map[string]string{
			"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
			"NODE_HOST_AGENT_HYGIENE_INTERVAL": "350ms",
			"NODE_HOST_AGENT_NODE_NAME":        "t3-p3-node",
		})
		kc := filepath.Join(sb.root, "kubeconfig")
		api.writeKubeconfig(t, kc)
		sb.envMap["KUBECONFIG"] = kc
		_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

		deadMount := filepath.Join(sb.kubeletPods, "dead-p3", "volumes", "kubernetes.io~empty-dir", "c")
		_ = os.MkdirAll(deadMount, 0o755)
		_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_MOUNTINFO_FILE"],
			[]byte(fmt.Sprintf("220 1 8:1 / %s rw - tmpfs tmpfs rw\n", deadMount)), 0o644)

		_, spoofPID := spawnDummySleep(t, 60)
		sid := strings.Repeat("a", 64)
		writeProcTask(t, sb.proc, spoofPID, "containerd-shim", "S", 1000,
			"0::/kubepods.slice/kubepods-pod123.slice/cri-containerd-spoof.scope\n",
			[]string{"containerd-shim-runc-v2", "-namespace", "k8s.io", "-id", sid, "-address", sb.envMap["NODE_HOST_AGENT_CONTAINERD_SOCKET"]},
			10*time.Minute)
		_ = os.WriteFile(filepath.Join(sb.proc, strconv.Itoa(spoofPID), "mountinfo"),
			[]byte(fmt.Sprintf("220 1 8:1 / %s rw - tmpfs tmpfs rw\n", deadMount)), 0o644)
		_ = os.Symlink(deadMount, filepath.Join(sb.proc, strconv.Itoa(spoofPID), "fd", "4"))

		ra := startReqAgent(t, bin, sb.envSlice())
		defer ra.stopAndWait(t)

		eventually(t, 6*time.Second, 100*time.Millisecond, "K3 detects wedge while F8 blocks spoofed PID kill", func() error {
			logBytes, _ := os.ReadFile(sb.logFile)
			cleanedLog := strings.ToLower(strings.ReplaceAll(string(logBytes), sb.root, ""))
			toolBytes, _ := os.ReadFile(sb.toolLog)
			if !strings.Contains(cleanedLog, "ebusy") && !strings.Contains(string(toolBytes), "umount") {
				return fmt.Errorf("K3 EBUSY wedge not detected yet")
			}
			return nil
		})
		if !pidAlive(spoofPID) {
			t.Fatalf("spoofed kubepods PID %d was killed!", spoofPID)
		}
		assertNoCtrShimKill(t, ra)
	})

	t.Run("Pair04_F8xF19_CtrImagesDoubleDashAndCiliumSocket", func(t *testing.T) {
		t.Parallel()
		api := newFakeE2EAPIServer(t)
		api.setNode(makeNode("t3-p4-node", "10.244.0.0/24"))
		pod := makePod("default", "bad-img-p4", "44444444-1111-1111-1111-111111111111", "t3-p4-node")
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name:  "app",
			Image: "registry.example.com/-dash:v1",
			State: corev1.ContainerState{
				Waiting: &corev1.ContainerStateWaiting{Reason: "ErrImagePull", Message: "content digest sha256:abcd: not found"},
			},
		}}
		api.setPod(pod)

		sb := newReqSandbox(t, map[string]string{
			"NODE_HOST_AGENT_ENABLE_HYGIENE":        "true",
			"NODE_HOST_AGENT_ENABLE_HOSTMETRICS":    "true",
			"NODE_HOST_AGENT_HYGIENE_INTERVAL":      "350ms",
			"NODE_HOST_AGENT_HYGIENE_CONSEC_NEEDED": "2",
			"NODE_HOST_AGENT_LATCH_INTERVAL":        "200ms",
			"NODE_HOST_AGENT_NODE_NAME":             "t3-p4-node",
		})
		kc := filepath.Join(sb.root, "kubeconfig")
		api.writeKubeconfig(t, kc)
		sb.envMap["KUBECONFIG"] = kc
		_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

		taskDir := filepath.Join(sb.ctrTaskRoot, strings.Repeat("c", 64))
		_ = os.MkdirAll(taskDir, 0o755)
		_ = os.WriteFile(filepath.Join(taskDir, "config.json"),
			[]byte(`{"annotations":{"io.kubernetes.pod.uid":"44444444-1111-1111-1111-111111111111","io.kubernetes.container.name":"cilium-agent"}}`), 0o644)
		_ = os.WriteFile(filepath.Join(taskDir, "init.pid"), []byte("0\n"), 0o644)

		sb.envMap["NODE_HOST_AGENT_CILIUM_SOCKET"] = startMockCiliumUnixServer(t, sb.envMap["NODE_HOST_AGENT_CILIUM_SOCKET"], func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/endpoint" {
				_, _ = w.Write([]byte(`[{"id":1,"status":{"identity":{"labels":["reserved:init"]}}}]`))
				return
			}
			_, _ = w.Write([]byte(`{}`))
		})

		ra := startReqAgent(t, bin, sb.envSlice())
		defer ra.stopAndWait(t)

		eventually(t, 7*time.Second, 100*time.Millisecond, "both -- RmImage and state-cilium-init-stuck succeed in same cycle", func() error {
			toolBytes, _ := os.ReadFile(sb.toolLog)
			if !strings.Contains(string(toolBytes), "images rm --sync -- registry.example.com/-dash:v1") {
				return fmt.Errorf("missing -- in RmImage: %s", string(toolBytes))
			}
			if _, err := os.Stat(filepath.Join(sb.state, "state-cilium-init-stuck")); err != nil {
				return err
			}
			v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_watchdog_state", `state="cilium-init-stuck"`)
			if !ok || v != 1 {
				return fmt.Errorf("cilium-init-stuck ok=%v v=%v", ok, v)
			}
			return nil
		})
	})

	t.Run("Pair05_F13xF24_CgroupCFSAndMemoryHighPSI", func(t *testing.T) {
		t.Parallel()
		api := newFakeE2EAPIServer(t)
		uid := "55555555-7777-8888-9999-000000000005"
		api.setNode(makeNode("t3-p5-node", "10.244.0.0/24"))
		api.setPod(makePod("default", "dual-throttle", uid, "t3-p5-node"))

		sb := newReqSandbox(t, map[string]string{
			"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
			"NODE_HOST_AGENT_HYGIENE_INTERVAL": "250ms",
			"NODE_HOST_AGENT_NODE_NAME":        "t3-p5-node",
		})
		kc := filepath.Join(sb.root, "kubeconfig")
		api.writeKubeconfig(t, kc)
		sb.envMap["KUBECONFIG"] = kc
		_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

		sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod55555555_7777_8888_9999_000000000005.slice")
		_ = os.MkdirAll(sliceDir, 0o755)
		_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"), []byte("nr_periods 100\nnr_throttled 0\n"), 0o644)
		_ = os.WriteFile(filepath.Join(sliceDir, "memory.pressure"),
			[]byte("some avg10=70.00 avg60=60.00 total=100\nfull avg10=70.00 avg60=60.00 total=100\n"), 0o644)
		_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"), []byte("high 10\nmax 10\n"), 0o644)

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

		eventually(t, 6*time.Second, 100*time.Millisecond, "both CPU CFS and MemoryHigh events + slash-free suspect file", func() error {
			if _, err := os.Stat(filepath.Join(sb.state, "last-suspect-cgroup-cfs-"+uid)); err != nil {
				return err
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
				return fmt.Errorf("cpu=%v mem=%v", gotCPU, gotMem)
			}
			return nil
		})
	})

	t.Run("Pair06_F24xF28Agent_MemoryHighPSIAndCgroupV2Reporter", func(t *testing.T) {
		t.Parallel()
		api := newFakeE2EAPIServer(t)
		uid := "55555555-7777-8888-9999-000000000006"
		api.setNode(makeNode("t3-p6-node", "10.244.0.0/24"))
		api.setPod(makePod("default", "mem-p6", uid, "t3-p6-node"))

		sb := newReqSandbox(t, map[string]string{
			"NODE_HOST_AGENT_ENABLE_HYGIENE":     "true",
			"NODE_HOST_AGENT_ENABLE_HOSTMETRICS": "true",
			"NODE_HOST_AGENT_ENABLE_REPORTER":    "true",
			"NODE_HOST_AGENT_HYGIENE_INTERVAL":   "300ms",
			"NODE_HOST_AGENT_LATCH_INTERVAL":     "300ms",
			"NODE_HOST_AGENT_REPORTER_INTERVAL":  "300ms",
			"NODE_HOST_AGENT_NODE_NAME":          "t3-p6-node",
		})
		kc := filepath.Join(sb.root, "kubeconfig")
		api.writeKubeconfig(t, kc)
		sb.envMap["KUBECONFIG"] = kc
		_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)
		_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
		_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_K0S_CONFIG"], []byte(legacyGateK0sYAML()), 0o644)

		sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod55555555_7777_8888_9999_000000000006.slice")
		_ = os.MkdirAll(sliceDir, 0o755)
		_ = os.WriteFile(filepath.Join(sliceDir, "memory.pressure"),
			[]byte("some avg10=70.00 avg60=60.00 total=100\nfull avg10=70.00 avg60=60.00 total=100\n"), 0o644)
		_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"), []byte("high 10\nmax 0\n"), 0o644)

		ra := startReqAgent(t, bin, sb.envSlice())
		defer ra.stopAndWait(t)

		ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
		for i := 1; i <= 5; i++ {
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"),
				[]byte(fmt.Sprintf("high %d\nmax 0\n", 10+i*10)), 0o644)
			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
		}
		eventually(t, 6*time.Second, 100*time.Millisecond, "F24 event + F28-agent K5 readiness + nodereporter patch", func() error {
			m := ra.scrapeMetrics(t)
			if !hasK5ReadinessSignal(m, sb) {
				return fmt.Errorf("missing K5 readiness metric/latch")
			}
			if api.countRequests(http.MethodPatch, "/api/v1/nodes/t3-p6-node/status") < 1 {
				return fmt.Errorf("no node status patch")
			}
			for _, ev := range api.getEvents() {
				if ev.Reason == "PodMemoryHighThrottled" {
					return nil
				}
			}
			return fmt.Errorf("missing PodMemoryHighThrottled")
		})
	})

	t.Run("Pair07_F26xF31Agent_MaintenanceHoldOnEBUSYAndUDP", func(t *testing.T) {
		t.Parallel()
		api := newFakeE2EAPIServer(t)
		n := makeNode("t3-p7-node", "10.244.0.0/16")
		n.Annotations["passiontech.dev/cluster-maintenance-until"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		api.setNode(n)

		sb := newReqSandbox(t, map[string]string{
			"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
			"NODE_HOST_AGENT_HYGIENE_INTERVAL": "300ms",
			"NODE_HOST_AGENT_NODE_NAME":        "t3-p7-node",
		})
		kc := filepath.Join(sb.root, "kubeconfig")
		api.writeKubeconfig(t, kc)
		sb.envMap["KUBECONFIG"] = kc
		_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

		deadMount := filepath.Join(sb.kubeletPods, "dead-p7", "volumes", "kubernetes.io~empty-dir", "c")
		_ = os.MkdirAll(deadMount, 0o755)
		_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_MOUNTINFO_FILE"],
			[]byte(fmt.Sprintf("230 1 8:1 / %s rw - tmpfs tmpfs rw\n", deadMount)), 0o644)
		_, pinPID := spawnDummySleep(t, 30)
		sid := strings.Repeat("f", 64)
		writeProcTask(t, sb.proc, pinPID, "containerd-shim", "S", 0,
			"0::/system.slice/k0sworker.service\n",
			[]string{"containerd-shim-runc-v2", "-namespace", "k8s.io", "-id", sid, "-address", sb.envMap["NODE_HOST_AGENT_CONTAINERD_SOCKET"]},
			10*time.Minute)
		_ = os.WriteFile(filepath.Join(sb.proc, strconv.Itoa(pinPID), "mountinfo"),
			[]byte(fmt.Sprintf("230 1 8:1 / %s rw - tmpfs tmpfs rw\n", deadMount)), 0o644)
		_ = os.Symlink(deadMount, filepath.Join(sb.proc, strconv.Itoa(pinPID), "fd", "4"))

		ra := startReqAgent(t, bin, sb.envSlice())
		defer ra.stopAndWait(t)

		eventually(t, 5*time.Second, 100*time.Millisecond, "udp-stale-socket completes while maintenance holds destructive F26 action", func() error {
			v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="udp-stale-socket"`, `result="ok"`)
			if !ok || v < 2 {
				return fmt.Errorf("udp-stale-socket ok=%v v=%v", ok, v)
			}
			return nil
		})
		if !pidAlive(pinPID) {
			t.Fatalf("pinPID killed despite active maintenance hold")
		}
		if api.countRequests(http.MethodGet, "/api/v1/nodes") < 1 {
			t.Fatalf("expected Nodes().List(RV=0)")
		}
	})

	t.Run("Pair08_F10xF33_EtcdguardAndKMSv2", func(t *testing.T) {
		t.Parallel()
		srv, certPEM, keyPEM, caPEM := newSelfSignedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/api/v1/namespaces/default/services":
				_, _ = w.Write([]byte(`{"metadata":{"resourceVersion":"100"},"items":[]}`))
			case r.URL.Path == "/api/v1/namespaces/default/endpoints/kubernetes":
				_, _ = w.Write([]byte(`{"subsets":[{"addresses":[{"ip":"127.0.0.1"}]}]}`))
			case strings.HasPrefix(r.URL.Path, "/healthz/kms-provider-"):
				w.WriteHeader(http.StatusInternalServerError)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		sb := newReqSandbox(t, map[string]string{
			"NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE": "true",
			"NODE_HOST_AGENT_CONTROLLER_INTERVAL":      "400ms",
			"NODE_HOST_AGENT_CONTROLLER_INSECURE_TLS":  "true",
			"NODE_HOST_AGENT_ETCD_DB_SIZE_LIMIT":       "1000",
			"NODE_HOST_AGENT_API_SELF":                 strings.TrimPrefix(srv.URL, "https://"),
		})
		sb.ensureShortHostRoot(t)
		_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
		_ = os.WriteFile(filepath.Join(sb.k0s, "pki", "etcd", "ca.crt"), []byte("CA"), 0o644)
		writeKubeconfigFile(t, filepath.Join(sb.k0s, "pki", "admin.conf"), srv.URL, certPEM, keyPEM, caPEM)
		startMockUnixEchoServer(t, filepath.Join(sb.hostroot, "run", "k0s", "kms.sock"))

		backupDir := filepath.Join(sb.hostroot, "var", "backups", "etcd")
		_ = os.Chmod(backupDir, 0o755)
		installFakeTool(t, sb.k0s, filepath.Join("bin", "etcdctl"), fmt.Sprintf(`#!/bin/sh
echo "etcdctl $*" >> %q
case "$*" in
  *"endpoint status"*) echo '[{"Endpoint":"127.0.0.1:2379","Status":{"dbSize":2000,"dbSizeInUse":1500,"leader":1,"raftTerm":2,"version":"3.5.0"}}]' ;;
  *"alarm list"*) exit 0 ;;
  *"snapshot save "*)
    for last; do :; done
    printf "ETCD_SNAP_P8" > "$last"
    ;;
  *"snapshot status "*) exit 0 ;;
esac
exit 0
`, sb.toolLog))

		ra := startReqAgent(t, bin, sb.envSlice())
		defer ra.stopAndWait(t)

		eventually(t, 7*time.Second, 100*time.Millisecond, "both etcdguard snapshot 0700/0600 and KMSv2 latch run", func() error {
			fi, err := os.Stat(backupDir)
			if err != nil || fi.Mode().Perm() != 0o700 {
				return fmt.Errorf("backupDir mode=%v err=%v", fi.Mode().Perm(), err)
			}
			snaps, _ := filepath.Glob(filepath.Join(backupDir, "premaint-*.db"))
			if len(snaps) == 0 {
				return fmt.Errorf("no premaint snapshot")
			}
			latches, _ := filepath.Glob(filepath.Join(sb.state, "state-*kms*"))
			if len(latches) == 0 {
				return fmt.Errorf("missing KMSv2 latch")
			}
			return nil
		})
	})

	t.Run("Pair09_F19xF23_NethealthCiliumAndGuards", func(t *testing.T) {
		t.Parallel()
		api := newFakeE2EAPIServer(t)
		api.setNode(makeNode("t3-p9-node", "10.244.0.0/24"))
		sb := newReqSandbox(t, map[string]string{
			"NODE_HOST_AGENT_ENABLE_HYGIENE":                   "true",
			"NODE_HOST_AGENT_ENABLE_NETHEALTH":                 "true",
			"NODE_HOST_AGENT_ENABLE_HOSTMETRICS":               "true",
			"NODE_HOST_AGENT_HYGIENE_INTERVAL":                 "300ms",
			"NODE_HOST_AGENT_NETHEALTH_INTERVAL":               "300ms",
			"NODE_HOST_AGENT_LATCH_INTERVAL":                   "200ms",
			"NODE_HOST_AGENT_NETFILTER_GUARD_INTERVAL_SECONDS": "1",
			"NODE_HOST_AGENT_NODE_NAME":                        "t3-p9-node",
		})
		kc := filepath.Join(sb.root, "kubeconfig")
		api.writeKubeconfig(t, kc)
		sb.envMap["KUBECONFIG"] = kc
		_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

		lockPath := sb.envMap["NODE_HOST_AGENT_NETFILTER_GUARD_LOCK_PATH"]
		lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		t.Cleanup(func() {
			_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
			_ = lf.Close()
		})

		tsUs := time.Now().UnixMicro()
		jline, _ := json.Marshal(map[string]any{
			"__CURSOR":             "p9c1",
			"__REALTIME_TIMESTAMP": strconv.FormatInt(tsUs, 10),
			"_SYSTEMD_UNIT":        "systemd-oomd.service",
			"MESSAGE":              "Killed process 888 in kubepods-podp9.slice",
		})
		installFakeTool(t, sb.fakebin, "journalctl", fmt.Sprintf("#!/bin/sh\necho '%s'\nexit 0\n", string(jline)))
		sb.envMap["NODE_HOST_AGENT_CILIUM_SOCKET"] = startMockCiliumUnixServer(t, sb.envMap["NODE_HOST_AGENT_CILIUM_SOCKET"], func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`[]`))
		})

		ra := startReqAgent(t, bin, sb.envSlice())
		defer ra.stopAndWait(t)

		eventually(t, 12*time.Second, 100*time.Millisecond, "netfilter-locked and systemd-oomd-kill latched alongside nethealth", func() error {
			for _, st := range []string{"netfilter-locked", "systemd-oomd-kill"} {
				if _, err := os.Stat(filepath.Join(sb.state, "state-"+st)); err != nil {
					return err
				}
			}
			m := ra.scrapeMetrics(t)
			v1, ok1 := parseMetricValue(m, "node_host_agent_watchdog_state", `state="netfilter-locked"`)
			v2, ok2 := parseMetricValue(m, "node_host_agent_watchdog_state", `state="systemd-oomd-kill"`)
			if !ok1 || v1 != 1 || !ok2 || v2 != 1 {
				return fmt.Errorf("nf(%v,%v) oomd(%v,%v)", ok1, v1, ok2, v2)
			}
			return nil
		})
	})

	t.Run("Pair10_F19xF33_APIProberDrainAndKMSv2", func(t *testing.T) {
		t.Parallel()
		srv, certPEM, keyPEM, caPEM := newSelfSignedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasPrefix(r.URL.Path, "/healthz/kms-provider-"):
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("kms fail"))
			case strings.Contains(r.URL.Path, "/services"):
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(strings.Repeat("E", 64*1024)))
			default:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"subsets":[{"addresses":[{"ip":"127.0.0.1"}]}]}`))
			}
		}))
		sb := newReqSandbox(t, map[string]string{
			"NODE_HOST_AGENT_ENABLE_APIPROBER":         "true",
			"NODE_HOST_AGENT_APIPROBER_INTERVAL":       "300ms",
			"NODE_HOST_AGENT_APIPROBER_MODE":           "dry-run",
			"NODE_HOST_AGENT_APIPROBER_INSECURE_TLS":   "true",
			"NODE_HOST_AGENT_APIPROBER_BACKEND":        "api_local_back",
			"NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE": "true",
			"NODE_HOST_AGENT_CONTROLLER_INTERVAL":      "300ms",
			"NODE_HOST_AGENT_CONTROLLER_INSECURE_TLS":  "true",
			"NODE_HOST_AGENT_API_SELF":                 strings.TrimPrefix(srv.URL, "https://"),
		})
		sb.ensureShortHostRoot(t)
		tokFile := filepath.Join(sb.root, "token")
		_ = os.WriteFile(tokFile, []byte("e2e-token"), 0o600)
		sb.envMap["NODE_HOST_AGENT_APIPROBER_TOKEN_FILE"] = tokFile
		sb.envMap["NODE_HOST_AGENT_APIPROBER_SOCKET"] = startMockHAProxyUnixSocket(t, sb.envMap["NODE_HOST_AGENT_APIPROBER_SOCKET"], "api_local_back", "ctrl1", strings.TrimPrefix(srv.URL, "https://"))
		_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
		writeKubeconfigFile(t, filepath.Join(sb.k0s, "pki", "admin.conf"), srv.URL, certPEM, keyPEM, caPEM)
		startHungUnixSocket(t, filepath.Join(sb.hostroot, "run", "k0s", "kms.sock"))

		ra := startReqAgent(t, bin, sb.envSlice())
		defer ra.stopAndWait(t)

		eventually(t, 7*time.Second, 100*time.Millisecond, "apiprober and KMSv2 share state store cleanly", func() error {
			m := ra.scrapeMetrics(t)
			v1, ok1 := parseMetricValue(m, "node_host_agent_apiprober_cycles_total")
			v2, ok2 := parseMetricValue(m, "node_host_agent_controllerhygiene_cycles_total")
			if !ok1 || v1 < 2 || !ok2 || v2 < 2 {
				return fmt.Errorf("apiprober(%v,%v) ctrl(%v,%v)", ok1, v1, ok2, v2)
			}
			latches, _ := filepath.Glob(filepath.Join(sb.state, "state-*kms*"))
			if len(latches) == 0 {
				return fmt.Errorf("missing KMSv2 latch")
			}
			return nil
		})
	})

	t.Run("Pair11_F23xF24_SystemdOOMDDiskBloatAndMemoryHigh", func(t *testing.T) {
		t.Parallel()
		api := newFakeE2EAPIServer(t)
		uid := "55555555-7777-8888-9999-000000000011"
		api.setNode(makeNode("t3-p11-node", "10.244.0.0/24"))
		api.setPod(makePod("default", "mem-p11", uid, "t3-p11-node"))

		sb := newReqSandbox(t, map[string]string{
			"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
			"NODE_HOST_AGENT_HYGIENE_INTERVAL": "250ms",
			"NODE_HOST_AGENT_NODE_NAME":        "t3-p11-node",
		})
		kc := filepath.Join(sb.root, "kubeconfig")
		api.writeKubeconfig(t, kc)
		sb.envMap["KUBECONFIG"] = kc
		_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

		tsUs := time.Now().UnixMicro()
		jline, _ := json.Marshal(map[string]any{
			"__CURSOR":             "p11c1",
			"__REALTIME_TIMESTAMP": strconv.FormatInt(tsUs, 10),
			"_SYSTEMD_UNIT":        "systemd-oomd.service",
			"MESSAGE":              "Killed process 777 in kubepods-podp11.slice",
		})
		installFakeTool(t, sb.fakebin, "journalctl", fmt.Sprintf("#!/bin/sh\necho '%s'\nexit 0\n", string(jline)))

		sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod55555555_7777_8888_9999_000000000011.slice")
		_ = os.MkdirAll(sliceDir, 0o755)
		_ = os.WriteFile(filepath.Join(sliceDir, "memory.pressure"),
			[]byte("some avg10=70.00 avg60=60.00 total=100\nfull avg10=70.00 avg60=60.00 total=100\n"), 0o644)
		_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"), []byte("high 10\nmax 10\n"), 0o644)

		ra := startReqAgent(t, bin, sb.envSlice())
		defer ra.stopAndWait(t)

		ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
		for i := 1; i <= 5; i++ {
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"),
				[]byte(fmt.Sprintf("high %d\nmax %d\n", 10+i*10, 10+i*10)), 0o644)
			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
		}

		eventually(t, 6*time.Second, 100*time.Millisecond, "node-agent-hygiene.prom carries oomd + memory_throttled", func() error {
			b, err := os.ReadFile(filepath.Join(sb.textfile, "node-agent-hygiene.prom"))
			if err != nil {
				return err
			}
			s := string(b)
			v1, ok1 := parseMetricValue(s, "node_agent_pod_cgroup_memory_throttled")
			v2, ok2 := parseMetricValue(s, "node_agent_systemd_oomd_kills_total")
			if !ok1 || v1 < 1 || !ok2 || v2 < 1 {
				return fmt.Errorf("mem(%v,%v) oomd(%v,%v)", ok1, v1, ok2, v2)
			}
			return nil
		})
	})

	t.Run("Pair12_F1xF28Agent_LatchDefsJanitorAndReporter", func(t *testing.T) {
		t.Parallel()
		api := newFakeE2EAPIServer(t)
		api.setNode(makeNode("t3-p12-node", "10.244.0.0/24"))
		sb := newReqSandbox(t, map[string]string{
			"NODE_HOST_AGENT_ENABLE_HOSTMETRICS": "true",
			"NODE_HOST_AGENT_ENABLE_JANITOR":     "true",
			"NODE_HOST_AGENT_ENABLE_REPORTER":    "true",
			"NODE_HOST_AGENT_JANITOR_INTERVAL":   "300ms",
			"NODE_HOST_AGENT_REPORTER_INTERVAL":  "300ms",
			"NODE_HOST_AGENT_NODE_NAME":          "t3-p12-node",
		})
		kc := filepath.Join(sb.root, "kubeconfig")
		api.writeKubeconfig(t, kc)
		sb.envMap["KUBECONFIG"] = kc
		// Active known latch + unknown stale latch.
		known := filepath.Join(sb.state, "state-netfilter-locked")
		_ = os.WriteFile(known, []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o644)

		ra := startReqAgent(t, bin, sb.envSlice())
		defer ra.stopAndWait(t)

		eventually(t, 6*time.Second, 100*time.Millisecond, "janitor preserves known latch while nodereporter + hostmetrics export it", func() error {
			if _, err := os.Stat(known); err != nil {
				return fmt.Errorf("known latch reaped: %w", err)
			}
			m := ra.scrapeMetrics(t)
			v, ok := parseMetricValue(m, "node_host_agent_watchdog_state", `state="netfilter-locked"`)
			if !ok || v != 1 {
				return fmt.Errorf("watchdog_state ok=%v v=%v", ok, v)
			}
			n, _ := api.getNode("t3-p12-node")
			for _, c := range n.Status.Conditions {
				if c.Type == "NetfilterLockWedged" && c.Status == corev1.ConditionTrue {
					return nil
				}
			}
			return fmt.Errorf("NetfilterLockWedged condition not True")
		})
	})

	t.Run("Pair13_F1xF20_EnvDocReleaseGlobAndWiring", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "test", "-race", "./internal/envdoc", "./internal/releaseglob", "./internal/latchdefs")
		cmd.Dir = filepath.Join("..", "..")
		cmd.Env = append(os.Environ(), "GOWORK=off")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("contract tests failed: %v\n%s", err, out)
		}

		sb := newReqSandbox(t, map[string]string{
			"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE": "true",
			"NODE_HOST_AGENT_ENABLE_HOSTMETRICS":     "true",
			"NODE_HOST_AGENT_ENABLE_JANITOR":         "true",
		})
		ra := startReqAgent(t, bin, sb.envSlice())
		defer ra.stopAndWait(t)
		for _, want := range []string{"concourse-cache", "hostmetrics", "janitor"} {
			if !slices.Contains(ra.start.Subsystems, want) {
				t.Fatalf("missing %q in %v", want, ra.start.Subsystems)
			}
		}
	})

	t.Run("Pair14_F9xF10_HostconfigKineRedactAndKinedbBackup", func(t *testing.T) {
		t.Parallel()
		sb := newReqSandbox(t, map[string]string{
			"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
			"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "400ms",
			"NODE_HOST_AGENT_ENABLE_KINEDB":       "true",
			"NODE_HOST_AGENT_NODE_NAME":           "t3-p14-node",
		})
		secret := "PAIR14_KINE_SECRET_888"
		writeHostconfigVars(t, sb.vars, fmt.Sprintf(
			"kine_service_hosts:\n  - t3-p14-node\nkine_endpoint: 'postgres://u:%s@db/kine\"bad'\n",
			secret,
		), "", "")
		envFile := filepath.Join(sb.hostroot, "opt", "apps", "postgres", ".env")
		_ = os.WriteFile(envFile, []byte("POSTGRES_USER=postgres\nPOSTGRES_PASSWORD=pw\n"), 0o600)
		installFakeRuntimeForKinedb(t, sb, false, false, 0)

		ra := startReqAgent(t, bin, sb.envSlice())
		defer ra.stopAndWait(t)

		eventually(t, 7*time.Second, 100*time.Millisecond, "hostconfig redacts kine_endpoint while kinedb creates 0600 backup", func() error {
			m := ra.scrapeMetrics(t)
			v1, ok1 := parseMetricValue(m, "node_host_agent_hostconfig_cycles_total", `group="kine"`, `result="error"`)
			v2, ok2 := parseMetricValue(m, "kine_db_backup_valid")
			if !ok1 || v1 < 1 || !ok2 || v2 != 1 {
				return fmt.Errorf("kine(%v,%v) kinedb(%v,%v)", ok1, v1, ok2, v2)
			}
			return nil
		})
		if strings.Contains(ra.logsCombined(), secret) {
			t.Fatalf("kine_endpoint secret leaked in logs")
		}
	})

	t.Run("Pair15_F13xF31Agent_CgroupThrottleAndUDPStaleSingleCycle", func(t *testing.T) {
		t.Parallel()
		api := newFakeE2EAPIServer(t)
		uid := "55555555-7777-8888-9999-000000000015"
		api.setNode(makeNode("t3-p15-node", "10.244.0.0/16"))
		api.setPod(makePod("default", "p15-pod", uid, "t3-p15-node"))

		sb := newReqSandbox(t, map[string]string{
			"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
			"NODE_HOST_AGENT_HYGIENE_INTERVAL": "250ms",
			"NODE_HOST_AGENT_NODE_NAME":        "t3-p15-node",
		})
		kc := filepath.Join(sb.root, "kubeconfig")
		api.writeKubeconfig(t, kc)
		sb.envMap["KUBECONFIG"] = kc
		_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

		sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod55555555_7777_8888_9999_000000000015.slice")
		_ = os.MkdirAll(sliceDir, 0o755)
		_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"), []byte("nr_periods 100\nnr_throttled 0\n"), 0o644)

		ra := startReqAgent(t, bin, sb.envSlice())
		defer ra.stopAndWait(t)

		ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
		for i := 1; i <= 6; i++ {
			_ = os.WriteFile(filepath.Join(sb.proc, "stat"),
				[]byte(fmt.Sprintf("cpu  %d 0 100 %d 0 0 0 0\n", 100+i*10, 1000+i*100)), 0o644)
			_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"),
				[]byte(fmt.Sprintf("nr_periods %d\nnr_throttled %d\n", 100+i*100, i*80)), 0o644)
			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
		}

		eventually(t, 6*time.Second, 100*time.Millisecond, "both cgroup-pod-throttle and udp-stale-socket succeed in shared cycle", func() error {
			if _, err := os.Stat(filepath.Join(sb.state, "last-suspect-cgroup-cfs-"+uid)); err != nil {
				return err
			}
			v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="udp-stale-socket"`, `result="ok"`)
			if !ok || v < 2 {
				return fmt.Errorf("udp-stale-socket ok=%v v=%v", ok, v)
			}
			return nil
		})
	})
}
