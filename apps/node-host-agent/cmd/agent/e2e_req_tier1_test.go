package main_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v3"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func runTier1Tests(t *testing.T, bin string) {
	t.Run("F1_RepoContracts", func(t *testing.T) {
		t.Run("EnvDocContract", func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "go", "test", "-race", "./internal/envdoc")
			cmd.Dir = filepath.Join("..", "..")
			cmd.Env = append(os.Environ(), "GOWORK=off")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("envdoc test failed: %v\n%s", err, out)
			}
		})

		t.Run("ReleaseGlobContract", func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "go", "test", "-race", "./internal/releaseglob")
			cmd.Dir = filepath.Join("..", "..")
			cmd.Env = append(os.Environ(), "GOWORK=off")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("releaseglob test failed: %v\n%s", err, out)
			}
		})

		t.Run("LatchDefsAndNodeCondContract", func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd1 := exec.CommandContext(ctx, "go", "test", "-race", "./internal/latchdefs")
			cmd1.Dir = filepath.Join("..", "..")
			cmd1.Env = append(os.Environ(), "GOWORK=off")
			if out, err := cmd1.CombinedOutput(); err != nil {
				t.Fatalf("latchdefs test failed: %v\n%s", err, out)
			}
			cmd2 := exec.CommandContext(ctx, "go", "test", "-race", "./nodecond")
			cmd2.Dir = filepath.Join("..", "..", "..", "..", "libs", "hostkit")
			cmd2.Env = append(os.Environ(), "GOWORK=off")
			if out, err := cmd2.CombinedOutput(); err != nil {
				t.Fatalf("nodecond test failed: %v\n%s", err, out)
			}
		})

		t.Run("StartupDescriptorOrderAndMetrics", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f1-node", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE": "true",
				"NODE_HOST_AGENT_ENABLE_APIPROBER":       "true",
				"NODE_HOST_AGENT_ENABLE_HOSTMETRICS":     "true",
				"NODE_HOST_AGENT_ENABLE_HYGIENE":         "true",
				"NODE_HOST_AGENT_ENABLE_REPORTER":        "true",
				"NODE_HOST_AGENT_NODE_NAME":              "f1-node",
				"POD_NAME":                               "f1-pod",
				"POD_NAMESPACE":                          "kube-system",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			wantOrder := []string{"concourse-cache", "apiprober", "hostmetrics", "workerhygiene", "nodereporter", "hubsync"}
			idx := 0
			for _, sub := range ra.start.Subsystems {
				if idx < len(wantOrder) && sub == wantOrder[idx] {
					idx++
				}
			}
			if idx != len(wantOrder) {
				t.Fatalf("startup subsystem order %v did not preserve expected subsequence %v", ra.start.Subsystems, wantOrder)
			}
			body := ra.scrapeMetrics(t)
			for _, metric := range []string{
				"node_host_agent_info",
				"node_host_agent_subsystem_up",
				"node_host_agent_subsystem_restarts_total",
				"node_host_agent_uptime_seconds",
			} {
				if !strings.Contains(body, metric) {
					t.Fatalf("/metrics missing baseline metric %q", metric)
				}
			}
		})

		t.Run("DaemonPprofLoopbackAndSignals", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_NODE_NAME": "f1-sig-node",
			})
			ra := startReqAgent(t, bin, sb.envSlice(), "--standalone")
			defer ra.stopAndWait(t)

			if code, _ := reqHTTPGet(t, ra.healthzURL()); code != http.StatusOK {
				t.Fatalf("/healthz status=%d want 200", code)
			}
			if code, _ := reqHTTPGet(t, ra.readyzURL()); code != http.StatusOK {
				t.Fatalf("/readyz status=%d want 200", code)
			}
			if code, _ := reqHTTPGet(t, "http://"+ra.addrs["metrics"]+"/debug/pprof/"); code != http.StatusNotFound {
				t.Fatalf("metrics /debug/pprof/ status=%d want 404", code)
			}
			if code, _ := reqHTTPGet(t, ra.pprofURL()); code != http.StatusOK {
				t.Fatalf("pprof loopback status=%d want 200", code)
			}
			if err := ra.cmd.Process.Signal(syscall.SIGHUP); err != nil {
				t.Fatalf("send SIGHUP: %v", err)
			}
			time.Sleep(100 * time.Millisecond)
			if code, _ := reqHTTPGet(t, ra.healthzURL()); code != http.StatusOK {
				t.Fatalf("/healthz after SIGHUP status=%d want 200", code)
			}
		})
	})

	t.Run("F2_ConcourseCacheSecurity", func(t *testing.T) {
		t.Run("AgePruneValidTreeAndProtectReferencedGoBuild", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE":   "true",
				"NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL": "100ms",
			})
			sc := filepath.Join(sb.openebs, "pvc-11111111-2222-3333-4444-555555555555", "shared-cache")
			for _, d := range []string{
				filepath.Join(sc, "build"),
				filepath.Join(sc, "go-build", "aa"),
				filepath.Join(sc, "go-build", "bb"),
				filepath.Join(sc, "go-build", "cc"),
			} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}

			oldTime := time.Now().Add(-100 * time.Hour)
			idxTime := time.Now().Add(-10 * time.Hour)
			refOID := strings.Repeat("b", 64)
			unrefOID := strings.Repeat("c", 64)
			actID := strings.Repeat("a", 64)

			oldBuild := filepath.Join(sc, "build", "old.bin")
			if err := os.WriteFile(oldBuild, []byte("old-artifact"), 0o644); err != nil {
				t.Fatal(err)
			}
			_ = os.Chtimes(oldBuild, oldTime, oldTime)

			refData := filepath.Join(sc, "go-build", "bb", refOID+"-d")
			if err := os.WriteFile(refData, []byte("keep-output"), 0o644); err != nil {
				t.Fatal(err)
			}
			_ = os.Chtimes(refData, oldTime, oldTime)

			unrefData := filepath.Join(sc, "go-build", "cc", unrefOID+"-d")
			if err := os.WriteFile(unrefData, []byte("drop-output"), 0o644); err != nil {
				t.Fatal(err)
			}
			_ = os.Chtimes(unrefData, oldTime, oldTime)

			// Exact 175-byte v1 index line referencing refOID.
			idxLine := fmt.Sprintf("v1 %s %s %20d %20d\n", actID, refOID, 11, time.Now().Unix())
			if len(idxLine) != 175 {
				t.Fatalf("test setup error: index len=%d want 175", len(idxLine))
			}
			idxPath := filepath.Join(sc, "go-build", "aa", actID+"-a")
			if err := os.WriteFile(idxPath, []byte(idxLine), 0o644); err != nil {
				t.Fatal(err)
			}
			_ = os.Chtimes(idxPath, idxTime, idxTime)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 8*time.Second, 100*time.Millisecond, "age prune + referenced go-build", func() error {
				if _, err := os.Stat(oldBuild); !os.IsNotExist(err) {
					return fmt.Errorf("old build artifact still exists")
				}
				if _, err := os.Stat(unrefData); !os.IsNotExist(err) {
					return fmt.Errorf("unreferenced go-build output still exists")
				}
				if _, err := os.Stat(refData); err != nil {
					return fmt.Errorf("referenced go-build output disappeared: %v", err)
				}
				m := ra.scrapeMetrics(t)
				v, ok := parseMetricValue(m, "node_host_agent_concourse_cache_cycles_total", `result="ok"`)
				if !ok || v < 1 {
					return fmt.Errorf("cycles ok=%v v=%v", ok, v)
				}
				return nil
			})
		})

		t.Run("GoBuildFIFOSurvivalNoBlock", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE":   "true",
				"NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL": "100ms",
			})
			sc := filepath.Join(sb.openebs, "pvc-22222222-2222-3333-4444-555555555555", "shared-cache")
			fifoDir := filepath.Join(sc, "go-build", "00")
			if err := os.MkdirAll(fifoDir, 0o755); err != nil {
				t.Fatal(err)
			}
			fifoPath := filepath.Join(fifoDir, strings.Repeat("0", 64)+"-a")
			if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
				t.Fatal(err)
			}
			age5h := time.Now().Add(-5 * time.Hour)
			_ = os.Chtimes(fifoPath, age5h, age5h)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "concourse-cache sweeps without blocking on FIFO", func() error {
				if code, _ := reqHTTPGet(t, ra.healthzURL()); code != http.StatusOK {
					return fmt.Errorf("healthz=%d", code)
				}
				m := ra.scrapeMetrics(t)
				v, ok := parseMetricValue(m, "node_host_agent_concourse_cache_cycles_total", `result="ok"`)
				if !ok || v < 2 {
					return fmt.Errorf("concourse-cache wedged on FIFO: cycles=%v ok=%v", v, ok)
				}
				return nil
			})
		})

		t.Run("StaticSymlinkEscapeBlocked", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE":   "true",
				"NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL": "100ms",
			})
			outside := filepath.Join(sb.root, "outside-secret")
			outsideRO := filepath.Join(sb.root, "outside-ro")
			if err := os.MkdirAll(outside, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(outsideRO, 0o755); err != nil {
				t.Fatal(err)
			}
			canary := filepath.Join(outside, "canary.txt")
			if err := os.WriteFile(canary, []byte("SAFE"), 0o644); err != nil {
				t.Fatal(err)
			}
			old := time.Now().Add(-100 * time.Hour)
			_ = os.Chtimes(canary, old, old)
			roSecret := filepath.Join(outsideRO, "secret.txt")
			if err := os.WriteFile(roSecret, []byte("KEEP"), 0o644); err != nil {
				t.Fatal(err)
			}
			_ = os.Chmod(outsideRO, 0o555)
			t.Cleanup(func() { _ = os.Chmod(outsideRO, 0o755) })

			sc := filepath.Join(sb.openebs, "pvc-33333333-2222-3333-4444-555555555555", "shared-cache")
			if err := os.MkdirAll(filepath.Join(sc, "build"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(sc, "node-deps"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(sc, "build", "escape")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outsideRO, filepath.Join(sc, "node-deps", "escape-ro")); err != nil {
				t.Fatal(err)
			}
			_ = os.Chtimes(filepath.Join(sc, "node-deps", "escape-ro"), old, old)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "at least 3 sweeps run", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_concourse_cache_cycles_total", `result="ok"`)
				if !ok || v < 3 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
			if b, err := os.ReadFile(canary); err != nil || string(b) != "SAFE" {
				t.Fatalf("symlink escape deleted or modified outside canary: err=%v data=%q", err, b)
			}
			if fi, err := os.Stat(outsideRO); err != nil || fi.Mode().Perm() != 0o555 {
				t.Fatalf("outsideRO permissions altered through symlink: err=%v mode=%v", err, fi.Mode().Perm())
			}
		})

		t.Run("ConcurrentIntermediateSymlinkTOCTOU", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE":   "true",
				"NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL": "50ms",
			})
			outside := filepath.Join(sb.root, "outside-toctou")
			if err := os.MkdirAll(outside, 0o755); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(outside, "target.txt")
			if err := os.WriteFile(target, []byte("DO_NOT_DELETE"), 0o644); err != nil {
				t.Fatal(err)
			}
			old := time.Now().Add(-100 * time.Hour)
			_ = os.Chtimes(target, old, old)

			sc := filepath.Join(sb.openebs, "pvc-44444444-2222-3333-4444-555555555555", "shared-cache")
			buildDir := filepath.Join(sc, "build")
			if err := os.MkdirAll(buildDir, 0o755); err != nil {
				t.Fatal(err)
			}
			racePath := filepath.Join(buildDir, "race")
			realDir := filepath.Join(buildDir, "real")
			if err := os.MkdirAll(realDir, 0o755); err != nil {
				t.Fatal(err)
			}

			stopFlip := make(chan struct{})
			flipDone := make(chan struct{})
			go func() {
				defer close(flipDone)
				for i := 0; ; i++ {
					select {
					case <-stopFlip:
						return
					default:
					}
					_ = os.RemoveAll(racePath)
					if i%2 == 0 {
						_ = os.Symlink(outside, racePath)
					} else {
						_ = os.MkdirAll(racePath, 0o755)
						f := filepath.Join(racePath, "target.txt")
						_ = os.WriteFile(f, []byte("temp"), 0o644)
						_ = os.Chtimes(f, old, old)
					}
				}
			}()
			t.Cleanup(func() {
				close(stopFlip)
				<-flipDone
			})

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "multiple sweeps during symlink race", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_concourse_cache_cycles_total", `result="ok"`)
				if !ok || v < 4 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})

			if _, err := os.Stat(target); err != nil {
				t.Fatalf("intermediate symlink TOCTOU escaped shared-cache and deleted outside target: %v", err)
			}
		})

		t.Run("NodeDepsWritableRecoveryInsideRootOnly", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE":   "true",
				"NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL": "100ms",
			})
			outsideRO := filepath.Join(sb.root, "outside-ro2")
			if err := os.MkdirAll(outsideRO, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(outsideRO, "keep"), []byte("1"), 0o644); err != nil {
				t.Fatal(err)
			}
			_ = os.Chmod(outsideRO, 0o555)
			t.Cleanup(func() { _ = os.Chmod(outsideRO, 0o755) })

			sc := filepath.Join(sb.openebs, "pvc-55555555-2222-3333-4444-555555555555", "shared-cache")
			cksum := filepath.Join(sc, "node-deps", "deadbeef")
			roSub := filepath.Join(cksum, "rosub")
			if err := os.MkdirAll(roSub, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(roSub, "pkg.tgz"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outsideRO, filepath.Join(cksum, "link-out")); err != nil {
				t.Fatal(err)
			}
			_ = os.Chmod(roSub, 0o555)
			old := time.Now().Add(-10 * 24 * time.Hour)
			_ = os.Chtimes(cksum, old, old)
			t.Cleanup(func() { _ = os.Chmod(roSub, 0o755) })

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "read-only node-deps inside root pruned safely", func() error {
				if _, err := os.Stat(cksum); !os.IsNotExist(err) {
					return fmt.Errorf("aged node-deps dir still exists: %v", err)
				}
				return nil
			})
			if fi, err := os.Stat(outsideRO); err != nil || fi.Mode().Perm() != 0o555 {
				t.Fatalf("outside read-only dir modified via symlink inside node-deps: err=%v mode=%v", err, fi.Mode().Perm())
			}
		})
	})

	t.Run("F3_HostconfigStagingAndValidation", func(t *testing.T) {
		t.Run("EtcdctlDownloadAndUntarSuccess", func(t *testing.T) {
			t.Parallel()
			tgzBytes, tgzSum := makeTarGz(t, []tarEntry{{name: "etcdctl", body: []byte("#!/bin/sh\necho etcdctl version: 3.7.3\n")}})
			uniqueName := fmt.Sprintf("etcdctl-%d.tar.gz", time.Now().UnixNano())
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/gzip")
				_, _ = w.Write(tgzBytes)
			}))
			defer srv.Close()

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
				"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "500ms",
				"NODE_HOST_AGENT_NODE_NAME":           "f3-ctrl-1",
			})
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sb.hostroot, "var", "lib", "k0s", "pki", "etcd", "ca.crt"), []byte("CA"), 0o644)
			writeHostconfigVars(t, sb.vars, fmt.Sprintf(
				"etcdctl_version: \"3.7.3\"\netcdctl_tgz_url: %q\netcdctl_tgz_sha256: %q\netcdctl_tgz_file: %q\n",
				srv.URL+"/"+uniqueName, tgzSum, uniqueName,
			), "", "")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			dstBin := filepath.Join(sb.hostroot, "var", "lib", "k0s", "bin", "etcdctl")
			dlDir := filepath.Join(sb.hostroot, "var", "lib", "node-watchdog", "downloads")
			eventually(t, 8*time.Second, 100*time.Millisecond, "etcdctl installed and staged under hostroot 0700", func() error {
				fi, err := os.Stat(dstBin)
				if err != nil {
					return err
				}
				if fi.Mode().Perm()&0o111 == 0 {
					return fmt.Errorf("etcdctl not executable: %v", fi.Mode().Perm())
				}
				dfi, err := os.Stat(dlDir)
				if err != nil {
					return fmt.Errorf("expected DownloadDir %s under hostroot: %w", dlDir, err)
				}
				if dfi.Mode().Perm() != 0o700 {
					return fmt.Errorf("DownloadDir mode=%v want 0700", dfi.Mode().Perm())
				}
				if _, err := os.Stat(filepath.Join("/tmp/hostconfig", uniqueName)); !os.IsNotExist(err) {
					return fmt.Errorf("unexpected staging file leaked into /tmp/hostconfig/%s", uniqueName)
				}
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_hostconfig_cycles_total", `group="etcdctl"`, `result="ok"`)
				if !ok || v < 1 {
					return fmt.Errorf("cycles etcdctl ok=%v v=%v", ok, v)
				}
				return nil
			})
		})

		t.Run("DownloadDirPreexisting0755TightenedTo0700", func(t *testing.T) {
			t.Parallel()
			tgzBytes, tgzSum := makeTarGz(t, []tarEntry{{name: "etcdctl", body: []byte("#!/bin/sh\necho etcdctl version: 3.7.3\n")}})
			uniqueName := fmt.Sprintf("etcdctl-tighten-%d.tar.gz", time.Now().UnixNano())
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(tgzBytes)
			}))
			defer srv.Close()

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
				"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "500ms",
				"NODE_HOST_AGENT_NODE_NAME":           "f3-ctrl-2",
			})
			dlDir := filepath.Join(sb.hostroot, "var", "lib", "node-watchdog", "downloads")
			if err := os.MkdirAll(dlDir, 0o755); err != nil {
				t.Fatal(err)
			}
			_ = os.Chmod(dlDir, 0o755)
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sb.hostroot, "var", "lib", "k0s", "pki", "etcd", "ca.crt"), []byte("CA"), 0o644)
			writeHostconfigVars(t, sb.vars, fmt.Sprintf(
				"etcdctl_version: \"3.7.3\"\netcdctl_tgz_url: %q\netcdctl_tgz_sha256: %q\netcdctl_tgz_file: %q\n",
				srv.URL+"/"+uniqueName, tgzSum, uniqueName,
			), "", "")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 8*time.Second, 100*time.Millisecond, "preexisting 0755 download dir tightened to 0700", func() error {
				fi, err := os.Stat(dlDir)
				if err != nil {
					return err
				}
				if fi.Mode().Perm() != 0o700 {
					return fmt.Errorf("DownloadDir mode=%v want 0700", fi.Mode().Perm())
				}
				return nil
			})
		})

		t.Run("PredictableDotDlSymlinkLPEBlocked", func(t *testing.T) {
			t.Parallel()
			tgzBytes, tgzSum := makeTarGz(t, []tarEntry{{name: "etcdctl", body: []byte("#!/bin/sh\necho etcdctl version: 3.7.3\n")}})
			uniqueName := fmt.Sprintf("etcdctl-dl-%d.tar.gz", time.Now().UnixNano())
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(tgzBytes)
			}))
			defer srv.Close()

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
				"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "500ms",
				"NODE_HOST_AGENT_NODE_NAME":           "f3-ctrl-3",
			})
			canary := filepath.Join(sb.root, "canary.txt")
			if err := os.WriteFile(canary, []byte("SAFE"), 0o644); err != nil {
				t.Fatal(err)
			}
			dlDir := filepath.Join(sb.hostroot, "var", "lib", "node-watchdog", "downloads")
			if err := os.MkdirAll(dlDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(canary, filepath.Join(dlDir, uniqueName+".dl")); err != nil {
				t.Fatal(err)
			}
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sb.hostroot, "var", "lib", "k0s", "pki", "etcd", "ca.crt"), []byte("CA"), 0o644)
			writeHostconfigVars(t, sb.vars, fmt.Sprintf(
				"etcdctl_version: \"3.7.3\"\netcdctl_tgz_url: %q\netcdctl_tgz_sha256: %q\netcdctl_tgz_file: %q\n",
				srv.URL+"/"+uniqueName, tgzSum, uniqueName,
			), "", "")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 8*time.Second, 100*time.Millisecond, "etcdctl installed without clobbering .dl symlink target", func() error {
				if _, err := os.Stat(filepath.Join(sb.hostroot, "var", "lib", "k0s", "bin", "etcdctl")); err != nil {
					return err
				}
				if _, err := os.Stat(filepath.Join(dlDir, uniqueName)); err != nil {
					return fmt.Errorf("staged archive missing from 0700 download dir: %w", err)
				}
				return nil
			})
			if b, err := os.ReadFile(canary); err != nil || string(b) != "SAFE" {
				t.Fatalf("predictable .dl symlink LPE overwrote canary: err=%v data=%q", err, b)
			}
		})

		t.Run("KineBinaryInstallPreservesUsrLocalBin0755", func(t *testing.T) {
			t.Parallel()
			kineBody := []byte("#!/bin/sh\necho kine\n")
			_, kineSum := makeTarGz(t, nil)
			_ = kineSum
			rawSumBytes := func() string {
				h := fmt.Sprintf("%x", sha256Sum(kineBody))
				return h
			}()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(kineBody)
			}))
			defer srv.Close()

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
				"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "500ms",
				"NODE_HOST_AGENT_NODE_NAME":           "f3-kine-node",
			})
			usrLocalBin := filepath.Join(sb.hostroot, "usr", "local", "bin")
			_ = os.Chmod(usrLocalBin, 0o755)
			writeHostconfigVars(t, sb.vars, fmt.Sprintf(
				"kine_service_hosts:\n  - f3-kine-node\nkine_endpoint: \"postgres://u:p@127.0.0.1:5432/kine\"\nkine_bin_url: %q\nkine_bin_sha256: %q\n",
				srv.URL+"/kine", rawSumBytes,
			), "", "")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 8*time.Second, 100*time.Millisecond, "kine installed preserving /usr/local/bin 0755", func() error {
				fi, err := os.Stat(filepath.Join(usrLocalBin, "kine"))
				if err != nil {
					return err
				}
				if fi.Mode().Perm() != 0o755 {
					return fmt.Errorf("kine mode=%v want 0755", fi.Mode().Perm())
				}
				return nil
			})
			// The sandbox pre-creates hostroot/etc/kine at 0755 and the
			// converge chmods it to 0700 in the same pass that lands the
			// binary — a beat after the binary becomes visible. Poll like
			// the binary check above instead of racing that window.
			eventually(t, 8*time.Second, 100*time.Millisecond, "kine dir/env modes converged", func() error {
				dfi, err := os.Stat(usrLocalBin)
				if err != nil {
					return err
				}
				if dfi.Mode().Perm() != 0o755 {
					return fmt.Errorf("/usr/local/bin mode=%v want 0755", dfi.Mode().Perm())
				}
				efi, err := os.Stat(filepath.Join(sb.hostroot, "etc", "kine"))
				if err != nil {
					return err
				}
				if efi.Mode().Perm() != 0o700 {
					return fmt.Errorf("/etc/kine mode=%v want 0700", efi.Mode().Perm())
				}
				kfi, err := os.Stat(filepath.Join(sb.hostroot, "etc", "kine", "kine.env"))
				if err != nil {
					return err
				}
				if kfi.Mode().Perm() != 0o600 {
					return fmt.Errorf("kine.env mode=%v want 0600", kfi.Mode().Perm())
				}
				return nil
			})
		})

		t.Run("SHA256TamperRejectedSingleFD", func(t *testing.T) {
			t.Parallel()
			tgzBytes, _ := makeTarGz(t, []tarEntry{{name: "etcdctl", body: []byte("evil-binary")}})
			uniqueName := fmt.Sprintf("etcdctl-tamper-%d.tar.gz", time.Now().UnixNano())
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(tgzBytes)
			}))
			defer srv.Close()

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
				"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "500ms",
				"NODE_HOST_AGENT_NODE_NAME":           "f3-ctrl-tamper",
			})
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sb.hostroot, "var", "lib", "k0s", "pki", "etcd", "ca.crt"), []byte("CA"), 0o644)
			writeHostconfigVars(t, sb.vars, fmt.Sprintf(
				"etcdctl_version: \"3.7.3\"\netcdctl_tgz_url: %q\netcdctl_tgz_sha256: %q\netcdctl_tgz_file: %q\n",
				srv.URL+"/"+uniqueName, strings.Repeat("0", 64), uniqueName,
			), "", "")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 8*time.Second, 100*time.Millisecond, "tampered sha256 rejected", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_hostconfig_cycles_total", `group="etcdctl"`, `result="error"`)
				if !ok || v < 1 {
					return fmt.Errorf("expected etcdctl error cycle, ok=%v v=%v", ok, v)
				}
				return nil
			})
			if _, err := os.Stat(filepath.Join(sb.hostroot, "var", "lib", "k0s", "bin", "etcdctl")); !os.IsNotExist(err) {
				t.Fatalf("tampered etcdctl was installed despite SHA-256 mismatch")
			}
			logs := strings.ToLower(ra.logsCombined())
			if !strings.Contains(logs, "sha256 mismatch") && !strings.Contains(logs, "checksum") {
				t.Fatalf("expected sha256 mismatch / checksum error in logs (not DownloadDir staging error):\n%s", ra.logsCombined())
			}
		})
	})

	t.Run("F8_WorkerHygieneCtrAntiSpoofAndArgs", func(t *testing.T) {
		t.Run("OrphanShimInKubepodsRejected", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f8-node-1", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f8-node-1",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			_, pid := spawnDummySleep(t, 60)
			sid := strings.Repeat("a", 64)
			writeProcTask(t, sb.proc, pid, "containerd-shim", "S", 1000,
				"0::/kubepods.slice/kubepods-pod123.slice/cri-containerd-foo.scope\n",
				[]string{"containerd-shim-runc-v2", "-namespace", "k8s.io", "-id", sid, "-address", sb.envMap["NODE_HOST_AGENT_CONTAINERD_SOCKET"]},
				10*time.Minute)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "ctr-tasks completes without killing kubepods spoof", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="ctr-tasks"`, `result="ok"`)
				if !ok || v < 2 {
					return fmt.Errorf("ctr-tasks ok=%v v=%v", ok, v)
				}
				return nil
			})
			if !pidAlive(pid) {
				t.Fatalf("spoofed containerd-shim inside kubepods cgroup (pid=%d) was killed!", pid)
			}
			assertNoCtrShimKill(t, ra)
		})

		t.Run("OrphanShimNonRootUIDRejected", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f8-node-2", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f8-node-2",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			_, pid := spawnDummySleep(t, 60)
			sid := strings.Repeat("b", 64)
			writeProcTask(t, sb.proc, pid, "containerd-shim", "S", 1000,
				"0::/system.slice/k0sworker.service\n",
				[]string{"containerd-shim-runc-v2", "-namespace", "k8s.io", "-id", sid, "-address", sb.envMap["NODE_HOST_AGENT_CONTAINERD_SOCKET"]},
				10*time.Minute)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "ctr-tasks completes without killing non-root shim", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="ctr-tasks"`, `result="ok"`)
				if !ok || v < 2 {
					return fmt.Errorf("ctr-tasks ok=%v v=%v", ok, v)
				}
				return nil
			})
			if !pidAlive(pid) {
				t.Fatalf("non-root spoofed containerd-shim (uid=1000, pid=%d) was killed!", pid)
			}
			assertNoCtrShimKill(t, ra)
		})

		t.Run("LegitimateRootHostCgroupShimAccepted", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f8-node-3", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f8-node-3",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			done, pid := spawnDummySleep(t, 60)
			sid := strings.Repeat("c", 64)
			writeProcTask(t, sb.proc, pid, "containerd-shim", "S", 0,
				"0::/system.slice/k0sworker.service\n",
				[]string{"containerd-shim-runc-v2", "-namespace", "k8s.io", "-id", sid, "-address", sb.envMap["NODE_HOST_AGENT_CONTAINERD_SOCKET"]},
				10*time.Minute)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "legitimate root host-cgroup orphan shim killed", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_actions_total", `check="ctr-tasks"`, `action="shim_kill"`)
				if !ok || v < 1 {
					return fmt.Errorf("shim_kill action ok=%v v=%v", ok, v)
				}
				return nil
			})
			<-done
		})

		t.Run("RmImageIncludesDoubleDash", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f8-node-4", "10.244.0.0/24"))
			pod := makePod("default", "bad-img", "11111111-1111-1111-1111-111111111111", "f8-node-4")
			pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
				Name:  "app",
				Image: "registry.example.com/app:v1",
				State: corev1.ContainerState{
					Waiting: &corev1.ContainerStateWaiting{
						Reason:  "ErrImagePull",
						Message: "content digest sha256:aaaa: not found",
					},
				},
			}}
			api.setPod(pod)

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f8-node-4",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "k0s ctr images rm invoked with -- delimiter", func() error {
				b, err := os.ReadFile(sb.toolLog)
				if err != nil {
					return err
				}
				want := "k0s ctr --namespace k8s.io images rm --sync -- registry.example.com/app:v1"
				if !strings.Contains(string(b), want) {
					return fmt.Errorf("toolLog missing %q:\n%s", want, string(b))
				}
				return nil
			})
		})

		t.Run("RmImageExecFormatHealsOnce", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f8-node-5", "10.244.0.0/24"))
			pod := makePod("default", "exec-fmt", "22222222-2222-2222-2222-222222222222", "f8-node-5")
			pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
				Name:  "app",
				Image: "registry.example.com/badarch:v2",
				State: corev1.ContainerState{
					Waiting: &corev1.ContainerStateWaiting{
						Reason:  "RunContainerError",
						Message: "exec format error",
					},
				},
			}}
			api.setPod(pod)

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "300ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f8-node-5",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "multiple cycles completed", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="ctr-image-healer"`, `result="ok"`)
				if !ok || v < 3 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
			b, _ := os.ReadFile(sb.toolLog)
			got := strings.Count("\n"+string(b), "\nk0s ctr --namespace k8s.io images rm --sync -- registry.example.com/badarch:v2")
			if got != 1 {
				t.Fatalf("expected 1 deduped RmImage invocation with --, got %d in:\n%s", got, string(b))
			}
		})
	})

	t.Run("F9_HostconfigRedactionAndJournald", func(t *testing.T) {
		t.Run("KineEndpointDoubleQuoteRedacted", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
				"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":           "f9-node-1",
			})
			secret := "TOPSECRET_KINE_PW_99"
			writeHostconfigVars(t, sb.vars, fmt.Sprintf(
				"kine_service_hosts:\n  - f9-node-1\nkine_endpoint: 'postgres://admin:%s@db:5432/kine\"inject'\n",
				secret,
			), "", "")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "kine group reports validation error", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_hostconfig_cycles_total", `group="kine"`, `result="error"`)
				if !ok || v < 1 {
					return fmt.Errorf("kine error ok=%v v=%v", ok, v)
				}
				return nil
			})
			if _, err := os.Stat(filepath.Join(sb.hostroot, "etc", "kine", "kine.env")); !os.IsNotExist(err) {
				t.Fatalf("kine.env written despite invalid kine_endpoint")
			}
			if strings.Contains(ra.logsCombined(), secret) {
				t.Fatalf("kine_endpoint secret %q leaked in agent logs:\n%s", secret, ra.logsCombined())
			}
		})

		t.Run("KineEndpointNewlineRedacted", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
				"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":           "f9-node-2",
			})
			secret := "TOPSECRET_NL_88"
			writeHostconfigVars(t, sb.vars, fmt.Sprintf(
				"kine_service_hosts:\n  - f9-node-2\nkine_endpoint: \"postgres://admin:%s@db/kine\\nINJECT=1\"\n",
				secret,
			), "", "")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "kine group rejects newline endpoint", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_hostconfig_cycles_total", `group="kine"`, `result="error"`)
				if !ok || v < 1 {
					return fmt.Errorf("kine error ok=%v v=%v", ok, v)
				}
				return nil
			})
			if _, err := os.Stat(filepath.Join(sb.hostroot, "etc", "kine", "kine.env")); !os.IsNotExist(err) {
				t.Fatalf("kine.env written despite newline injection")
			}
			if strings.Contains(ra.logsCombined(), secret) {
				t.Fatalf("kine_endpoint secret %q leaked in agent logs", secret)
			}
		})

		t.Run("NonSecretValidationStillReportsContext", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
				"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":           "f9-node-3",
			})
			secret := "SECRET_KEEP_HIDDEN_3"
			writeHostconfigVars(t, sb.vars, fmt.Sprintf(
				"kine_service_hosts:\n  - f9-node-3\nkine_endpoint: \"postgres://u:%s@db/kine\"\nkine_listen_address: \"tcp://127.0.0.1:2379;rm -rf\"\n",
				secret,
			), "", "")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "non-secret listen error reported", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_hostconfig_cycles_total", `group="kine"`, `result="error"`)
				if !ok || v < 1 {
					return fmt.Errorf("kine error ok=%v v=%v", ok, v)
				}
				return nil
			})
			if _, err := os.Stat(filepath.Join(sb.hostroot, "etc", "kine", "kine.env")); !os.IsNotExist(err) {
				t.Fatalf("kine.env written despite invalid kine_listen_address")
			}
			if !strings.Contains(ra.logsCombined(), "kine_listen_address") {
				t.Fatalf("non-secret field context missing from logs:\n%s", ra.logsCombined())
			}
			if strings.Contains(ra.logsCombined(), secret) {
				t.Fatalf("secret leaked in logs:\n%s", ra.logsCombined())
			}
		})

		t.Run("ValidKineEndpointConvergesEnv0600", func(t *testing.T) {
			t.Parallel()
			kineBody := []byte("#!/bin/sh\necho kine\n")
			sum := fmt.Sprintf("%x", sha256Sum(kineBody))
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(kineBody)
			}))
			defer srv.Close()

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
				"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":           "f9-node-4",
			})
			dsn := "postgres://u:goodpass@127.0.0.1:5432/kine?sslmode=disable"
			writeHostconfigVars(t, sb.vars, fmt.Sprintf(
				"kine_service_hosts:\n  - f9-node-4\nkine_endpoint: %q\nkine_bin_url: %q\nkine_bin_sha256: %q\n",
				dsn, srv.URL+"/kine", sum,
			), "", "")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			envPath := filepath.Join(sb.hostroot, "etc", "kine", "kine.env")
			eventually(t, 8*time.Second, 100*time.Millisecond, "kine.env converged at 0600", func() error {
				fi, err := os.Stat(envPath)
				if err != nil {
					return err
				}
				if fi.Mode().Perm() != 0o600 {
					return fmt.Errorf("kine.env mode=%v want 0600", fi.Mode().Perm())
				}
				b, err := os.ReadFile(envPath)
				if err != nil {
					return err
				}
				if !strings.Contains(string(b), "KINE_ENDPOINT="+dsn) {
					return fmt.Errorf("unexpected kine.env content: %q", string(b))
				}
				return nil
			})
		})

		t.Run("VarsReloadFixesRedactedEndpoint", func(t *testing.T) {
			t.Parallel()
			kineBody := []byte("#!/bin/sh\necho kine\n")
			sum := fmt.Sprintf("%x", sha256Sum(kineBody))
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(kineBody)
			}))
			defer srv.Close()

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
				"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":           "f9-node-5",
			})
			badSecret := "BAD_INITIAL_PW_55"
			writeHostconfigVars(t, sb.vars, fmt.Sprintf(
				"kine_service_hosts:\n  - f9-node-5\nkine_endpoint: 'postgres://u:%s@db/kine\"bad'\nkine_bin_url: %q\nkine_bin_sha256: %q\n",
				badSecret, srv.URL+"/kine", sum,
			), "", "")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "initial bad kine_endpoint rejected", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_hostconfig_cycles_total", `group="kine"`, `result="error"`)
				if !ok || v < 1 {
					return fmt.Errorf("kine error ok=%v v=%v", ok, v)
				}
				return nil
			})
			if strings.Contains(ra.logsCombined(), badSecret) {
				t.Fatalf("bad initial secret leaked in logs")
			}

			goodDSN := "postgres://u:good2@127.0.0.1:5432/kine"
			writeHostconfigVars(t, sb.vars, fmt.Sprintf(
				"kine_service_hosts:\n  - f9-node-5\nkine_endpoint: %q\nkine_bin_url: %q\nkine_bin_sha256: %q\n",
				goodDSN, srv.URL+"/kine", sum,
			), "", "")

			envPath := filepath.Join(sb.hostroot, "etc", "kine", "kine.env")
			eventually(t, 8*time.Second, 100*time.Millisecond, "kine.env converges after reload", func() error {
				b, err := os.ReadFile(envPath)
				if err != nil {
					return err
				}
				if !strings.Contains(string(b), "KINE_ENDPOINT="+goodDSN) {
					return fmt.Errorf("content=%q", string(b))
				}
				return nil
			})
		})
	})

	t.Run("F10_KinedbAndEtcdguardBackupSecurity", func(t *testing.T) {
		t.Run("KinedbBackupDir0700AndDump0600", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_KINEDB":          "true",
				"NODE_HOST_AGENT_KINEDB_BACKUP_INTERVAL": "6h",
			})
			backupDir := filepath.Join(sb.hostroot, "var", "backups", "kine")
			_ = os.Chmod(backupDir, 0o755)
			envFile := filepath.Join(sb.hostroot, "opt", "apps", "postgres", ".env")
			if err := os.WriteFile(envFile, []byte("POSTGRES_USER=postgres\nPOSTGRES_PASSWORD=pw\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			installFakeRuntimeForKinedb(t, sb, false, false, 0)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 8*time.Second, 100*time.Millisecond, "kinedb backup dir 0700 and dump 0600 created", func() error {
				fi, err := os.Stat(backupDir)
				if err != nil {
					return err
				}
				if fi.Mode().Perm() != 0o700 {
					return fmt.Errorf("backupDir mode=%v want 0700", fi.Mode().Perm())
				}
				dumps, _ := filepath.Glob(filepath.Join(backupDir, "kine-*.dump"))
				if len(dumps) == 0 {
					return fmt.Errorf("no kine-*.dump in %s", backupDir)
				}
				dfi, err := os.Stat(dumps[0])
				if err != nil {
					return err
				}
				if dfi.Mode().Perm() != 0o600 {
					return fmt.Errorf("dump mode=%v want 0600", dfi.Mode().Perm())
				}
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "kine_db_backup_valid")
				if !ok || v != 1 {
					return fmt.Errorf("kine_db_backup_valid ok=%v v=%v", ok, v)
				}
				return nil
			})

			b, _ := os.ReadFile(sb.toolLog)
			if !strings.Contains(string(b), "umask 077") && !strings.Contains(string(b), "0700") {
				t.Fatalf("kinedb pg_dump container staging missing umask 077 / 0700 dir protection in:\n%s", string(b))
			}
		})

		t.Run("KinedbPgDumpFailureCleansTmpWithoutCancel", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_KINEDB": "true",
			})
			backupDir := filepath.Join(sb.hostroot, "var", "backups", "kine")
			envFile := filepath.Join(sb.hostroot, "opt", "apps", "postgres", ".env")
			_ = os.WriteFile(envFile, []byte("POSTGRES_USER=postgres\nPOSTGRES_PASSWORD=pw\n"), 0o600)
			installFakeRuntimeForKinedb(t, sb, true, false, 0)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 8*time.Second, 100*time.Millisecond, "kinedb cleans container tmp after pg_dump failure", func() error {
				b, err := os.ReadFile(sb.toolLog)
				if err != nil {
					return err
				}
				if !strings.Contains(string(b), "rm -rf") && !strings.Contains(string(b), "rm -f") {
					return fmt.Errorf("missing rm cleanup in:\n%s", string(b))
				}
				return nil
			})
			tmps, _ := filepath.Glob(filepath.Join(backupDir, "*.tmp"))
			if len(tmps) != 0 {
				t.Fatalf("leftover .tmp files in %s: %v", backupDir, tmps)
			}
		})

		t.Run("KinedbSIGTERMRunsWithoutCancelCleanup", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_KINEDB": "true",
			})
			envFile := filepath.Join(sb.hostroot, "opt", "apps", "postgres", ".env")
			_ = os.WriteFile(envFile, []byte("POSTGRES_USER=postgres\nPOSTGRES_PASSWORD=pw\n"), 0o600)
			// Delay 300ms inside pg_dump, then exit 1 so backupVerify runs cleanup after SIGTERM.
			installFakeRuntimeForKinedb(t, sb, true, false, 300)

			ra := startReqAgent(t, bin, sb.envSlice())
			eventually(t, 15*time.Second, 50*time.Millisecond, "pg_dump started", func() error {
				b, err := os.ReadFile(sb.toolLog)
				if err != nil {
					return err
				}
				if !strings.Contains(string(b), "pg_dump") {
					return fmt.Errorf("pg_dump not yet started")
				}
				return nil
			})

			ra.stopAndWait(t)
			b, _ := os.ReadFile(sb.toolLog)
			if !strings.Contains(string(b), "rm -rf") && !strings.Contains(string(b), "rm -f") {
				t.Fatalf("SIGTERM during pg_dump skipped WithoutCancel rm cleanup:\n%s", string(b))
			}
		})

		t.Run("EtcdguardBackupDir0700AndTmp0600Rename", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE": "true",
				"NODE_HOST_AGENT_CONTROLLER_INTERVAL":      "500ms",
				"NODE_HOST_AGENT_ETCD_DB_SIZE_LIMIT":       "1000",
			})
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sb.k0s, "pki", "etcd", "ca.crt"), []byte("CA"), 0o644)
			backupDir := filepath.Join(sb.hostroot, "var", "backups", "etcd")
			_ = os.Chmod(backupDir, 0o755)

			installFakeTool(t, sb.k0s, filepath.Join("bin", "etcdctl"), fmt.Sprintf(`#!/bin/sh
echo "etcdctl $*" >> %q
case "$*" in
  *"endpoint status"*) echo '[{"Endpoint":"127.0.0.1:2379","Status":{"dbSize":2000,"dbSizeInUse":1500,"leader":1,"raftTerm":2,"version":"3.5.0"}}]' ;;
  *"alarm list"*) exit 0 ;;
  *"snapshot save "*)
    for last; do :; done
    echo "snapshot-save-target=$last" >> %q
    printf "ETCD_SNAP_BYTES" > "$last"
    chmod 0644 "$last"
    ;;
  *"snapshot status "*) exit 0 ;;
esac
exit 0
`, sb.toolLog, sb.toolLog))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 8*time.Second, 100*time.Millisecond, "etcdguard writes 0700 dir + .tmp -> 0600 rename", func() error {
				fi, err := os.Stat(backupDir)
				if err != nil {
					return err
				}
				if fi.Mode().Perm() != 0o700 {
					return fmt.Errorf("etcd backup dir mode=%v want 0700", fi.Mode().Perm())
				}
				snaps, _ := filepath.Glob(filepath.Join(backupDir, "premaint-*.db"))
				if len(snaps) == 0 {
					return fmt.Errorf("no premaint-*.db in %s", backupDir)
				}
				sfi, err := os.Stat(snaps[0])
				if err != nil {
					return err
				}
				if sfi.Mode().Perm() != 0o600 {
					return fmt.Errorf("snapshot mode=%v want 0600", sfi.Mode().Perm())
				}
				logBytes, _ := os.ReadFile(sb.toolLog)
				if !strings.Contains(string(logBytes), "snapshot-save-target=") || !strings.Contains(string(logBytes), ".tmp\n") {
					return fmt.Errorf("etcdctl snapshot save did not target .tmp file:\n%s", string(logBytes))
				}
				return nil
			})
			tmps, _ := filepath.Glob(filepath.Join(backupDir, "*.tmp"))
			if len(tmps) != 0 {
				t.Fatalf("leftover .tmp snapshot files: %v", tmps)
			}
		})

		t.Run("EtcdguardFailedVerifyRemovesTmpLeavesNoPremaint", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE": "true",
				"NODE_HOST_AGENT_CONTROLLER_INTERVAL":      "500ms",
				"NODE_HOST_AGENT_ETCD_DB_SIZE_LIMIT":       "1000",
			})
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sb.k0s, "pki", "etcd", "ca.crt"), []byte("CA"), 0o644)
			backupDir := filepath.Join(sb.hostroot, "var", "backups", "etcd")

			installFakeTool(t, sb.k0s, filepath.Join("bin", "etcdctl"), fmt.Sprintf(`#!/bin/sh
echo "etcdctl $*" >> %q
case "$*" in
  *"endpoint status"*) echo '[{"Endpoint":"127.0.0.1:2379","Status":{"dbSize":2000,"dbSizeInUse":1500,"leader":1,"raftTerm":2,"version":"3.5.0"}}]' ;;
  *"alarm list"*) exit 0 ;;
  *"snapshot save "*)
    for last; do :; done
    printf "BAD_SNAP" > "$last"
    ;;
  *"snapshot status "*) exit 1 ;;
esac
exit 0
`, sb.toolLog))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 8*time.Second, 100*time.Millisecond, "etcdguard records snapshot_error on verify failure", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_controllerhygiene_cycles_total", `check="etcd-quota"`, `result="snapshot_error"`)
				if !ok || v < 1 {
					return fmt.Errorf("snapshot_error ok=%v v=%v", ok, v)
				}
				return nil
			})
			snaps, _ := filepath.Glob(filepath.Join(backupDir, "premaint-*.db"))
			if len(snaps) != 0 {
				t.Fatalf("failed verification still published premaint snapshot: %v", snaps)
			}
			tmps, _ := filepath.Glob(filepath.Join(backupDir, "*.tmp"))
			if len(tmps) != 0 {
				t.Fatalf("failed verification leaked .tmp snapshot: %v", tmps)
			}
		})
	})

	t.Run("F13_CgroupThrottleSlashFreeSuspectKey", func(t *testing.T) {
		t.Run("CPUCFSThrottleCreatesSlashFreeSuspectFile", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			uid := "11111111-2222-3333-4444-555555555555"
			api.setNode(makeNode("f13-node-1", "10.244.0.0/24"))
			api.setPod(makePod("default", "throttled-pod", uid, "f13-node-1"))

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f13-node-1",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod11111111_2222_3333_4444_555555555555.slice")
			if err := os.MkdirAll(sliceDir, 0o755); err != nil {
				t.Fatal(err)
			}
			_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"), []byte("nr_periods 100\nnr_throttled 0\nthrottled_usec 0\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sb.proc, "stat"), []byte("cpu  100 0 100 1000 0 0 0 0\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			// Synchronize proc/stat + cpu.stat advances with actual cgroup-pod-throttle cycles.
			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			for i := 1; i <= 4; i++ {
				_ = os.WriteFile(filepath.Join(sb.proc, "stat"),
					[]byte(fmt.Sprintf("cpu  %d 0 100 %d 0 0 0 0\n", 100+i*10, 1000+i*100)), 0o644)
				_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"),
					[]byte(fmt.Sprintf("nr_periods %d\nnr_throttled %d\nthrottled_usec 1000\n", 100+i*100, i*80)), 0o644)
				ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			}

			suspectFile := filepath.Join(sb.state, "last-suspect-cgroup-cfs-"+uid)
			eventually(t, 6*time.Second, 100*time.Millisecond, "slash-free suspect file and event created", func() error {
				if _, err := os.Stat(suspectFile); err != nil {
					return fmt.Errorf("missing %s: %w", suspectFile, err)
				}
				for _, ev := range api.getEvents() {
					if ev.Reason == "PodCPUCFSThrottled" {
						return nil
					}
				}
				return fmt.Errorf("PodCPUCFSThrottled event not yet posted")
			})
			if strings.Contains(ra.logsCombined(), "ENOENT") || strings.Contains(ra.logsCombined(), "no such file or directory") {
				t.Fatalf("ENOENT error logged during SuspectLog:\n%s", ra.logsCombined())
			}
		})

		t.Run("CPUCFSThrottleLogRateLimitedAcrossCycles", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			uid := "11111111-2222-3333-4444-555555555556"
			api.setNode(makeNode("f13-node-2", "10.244.0.0/24"))
			api.setPod(makePod("default", "throttled-2", uid, "f13-node-2"))

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "300ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f13-node-2",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod11111111_2222_3333_4444_555555555556.slice")
			_ = os.MkdirAll(sliceDir, 0o755)
			_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"), []byte("nr_periods 100\nnr_throttled 0\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			// Synchronize on actual cycle boundaries: 3 delta cycles trigger suspect + 2 extra cycles verify rate-limiting.
			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			for i := 1; i <= 5; i++ {
				_ = os.WriteFile(filepath.Join(sb.proc, "stat"),
					[]byte(fmt.Sprintf("cpu  %d 0 100 %d 0 0 0 0\n", 100+i*10, 1000+i*100)), 0o644)
				_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"),
					[]byte(fmt.Sprintf("nr_periods %d\nnr_throttled %d\n", 100+i*100, i*80)), 0o644)
				ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			}

			suspectFile := filepath.Join(sb.state, "last-suspect-cgroup-cfs-"+uid)
			eventually(t, 6*time.Second, 100*time.Millisecond, "suspect file written", func() error {
				_, err := os.Stat(suspectFile)
				return err
			})
			logBytes, _ := os.ReadFile(sb.logFile)
			cnt := strings.Count(string(logBytes), "suspect: cgroup-pod-throttle pod uid="+uid+" cpu.stat")
			if cnt != 1 {
				t.Fatalf("expected rate-limited suspect log count=1, got %d in:\n%s", cnt, string(logBytes))
			}
		})

		t.Run("BurstableNestedSliceUIDExtracted", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			uid := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
			api.setNode(makeNode("f13-node-3", "10.244.0.0/24"))
			api.setPod(makePod("default", "burst-pod", uid, "f13-node-3"))

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "300ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f13-node-3",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-burstable.slice", "kubepods-burstable-podaaaaaaaa_bbbb_cccc_dddd_eeeeeeeeeeee.slice")
			_ = os.MkdirAll(sliceDir, 0o755)
			_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"), []byte("nr_periods 100\nnr_throttled 0\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			for i := 1; i <= 4; i++ {
				_ = os.WriteFile(filepath.Join(sb.proc, "stat"),
					[]byte(fmt.Sprintf("cpu  %d 0 100 %d 0 0 0 0\n", 100+i*10, 1000+i*100)), 0o644)
				_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"),
					[]byte(fmt.Sprintf("nr_periods %d\nnr_throttled %d\n", 100+i*100, i*80)), 0o644)
				ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			}

			suspectFile := filepath.Join(sb.state, "last-suspect-cgroup-cfs-"+uid)
			eventually(t, 6*time.Second, 100*time.Millisecond, "burstable slash-free suspect file", func() error {
				_, err := os.Stat(suspectFile)
				return err
			})
		})

		t.Run("ChildScopeCPUStatAttributedToPodUID", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			uid := "33333333-4444-5555-6666-777777777777"
			api.setNode(makeNode("f13-node-4", "10.244.0.0/24"))
			api.setPod(makePod("default", "scope-pod", uid, "f13-node-4"))

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "300ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f13-node-4",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod33333333_4444_5555_6666_777777777777.slice")
			scopeDir := filepath.Join(sliceDir, "cri-containerd-abc.scope")
			_ = os.MkdirAll(scopeDir, 0o755)
			_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"), []byte("nr_periods 100\nnr_throttled 0\n"), 0o644)
			_ = os.WriteFile(filepath.Join(scopeDir, "cpu.stat"), []byte("nr_periods 100\nnr_throttled 0\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			for i := 1; i <= 4; i++ {
				_ = os.WriteFile(filepath.Join(sb.proc, "stat"),
					[]byte(fmt.Sprintf("cpu  %d 0 100 %d 0 0 0 0\n", 100+i*10, 1000+i*100)), 0o644)
				_ = os.WriteFile(filepath.Join(scopeDir, "cpu.stat"),
					[]byte(fmt.Sprintf("nr_periods %d\nnr_throttled %d\n", 100+i*100, i*80)), 0o644)
				ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			}

			suspectFile := filepath.Join(sb.state, "last-suspect-cgroup-cfs-"+uid)
			eventually(t, 6*time.Second, 100*time.Millisecond, "child scope attributed to pod uid suspect file", func() error {
				_, err := os.Stat(suspectFile)
				return err
			})
		})

		t.Run("RecoveredSliceDropsStreakWithoutSuspect", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			uid := "44444444-5555-6666-7777-888888888888"
			api.setNode(makeNode("f13-node-5", "10.244.0.0/24"))
			api.setPod(makePod("default", "recover-pod", uid, "f13-node-5"))

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f13-node-5",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod44444444_5555_6666_7777_888888888888.slice")
			_ = os.MkdirAll(sliceDir, 0o755)
			_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"), []byte("nr_periods 100\nnr_throttled 0\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			// Synchronize on cycle boundaries: 2 throttled deltas (<3), then 3 flat cycles.
			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			for i := 1; i <= 2; i++ {
				_ = os.WriteFile(filepath.Join(sb.proc, "stat"),
					[]byte(fmt.Sprintf("cpu  %d 0 100 %d 0 0 0 0\n", 100+i*10, 1000+i*100)), 0o644)
				_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"),
					[]byte(fmt.Sprintf("nr_periods %d\nnr_throttled %d\n", 100+i*100, i*80)), 0o644)
				ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			}
			for i := 3; i <= 5; i++ {
				_ = os.WriteFile(filepath.Join(sb.proc, "stat"),
					[]byte(fmt.Sprintf("cpu  %d 0 100 %d 0 0 0 0\n", 100+i*10, 1000+i*100)), 0o644)
				_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"),
					[]byte(fmt.Sprintf("nr_periods %d\nnr_throttled 160\n", 100+i*100)), 0o644)
				ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			}

			if _, err := os.Stat(filepath.Join(sb.state, "last-suspect-cgroup-cfs-"+uid)); !os.IsNotExist(err) {
				t.Fatalf("suspect file created despite <3 consecutive throttled cycles")
			}
		})
	})

	t.Run("F19_PerfMemoryAndCiliumUnixSocket", func(t *testing.T) {
		t.Run("CiliumUnixSocketEndpointInitStuckAndRecovery", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f19-node-1", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":        "true",
				"NODE_HOST_AGENT_ENABLE_HOSTMETRICS":    "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL":      "350ms",
				"NODE_HOST_AGENT_HYGIENE_CONSEC_NEEDED": "2",
				"NODE_HOST_AGENT_LATCH_INTERVAL":        "200ms",
				"NODE_HOST_AGENT_NODE_NAME":             "f19-node-1",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			taskDir := filepath.Join(sb.ctrTaskRoot, strings.Repeat("1", 64))
			_ = os.MkdirAll(taskDir, 0o755)
			_ = os.WriteFile(filepath.Join(taskDir, "config.json"),
				[]byte(`{"annotations":{"io.kubernetes.pod.uid":"11111111-1111-1111-1111-111111111111","io.kubernetes.container.name":"cilium-agent"}}`), 0o644)
			_ = os.WriteFile(filepath.Join(taskDir, "init.pid"), []byte("0\n"), 0o644)

			var stuck atomic.Bool
			stuck.Store(true)
			sb.envMap["NODE_HOST_AGENT_CILIUM_SOCKET"] = startMockCiliumUnixServer(t, sb.envMap["NODE_HOST_AGENT_CILIUM_SOCKET"], func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/endpoint" {
					if stuck.Load() {
						_, _ = w.Write([]byte(`[{"id":1,"status":{"identity":{"labels":["reserved:init"]}}}]`))
					} else {
						_, _ = w.Write([]byte(`[{"id":1,"status":{"identity":{"labels":["k8s:app=ok"]}}}]`))
					}
					return
				}
				_, _ = w.Write([]byte(`{}`))
			})

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 8*time.Second, 100*time.Millisecond, "cilium-init-stuck latched", func() error {
				if _, err := os.Stat(filepath.Join(sb.state, "state-cilium-init-stuck")); err != nil {
					return err
				}
				m := ra.scrapeMetrics(t)
				v, ok := parseMetricValue(m, "node_host_agent_watchdog_state", `state="cilium-init-stuck"`)
				if !ok || v != 1 {
					return fmt.Errorf("watchdog_state cilium-init-stuck ok=%v v=%v", ok, v)
				}
				return nil
			})

			stuck.Store(false)
			eventually(t, 12*time.Second, 150*time.Millisecond, "cilium-init-stuck cleared on recovery", func() error {
				if _, err := os.Stat(filepath.Join(sb.state, "state-cilium-init-stuck")); !os.IsNotExist(err) {
					return fmt.Errorf("state-cilium-init-stuck still on disk")
				}
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_watchdog_state", `state="cilium-init-stuck"`)
				if !ok || v != 0 {
					return fmt.Errorf("watchdog_state cilium-init-stuck still %v (ok=%v)", v, ok)
				}
				return nil
			})
		})

		t.Run("CiliumUnixSocketHealthzAndService", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f19-node-2", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":     "true",
				"NODE_HOST_AGENT_ENABLE_NETHEALTH":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL":   "400ms",
				"NODE_HOST_AGENT_NETHEALTH_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":          "f19-node-2",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			taskDir := filepath.Join(sb.ctrTaskRoot, strings.Repeat("2", 64))
			_ = os.MkdirAll(taskDir, 0o755)
			_ = os.WriteFile(filepath.Join(taskDir, "config.json"),
				[]byte(`{"annotations":{"io.kubernetes.pod.uid":"22222222-2222-2222-2222-222222222222","io.kubernetes.container.name":"cilium-agent"}}`), 0o644)
			_ = os.WriteFile(filepath.Join(taskDir, "init.pid"), []byte("0\n"), 0o644)

			var healthzHits atomic.Int64
			sb.envMap["NODE_HOST_AGENT_CILIUM_SOCKET"] = startMockCiliumUnixServer(t, sb.envMap["NODE_HOST_AGENT_CILIUM_SOCKET"], func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/healthz" {
					healthzHits.Add(1)
				}
				_, _ = w.Write([]byte(`[]`))
			})

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "cilium unix socket queried repeatedly", func() error {
				if healthzHits.Load() < 3 {
					return fmt.Errorf("healthzHits=%d", healthzHits.Load())
				}
				return nil
			})
		})

		t.Run("APIProberNon200DrainAndRecovery", func(t *testing.T) {
			t.Parallel()
			var fail atomic.Bool
			fail.Store(true)
			bigBody := strings.Repeat("X", 128*1024)
			srv, _, _, _ := newSelfSignedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if fail.Load() {
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte(bigBody))
					return
				}
				_, _ = w.Write([]byte(`{"metadata":{"resourceVersion":"42"}}`))
			}))
			backendAddr := strings.TrimPrefix(srv.URL, "https://")

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_APIPROBER":       "true",
				"NODE_HOST_AGENT_APIPROBER_INTERVAL":     "300ms",
				"NODE_HOST_AGENT_APIPROBER_MODE":         "dry-run",
				"NODE_HOST_AGENT_APIPROBER_INSECURE_TLS": "true",
				"NODE_HOST_AGENT_APIPROBER_BACKEND":      "api_local_back",
			})
			tokFile := filepath.Join(sb.root, "token")
			_ = os.WriteFile(tokFile, []byte("e2e-token"), 0o600)
			sb.envMap["NODE_HOST_AGENT_APIPROBER_TOKEN_FILE"] = tokFile
			sb.envMap["NODE_HOST_AGENT_APIPROBER_SOCKET"] = startMockHAProxyUnixSocket(t, sb.envMap["NODE_HOST_AGENT_APIPROBER_SOCKET"], "api_local_back", "ctrl1", backendAddr)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "apiprober drains 503 bodies", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_apiprober_cycles_total")
				if !ok || v < 2 {
					return fmt.Errorf("apiprober cycles ok=%v v=%v", ok, v)
				}
				return nil
			})
			fail.Store(false)
			eventually(t, 6*time.Second, 100*time.Millisecond, "apiprober recovers on 200", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_apiprober_cycles_total", `result="ok"`)
				if !ok || v < 1 {
					return fmt.Errorf("apiprober ok=%v v=%v", ok, v)
				}
				return nil
			})
		})

		t.Run("MountinfoOctalUnescapeAndInotifySharedFDCache", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f19-node-4", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":     "true",
				"NODE_HOST_AGENT_ENABLE_HOSTMETRICS": "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL":   "400ms",
				"NODE_HOST_AGENT_NODE_NAME":          "f19-node-4",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			mountLine := "101 1 8:1 / /var/lib/my\\040mount\\011tab\\134slash rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_MOUNTINFO_FILE"], []byte(mountLine), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "inotify-pressure and mountinfo checks run", func() error {
				m := ra.scrapeMetrics(t)
				v1, ok1 := parseMetricValue(m, "node_host_agent_workerhygiene_cycles_total", `check="inotify-pressure-hygiene"`)
				v2, ok2 := parseMetricValue(m, "node_host_agent_workerhygiene_cycles_total", `check="mountinfo-hygiene"`)
				if !ok1 || v1 < 1 || !ok2 || v2 < 1 {
					return fmt.Errorf("inotify(%v,%v) mount(%v,%v)", ok1, v1, ok2, v2)
				}
				return nil
			})
		})

		t.Run("MultiSubsystemNoSyncAndWatchdogCollectSkip", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f19-node-5", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTMETRICS": "true",
				"NODE_HOST_AGENT_ENABLE_NETHEALTH":   "true",
				"NODE_HOST_AGENT_ENABLE_HYGIENE":     "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL":   "300ms",
				"NODE_HOST_AGENT_NETHEALTH_INTERVAL": "300ms",
				"NODE_HOST_AGENT_NODE_NAME":          "f19-node-5",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 8*time.Second, 100*time.Millisecond, "5+ rapid cycles across subsystems", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="mountinfo-hygiene"`)
				if !ok || v < 4 {
					return fmt.Errorf("workerhygiene cycles=%v", v)
				}
				return nil
			})
			start := time.Now()
			_ = ra.scrapeMetrics(t)
			if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
				t.Fatalf("/metrics scrape took %v > 500ms", elapsed)
			}
		})
	})

	t.Run("F20_CIPipelineAndDockerfile", func(t *testing.T) {
		t.Run("CiYmlConsumerMappingContract", func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "go", "test", "-race", "-run", "TestDockerDetectMappingMatchesDeps", "./internal/releaseglob")
			cmd.Dir = filepath.Join("..", "..")
			cmd.Env = append(os.Environ(), "GOWORK=off")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("TestDockerDetectMappingMatchesDeps failed: %v\n%s", err, out)
			}
		})

		t.Run("CiYmlMiseTomlContract", func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "go", "test", "-race", "-run", "TestMiseTomlConsumers", "./internal/releaseglob")
			cmd.Dir = filepath.Join("..", "..")
			cmd.Env = append(os.Environ(), "GOWORK=off")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("TestMiseTomlConsumers failed: %v\n%s", err, out)
			}
		})

		t.Run("HadolintDockerfileClean", func(t *testing.T) {
			t.Parallel()
			dfPath := filepath.Join("..", "..", "Dockerfile")
			b, err := os.ReadFile(dfPath)
			if err != nil {
				t.Fatal(err)
			}
			content := string(b)
			if !regexp.MustCompile(`(?im)^\s*FROM\s+(?:--platform=\S+\s+)?golang:1\.27\.4-alpine(?:\s|$)`).MatchString(content) {
				t.Fatalf("Dockerfile missing golang:1.27.4-alpine builder:\n%s", content)
			}
			if !strings.Contains(content, "ENV GOWORK=off") {
				t.Fatalf("Dockerfile missing ENV GOWORK=off")
			}
			if !strings.Contains(content, "GOOS=${TARGETOS}") || !strings.Contains(content, "GOARCH=${TARGETARCH}") {
				t.Fatalf("Dockerfile missing GOOS/GOARCH cross-build flags")
			}
			if !strings.Contains(content, "CGO_ENABLED=0") {
				t.Fatalf("Dockerfile missing CGO_ENABLED=0")
			}
			if !strings.Contains(content, "USER 65532:65532") {
				t.Fatalf("Dockerfile missing non-root USER 65532:65532")
			}
			if !strings.Contains(content, "tini") {
				t.Fatalf("Dockerfile missing tini entrypoint")
			}
			if hadolint, err := exec.LookPath("hadolint"); err == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, hadolint, dfPath)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("hadolint failed: %v\n%s", err, out)
				}
			}
		})

		t.Run("GoWorkSyncInvariants", func(t *testing.T) {
			t.Parallel()
			gm, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(gm), "go 1.27.4") {
				t.Fatalf("go.mod missing go 1.27.4")
			}
			if !strings.Contains(string(gm), "replace github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit => ../../libs/hostkit") {
				t.Fatalf("go.mod missing hostkit replace directive")
			}
			gw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "go.work"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(gw), "./apps/node-host-agent") {
				t.Fatalf("go.work missing ./apps/node-host-agent")
			}
		})

		t.Run("MoonYamlTaskInputsContract", func(t *testing.T) {
			t.Parallel()
			b, err := os.ReadFile(filepath.Join("..", "..", "moon.yml"))
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Tasks map[string]struct {
					Inputs []string `yaml:"inputs"`
				} `yaml:"tasks"`
			}
			if err := yaml.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}
			for _, task := range []string{"test", "vet", "lint", "build", "envdoc"} {
				if _, ok := doc.Tasks[task]; !ok {
					t.Fatalf("moon.yml missing task %q", task)
				}
			}
			if !slices.Contains(doc.Tasks["test"].Inputs, "/libs/hostkit/**/*.go") {
				t.Fatalf("moon.yml test task missing /libs/hostkit/**/*.go input: %v", doc.Tasks["test"].Inputs)
			}
		})
	})

	t.Run("F23_Smoke", func(t *testing.T) {
		t.Run("SystemdOOMDKillDetectedFromJournal", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f23-node-1", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":     "true",
				"NODE_HOST_AGENT_ENABLE_HOSTMETRICS": "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL":   "350ms",
				"NODE_HOST_AGENT_LATCH_INTERVAL":     "200ms",
				"NODE_HOST_AGENT_NODE_NAME":          "f23-node-1",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			tsUs := time.Now().UnixMicro()
			jline, _ := json.Marshal(map[string]any{
				"__CURSOR":             "c1",
				"__REALTIME_TIMESTAMP": strconv.FormatInt(tsUs, 10),
				"_SYSTEMD_UNIT":        "systemd-oomd.service",
				"MESSAGE":              "Killed process 999 in kubepods-pod123.slice",
			})
			installFakeTool(t, sb.fakebin, "journalctl", fmt.Sprintf("#!/bin/sh\necho '%s'\nexit 0\n", string(jline)))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 12*time.Second, 100*time.Millisecond, "systemd-oomd kill latched", func() error {
				if _, err := os.Stat(filepath.Join(sb.state, "state-systemd-oomd-kill")); err != nil {
					return err
				}
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_watchdog_state", `state="systemd-oomd-kill"`)
				if !ok || v != 1 {
					return fmt.Errorf("watchdog_state systemd-oomd-kill ok=%v v=%v", ok, v)
				}
				return nil
			})
		})

		t.Run("NetfilterLockHeldFor3CyclesLatches", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f23-node-2", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":                   "true",
				"NODE_HOST_AGENT_ENABLE_HOSTMETRICS":               "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL":                 "300ms",
				"NODE_HOST_AGENT_LATCH_INTERVAL":                   "200ms",
				"NODE_HOST_AGENT_NETFILTER_GUARD_INTERVAL_SECONDS": "1",
				"NODE_HOST_AGENT_NODE_NAME":                        "f23-node-2",
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
			if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
				_ = lf.Close()
			})

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 12*time.Second, 100*time.Millisecond, "netfilter-locked latch after 3 held cycles", func() error {
				if _, err := os.Stat(filepath.Join(sb.state, "state-netfilter-locked")); err != nil {
					return err
				}
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_watchdog_state", `state="netfilter-locked"`)
				if !ok || v != 1 {
					return fmt.Errorf("watchdog_state netfilter-locked ok=%v v=%v", ok, v)
				}
				return nil
			})
		})

		t.Run("NetfilterLegacyRulesCounted", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f23-node-3", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":                     "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL":                   "350ms",
				"NODE_HOST_AGENT_NETFILTER_GUARD_INTERVAL_SECONDS":   "1",
				"NODE_HOST_AGENT_NETFILTER_GUARD_LEGACY_TABLE_PROBE": "true",
				"NODE_HOST_AGENT_NODE_NAME":                          "f23-node-3",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sb.proc, "1", "net", "ip_tables_names"), []byte("filter\n"), 0o644)
			installFakeTool(t, sb.fakebin, "iptables-legacy-save", "#!/bin/sh\necho '*filter'\necho '-A INPUT -j ACCEPT'\necho '-A FORWARD -j DROP'\necho 'COMMIT'\n")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			promFile := filepath.Join(sb.textfile, "node-agent-hygiene.prom")
			eventually(t, 8*time.Second, 100*time.Millisecond, "node_agent_iptables_legacy_leaked_rules 2 emitted", func() error {
				b, err := os.ReadFile(promFile)
				if err != nil {
					return err
				}
				v, ok := parseMetricValue(string(b), "node_agent_iptables_legacy_leaked_rules")
				if !ok || v != 2 {
					return fmt.Errorf("leaked rules ok=%v v=%v in:\n%s", ok, v, string(b))
				}
				return nil
			})
		})

		t.Run("CSI", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f23-node-4", "10.244.0.0/24"))
			api.setCSINode(&storagev1.CSINode{
				ObjectMeta: metav1.ObjectMeta{Name: "f23-node-4"},
				Spec: storagev1.CSINodeSpec{
					Drivers: []storagev1.CSINodeDriver{{Name: "csi.io", NodeID: "f23-node-4"}},
				},
			})

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f23-node-4",
			})
			csiBase := sb.root
			if len(filepath.Join(sb.root, "plugins_registry", "csi.io-reg.sock")) >= 95 {
				var err error
				csiBase, err = os.MkdirTemp(shortTempBase(), "csi-")
				if err != nil {
					t.Fatalf("mkdtemp csi dir: %v", err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(csiBase) })
			}
			shortPods := filepath.Join(csiBase, "p")
			shortReg := filepath.Join(csiBase, "plugins_registry")
			_ = os.MkdirAll(shortPods, 0o755)
			_ = os.MkdirAll(shortReg, 0o755)
			sb.envMap["NODE_HOST_AGENT_KUBELET_PODS_DIR"] = shortPods

			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			sockPath := filepath.Join(shortReg, "csi.io-reg.sock")
			ln, _ := listenShortUnixSocket(t, sockPath)
			t.Cleanup(func() { _ = ln.Close() })

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "csi-registration-guard completes ok", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="csi-registration-guard"`, `result="ok"`)
				if !ok || v < 1 {
					return fmt.Errorf("csi-registration-guard ok=%v v=%v", ok, v)
				}
				return nil
			})
		})

		t.Run("DiskBloatAndNetlinkxMetricsSmoke", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f23-node-5", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":     "true",
				"NODE_HOST_AGENT_ENABLE_HOSTMETRICS": "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL":   "400ms",
				"NODE_HOST_AGENT_NODE_NAME":          "f23-node-5",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			// mountinfo-hygiene genuinely reads NODE_HOST_AGENT_MOUNTINFO_FILE.
			// Note: disk-bloat's K0sDataDir (/host/var/lib/k0s) has no env override, so it
			// reports result="abort" when /host/var/lib/k0s is absent and result="ok" when present.
			mountLine := fmt.Sprintf("10 1 8:1 / %s/mnt1 rw,relatime - ext4 /dev/sda1 rw\n", sb.root)
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_MOUNTINFO_FILE"], []byte(mountLine), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			_, k0sErr := os.Stat("/host/var/lib/k0s")
			wantDiskBloatResult := `result="ok"`
			if k0sErr != nil {
				wantDiskBloatResult = `result="abort"`
			}

			// Determine whether netlinkx.TCPTables(1) can run in this process's privilege/netns posture.
			canReadPid1NetNS := false
			if selfFI, sErr := os.Stat("/proc/self/ns/net"); sErr == nil {
				if p1FI, pErr := os.Stat("/proc/1/ns/net"); pErr == nil && os.SameFile(selfFI, p1FI) {
					canReadPid1NetNS = true
				}
			}
			if !canReadPid1NetNS {
				if f, oErr := os.Open("/proc/1/ns/net"); oErr == nil {
					_ = f.Close()
					canReadPid1NetNS = true
				}
			}

			eventually(t, 6*time.Second, 100*time.Millisecond, "workerhygiene disk/mountinfo/ephemeral-ports and hostmetrics exported", func() error {
				m := ra.scrapeMetrics(t)
				if v, ok := parseMetricValue(m, "node_host_agent_workerhygiene_cycles_total", `check="mountinfo-hygiene"`, `result="ok"`); !ok || v < 1 {
					return fmt.Errorf("mountinfo-hygiene ok=(%v,%v)", ok, v)
				}
				if v, ok := parseMetricValue(m, "node_host_agent_workerhygiene_cycles_total", `check="writable-layer-scan"`, `result="ok"`); !ok || v < 1 {
					return fmt.Errorf("writable-layer-scan ok=(%v,%v)", ok, v)
				}
				if v, ok := parseMetricValue(m, "node_host_agent_workerhygiene_cycles_total", `check="disk-bloat"`, wantDiskBloatResult); !ok || v < 1 {
					return fmt.Errorf("disk-bloat %s ok=(%v,%v)", wantDiskBloatResult, ok, v)
				}
				if canReadPid1NetNS {
					if v, ok := parseMetricValue(m, "node_host_agent_workerhygiene_cycles_total", `check="ephemeral-port-pressure"`, `result="ok"`); !ok || v < 1 {
						return fmt.Errorf("ephemeral-port-pressure ok=(%v,%v)", ok, v)
					}
					if _, ok := parseMetricValue(m, "node_host_agent_sockstat_tcp_state_sockets"); !ok {
						return fmt.Errorf("missing node_host_agent_sockstat_tcp_state_sockets despite accessible pid1 netns")
					}
				} else {
					if v, ok := parseMetricValue(m, "node_host_agent_workerhygiene_cycles_total", `check="ephemeral-port-pressure"`, `result="inconclusive"`); !ok || v < 1 {
						return fmt.Errorf("ephemeral-port-pressure inconclusive=(%v,%v)", ok, v)
					}
				}
				if _, ok := parseMetricValue(m, "node_host_agent_mountinfo_entries_count"); !ok {
					return fmt.Errorf("missing node_host_agent_mountinfo_entries_count")
				}
				if _, ok := parseMetricValue(m, "node_host_agent_sockstat_tcp_inuse"); !ok {
					return fmt.Errorf("missing node_host_agent_sockstat_tcp_inuse")
				}
				return nil
			})
		})
	})

	t.Run("F24_CgroupMemoryHighAndPSI", func(t *testing.T) {
		t.Run("MemoryHighAndFullPSIEmitsEventAndMetric", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			uid := "55555555-1111-2222-3333-444444444444"
			api.setNode(makeNode("f24-node-1", "10.244.0.0/24"))
			api.setPod(makePod("default", "mem-pod-1", uid, "f24-node-1"))

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "300ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f24-node-1",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod55555555_1111_2222_3333_444444444444.slice")
			_ = os.MkdirAll(sliceDir, 0o755)
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.pressure"),
				[]byte("some avg10=50.00 avg60=45.00 avg300=10.00 total=100\nfull avg10=60.00 avg60=55.00 avg300=20.00 total=100\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"), []byte("low 0\nhigh 10\nmax 0\noom 0\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			for i := 1; i <= 5; i++ {
				_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"),
					[]byte(fmt.Sprintf("low 0\nhigh %d\nmax 0\noom 0\n", 10+i*10)), 0o644)
				ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			}

			eventually(t, 6*time.Second, 100*time.Millisecond, "PodMemoryHighThrottled event and prom series", func() error {
				b, err := os.ReadFile(filepath.Join(sb.textfile, "node-agent-hygiene.prom"))
				if err != nil {
					return err
				}
				v, ok := parseMetricValue(string(b), "node_agent_pod_cgroup_memory_throttled")
				if !ok || v < 1 {
					return fmt.Errorf("memory_throttled ok=%v v=%v", ok, v)
				}
				for _, ev := range api.getEvents() {
					if ev.Reason == "PodMemoryHighThrottled" {
						return nil
					}
				}
				return fmt.Errorf("missing PodMemoryHighThrottled event")
			})
		})

		t.Run("SomePSIAndMemoryEventsMaxDetected", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			uid := "55555555-2222-3333-4444-555555555555"
			api.setNode(makeNode("f24-node-2", "10.244.0.0/24"))
			api.setPod(makePod("default", "mem-pod-2", uid, "f24-node-2"))

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "300ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f24-node-2",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod55555555_2222_3333_4444_555555555555.slice")
			_ = os.MkdirAll(sliceDir, 0o755)
			// K1: high `some` PSI + `memory.events:max` incrementing even when `full avg60` is low (10.0) and `high` is 0.
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.pressure"),
				[]byte("some avg10=75.00 avg60=65.00 avg300=40.00 total=500\nfull avg10=12.00 avg60=10.00 avg300=5.00 total=100\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"), []byte("low 0\nhigh 0\nmax 10\noom 0\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			for i := 1; i <= 5; i++ {
				_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"),
					[]byte(fmt.Sprintf("low 0\nhigh 0\nmax %d\noom 0\n", 10+i*10)), 0o644)
				ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			}

			eventually(t, 6*time.Second, 100*time.Millisecond, "K1 detects some PSI + memory.events:max starvation", func() error {
				b, err := os.ReadFile(filepath.Join(sb.textfile, "node-agent-hygiene.prom"))
				if err != nil {
					return err
				}
				v, ok := parseMetricValue(string(b), "node_agent_pod_cgroup_memory_throttled")
				if !ok || v < 1 {
					return fmt.Errorf("K1 memory_throttled ok=%v v=%v", ok, v)
				}
				for _, ev := range api.getEvents() {
					if ev.Reason == "PodMemoryHighThrottled" {
						return nil
					}
				}
				return fmt.Errorf("K1 PodMemoryHighThrottled event not emitted for some PSI + max delta")
			})
		})

		t.Run("ConsecutiveCycleGatingPreventsSingleSpike", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			uid := "55555555-3333-4444-5555-666666666666"
			api.setNode(makeNode("f24-node-3", "10.244.0.0/24"))
			api.setPod(makePod("default", "mem-pod-3", uid, "f24-node-3"))

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f24-node-3",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod55555555_3333_4444_5555_666666666666.slice")
			_ = os.MkdirAll(sliceDir, 0o755)
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.pressure"),
				[]byte("some avg10=60.00 avg60=55.00 avg300=20.00 total=100\nfull avg10=60.00 avg60=55.00 avg300=20.00 total=100\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"), []byte("low 0\nhigh 10\nmax 0\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			// Wait for baseline cycle 1, bump high ONCE for cycle 2, then keep high constant and PSI low.
			eventually(t, 4*time.Second, 50*time.Millisecond, "cycle 1 complete", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="cgroup-pod-throttle"`)
				if !ok || v < 1 {
					return fmt.Errorf("waiting cycle 1")
				}
				return nil
			})
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"), []byte("low 0\nhigh 25\nmax 0\n"), 0o644)
			eventually(t, 4*time.Second, 50*time.Millisecond, "cycle 2 complete", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="cgroup-pod-throttle"`)
				if !ok || v < 2 {
					return fmt.Errorf("waiting cycle 2")
				}
				return nil
			})
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.pressure"),
				[]byte("some avg10=1.00 avg60=1.00 avg300=1.00 total=100\nfull avg10=1.00 avg60=1.00 avg300=1.00 total=100\n"), 0o644)
			eventually(t, 4*time.Second, 50*time.Millisecond, "cycle 4 complete", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="cgroup-pod-throttle"`)
				if !ok || v < 4 {
					return fmt.Errorf("waiting cycle 4")
				}
				return nil
			})

			for _, ev := range api.getEvents() {
				if ev.Reason == "PodMemoryHighThrottled" {
					t.Fatalf("single-cycle spike falsely emitted PodMemoryHighThrottled (missing K1 consecutive-cycle gating)")
				}
			}
		})

		t.Run("NonThrottleRecoveryRearmsEpisode", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			uid := "55555555-4444-5555-6666-777777777777"
			api.setNode(makeNode("f24-node-4", "10.244.0.0/24"))
			api.setPod(makePod("default", "mem-pod-4", uid, "f24-node-4"))

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "250ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f24-node-4",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod55555555_4444_5555_6666_777777777777.slice")
			_ = os.MkdirAll(sliceDir, 0o755)
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.pressure"),
				[]byte("some avg10=60.00 avg60=55.00 total=100\nfull avg10=60.00 avg60=55.00 total=100\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"), []byte("high 10\nmax 0\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			// Episode 1: synchronize memory.events increments with cycle boundaries.
			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			for i := 1; i <= 4; i++ {
				_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"),
					[]byte(fmt.Sprintf("high %d\nmax 0\n", 10+i*10)), 0o644)
				ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			}
			eventually(t, 5*time.Second, 100*time.Millisecond, "episode 1 event", func() error {
				if len(api.getEvents()) < 1 {
					return fmt.Errorf("no event yet")
				}
				return nil
			})
			// Recovery: hold low PSI for >= 2 full cycles so episode re-arms cleanly.
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.pressure"),
				[]byte("some avg10=0.00 avg60=0.00 total=100\nfull avg10=0.00 avg60=0.00 total=100\n"), 0o644)
			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)

			// Episode 2: synchronize high PSI + memory.events increments across cycle boundaries.
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.pressure"),
				[]byte("some avg10=60.00 avg60=55.00 total=100\nfull avg10=60.00 avg60=55.00 total=100\n"), 0o644)
			for i := 5; i <= 9; i++ {
				_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"),
					[]byte(fmt.Sprintf("high %d\nmax 0\n", 10+i*10)), 0o644)
				ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			}
			eventually(t, 6*time.Second, 100*time.Millisecond, "episode 2 rearmed event", func() error {
				cnt := 0
				for _, ev := range api.getEvents() {
					if ev.Reason == "PodMemoryHighThrottled" {
						cnt++
					}
				}
				if cnt < 2 {
					return fmt.Errorf("expected >=2 PodMemoryHighThrottled events across 2 episodes, got %d", cnt)
				}
				return nil
			})
		})

		t.Run("FlatCounterWithHighPSIDoesNotFire", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			uid := "55555555-5555-6666-7777-888888888888"
			api.setNode(makeNode("f24-node-5", "10.244.0.0/24"))
			api.setPod(makePod("default", "mem-pod-5", uid, "f24-node-5"))

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "300ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f24-node-5",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod55555555_5555_6666_7777_888888888888.slice")
			_ = os.MkdirAll(sliceDir, 0o755)
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.pressure"),
				[]byte("some avg10=80.00 avg60=70.00 total=100\nfull avg10=80.00 avg60=70.00 total=100\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"), []byte("high 500\nmax 500\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "3+ cycles run", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="cgroup-pod-throttle"`, `result="ok"`)
				if !ok || v < 3 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
			if len(api.getEvents()) != 0 {
				t.Fatalf("flat counters unexpectedly emitted events: %+v", api.getEvents())
			}
		})
	})

	t.Run("F26_ContainerdShimStaleMount", func(t *testing.T) {
		t.Run("DeadPodMountinfoPinnedByPidDetectedAndRemediated", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f26-node-1", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":     "true",
				"NODE_HOST_AGENT_ENABLE_HOSTMETRICS": "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL":   "350ms",
				"NODE_HOST_AGENT_NODE_NAME":          "f26-node-1",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			deadUID := "dead0000-1111-2222-3333-444444444444"
			deadMount := filepath.Join(sb.kubeletPods, deadUID, "volumes", "kubernetes.io~empty-dir", "cache")
			_ = os.MkdirAll(deadMount, 0o755)
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_MOUNTINFO_FILE"],
				[]byte(fmt.Sprintf("201 1 8:1 / %s rw,relatime - tmpfs tmpfs rw\n", deadMount)), 0o644)

			_, liveInitPID := spawnDummySleep(t, 60)
			sid := strings.Repeat("d", 64)
			writeLiveCtrTaskDir(t, sb.ctrTaskRoot, sid, liveInitPID)
			_, pinPID := spawnDummySleep(t, 60)
			writeProcTask(t, sb.proc, pinPID, "containerd-shim", "S", 0,
				"0::/system.slice/k0sworker.service\n",
				[]string{"containerd-shim-runc-v2", "-namespace", "k8s.io", "-id", sid, "-address", sb.envMap["NODE_HOST_AGENT_CONTAINERD_SOCKET"]},
				10*time.Minute)
			_ = os.WriteFile(filepath.Join(sb.proc, strconv.Itoa(pinPID), "mountinfo"),
				[]byte(fmt.Sprintf("201 1 8:1 / %s rw,relatime - tmpfs tmpfs rw\n", deadMount)), 0o644)
			_ = os.Symlink(deadMount, filepath.Join(sb.proc, strconv.Itoa(pinPID), "fd", "4"))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 7*time.Second, 100*time.Millisecond, "K3 EBUSY mount-namespace wedge detected", func() error {
				logBytes, _ := os.ReadFile(sb.logFile)
				cleanedLog := strings.ToLower(strings.ReplaceAll(string(logBytes), sb.root, ""))
				toolBytes, _ := os.ReadFile(sb.toolLog)
				m := ra.scrapeMetrics(t)
				if strings.Contains(cleanedLog, "ebusy") ||
					(strings.Contains(cleanedLog, "mount") && strings.Contains(cleanedLog, strings.ToLower(deadUID))) ||
					strings.Contains(string(toolBytes), "umount") ||
					!pidAlive(pinPID) ||
					strings.Contains(m, "ebusy") {
					return nil
				}
				return fmt.Errorf("K3 EBUSY wedge not yet detected/acted upon")
			})
		})

		t.Run("LivePodMountNotTouched", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			liveUID := "1111dead-1111-2222-3333-444444444444"
			api.setNode(makeNode("f26-node-2", "10.244.0.0/24"))
			api.setPod(makePod("default", "live-pod", liveUID, "f26-node-2"))

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "350ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f26-node-2",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			liveMount := filepath.Join(sb.kubeletPods, liveUID, "volumes", "kubernetes.io~empty-dir", "data")
			_ = os.MkdirAll(liveMount, 0o755)
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_MOUNTINFO_FILE"],
				[]byte(fmt.Sprintf("202 1 8:1 / %s rw,relatime - tmpfs tmpfs rw\n", liveMount)), 0o644)

			_, pinPID := spawnDummySleep(t, 60)
			sid := strings.Repeat("e", 64)
			writeProcTask(t, sb.proc, pinPID, "containerd-shim", "S", 0,
				"0::/system.slice/k0sworker.service\n",
				[]string{"containerd-shim-runc-v2", "-namespace", "k8s.io", "-id", sid, "-address", sb.envMap["NODE_HOST_AGENT_CONTAINERD_SOCKET"]},
				10*time.Minute)
			_ = os.WriteFile(filepath.Join(sb.proc, strconv.Itoa(pinPID), "mountinfo"),
				[]byte(fmt.Sprintf("202 1 8:1 / %s rw,relatime - tmpfs tmpfs rw\n", liveMount)), 0o644)
			_ = os.Symlink(liveMount, filepath.Join(sb.proc, strconv.Itoa(pinPID), "fd", "4"))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "3 hygiene cycles run", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="mountinfo-hygiene"`)
				if !ok || v < 3 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
			toolBytes, _ := os.ReadFile(sb.toolLog)
			if strings.Contains(string(toolBytes), liveMount) {
				t.Fatalf("live pod mount was touched: %s", string(toolBytes))
			}
		})

		t.Run("DeadPodUnpinnedStaleMountOnly", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f26-node-3", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "350ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f26-node-3",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			deadUID := "dead0001-1111-2222-3333-444444444444"
			deadMount := filepath.Join(sb.kubeletPods, deadUID, "volumes", "kubernetes.io~empty-dir", "cache")
			_ = os.MkdirAll(deadMount, 0o755)
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_MOUNTINFO_FILE"],
				[]byte(fmt.Sprintf("203 1 8:1 / %s rw,relatime - tmpfs tmpfs rw\n", deadMount)), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "3 hygiene cycles without pinning PID", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="mountinfo-hygiene"`)
				if !ok || v < 3 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
			logBytes, _ := os.ReadFile(sb.logFile)
			cleanedLog := strings.ToLower(strings.ReplaceAll(string(logBytes), sb.root, ""))
			if strings.Contains(cleanedLog, "ebusy") {
				t.Fatalf("unexpected EBUSY escalation when no PID pins dead pod mount:\n%s", string(logBytes))
			}
		})

		t.Run("MultiCyclePersistenceBeforeEscalation", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f26-node-4", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":        "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL":      "350ms",
				"NODE_HOST_AGENT_HYGIENE_CONSEC_NEEDED": "3",
				"NODE_HOST_AGENT_NODE_NAME":             "f26-node-4",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			deadUID := "dead0002-1111-2222-3333-444444444444"
			deadMount := filepath.Join(sb.kubeletPods, deadUID, "volumes", "kubernetes.io~empty-dir", "cache")
			_ = os.MkdirAll(deadMount, 0o755)
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_MOUNTINFO_FILE"],
				[]byte(fmt.Sprintf("204 1 8:1 / %s rw,relatime - tmpfs tmpfs rw\n", deadMount)), 0o644)

			_, liveInitPID := spawnDummySleep(t, 60)
			sid := strings.Repeat("f", 64)
			writeLiveCtrTaskDir(t, sb.ctrTaskRoot, sid, liveInitPID)
			_, pinPID := spawnDummySleep(t, 60)
			writeProcTask(t, sb.proc, pinPID, "containerd-shim", "S", 0,
				"0::/system.slice/k0sworker.service\n",
				[]string{"containerd-shim-runc-v2", "-namespace", "k8s.io", "-id", sid, "-address", sb.envMap["NODE_HOST_AGENT_CONTAINERD_SOCKET"]},
				10*time.Minute)
			_ = os.WriteFile(filepath.Join(sb.proc, strconv.Itoa(pinPID), "mountinfo"),
				[]byte(fmt.Sprintf("204 1 8:1 / %s rw,relatime - tmpfs tmpfs rw\n", deadMount)), 0o644)
			_ = os.Symlink(deadMount, filepath.Join(sb.proc, strconv.Itoa(pinPID), "fd", "4"))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 7*time.Second, 100*time.Millisecond, "K3 multi-cycle persistence acts after >=3 cycles", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="mountinfo-hygiene"`)
				if !ok || v < 3 {
					return fmt.Errorf("cycles=%v", v)
				}
				logBytes, _ := os.ReadFile(sb.logFile)
				cleanedLog := strings.ToLower(strings.ReplaceAll(string(logBytes), sb.root, ""))
				toolBytes, _ := os.ReadFile(sb.toolLog)
				if !strings.Contains(cleanedLog, "ebusy") && !strings.Contains(string(toolBytes), "umount") && pidAlive(pinPID) {
					return fmt.Errorf("expected K3 EBUSY detection/remediation after >=3 cycles")
				}
				return nil
			})
		})

		t.Run("RecoveryClearsLatch", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f26-node-5", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "300ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f26-node-5",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			deadUID := "dead0003-1111-2222-3333-444444444444"
			deadMount := filepath.Join(sb.kubeletPods, deadUID, "volumes", "kubernetes.io~empty-dir", "cache")
			_ = os.MkdirAll(deadMount, 0o755)
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_MOUNTINFO_FILE"],
				[]byte(fmt.Sprintf("205 1 8:1 / %s rw,relatime - tmpfs tmpfs rw\n", deadMount)), 0o644)

			_, liveInitPID := spawnDummySleep(t, 60)
			sid := strings.Repeat("9", 64)
			writeLiveCtrTaskDir(t, sb.ctrTaskRoot, sid, liveInitPID)
			_, pinPID := spawnDummySleep(t, 60)
			writeProcTask(t, sb.proc, pinPID, "containerd-shim", "S", 0,
				"0::/system.slice/k0sworker.service\n",
				[]string{"containerd-shim-runc-v2", "-namespace", "k8s.io", "-id", sid, "-address", sb.envMap["NODE_HOST_AGENT_CONTAINERD_SOCKET"]},
				10*time.Minute)
			_ = os.WriteFile(filepath.Join(sb.proc, strconv.Itoa(pinPID), "mountinfo"),
				[]byte(fmt.Sprintf("205 1 8:1 / %s rw,relatime - tmpfs tmpfs rw\n", deadMount)), 0o644)
			_ = os.Symlink(deadMount, filepath.Join(sb.proc, strconv.Itoa(pinPID), "fd", "4"))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			latchPath := filepath.Join(sb.state, "state-pod-teardown-wedged")
			eventually(t, 6*time.Second, 100*time.Millisecond, "K3 EBUSY wedge observed and latch created", func() error {
				logBytes, _ := os.ReadFile(sb.logFile)
				cleanedLog := strings.ToLower(strings.ReplaceAll(string(logBytes), sb.root, ""))
				toolBytes, _ := os.ReadFile(sb.toolLog)
				if !strings.Contains(cleanedLog, "ebusy") && !strings.Contains(string(toolBytes), "umount") && pidAlive(pinPID) {
					return fmt.Errorf("missing EBUSY detection log")
				}
				if _, err := os.Stat(latchPath); err != nil {
					return fmt.Errorf("expected latch %s before recovery: %w", latchPath, err)
				}
				return nil
			})
			// Clear dead mount and pinning proc.
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_MOUNTINFO_FILE"], []byte(""), 0o644)
			_ = os.RemoveAll(filepath.Join(sb.proc, strconv.Itoa(pinPID)))
			eventually(t, 5*time.Second, 100*time.Millisecond, "K3 clears latch after recovery", func() error {
				if _, err := os.Stat(latchPath); !os.IsNotExist(err) {
					return fmt.Errorf("expected latch %s to be absent after recovery (err=%v)", latchPath, err)
				}
				return nil
			})
		})
	})

	t.Run("F28Agent_CgroupV2AndKubeletReadiness", func(t *testing.T) {
		t.Run("CgroupV2ReadyHostReportsHealthy", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f28-node-1", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTMETRICS": "true",
				"NODE_HOST_AGENT_ENABLE_REPORTER":    "true",
				"NODE_HOST_AGENT_LATCH_INTERVAL":     "400ms",
				"NODE_HOST_AGENT_REPORTER_INTERVAL":  "400ms",
				"NODE_HOST_AGENT_NODE_NAME":          "f28-node-1",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sb.hostroot, "sys", "fs", "cgroup", "cgroup.controllers"), []byte("cpu memory io pids\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sb.cgroup, "cgroup.controllers"), []byte("cpu memory io pids\n"), 0o644)
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_MOUNTINFO_FILE"],
				[]byte("25 1 0:23 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw\n"), 0o644)
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_K0S_CONFIG"], []byte(cleanK0sYAML()), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "healthy cgroup2 host emits 0 drift", func() error {
				m := ra.scrapeMetrics(t)
				v, ok := parseMetricValue(m, "node_k0s_config_drift", `reason="none"`, `key="none"`)
				if !ok || v != 0 {
					return fmt.Errorf("k0s drift ok=%v v=%v", ok, v)
				}
				return nil
			})
		})

		t.Run("CgroupV1OrCgroupfsLegacyGateDetected", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f28-node-2", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTMETRICS": "true",
				"NODE_HOST_AGENT_ENABLE_REPORTER":    "true",
				"NODE_HOST_AGENT_LATCH_INTERVAL":     "400ms",
				"NODE_HOST_AGENT_REPORTER_INTERVAL":  "400ms",
				"NODE_HOST_AGENT_NODE_NAME":          "f28-node-2",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			// Legacy cgroup v1 mount + legacy kubelet feature gate / cgroupfs driver.
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_MOUNTINFO_FILE"],
				[]byte("25 1 0:23 / /sys/fs/cgroup/memory rw,relatime - cgroup cgroup rw,memory\n"), 0o644)
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_K0S_CONFIG"], []byte(legacyGateK0sYAML()), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "K5 detects legacy cgroupv1 / cgroupfs / KubeletEnsureSecretPulledImages gate", func() error {
				if !hasK5ReadinessSignal(ra.scrapeMetrics(t), sb) {
					return fmt.Errorf("K5 readiness metric/latch not flagged in /metrics or state/logs")
				}
				return nil
			})
		})

		t.Run("K0sConfigRemovedFlagsAndLegacyKubeletGate", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTMETRICS": "true",
				"NODE_HOST_AGENT_LATCH_INTERVAL":     "400ms",
				"NODE_HOST_AGENT_NODE_NAME":          "f28-node-3",
			})
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_K0S_CONFIG"], []byte(`apiVersion: k0s.k0sproject.io/v1beta1
kind: ClusterConfig
spec:
  controllerManager:
    extraArgs:
      concurrent-service-syncs: "20"
  workerProfiles:
    - name: default
      values:
        cgroupDriver: cgroupfs
        failCgroupV1: false
        featureGates:
          KubeletEnsureSecretPulledImages: false
`), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "removed-flag + K5 legacy gate surfaced", func() error {
				m := ra.scrapeMetrics(t)
				v, ok := parseMetricValue(m, "node_k0s_config_drift", `reason="removed-flag"`, `key="concurrent-service-syncs"`)
				if !ok || v != 1 {
					return fmt.Errorf("removed-flag ok=%v v=%v", ok, v)
				}
				if !hasK5ReadinessSignal(m, sb) {
					return fmt.Errorf("missing K5 readiness series/latch")
				}
				return nil
			})
		})

		t.Run("NodeReporterReflectsLatchToCondition", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f28-node-4", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTMETRICS": "true",
				"NODE_HOST_AGENT_ENABLE_REPORTER":    "true",
				"NODE_HOST_AGENT_REPORTER_INTERVAL":  "400ms",
				"NODE_HOST_AGENT_NODE_NAME":          "f28-node-4",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.state, "state-host-kernel-drift"), []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "nodereporter patches NodeCondition True", func() error {
				n, ok := api.getNode("f28-node-4")
				if !ok {
					return fmt.Errorf("node missing")
				}
				for _, c := range n.Status.Conditions {
					if c.Type == "HostKernelDrift" && c.Status == corev1.ConditionTrue {
						return nil
					}
				}
				return fmt.Errorf("HostKernelDrift condition not True: %+v", n.Status.Conditions)
			})
		})

		t.Run("RecoveryClearsReadinessSignal", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f28-node-5", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTMETRICS": "true",
				"NODE_HOST_AGENT_ENABLE_REPORTER":    "true",
				"NODE_HOST_AGENT_LATCH_INTERVAL":     "300ms",
				"NODE_HOST_AGENT_REPORTER_INTERVAL":  "300ms",
				"NODE_HOST_AGENT_NODE_NAME":          "f28-node-5",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_K0S_CONFIG"], []byte(legacyGateK0sYAML()), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "K5 readiness non-ready detected", func() error {
				if !hasK5ReadinessSignal(ra.scrapeMetrics(t), sb) {
					return fmt.Errorf("missing K5 readiness signal")
				}
				return nil
			})
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_K0S_CONFIG"], []byte(cleanK0sYAML()), 0o644)
			_ = os.WriteFile(filepath.Join(sb.hostroot, "sys", "fs", "cgroup", "cgroup.controllers"), []byte("cpu memory io pids\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sb.cgroup, "cgroup.controllers"), []byte("cpu memory io pids\n"), 0o644)
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_MOUNTINFO_FILE"],
				[]byte("25 1 0:23 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw\n"), 0o644)
			eventually(t, 6*time.Second, 100*time.Millisecond, "drift and K5 latch clear after config fix", func() error {
				m := ra.scrapeMetrics(t)
				v, ok := parseMetricValue(m, "node_k0s_config_drift", `reason="none"`, `key="none"`)
				if !ok || v != 0 {
					return fmt.Errorf("drift=%v ok=%v", v, ok)
				}
				if hasK5WatchdogLatch(sb) {
					return fmt.Errorf("K5 state-* latch still present after recovery")
				}
				return nil
			})
		})
	})

	t.Run("F31Agent_StaleUDPConntrack", func(t *testing.T) {
		t.Run("HealthyPodCIDRNodesNoPauseTasksCompletesOK", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f31-node-1", "10.244.0.0/16"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f31-node-1",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "udp-stale-socket completes ok", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="udp-stale-socket"`, `result="ok"`)
				if !ok || v < 1 {
					return fmt.Errorf("udp-stale-socket ok=%v v=%v", ok, v)
				}
				return nil
			})
			foundRV0 := false
			for _, req := range api.getRequests() {
				if req.Method == http.MethodGet && req.Path == "/api/v1/nodes" && strings.Contains(req.RawQuery, "resourceVersion=0") {
					foundRV0 = true
					break
				}
			}
			if !foundRV0 {
				t.Fatalf("expected GET /api/v1/nodes?resourceVersion=0 in requests: %+v", api.getRequests())
			}
		})

		t.Run("PauseTaskSharingHostNetnsSkippedCleanly", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f31-node-2", "10.244.0.0/16"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f31-node-2",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			_, pid := spawnDummySleep(t, 30)
			_ = os.MkdirAll(filepath.Join(sb.proc, "1", "ns"), 0o755)
			_ = os.Symlink("net:[4026531992]", filepath.Join(sb.proc, "1", "ns", "net"))
			_ = os.MkdirAll(filepath.Join(sb.proc, strconv.Itoa(pid), "ns"), 0o755)
			_ = os.Symlink("net:[4026531992]", filepath.Join(sb.proc, strconv.Itoa(pid), "ns", "net"))

			taskDir := filepath.Join(sb.ctrTaskRoot, strings.Repeat("7", 64))
			_ = os.MkdirAll(taskDir, 0o755)
			_ = os.WriteFile(filepath.Join(taskDir, "config.json"),
				[]byte(`{"annotations":{"io.kubernetes.pod.uid":"77777777-1111-2222-3333-444444444444","io.kubernetes.container.name":"pause"}}`), 0o644)
			_ = os.WriteFile(filepath.Join(taskDir, "init.pid"), []byte(strconv.Itoa(pid)+"\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "host netns pause task skipped cleanly", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="udp-stale-socket"`, `result="ok"`)
				if !ok || v < 1 {
					return fmt.Errorf("udp-stale-socket ok=%v v=%v", ok, v)
				}
				return nil
			})
		})

		t.Run("PauseTaskDifferentNetnsUnprivilegedDegradesCleanly", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f31-node-3", "10.244.0.0/16"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f31-node-3",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			_, pid := spawnDummySleep(t, 30)
			_ = os.MkdirAll(filepath.Join(sb.proc, "1", "ns"), 0o755)
			_ = os.Symlink("net:[4026531992]", filepath.Join(sb.proc, "1", "ns", "net"))
			_ = os.MkdirAll(filepath.Join(sb.proc, strconv.Itoa(pid), "ns"), 0o755)
			_ = os.Symlink("net:[4026539999]", filepath.Join(sb.proc, strconv.Itoa(pid), "ns", "net"))

			taskDir := filepath.Join(sb.ctrTaskRoot, strings.Repeat("8", 64))
			_ = os.MkdirAll(taskDir, 0o755)
			_ = os.WriteFile(filepath.Join(taskDir, "config.json"),
				[]byte(`{"annotations":{"io.kubernetes.pod.uid":"88888888-1111-2222-3333-444444444444","io.kubernetes.container.name":"pause"}}`), 0o644)
			_ = os.WriteFile(filepath.Join(taskDir, "init.pid"), []byte(strconv.Itoa(pid)+"\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "distinct netns degrades gracefully without panic", func() error {
				if code, _ := reqHTTPGet(t, ra.healthzURL()); code != http.StatusOK {
					return fmt.Errorf("healthz=%d", code)
				}
				m := ra.scrapeMetrics(t)
				vAbort, okAbort := parseMetricValue(m, "node_host_agent_workerhygiene_cycles_total", `check="udp-stale-socket"`, `result="abort"`)
				vOK, okOK := parseMetricValue(m, "node_host_agent_workerhygiene_cycles_total", `check="udp-stale-socket"`, `result="ok"`)
				if (!okAbort || vAbort < 1) && (!okOK || vOK < 1) {
					return fmt.Errorf("udp-stale-socket abort=(%v,%v) ok=(%v,%v)", okAbort, vAbort, okOK, vOK)
				}
				return nil
			})
		})

		t.Run("DisableDestroyEnvFlagRespected", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f31-node-4", "10.244.0.0/16"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":            "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL":          "400ms",
				"NODE_HOST_AGENT_UDP_STALE_DESTROY_ENABLED": "false",
				"NODE_HOST_AGENT_NODE_NAME":                 "f31-node-4",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "udp-stale-socket gated/ok with destroy disabled", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="udp-stale-socket"`)
				if !ok || v < 1 {
					return fmt.Errorf("udp-stale-socket ok=%v v=%v", ok, v)
				}
				return nil
			})
		})

		t.Run("PodCIDROverrideEnvWithMultipleCIDRs", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			n := makeNode("f31-node-5", "10.244.0.0/16")
			n.Annotations["io.cilium.network.ipv4-health-ip"] = "10.244.0.5"
			api.setNode(n)
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":      "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL":    "400ms",
				"NODE_HOST_AGENT_UDP_STALE_POD_CIDRS": "10.244.0.0/16,fd00:10:244::/56",
				"NODE_HOST_AGENT_NODE_NAME":           "f31-node-5",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "multi-CIDR override completes ok and queries nodes", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="udp-stale-socket"`, `result="ok"`)
				if !ok || v < 1 {
					return fmt.Errorf("ok=%v v=%v", ok, v)
				}
				return nil
			})
			if api.countRequests(http.MethodGet, "/api/v1/nodes") < 1 {
				t.Fatalf("expected Nodes().List call to collect Cilium health IP exemptions")
			}
		})
	})

	t.Run("F33_KMSv2EncryptionGuard", func(t *testing.T) {
		t.Run("AbsentKMSSkipsGracefully", func(t *testing.T) {
			t.Parallel()
			srv, certPEM, keyPEM, caPEM := newSelfSignedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/namespaces/default/services":
					_, _ = w.Write([]byte(`{"metadata":{"resourceVersion":"100"},"items":[]}`))
				case "/api/v1/namespaces/default/endpoints/kubernetes":
					_, _ = w.Write([]byte(`{"subsets":[{"addresses":[{"ip":"127.0.0.1"}]}]}`))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE": "true",
				"NODE_HOST_AGENT_CONTROLLER_INTERVAL":      "400ms",
				"NODE_HOST_AGENT_CONTROLLER_INSECURE_TLS":  "true",
				"NODE_HOST_AGENT_API_SELF":                 strings.TrimPrefix(srv.URL, "https://"),
			})
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			writeKubeconfigFile(t, filepath.Join(sb.k0s, "pki", "admin.conf"), srv.URL, certPEM, keyPEM, caPEM)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "controllerhygiene cycles ok with no KMS", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_controllerhygiene_cycles_total")
				if !ok || v < 2 {
					return fmt.Errorf("cycles ok=%v v=%v", ok, v)
				}
				return nil
			})
			latches, _ := filepath.Glob(filepath.Join(sb.state, "state-*kms*"))
			if len(latches) != 0 {
				t.Fatalf("unexpected KMS latch when KMS absent: %v", latches)
			}
		})

		t.Run("HealthyKMSv2SocketAndHealthzOK", func(t *testing.T) {
			t.Parallel()
			srv, certPEM, keyPEM, caPEM := newSelfSignedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/api/v1/namespaces/default/services":
					_, _ = w.Write([]byte(`{"metadata":{"resourceVersion":"100"},"items":[]}`))
				case r.URL.Path == "/api/v1/namespaces/default/endpoints/kubernetes":
					_, _ = w.Write([]byte(`{"subsets":[{"addresses":[{"ip":"127.0.0.1"}]}]}`))
				case strings.HasPrefix(r.URL.Path, "/healthz/kms-provider-"):
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("ok"))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE": "true",
				"NODE_HOST_AGENT_CONTROLLER_INTERVAL":      "400ms",
				"NODE_HOST_AGENT_CONTROLLER_INSECURE_TLS":  "true",
				"NODE_HOST_AGENT_API_SELF":                 strings.TrimPrefix(srv.URL, "https://"),
			})
			sb.ensureShortHostRoot(t)
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			writeKubeconfigFile(t, filepath.Join(sb.k0s, "pki", "admin.conf"), srv.URL, certPEM, keyPEM, caPEM)
			startMockUnixEchoServer(t, filepath.Join(sb.hostroot, "run", "k0s", "kms.sock"))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "healthy KMSv2 cycles", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_controllerhygiene_cycles_total")
				if !ok || v < 2 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
			latches, _ := filepath.Glob(filepath.Join(sb.state, "state-*kms*"))
			if len(latches) != 0 {
				t.Fatalf("unexpected KMS latch when KMS healthy: %v", latches)
			}
			toolBytes, _ := os.ReadFile(sb.toolLog)
			if strings.Contains(string(toolBytes), "restart k0scontroller") {
				t.Fatalf("unexpected controller restart on healthy KMSv2:\n%s", string(toolBytes))
			}
		})

		t.Run("UnhealthyKMSv2Healthz500LatchesAndAlerts", func(t *testing.T) {
			t.Parallel()
			srv, certPEM, keyPEM, caPEM := newSelfSignedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/api/v1/namespaces/default/services":
					_, _ = w.Write([]byte(`{"metadata":{"resourceVersion":"100"},"items":[]}`))
				case r.URL.Path == "/api/v1/namespaces/default/endpoints/kubernetes":
					_, _ = w.Write([]byte(`{"subsets":[{"addresses":[{"ip":"127.0.0.1"}]}]}`))
				case strings.HasPrefix(r.URL.Path, "/healthz/kms-provider-"):
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte("kms unhealthy"))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE": "true",
				"NODE_HOST_AGENT_CONTROLLER_INTERVAL":      "350ms",
				"NODE_HOST_AGENT_CONTROLLER_INSECURE_TLS":  "true",
				"NODE_HOST_AGENT_API_SELF":                 strings.TrimPrefix(srv.URL, "https://"),
			})
			sb.ensureShortHostRoot(t)
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			writeKubeconfigFile(t, filepath.Join(sb.k0s, "pki", "admin.conf"), srv.URL, certPEM, keyPEM, caPEM)
			startMockUnixEchoServer(t, filepath.Join(sb.hostroot, "run", "k0s", "kms.sock"))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 7*time.Second, 100*time.Millisecond, "K10 unhealthy KMSv2 latched or logged", func() error {
				latches, _ := filepath.Glob(filepath.Join(sb.state, "state-*kms*"))
				logBytes, _ := os.ReadFile(sb.logFile)
				m := ra.scrapeMetrics(t)
				if len(latches) > 0 || strings.Contains(strings.ToLower(string(logBytes)), "kms") || strings.Contains(strings.ToLower(m), "kms") {
					return nil
				}
				return fmt.Errorf("K10 KMSv2 degradation not detected")
			})
		})

		t.Run("HungKMSv2SocketDoesNotWedgeAgentHealthz", func(t *testing.T) {
			t.Parallel()
			srv, certPEM, keyPEM, caPEM := newSelfSignedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/namespaces/default/services":
					_, _ = w.Write([]byte(`{"metadata":{"resourceVersion":"100"},"items":[]}`))
				case "/api/v1/namespaces/default/endpoints/kubernetes":
					_, _ = w.Write([]byte(`{"subsets":[{"addresses":[{"ip":"127.0.0.1"}]}]}`))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE": "true",
				"NODE_HOST_AGENT_CONTROLLER_INTERVAL":      "350ms",
				"NODE_HOST_AGENT_CONTROLLER_INSECURE_TLS":  "true",
				"NODE_HOST_AGENT_API_SELF":                 strings.TrimPrefix(srv.URL, "https://"),
			})
			sb.ensureShortHostRoot(t)
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			writeKubeconfigFile(t, filepath.Join(sb.k0s, "pki", "admin.conf"), srv.URL, certPEM, keyPEM, caPEM)
			startHungUnixSocket(t, filepath.Join(sb.hostroot, "run", "k0s", "kms.sock"))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "controllerhygiene advances despite hung KMSv2 socket", func() error {
				if code, _ := reqHTTPGet(t, ra.healthzURL()); code != http.StatusOK {
					return fmt.Errorf("healthz=%d", code)
				}
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_controllerhygiene_cycles_total")
				if !ok || v < 2 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
		})

		t.Run("KMSv2RecoveryClearsLatch", func(t *testing.T) {
			t.Parallel()
			var healthy atomic.Bool
			srv, certPEM, keyPEM, caPEM := newSelfSignedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/api/v1/namespaces/default/services":
					_, _ = w.Write([]byte(`{"metadata":{"resourceVersion":"100"},"items":[]}`))
				case r.URL.Path == "/api/v1/namespaces/default/endpoints/kubernetes":
					_, _ = w.Write([]byte(`{"subsets":[{"addresses":[{"ip":"127.0.0.1"}]}]}`))
				case strings.HasPrefix(r.URL.Path, "/healthz/kms-provider-"):
					if healthy.Load() {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte("ok"))
					} else {
						w.WriteHeader(http.StatusInternalServerError)
						_, _ = w.Write([]byte("fail"))
					}
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE": "true",
				"NODE_HOST_AGENT_CONTROLLER_INTERVAL":      "300ms",
				"NODE_HOST_AGENT_CONTROLLER_INSECURE_TLS":  "true",
				"NODE_HOST_AGENT_API_SELF":                 strings.TrimPrefix(srv.URL, "https://"),
			})
			sb.ensureShortHostRoot(t)
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			writeKubeconfigFile(t, filepath.Join(sb.k0s, "pki", "admin.conf"), srv.URL, certPEM, keyPEM, caPEM)
			startMockUnixEchoServer(t, filepath.Join(sb.hostroot, "run", "k0s", "kms.sock"))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "K10 unhealthy KMSv2 enters latch", func() error {
				latches, _ := filepath.Glob(filepath.Join(sb.state, "state-*kms*"))
				if len(latches) == 0 {
					return fmt.Errorf("expected state-*kms* latch")
				}
				return nil
			})
			healthy.Store(true)
			eventually(t, 6*time.Second, 100*time.Millisecond, "K10 clears latch on recovery", func() error {
				latches, _ := filepath.Glob(filepath.Join(sb.state, "state-*kms*"))
				if len(latches) != 0 {
					return fmt.Errorf("latch not cleared: %v", latches)
				}
				return nil
			})
		})
	})
}

func sha256Sum(b []byte) [32]byte {
	return sha256Bytes(b)
}

// installFakeRuntimeForKinedb stubs the container runtime under BOTH
// names. kdeps.ApplyDefaults auto-detects podman first when it is on
// PATH — GitHub's ubuntu-latest runners ship podman while most dev
// boxes do not — so a docker-only fake leaves the agent shelling out
// to the real podman on CI (every inspect/exec fails, the guard
// cycle marks the postgres container down and the backup verifier
// never runs). fakebin precedes PATH, so LookPath resolves whichever
// name the detector picks to this stub either way; the argv shape
// is identical for podman and docker.
func installFakeRuntimeForKinedb(t *testing.T, sb *reqSandbox, failDump, failRestore bool, sleepMs int) {
	t.Helper()
	for _, name := range []string{"docker", "podman"} {
		script := fmt.Sprintf(`#!/bin/sh
echo "%s $*" >> %q
cmd="$1"
shift
case "$cmd" in
  inspect)
    if [ "$1" = "-f" ]; then echo "true"; fi
    exit 0 ;;
  cp)
    for last; do :; done
    printf "PGDMP-fake-backup" > "$last"
    chmod 0644 "$last"
    exit 0 ;;
  exec)
    case "$*" in
      *"mktemp -d"*) echo "/tmp/kine-backup.AbC123"; exit 0 ;;
      *"pg_locks"*) echo "1"; exit 0 ;;
      *"COALESCE((SELECT MAX(id)"*) printf "100\t100\t10\t1\n"; exit 0 ;;
      *"-f -"*)
        sleep 5
        exit 0 ;;
      *"pg_dump"*)
        if [ %d -gt 0 ]; then
          sleep 0.%03d
        fi
        if [ "%v" = "true" ]; then exit 1; fi
        exit 0 ;;
      *"pg_restore"*)
        if [ "%v" = "true" ]; then exit 1; fi
        exit 0 ;;
      *"rm -rf"*|*"rm -f"*) exit 0 ;;
    esac
    exit 0 ;;
esac
exit 0
`, name, sb.toolLog, sleepMs, sleepMs, failDump, failRestore)
		installFakeTool(t, sb.fakebin, name, script)
	}
}

func startMockCiliumUnixServer(t *testing.T, sockPath string, handler http.HandlerFunc) string {
	t.Helper()
	ln, actualPath := listenShortUnixSocket(t, sockPath)
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	})
	return actualPath
}

func startMockUnixEchoServer(t *testing.T, sockPath string) {
	t.Helper()
	ln, _ := listenShortUnixSocket(t, sockPath)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
}

func startHungUnixSocket(t *testing.T, sockPath string) {
	t.Helper()
	ln, _ := listenShortUnixSocket(t, sockPath)
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns = append(conns, c)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
		for _, c := range conns {
			_ = c.Close()
		}
	})
}

func cleanK0sYAML() string {
	return `apiVersion: k0s.k0sproject.io/v1beta1
kind: ClusterConfig
spec:
  controllerManager:
    extraArgs:
      concurrent-deployment-syncs: "10"
      concurrent-gc-syncs: "20"
      concurrent-replicaset-syncs: "10"
      kube-api-burst: "200"
      kube-api-qps: "100"
      leader-elect-lease-duration: "30s"
      leader-elect-renew-deadline: "20s"
      leader-elect-retry-period: "5s"
      node-monitor-grace-period: "40s"
      node-monitor-period: "5s"
      terminated-pod-gc-threshold: "100"
`
}

func legacyGateK0sYAML() string {
	return `apiVersion: k0s.k0sproject.io/v1beta1
kind: ClusterConfig
spec:
  workerProfiles:
    - name: default
      values:
        cgroupDriver: cgroupfs
        failCgroupV1: false
        featureGates:
          KubeletEnsureSecretPulledImages: false
`
}

var _ = discoveryv1.SchemeGroupVersion
