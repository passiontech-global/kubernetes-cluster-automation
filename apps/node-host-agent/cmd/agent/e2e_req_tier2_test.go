package main_test

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v3"
	corev1 "k8s.io/api/core/v1"
)

func runTier2Tests(t *testing.T, bin string) {
	t.Run("F1_RepoContractsBoundary", func(t *testing.T) {
		t.Run("EnvDurationInvalidFallback", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE":   "true",
				"NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL": "not-a-dur",
			})
			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			if code, _ := reqHTTPGet(t, ra.healthzURL()); code != http.StatusOK {
				t.Fatalf("/healthz status=%d want 200", code)
			}
			if !strings.Contains(ra.logsCombined(), "using default") {
				t.Fatalf("expected envx fallback warning in logs:\n%s", ra.logsCombined())
			}

			sbNeg := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE":   "true",
				"NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL": "-5s",
			})
			raNeg := startReqAgent(t, bin, sbNeg.envSlice())
			defer raNeg.stopAndWait(t)
			if code, _ := reqHTTPGet(t, raNeg.healthzURL()); code != http.StatusOK {
				t.Fatalf("negative duration /healthz status=%d want 200", code)
			}
		})

		t.Run("EnableModeTriState", func(t *testing.T) {
			t.Parallel()
			for _, val := range []string{"off", "0", "false"} {
				sb := newReqSandbox(t, map[string]string{
					"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE": val,
				})
				ra := startReqAgent(t, bin, sb.envSlice())
				if !slices.Contains(ra.start.Off, "concourse-cache") {
					ra.stopAndWait(t)
					t.Fatalf("val=%q expected concourse-cache in Off, got Off=%v Subsystems=%v",
						val, ra.start.Off, ra.start.Subsystems)
				}
				ra.stopAndWait(t)
			}

			sbBogus := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE": "bogus-mode",
			})
			raBogus := startReqAgent(t, bin, sbBogus.envSlice())
			defer raBogus.stopAndWait(t)
			if !slices.Contains(raBogus.start.Subsystems, "concourse-cache") {
				t.Fatalf("bogus tri-state should fall back to pod default ON, got Subsystems=%v Off=%v",
					raBogus.start.Subsystems, raBogus.start.Off)
			}
		})

		t.Run("NodeNamePrecedenceBoundaries", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":  "true",
				"NODE_HOST_AGENT_ENABLE_REPORTER": "true",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc

			ra := startReqAgent(t, bin, sb.envSlice(), "--node-name=")
			defer ra.stopAndWait(t)

			for _, sub := range []string{"workerhygiene", "nodereporter"} {
				if !slices.Contains(ra.start.Skipped, sub) {
					t.Fatalf("empty node name should skip %q, got Skipped=%v Subsystems=%v",
						sub, ra.start.Skipped, ra.start.Subsystems)
				}
			}
			if code, _ := reqHTTPGet(t, ra.healthzURL()); code != http.StatusOK {
				t.Fatalf("/healthz=%d want 200", code)
			}
		})

		t.Run("KubeClientMissingCredentialsDegrades", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_SWEEPER":         "true",
				"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE": "true",
				"NODE_HOST_AGENT_ENABLE_HOSTMETRICS":     "true",
				"NODE_HOST_AGENT_ENABLE_HYGIENE":         "true",
				"NODE_HOST_AGENT_ENABLE_REPORTER":        "true",
				"NODE_HOST_AGENT_NODE_NAME":              "f1-nokube",
				"POD_NAME":                               "f1-nokube-pod",
			})
			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			for _, sub := range []string{"sweeper", "workerhygiene", "nodereporter", "hubsync"} {
				if !slices.Contains(ra.start.Skipped, sub) {
					t.Fatalf("missing kubeconfig expected %q in Skipped, got %v", sub, ra.start.Skipped)
				}
			}
			for _, sub := range []string{"concourse-cache", "hostmetrics"} {
				if !slices.Contains(ra.start.Subsystems, sub) {
					t.Fatalf("expected %q in Subsystems, got %v", sub, ra.start.Subsystems)
				}
			}
		})

		t.Run("SubcommandUnknownAndArgBoundary", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, nil)
			for _, arg := range []string{"", "unknown-cmd"} {
				_, stderr, code := runCLI(t, bin, sb.envSlice(), arg)
				if code != 2 {
					t.Fatalf("arg=%q exit=%d want 2; stderr:\n%s", arg, code, stderr)
				}
				for _, sub := range []string{
					"version", "concourse-worker-init", "concourse-runc-wrapper",
					"converge-once", "nebula-sign", "purge-events",
					"check-kine-db", "check-k0s-drift", "rescue-etcd",
				} {
					if !strings.Contains(stderr, sub) {
						t.Fatalf("usage output for %q missing %q:\n%s", arg, sub, stderr)
					}
				}
			}
		})
	})

	t.Run("F2_ConcourseCacheBoundary", func(t *testing.T) {
		t.Run("NonUUIDPvcDirIgnored", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE":   "true",
				"NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL": "100ms",
			})
			badFile := filepath.Join(sb.openebs, "pvc-not-a-uuid", "shared-cache", "build", "old.bin")
			_ = os.MkdirAll(filepath.Dir(badFile), 0o755)
			_ = os.WriteFile(badFile, []byte("keep"), 0o644)
			old := time.Now().Add(-100 * time.Hour)
			_ = os.Chtimes(badFile, old, old)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "3 sweeps run", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_concourse_cache_cycles_total", `result="ok"`)
				if !ok || v < 3 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
			if _, err := os.Stat(badFile); err != nil {
				t.Fatalf("non-UUID pvc dir file unexpectedly deleted: %v", err)
			}
		})

		t.Run("GoBuildGraceAge2hBoundary", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE":   "true",
				"NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL": "100ms",
			})
			sc := filepath.Join(sb.openebs, "pvc-66666666-2222-3333-4444-555555555555", "shared-cache")
			dir := filepath.Join(sc, "go-build", "aa")
			_ = os.MkdirAll(dir, 0o755)
			fresh := filepath.Join(dir, strings.Repeat("d", 64)+"-d")
			_ = os.WriteFile(fresh, []byte("recent"), 0o644)
			withinGrace := time.Now().Add(-118 * time.Minute)
			_ = os.Chtimes(fresh, withinGrace, withinGrace)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "3 sweeps run", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_concourse_cache_cycles_total", `result="ok"`)
				if !ok || v < 3 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
			if _, err := os.Stat(fresh); err != nil {
				t.Fatalf("go-build file within 2h grace period was deleted: %v", err)
			}
		})

		t.Run("GoBuildIndexLen174vs175vs176Boundary", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE":   "true",
				"NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL": "100ms",
			})
			sc := filepath.Join(sb.openebs, "pvc-77777777-2222-3333-4444-555555555555", "shared-cache")
			for _, sub := range []string{"aa", "bb", "cc", "11", "22", "33"} {
				_ = os.MkdirAll(filepath.Join(sc, "go-build", sub), 0o755)
			}
			old := time.Now().Add(-100 * time.Hour)
			idxAge := time.Now().Add(-10 * time.Hour)

			oid174 := strings.Repeat("1", 64)
			oid175 := strings.Repeat("2", 64)
			oid176 := strings.Repeat("3", 64)
			for _, oid := range []string{oid174, oid175, oid176} {
				p := filepath.Join(sc, "go-build", oid[:2], oid+"-d")
				_ = os.WriteFile(p, []byte("data"), 0o644)
				_ = os.Chtimes(p, old, old)
			}

			line175 := fmt.Sprintf("v1 %s %s %20d %20d\n", strings.Repeat("a", 64), oid175, 4, time.Now().Unix())
			line174 := fmt.Sprintf("v1 %s %s %20d %19d\n", strings.Repeat("b", 64), oid174, 4, time.Now().Unix())
			line176 := fmt.Sprintf("v1 %s %s %20d %21d\n", strings.Repeat("c", 64), oid176, 4, time.Now().Unix())

			for _, pair := range []struct {
				name, body string
			}{
				{strings.Repeat("a", 64) + "-a", line175},
				{strings.Repeat("b", 64) + "-a", line174},
				{strings.Repeat("c", 64) + "-a", line176},
			} {
				p := filepath.Join(sc, "go-build", "aa", pair.name)
				_ = os.WriteFile(p, []byte(pair.body), 0o644)
				_ = os.Chtimes(p, idxAge, idxAge)
			}

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "174/176-byte index ignored, 175-byte index protects", func() error {
				if _, err := os.Stat(filepath.Join(sc, "go-build", oid174[:2], oid174+"-d")); !os.IsNotExist(err) {
					return fmt.Errorf("oid174-d not pruned")
				}
				if _, err := os.Stat(filepath.Join(sc, "go-build", oid176[:2], oid176+"-d")); !os.IsNotExist(err) {
					return fmt.Errorf("oid176-d not pruned")
				}
				if _, err := os.Stat(filepath.Join(sc, "go-build", oid175[:2], oid175+"-d")); err != nil {
					return fmt.Errorf("oid175-d should be protected: %w", err)
				}
				return nil
			})
		})

		t.Run("PersistentBucketsNeverPruned", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE":   "true",
				"NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL": "100ms",
			})
			sc := filepath.Join(sb.openebs, "pvc-88888888-2222-3333-4444-555555555555", "shared-cache")
			old := time.Now().Add(-30 * 24 * time.Hour)
			var keep []string
			for _, b := range []string{"go-mod", "mise", "ci-tool"} {
				p := filepath.Join(sc, b, "old.bin")
				_ = os.MkdirAll(filepath.Dir(p), 0o755)
				_ = os.WriteFile(p, []byte("keep"), 0o644)
				_ = os.Chtimes(p, old, old)
				keep = append(keep, p)
			}

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "3 sweeps run", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_concourse_cache_cycles_total", `result="ok"`)
				if !ok || v < 3 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
			for _, p := range keep {
				if _, err := os.Stat(p); err != nil {
					t.Fatalf("persistent bucket file %s deleted: %v", p, err)
				}
			}
		})

		t.Run("SymlinkedSharedCacheRootIgnored", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE":   "true",
				"NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL": "100ms",
			})
			outside := filepath.Join(sb.root, "outside-root")
			_ = os.MkdirAll(filepath.Join(outside, "build"), 0o755)
			canary := filepath.Join(outside, "build", "old.bin")
			_ = os.WriteFile(canary, []byte("SAFE"), 0o644)
			old := time.Now().Add(-100 * time.Hour)
			_ = os.Chtimes(canary, old, old)

			pvcDir := filepath.Join(sb.openebs, "pvc-99999999-2222-3333-4444-555555555555")
			_ = os.MkdirAll(pvcDir, 0o755)
			_ = os.Symlink(outside, filepath.Join(pvcDir, "shared-cache"))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "3 sweeps run", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_concourse_cache_cycles_total", `result="ok"`)
				if !ok || v < 3 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
			if _, err := os.Stat(canary); err != nil {
				t.Fatalf("symlinked shared-cache root allowed outside deletion: %v", err)
			}
		})
	})

	t.Run("F3_HostconfigBoundary", func(t *testing.T) {
		t.Run("BasenameTraversalRejected", func(t *testing.T) {
			t.Parallel()
			var hits atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
				"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":           "f3-t2-1",
			})
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sb.hostroot, "var", "lib", "k0s", "pki", "etcd", "ca.crt"), []byte("CA"), 0o644)
			writeHostconfigVars(t, sb.vars, fmt.Sprintf(
				"etcdctl_version: \"3.7.3\"\netcdctl_tgz_url: %q\netcdctl_tgz_sha256: %q\netcdctl_tgz_file: \"../../evil.tgz\"\n",
				srv.URL+"/good.tgz", strings.Repeat("a", 64),
			), "", "")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "basename traversal rejected", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_hostconfig_cycles_total", `group="etcdctl"`, `result="error"`)
				if !ok || v < 1 {
					return fmt.Errorf("etcdctl error ok=%v v=%v", ok, v)
				}
				return nil
			})
			if hits.Load() != 0 {
				t.Fatalf("expected 0 HTTP download hits on basename traversal, got %d", hits.Load())
			}
			if _, err := os.Stat(filepath.Join(sb.hostroot, "var", "lib", "evil.tgz")); !os.IsNotExist(err) {
				t.Fatalf("traversal wrote evil.tgz outside DownloadDir")
			}
		})

		t.Run("TarMemberPathTraversalIgnoredOrRejected", func(t *testing.T) {
			t.Parallel()
			evilBytes, evilSum := makeTarGz(t, []tarEntry{
				{name: "../../evil_escape", body: []byte("PWN"), typeflag: tar.TypeReg},
				{name: "etcdctl", body: []byte("PWN"), typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
			})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(evilBytes)
			}))
			defer srv.Close()

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
				"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":           "f3-t2-2",
			})
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sb.hostroot, "var", "lib", "k0s", "pki", "etcd", "ca.crt"), []byte("CA"), 0o644)
			writeHostconfigVars(t, sb.vars, fmt.Sprintf(
				"etcdctl_version: \"3.7.3\"\netcdctl_tgz_url: %q\netcdctl_tgz_sha256: %q\netcdctl_tgz_file: \"evil_member.tgz\"\n",
				srv.URL+"/evil.tgz", evilSum,
			), "", "")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "symlink/traversal tarball fails etcdctl install", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_hostconfig_cycles_total", `group="etcdctl"`, `result="error"`)
				if !ok || v < 1 {
					return fmt.Errorf("etcdctl error ok=%v v=%v", ok, v)
				}
				return nil
			})
			if _, err := os.Stat(filepath.Join(sb.hostroot, "var", "lib", "k0s", "bin", "etcdctl")); !os.IsNotExist(err) {
				t.Fatalf("symlink/traversal tar entry installed etcdctl")
			}
		})

		t.Run("MissingSHA256OrURLFailsClosed", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
				"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":           "f3-t2-3",
			})
			writeHostconfigVars(t, sb.vars,
				"kine_service_hosts:\n  - f3-t2-3\nkine_endpoint: \"postgres://u:p@127.0.0.1:5432/kine\"\nkine_bin_url: \"http://127.0.0.1:1/kine\"\nkine_bin_sha256: \"\"\n",
				"", "")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "missing sha256 pin fails closed", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_hostconfig_cycles_total", `group="kine"`, `result="error"`)
				if !ok || v < 1 {
					return fmt.Errorf("kine error ok=%v v=%v", ok, v)
				}
				return nil
			})
			if _, err := os.Stat(filepath.Join(sb.hostroot, "usr", "local", "bin", "kine")); !os.IsNotExist(err) {
				t.Fatalf("kine written despite empty sha256 pin")
			}
		})

		t.Run("HTTPNon200DownloadFailsCleanly", func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer srv.Close()

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
				"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":           "f3-t2-4",
			})
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sb.hostroot, "var", "lib", "k0s", "pki", "etcd", "ca.crt"), []byte("CA"), 0o644)
			writeHostconfigVars(t, sb.vars, fmt.Sprintf(
				"etcdctl_version: \"3.7.3\"\netcdctl_tgz_url: %q\netcdctl_tgz_sha256: %q\netcdctl_tgz_file: \"http500.tgz\"\n",
				srv.URL+"/500.tgz", strings.Repeat("b", 64),
			), "", "")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "HTTP 500 fails cleanly", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_hostconfig_cycles_total", `group="etcdctl"`, `result="error"`)
				if !ok || v < 1 {
					return fmt.Errorf("etcdctl error ok=%v v=%v", ok, v)
				}
				return nil
			})
			dls, _ := filepath.Glob(filepath.Join(sb.hostroot, "var", "lib", "node-watchdog", "downloads", "*"))
			if len(dls) != 0 {
				t.Fatalf("partial temp files left in downloads dir after HTTP 500: %v", dls)
			}
		})

		t.Run("ConvergeOnceUsageBoundary", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, nil)
			_, stderr, code := runCLI(t, bin, sb.envSlice(), "converge-once", "--bogus")
			if code != 2 {
				t.Fatalf("converge-once --bogus exit=%d want 2; stderr:\n%s", code, stderr)
			}
			_, stderr2, code2 := runCLI(t, bin, sb.envSlice(), "converge-once", "--vars-dir="+filepath.Join(sb.root, "does-not-exist"))
			if code2 != 1 {
				t.Fatalf("converge-once missing vars-dir exit=%d want 1; stderr:\n%s", code2, stderr2)
			}
		})
	})

	t.Run("F8_WorkerHygieneCtrBoundary", func(t *testing.T) {
		t.Run("RmImageLeadingDashImageArg", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f8-t2-1", "10.244.0.0/24"))
			pod := makePod("default", "dash-img", "33333333-1111-1111-1111-111111111111", "f8-t2-1")
			pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
				Name:  "app",
				Image: "registry.example.com/-evil:v1",
				State: corev1.ContainerState{
					Waiting: &corev1.ContainerStateWaiting{
						Reason:  "ImagePullBackOff",
						Message: "failed to extract layer",
					},
				},
			}}
			api.setPod(pod)

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f8-t2-1",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "RmImage passes -- before leading-dash image", func() error {
				b, err := os.ReadFile(sb.toolLog)
				if err != nil {
					return err
				}
				want := "images rm --sync -- registry.example.com/-evil:v1"
				if !strings.Contains(string(b), want) {
					return fmt.Errorf("missing %q in:\n%s", want, string(b))
				}
				return nil
			})
		})

		t.Run("OrphanShimFreshAgeUnder5mIgnored", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f8-t2-2", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f8-t2-2",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			_, pid := spawnDummySleep(t, 30)
			sid := strings.Repeat("1", 64)
			writeProcTask(t, sb.proc, pid, "containerd-shim", "S", 0,
				"0::/system.slice/k0sworker.service\n",
				[]string{"containerd-shim-runc-v2", "-namespace", "k8s.io", "-id", sid, "-address", sb.envMap["NODE_HOST_AGENT_CONTAINERD_SOCKET"]},
				2*time.Minute)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "2+ ctr-tasks cycles", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="ctr-tasks"`, `result="ok"`)
				if !ok || v < 2 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
			if !pidAlive(pid) {
				t.Fatalf("fresh (<5m) orphan shim candidate was prematurely killed")
			}
			assertNoCtrShimKill(t, ra)
		})

		t.Run("DZStateShimKubepodsSpoofRejected", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f8-t2-3", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f8-t2-3",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			sid := strings.Repeat("2", 64)
			writeProcTask(t, sb.proc, 424242, "containerd-shim", "D", 1000,
				"0::/kubepods.slice/kubepods-pod999.slice/cri-containerd-spoof.scope\n",
				nil, 10*time.Minute)
			_ = os.Symlink(filepath.Join(sb.ctrTaskRoot, sid, "work"), filepath.Join(sb.proc, "424242", "fd", "3"))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "2+ ctr-tasks cycles", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="ctr-tasks"`)
				if !ok || v < 2 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
			if _, err := os.Stat(filepath.Join(sb.state, "state-pod-teardown-wedged")); !os.IsNotExist(err) {
				t.Fatalf("kubepods D-state spoof escalated to state-pod-teardown-wedged!")
			}
			assertNoCtrShimKill(t, ra)
		})

		t.Run("UnreadableStatusOrCgroupFailsClosed", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f8-t2-4", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f8-t2-4",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			_, pid := spawnDummySleep(t, 30)
			sid := strings.Repeat("3", 64)
			writeProcTask(t, sb.proc, pid, "containerd-shim", "S", 0,
				"0::/system.slice/k0sworker.service\n",
				[]string{"containerd-shim-runc-v2", "-namespace", "k8s.io", "-id", sid, "-address", sb.envMap["NODE_HOST_AGENT_CONTAINERD_SOCKET"]},
				10*time.Minute)
			// Corrupt/remove Uid line in status so root UID verification cannot succeed.
			_ = os.WriteFile(filepath.Join(sb.proc, strconv.Itoa(pid), "status"), []byte("Name:\tcontainerd-shim\nState:\tS\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "2+ ctr-tasks cycles", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="ctr-tasks"`)
				if !ok || v < 2 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
			if !pidAlive(pid) {
				t.Fatalf("orphan shim killed despite missing Uid in /proc/<pid>/status (should fail closed)")
			}
			assertNoCtrShimKill(t, ra)
		})

		t.Run("ForeignSocketShimIgnored", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f8-t2-5", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f8-t2-5",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			_, pid := spawnDummySleep(t, 30)
			sid := strings.Repeat("4", 64)
			writeProcTask(t, sb.proc, pid, "containerd-shim", "S", 0,
				"0::/system.slice/docker.service\n",
				[]string{"containerd-shim-runc-v2", "-namespace", "moby", "-id", sid, "-address", "/var/run/docker/containerd.sock"},
				10*time.Minute)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "2+ ctr-tasks cycles", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="ctr-tasks"`, `result="ok"`)
				if !ok || v < 2 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
			if !pidAlive(pid) {
				t.Fatalf("foreign containerd socket shim was killed")
			}
			assertNoCtrShimKill(t, ra)
		})
	})

	t.Run("F9_HostconfigBoundary", func(t *testing.T) {
		t.Run("EmptyKineEndpointFailsClosed", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
				"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":           "f9-t2-1",
			})
			writeHostconfigVars(t, sb.vars, "kine_service_hosts:\n  - f9-t2-1\nkine_endpoint: \"\"\n", "", "")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "empty kine_endpoint fails closed", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_hostconfig_cycles_total", `group="kine"`, `result="error"`)
				if !ok || v < 1 {
					return fmt.Errorf("ok=%v v=%v", ok, v)
				}
				return nil
			})
			if _, err := os.Stat(filepath.Join(sb.hostroot, "etc", "kine", "kine.env")); !os.IsNotExist(err) {
				t.Fatalf("kine.env written with empty kine_endpoint")
			}
		})

		t.Run("ControlCharInKineEndpointRedacted", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
				"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":           "f9-t2-2",
			})
			secret := "SECRET_CTRL_TAB_77"
			writeHostconfigVars(t, sb.vars, fmt.Sprintf(
				"kine_service_hosts:\n  - f9-t2-2\nkine_endpoint: \"postgres://u:%s@db/kine\\tbad\"\n",
				secret,
			), "", "")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "control char endpoint rejected", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_hostconfig_cycles_total", `group="kine"`, `result="error"`)
				if !ok || v < 1 {
					return fmt.Errorf("ok=%v v=%v", ok, v)
				}
				return nil
			})
			if strings.Contains(ra.logsCombined(), secret) {
				t.Fatalf("secret leaked in logs:\n%s", ra.logsCombined())
			}
		})

		t.Run("NonLoopbackTCPWithoutMTLSRefused", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
				"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":           "f9-t2-3",
			})
			secret := "SECRET_MTLS_REFUSED_3"
			writeHostconfigVars(t, sb.vars, fmt.Sprintf(
				"kine_service_hosts:\n  - f9-t2-3\nkine_endpoint: \"postgres://u:%s@db/kine\"\nkine_listen_address: \"tcp://0.0.0.0:2379\"\n",
				secret,
			), "", "")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "non-loopback tcp without mTLS refused", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_hostconfig_cycles_total", `group="kine"`, `result="error"`)
				if !ok || v < 1 {
					return fmt.Errorf("ok=%v v=%v", ok, v)
				}
				return nil
			})
			if _, err := os.Stat(filepath.Join(sb.hostroot, "etc", "kine", "kine.env")); !os.IsNotExist(err) {
				t.Fatalf("kine.env written despite missing mTLS certs")
			}
			if strings.Contains(ra.logsCombined(), secret) {
				t.Fatalf("secret leaked in logs")
			}
		})

		t.Run("WatchdogConfSecretNotLeakedOnBadScalar", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
				"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":           "f9-t2-4",
			})
			writeHostconfigVars(t, sb.vars,
				"cp_endpoint: \"https://127.0.0.1:6443;touch /tmp/pwn\"\napi_self: \"127.0.0.1:6443\"\n",
				"", "")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "hostconfig completes cycle safely", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_hostconfig_cycles_total", `group="watchdog"`)
				if !ok || v < 1 {
					return fmt.Errorf("watchdog ok=%v v=%v", ok, v)
				}
				return nil
			})
		})

		t.Run("ConvergeOnceMissingVarsAndHostileMachineIDSafe", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTCONFIG":   "true",
				"NODE_HOST_AGENT_HOSTCONFIG_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":           "f9-t2-5",
			})

			// 1. Verify converge-once CLI fails closed on missing vars-dir without modifying host /.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cliCmd := exec.CommandContext(ctx, bin, "converge-once", "--vars-dir="+filepath.Join(sb.root, "missing-vars"), "--node-name=f9-t2-5")
			cliCmd.Env = sb.envSlice()
			out, err := cliCmd.CombinedOutput()
			if err == nil {
				t.Fatalf("converge-once with missing vars-dir unexpectedly succeeded:\n%s", out)
			}

			// 2. Exercise hostconfig base/journaldIntegrity + kine validation in sandboxed hostroot
			// with hostile /etc/machine-id and secret-bearing bad kine_endpoint.
			canary := filepath.Join(sb.root, "mid-pwned")
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "machine-id"),
				[]byte("$(touch "+canary+")\n"), 0o644)
			_ = os.MkdirAll(filepath.Join(sb.hostroot, "var", "log", "journal", "bad$(id)"), 0o755)
			secret := "SECRET_F9_T2_5_JOURNALD"
			writeHostconfigVars(t, sb.vars, fmt.Sprintf(
				"kine_service_hosts:\n  - f9-t2-5\nkine_endpoint: \"postgres://u:%s@db/kine;rm -rf\"\n",
				secret,
			), "", "")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "hostconfig base and kine groups complete safely", func() error {
				m := ra.scrapeMetrics(t)
				vBase, okBase := parseMetricValue(m, "node_host_agent_hostconfig_cycles_total", `group="base"`)
				vKine, okKine := parseMetricValue(m, "node_host_agent_hostconfig_cycles_total", `group="kine"`, `result="error"`)
				if !okBase || vBase < 1 || !okKine || vKine < 1 {
					return fmt.Errorf("base=(%v,%v) kine=(%v,%v)", okBase, vBase, okKine, vKine)
				}
				return nil
			})
			if _, statErr := os.Stat(canary); !os.IsNotExist(statErr) {
				t.Fatalf("hostile /etc/machine-id executed shell injection canary %s", canary)
			}
			if strings.Contains(ra.logsCombined(), secret) {
				t.Fatalf("secret %q leaked in logs:\n%s", secret, ra.logsCombined())
			}
		})
	})

	t.Run("F10_KinedbAndEtcdguardBoundary", func(t *testing.T) {
		t.Run("KinedbRetentionPrunesOlderThan4Dumps", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_KINEDB":          "true",
				"NODE_HOST_AGENT_KINEDB_BACKUP_INTERVAL": "6h",
			})
			backupDir := filepath.Join(sb.hostroot, "var", "backups", "kine")
			envFile := filepath.Join(sb.hostroot, "opt", "apps", "postgres", ".env")
			_ = os.WriteFile(envFile, []byte("POSTGRES_USER=postgres\nPOSTGRES_PASSWORD=pw\n"), 0o600)
			installFakeRuntimeForKinedb(t, sb, false, false, 0)

			// Pre-seed 5 aged dumps (> 6h old) so backupVerify generates a 6th and prunes down to <= 4.
			base := time.Now().Add(-10 * time.Hour)
			for i := 0; i < 5; i++ {
				p := filepath.Join(backupDir, fmt.Sprintf("kine-%d.dump", 1700000000+i))
				_ = os.WriteFile(p, []byte("PGDMP-old"), 0o600)
				mt := base.Add(time.Duration(i) * time.Minute)
				_ = os.Chtimes(p, mt, mt)
			}

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 8*time.Second, 100*time.Millisecond, "retention prunes to <= 4 dumps", func() error {
				dumps, _ := filepath.Glob(filepath.Join(backupDir, "kine-*.dump"))
				if len(dumps) == 0 || len(dumps) > 4 {
					return fmt.Errorf("dumps count=%d want 1..4", len(dumps))
				}
				return nil
			})
		})

		t.Run("KinedbInvalidMagicTriggersRegen", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_KINEDB":          "true",
				"NODE_HOST_AGENT_KINEDB_BACKUP_INTERVAL": "6h",
			})
			backupDir := filepath.Join(sb.hostroot, "var", "backups", "kine")
			envFile := filepath.Join(sb.hostroot, "opt", "apps", "postgres", ".env")
			_ = os.WriteFile(envFile, []byte("POSTGRES_USER=postgres\nPOSTGRES_PASSWORD=pw\n"), 0o600)
			installFakeRuntimeForKinedb(t, sb, false, false, 0)

			bad := filepath.Join(backupDir, "kine-1700000001.dump")
			_ = os.WriteFile(bad, []byte("BAD_MAGIC"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 8*time.Second, 100*time.Millisecond, "invalid magic regenerated with valid 0600 dump", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "kine_db_backup_valid")
				if !ok || v != 1 {
					return fmt.Errorf("kine_db_backup_valid ok=%v v=%v", ok, v)
				}
				return nil
			})
		})

		t.Run("EtcdguardZeroByteSnapshotRejected", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE": "true",
				"NODE_HOST_AGENT_CONTROLLER_INTERVAL":      "400ms",
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
    : > "$last"
    ;;
esac
exit 0
`, sb.toolLog))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "zero-byte snapshot rejected", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_controllerhygiene_cycles_total", `check="etcd-quota"`, `result="snapshot_error"`)
				if !ok || v < 1 {
					return fmt.Errorf("snapshot_error ok=%v v=%v", ok, v)
				}
				return nil
			})
			snaps, _ := filepath.Glob(filepath.Join(backupDir, "premaint-*.db"))
			if len(snaps) != 0 {
				t.Fatalf("zero-byte snapshot published: %v", snaps)
			}
		})

		t.Run("EtcdguardCorruptAlarmBlocksSnapshotAndRescue", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE": "true",
				"NODE_HOST_AGENT_CONTROLLER_INTERVAL":      "400ms",
				"NODE_HOST_AGENT_ETCD_DB_SIZE_LIMIT":       "1000",
			})
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sb.k0s, "pki", "etcd", "ca.crt"), []byte("CA"), 0o644)

			installFakeTool(t, sb.k0s, filepath.Join("bin", "etcdctl"), fmt.Sprintf(`#!/bin/sh
echo "etcdctl $*" >> %q
case "$*" in
  *"endpoint status"*) echo '[{"Endpoint":"127.0.0.1:2379","Status":{"dbSize":2000,"dbSizeInUse":1500,"leader":1,"raftTerm":2,"version":"3.5.0"}}]' ;;
  *"alarm list"*) echo "memberID:1 alarm:CORRUPT" ;;
esac
exit 0
`, sb.toolLog))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "corrupt alarm blocks snapshot and rescue", func() error {
				m := ra.scrapeMetrics(t)
				v, ok := parseMetricValue(m, "node_host_agent_controllerhygiene_etcd_corrupt_alarm")
				if !ok || v != 1 {
					return fmt.Errorf("corrupt alarm metric ok=%v v=%v", ok, v)
				}
				return nil
			})
			b, _ := os.ReadFile(sb.toolLog)
			if strings.Contains(string(b), "snapshot save") {
				t.Fatalf("snapshot save ran despite CORRUPT alarm:\n%s", string(b))
			}
		})

		t.Run("EtcdguardMissingPKISkipsCleanly", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE": "true",
				"NODE_HOST_AGENT_CONTROLLER_INTERVAL":      "400ms",
			})
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			installFakeTool(t, sb.k0s, filepath.Join("bin", "etcdctl"), "#!/bin/sh\nexit 0\n")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "missing etcd pki yields no_etcd_pki", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_controllerhygiene_cycles_total", `check="etcd-quota"`, `result="no_etcd_pki"`)
				if !ok || v < 1 {
					return fmt.Errorf("no_etcd_pki ok=%v v=%v", ok, v)
				}
				return nil
			})
		})
	})

	t.Run("F13_CgroupThrottleBoundary", func(t *testing.T) {
		t.Run("HostBusyBelowIdleFloorSuppressesThrottle", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			uid := "11111111-0000-0000-0000-000000000001"
			api.setNode(makeNode("f13-t2-1", "10.244.0.0/24"))
			api.setPod(makePod("default", "busy-host", uid, "f13-t2-1"))

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "300ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f13-t2-1",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod11111111_0000_0000_0000_000000000001.slice")
			_ = os.MkdirAll(sliceDir, 0o755)
			_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"), []byte("nr_periods 100\nnr_throttled 0\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			// Idle ratio 0.20 (< 0.40 floor), synchronized on cycle boundaries.
			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			for i := 1; i <= 5; i++ {
				_ = os.WriteFile(filepath.Join(sb.proc, "stat"),
					[]byte(fmt.Sprintf("cpu  %d 0 100 %d 0 0 0 0\n", 100+i*80, 1000+i*20)), 0o644)
				_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"),
					[]byte(fmt.Sprintf("nr_periods %d\nnr_throttled %d\n", 100+i*100, i*90)), 0o644)
				ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			}
			if _, err := os.Stat(filepath.Join(sb.state, "last-suspect-cgroup-cfs-"+uid)); !os.IsNotExist(err) {
				t.Fatalf("CFS suspect written despite host idle < 40%%")
			}
		})

		t.Run("PeriodsDeltaBelow20Ignored", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			uid := "11111111-0000-0000-0000-000000000002"
			api.setNode(makeNode("f13-t2-2", "10.244.0.0/24"))
			api.setPod(makePod("default", "low-periods", uid, "f13-t2-2"))

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "300ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f13-t2-2",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod11111111_0000_0000_0000_000000000002.slice")
			_ = os.MkdirAll(sliceDir, 0o755)
			_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"), []byte("nr_periods 100\nnr_throttled 0\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			for i := 1; i <= 5; i++ {
				_ = os.WriteFile(filepath.Join(sb.proc, "stat"),
					[]byte(fmt.Sprintf("cpu  %d 0 100 %d 0 0 0 0\n", 100+i*10, 1000+i*100)), 0o644)
				_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"),
					[]byte(fmt.Sprintf("nr_periods %d\nnr_throttled %d\n", 100+i*19, i*19)), 0o644)
				ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			}
			if _, err := os.Stat(filepath.Join(sb.state, "last-suspect-cgroup-cfs-"+uid)); !os.IsNotExist(err) {
				t.Fatalf("CFS suspect written despite dPeriods < 20")
			}
		})

		t.Run("ThrottleRatioExact50PctBoundary", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			uid := "11111111-0000-0000-0000-000000000003"
			api.setNode(makeNode("f13-t2-3", "10.244.0.0/24"))
			api.setPod(makePod("default", "exact-50", uid, "f13-t2-3"))

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "250ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f13-t2-3",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod11111111_0000_0000_0000_000000000003.slice")
			_ = os.MkdirAll(sliceDir, 0o755)
			_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"), []byte("nr_periods 100\nnr_throttled 0\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			for i := 1; i <= 4; i++ {
				_ = os.WriteFile(filepath.Join(sb.proc, "stat"),
					[]byte(fmt.Sprintf("cpu  %d 0 100 %d 0 0 0 0\n", 100+i*10, 1000+i*100)), 0o644)
				_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"),
					[]byte(fmt.Sprintf("nr_periods %d\nnr_throttled %d\n", 100+i*100, i*50)), 0o644)
				ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			}
			if _, err := os.Stat(filepath.Join(sb.state, "last-suspect-cgroup-cfs-"+uid)); !os.IsNotExist(err) {
				t.Fatalf("exact 0.50 ratio should NOT trigger (>0.50 required)")
			}
		})

		t.Run("VanishedPodSlicePrunesState", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			uid := "11111111-0000-0000-0000-000000000004"
			api.setNode(makeNode("f13-t2-4", "10.244.0.0/24"))
			api.setPod(makePod("default", "vanish-pod", uid, "f13-t2-4"))

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "250ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f13-t2-4",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod11111111_0000_0000_0000_000000000004.slice")
			_ = os.MkdirAll(sliceDir, 0o755)
			_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"), []byte("nr_periods 100\nnr_throttled 0\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			// 2 throttled deltas (<3), then remove slice dir, run prune cycle, recreate with 1 delta.
			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			for i := 1; i <= 2; i++ {
				_ = os.WriteFile(filepath.Join(sb.proc, "stat"),
					[]byte(fmt.Sprintf("cpu  %d 0 100 %d 0 0 0 0\n", 100+i*10, 1000+i*100)), 0o644)
				_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"),
					[]byte(fmt.Sprintf("nr_periods %d\nnr_throttled %d\n", 100+i*100, i*80)), 0o644)
				ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			}
			_ = os.RemoveAll(sliceDir)
			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			_ = os.MkdirAll(sliceDir, 0o755)
			_ = os.WriteFile(filepath.Join(sliceDir, "cpu.stat"), []byte("nr_periods 1000\nnr_throttled 800\n"), 0o644)
			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)

			if _, err := os.Stat(filepath.Join(sb.state, "last-suspect-cgroup-cfs-"+uid)); !os.IsNotExist(err) {
				t.Fatalf("vanished slice retained stale streak across deletion")
			}
		})

		t.Run("MissingKubepodsSliceAbortsCleanly", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f13-t2-5", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "300ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f13-t2-5",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "missing kubepods.slice aborts cleanly", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="cgroup-pod-throttle"`, `result="abort"`)
				if !ok || v < 1 {
					return fmt.Errorf("abort ok=%v v=%v", ok, v)
				}
				return nil
			})
		})
	})

	t.Run("F19_PerfMemoryBoundary", func(t *testing.T) {
		t.Run("CiliumUnixSocket4MiBCapAnd500Error", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f19-t2-1", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "350ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f19-t2-1",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			taskDir := filepath.Join(sb.ctrTaskRoot, strings.Repeat("5", 64))
			_ = os.MkdirAll(taskDir, 0o755)
			_ = os.WriteFile(filepath.Join(taskDir, "config.json"),
				[]byte(`{"annotations":{"io.kubernetes.pod.uid":"55555555-5555-5555-5555-555555555555","io.kubernetes.container.name":"cilium-agent"}}`), 0o644)
			_ = os.WriteFile(filepath.Join(taskDir, "init.pid"), []byte("0\n"), 0o644)

			bigPayload := strings.Repeat("A", 5<<20)
			var hits atomic.Int64
			sb.envMap["NODE_HOST_AGENT_CILIUM_SOCKET"] = startMockCiliumUnixServer(t, sb.envMap["NODE_HOST_AGENT_CILIUM_SOCKET"], func(w http.ResponseWriter, r *http.Request) {
				if hits.Add(1)%2 == 1 {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte("err"))
					return
				}
				_, _ = w.Write([]byte(bigPayload))
			})

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "cilium-init-stuck aborts cleanly on 500/oversize", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="cilium-init-stuck"`, `result="abort"`)
				if !ok || v < 1 {
					return fmt.Errorf("abort ok=%v v=%v", ok, v)
				}
				return nil
			})
		})

		t.Run("CiliumUnixSocketMalformedJSON", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f19-t2-2", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "350ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f19-t2-2",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			taskDir := filepath.Join(sb.ctrTaskRoot, strings.Repeat("6", 64))
			_ = os.MkdirAll(taskDir, 0o755)
			_ = os.WriteFile(filepath.Join(taskDir, "config.json"),
				[]byte(`{"annotations":{"io.kubernetes.pod.uid":"66666666-6666-6666-6666-666666666666","io.kubernetes.container.name":"cilium-agent"}}`), 0o644)
			_ = os.WriteFile(filepath.Join(taskDir, "init.pid"), []byte("0\n"), 0o644)

			sb.envMap["NODE_HOST_AGENT_CILIUM_SOCKET"] = startMockCiliumUnixServer(t, sb.envMap["NODE_HOST_AGENT_CILIUM_SOCKET"], func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("{corrupt-json"))
			})

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "malformed json handled without panic", func() error {
				if code, _ := reqHTTPGet(t, ra.healthzURL()); code != http.StatusOK {
					return fmt.Errorf("healthz=%d", code)
				}
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="cilium-init-stuck"`)
				if !ok || v < 2 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
		})

		t.Run("MissingCiliumSocketAndApiproberSocket", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_APIPROBER":   "true",
				"NODE_HOST_AGENT_APIPROBER_INTERVAL": "300ms",
			})
			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "missing socket yields no_socket", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_apiprober_cycles_total", `result="no_socket"`)
				if !ok || v < 1 {
					return fmt.Errorf("no_socket ok=%v v=%v", ok, v)
				}
				return nil
			})
		})

		t.Run("APIProberOversizeNon200Body", func(t *testing.T) {
			t.Parallel()
			bigBody := strings.Repeat("Z", 2<<20)
			srv, _, _, _ := newSelfSignedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(bigBody))
			}))
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
			sb.envMap["NODE_HOST_AGENT_APIPROBER_SOCKET"] = startMockHAProxyUnixSocket(t, sb.envMap["NODE_HOST_AGENT_APIPROBER_SOCKET"], "api_local_back", "ctrl1", strings.TrimPrefix(srv.URL, "https://"))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "apiprober handles 2MiB 500 body cleanly", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_apiprober_cycles_total")
				if !ok || v < 2 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
		})

		t.Run("ScrapesDoNotLeakGoroutines", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTMETRICS": "true",
				"NODE_HOST_AGENT_LATCH_INTERVAL":     "250ms",
			})
			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			var wg sync.WaitGroup
			errCh := make(chan error, 20)
			client := &http.Client{Timeout: 4 * time.Second}
			metricsURL := ra.metricsURL()
			for i := 0; i < 20; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, metricsURL, nil)
					if err != nil {
						errCh <- err
						return
					}
					resp, err := client.Do(req)
					if err != nil {
						errCh <- err
						return
					}
					_, rerr := io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<20))
					_ = resp.Body.Close()
					if rerr != nil {
						errCh <- rerr
						return
					}
					if resp.StatusCode != http.StatusOK {
						errCh <- fmt.Errorf("GET %s status=%d", metricsURL, resp.StatusCode)
					}
				}()
			}
			wg.Wait()
			close(errCh)
			for err := range errCh {
				t.Fatalf("concurrent scrape failed: %v", err)
			}
			m := ra.scrapeMetrics(t)
			g, ok := parseMetricValue(m, "go_goroutines")
			if !ok || g > 200 {
				t.Fatalf("unexpected goroutine count after concurrent scrapes: ok=%v g=%v", ok, g)
			}
		})
	})

	t.Run("F20_CIPipelineBoundary", func(t *testing.T) {
		t.Run("ReleaseWorkflowExcludesMarkdown", func(t *testing.T) {
			t.Parallel()
			b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", ".github", "workflows", "release-node-host-agent.yml"))
			if err != nil {
				t.Fatal(err)
			}
			s := string(b)
			if !strings.Contains(s, "!**/*.md") {
				t.Fatalf("release-node-host-agent.yml missing '!**/*.md'")
			}
			if !strings.Contains(s, "amd64_alias: true") {
				t.Fatalf("release-node-host-agent.yml missing amd64_alias: true")
			}
		})

		t.Run("ReleaseWorkflowLibPathsMatchesPaths", func(t *testing.T) {
			t.Parallel()
			b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", ".github", "workflows", "release-node-host-agent.yml"))
			if err != nil {
				t.Fatal(err)
			}
			var wf struct {
				On struct {
					Push struct {
						Paths []string `yaml:"paths"`
					} `yaml:"push"`
				} `yaml:"on"`
				Jobs map[string]struct {
					With struct {
						LibPaths string `yaml:"lib_paths"`
					} `yaml:"with"`
				} `yaml:"jobs"`
			}
			if err := yaml.Unmarshal(b, &wf); err != nil {
				t.Fatal(err)
			}
			pathLibs := map[string]bool{}
			for _, p := range wf.On.Push.Paths {
				if strings.HasPrefix(p, "libs/") {
					pathLibs[strings.TrimSuffix(p, "/**")] = true
				}
			}
			jobLibs := map[string]bool{}
			for _, j := range wf.Jobs {
				for _, f := range strings.Fields(j.With.LibPaths) {
					jobLibs[strings.TrimSuffix(strings.TrimSuffix(f, "/**"), "/")] = true
				}
			}
			if len(pathLibs) == 0 || len(pathLibs) != len(jobLibs) {
				t.Fatalf("release-node-host-agent.yml paths(%v) != lib_paths(%v)", pathLibs, jobLibs)
			}
			for k := range pathLibs {
				if !jobLibs[k] {
					t.Fatalf("lib %q in push paths missing from with.lib_paths %v", k, jobLibs)
				}
			}
		})

		t.Run("DockerfileNoGoWorkCopied", func(t *testing.T) {
			t.Parallel()
			b, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
			if err != nil {
				t.Fatal(err)
			}
			var nonComments []string
			for line := range strings.SplitSeq(string(b), "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || strings.HasPrefix(trimmed, "#") {
					continue
				}
				nonComments = append(nonComments, trimmed)
			}
			stripped := strings.Join(nonComments, "\n")
			reCopyGoWork := regexp.MustCompile(`(?im)^\s*COPY\b.*\bgo\.work\b`)
			if reCopyGoWork.MatchString(stripped) || strings.Contains(stripped, "go.work") {
				t.Fatalf("Dockerfile must not COPY go.work (CI uses GOWORK=off parity):\n%s", stripped)
			}
			reFromAlpine := regexp.MustCompile(`(?im)^\s*FROM\s+(?:--platform=\S+\s+)?golang:1\.27\.4-alpine(?:\s|$)`)
			if !reFromAlpine.MatchString(stripped) {
				t.Fatalf("Dockerfile builder stage must use FROM golang:1.27.4-alpine (R4.3):\n%s", stripped)
			}
			// Collapse backslash line continuations before checking apk add packages for bash.
			joined := strings.ReplaceAll(stripped, "\\\n", " ")
			reApkBash := regexp.MustCompile(`(?im)\bapk\s+add\b[^\n;]*\bbash\b`)
			if reApkBash.MatchString(joined) {
				t.Fatalf("Dockerfile runtime stage must not install unused bash in apk add (R4.3):\n%s", joined)
			}
		})

		t.Run("CiYmlNoRunIDCacheKey", func(t *testing.T) {
			t.Parallel()
			b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", ".github", "workflows", "ci.yml"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "github.run_id") {
				t.Fatalf("ci.yml still embeds github.run_id in cache keys causing 100%% miss/thrash")
			}
		})

		t.Run("CiYmlChecksNoDockerDetectNeedsAndHasGovulncheck", func(t *testing.T) {
			t.Parallel()
			b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", ".github", "workflows", "ci.yml"))
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Jobs struct {
					Checks struct {
						Needs any `yaml:"needs"`
					} `yaml:"checks"`
				} `yaml:"jobs"`
			}
			if err := yaml.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}
			if doc.Jobs.Checks.Needs != nil {
				t.Fatalf("ci.yml jobs.checks still has needs=%v (should drop needs: docker-detect)", doc.Jobs.Checks.Needs)
			}
			if !strings.Contains(string(b), "govulncheck") {
				t.Fatalf("ci.yml missing govulncheck step")
			}
		})
	})

	t.Run("F23_UnitCoverageTargetsBoundary", func(t *testing.T) {
		t.Run("SystemdOOMDInactiveUnitClearsLatch", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f23-t2-1", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f23-t2-1",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sb.state, "state-systemd-oomd-kill"), []byte("1700000000"), 0o644)
			installFakeTool(t, sb.fakebin, "systemctl", "#!/bin/sh\nif [ \"$1\" = \"is-active\" ] && [ \"$2\" = \"systemd-oomd.service\" ]; then echo inactive; exit 3; fi\necho active\nexit 0\n")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "inactive systemd-oomd clears latch", func() error {
				if _, err := os.Stat(filepath.Join(sb.state, "state-systemd-oomd-kill")); !os.IsNotExist(err) {
					return fmt.Errorf("latch still present")
				}
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="systemd-oomd"`, `result="gated"`)
				if !ok || v < 1 {
					return fmt.Errorf("gated ok=%v v=%v", ok, v)
				}
				return nil
			})
		})

		t.Run("NetfilterLockReleasedBefore3Cycles", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f23-t2-2", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":                   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL":                 "300ms",
				"NODE_HOST_AGENT_NETFILTER_GUARD_INTERVAL_SECONDS": "1",
				"NODE_HOST_AGENT_NODE_NAME":                        "f23-t2-2",
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

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			// Wait 1 cycle, then unlock before cycle 3.
			eventually(t, 4*time.Second, 50*time.Millisecond, "1 netfilter-guard cycle", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="netfilter-guard"`)
				if !ok || v < 1 {
					return fmt.Errorf("waiting cycle 1")
				}
				return nil
			})
			_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
			_ = lf.Close()

			eventually(t, 4*time.Second, 100*time.Millisecond, "3+ cycles after unlock", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="netfilter-guard"`)
				if !ok || v < 4 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
			if _, err := os.Stat(filepath.Join(sb.state, "state-netfilter-locked")); !os.IsNotExist(err) {
				t.Fatalf("netfilter-locked entered despite lock release before 3 cycles")
			}
		})

		t.Run("NetfilterLegacyEmptyTablesSkipsProbe", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f23-t2-3", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":                     "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL":                   "300ms",
				"NODE_HOST_AGENT_NETFILTER_GUARD_INTERVAL_SECONDS":   "1",
				"NODE_HOST_AGENT_NETFILTER_GUARD_LEGACY_TABLE_PROBE": "true",
				"NODE_HOST_AGENT_NODE_NAME":                          "f23-t2-3",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sb.proc, "1", "net", "ip_tables_names"), []byte(""), 0o644)
			installFakeTool(t, sb.fakebin, "iptables-legacy-save", "#!/bin/sh\necho '-A INPUT -j ACCEPT'\n")

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "legacy probe skipped when ip_tables_names empty", func() error {
				b, err := os.ReadFile(filepath.Join(sb.textfile, "node-agent-hygiene.prom"))
				if err != nil {
					return err
				}
				v, ok := parseMetricValue(string(b), "node_agent_iptables_legacy_leaked_rules")
				if !ok || v != 0 {
					return fmt.Errorf("leaked rules ok=%v v=%v", ok, v)
				}
				return nil
			})
		})

		t.Run("CSIGuard403FallbackToNodeAnnotation", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.csiNodeStatusCode = http.StatusForbidden
			n := makeNode("f23-t2-4", "10.244.0.0/24")
			n.Annotations["csi.volume.kubernetes.io/nodeid"] = `{"csi.fallback.io":"f23-t2-4"}`
			api.setNode(n)

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "400ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f23-t2-4",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sb.pluginsReg, "csi.fallback.io-reg.sock"), []byte("sock"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "csi-registration-guard 403 falls back to node annotation", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="csi-registration-guard"`, `result="ok"`)
				if !ok || v < 1 {
					return fmt.Errorf("csi-registration-guard ok=%v v=%v", ok, v)
				}
				return nil
			})
		})

		t.Run("DiskBloatEmptyDirsAndMissingMountinfo", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f23-t2-5", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":       "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL":     "400ms",
				"NODE_HOST_AGENT_WLAYER_SNAPSHOTS_DIR": "/nonexistent/wlayer",
				"NODE_HOST_AGENT_NODE_NAME":            "f23-t2-5",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_MOUNTINFO_FILE"], []byte("malformed-line\n10 1\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			_, k0sErr := os.Stat("/host/var/lib/k0s")
			wantDiskBloatResult := `result="ok"`
			if k0sErr != nil {
				wantDiskBloatResult = `result="abort"`
			}

			eventually(t, 5*time.Second, 100*time.Millisecond, "writable-layer-scan, mountinfo-hygiene, and disk-bloat survive missing dir and malformed mountinfo", func() error {
				if code, _ := reqHTTPGet(t, ra.healthzURL()); code != http.StatusOK {
					return fmt.Errorf("healthz=%d", code)
				}
				m := ra.scrapeMetrics(t)
				if v, ok := parseMetricValue(m, "node_host_agent_workerhygiene_cycles_total", `check="writable-layer-scan"`, `result="ok"`); !ok || v < 1 {
					return fmt.Errorf("writable-layer-scan ok=(%v,%v)", ok, v)
				}
				if v, ok := parseMetricValue(m, "node_host_agent_workerhygiene_cycles_total", `check="mountinfo-hygiene"`, `result="ok"`); !ok || v < 1 {
					return fmt.Errorf("mountinfo-hygiene ok=(%v,%v)", ok, v)
				}
				if v, ok := parseMetricValue(m, "node_host_agent_workerhygiene_cycles_total", `check="disk-bloat"`, wantDiskBloatResult); !ok || v < 1 {
					return fmt.Errorf("disk-bloat %s ok=(%v,%v)", wantDiskBloatResult, ok, v)
				}
				return nil
			})
		})
	})

	t.Run("F24_CgroupMemoryHighBoundary", func(t *testing.T) {
		t.Run("NodeThrashLatchSuppressesPodThrottle", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			uid := "55555555-6666-7777-8888-999999999991"
			api.setNode(makeNode("f24-t2-1", "10.244.0.0/24"))
			api.setPod(makePod("default", "suppressed", uid, "f24-t2-1"))

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "300ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f24-t2-1",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sb.state, "state-psi-memory-thrash"), []byte("1700000000"), 0o644)

			sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod55555555_6666_7777_8888_999999999991.slice")
			_ = os.MkdirAll(sliceDir, 0o755)
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.pressure"),
				[]byte("some avg10=70.00 avg60=65.00 total=100\nfull avg10=70.00 avg60=65.00 total=100\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"), []byte("high 10\nmax 0\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			for i := 1; i <= 4; i++ {
				_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"),
					[]byte(fmt.Sprintf("high %d\nmax 0\n", 10+i*10)), 0o644)
				ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			}
			for _, ev := range api.getEvents() {
				if ev.Reason == "PodMemoryHighThrottled" {
					t.Fatalf("pod throttle fired while state-psi-memory-thrash active")
				}
			}
		})

		t.Run("ThresholdBoundaries", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			uid := "55555555-6666-7777-8888-999999999992"
			api.setNode(makeNode("f24-t2-2", "10.244.0.0/24"))
			api.setPod(makePod("default", "boundary-pod", uid, "f24-t2-2"))

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "250ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f24-t2-2",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod55555555_6666_7777_8888_999999999992.slice")
			_ = os.MkdirAll(sliceDir, 0o755)
			// Exactly 40.00 (not > 40.0).
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.pressure"),
				[]byte("some avg10=10.00 avg60=10.00 total=100\nfull avg10=40.00 avg60=40.00 total=100\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"), []byte("high 10\nmax 0\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			for i := 1; i <= 4; i++ {
				_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"),
					[]byte(fmt.Sprintf("high %d\nmax 0\n", 10+i*10)), 0o644)
				ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			}
			for _, ev := range api.getEvents() {
				if ev.Reason == "PodMemoryHighThrottled" {
					t.Fatalf("exact avg60=40.00 boundary should not fire (>40 required)")
				}
			}
		})

		t.Run("UnresolvablePodUIDLogsAndSkipsEvent", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f24-t2-3", "10.244.0.0/24"))
			// Intentionally do NOT register Pod in fakeE2EAPIServer.
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "250ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f24-t2-3",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod55555555_6666_7777_8888_999999999993.slice")
			_ = os.MkdirAll(sliceDir, 0o755)
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.pressure"),
				[]byte("some avg10=70.00 avg60=60.00 total=100\nfull avg10=70.00 avg60=60.00 total=100\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"), []byte("high 10\nmax 0\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			for i := 1; i <= 4; i++ {
				_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"),
					[]byte(fmt.Sprintf("high %d\nmax 0\n", 10+i*10)), 0o644)
				ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			}
			eventually(t, 5*time.Second, 100*time.Millisecond, "unresolvable pod logged without posting event", func() error {
				b, err := os.ReadFile(sb.logFile)
				if err != nil {
					return err
				}
				if !strings.Contains(string(b), "pod unresolvable") {
					return fmt.Errorf("missing 'pod unresolvable' in:\n%s", string(b))
				}
				return nil
			})
			if len(api.getEvents()) != 0 {
				t.Fatalf("event posted for unresolvable pod UID")
			}
		})

		t.Run("UnreadableMemoryPressureHoldsDedup", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			uid := "55555555-6666-7777-8888-999999999994"
			api.setNode(makeNode("f24-t2-4", "10.244.0.0/24"))
			api.setPod(makePod("default", "hold-dedup", uid, "f24-t2-4"))

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "250ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f24-t2-4",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			sliceDir := filepath.Join(sb.cgroup, "kubepods.slice", "kubepods-pod55555555_6666_7777_8888_999999999994.slice")
			_ = os.MkdirAll(sliceDir, 0o755)
			mp := filepath.Join(sliceDir, "memory.pressure")
			_ = os.WriteFile(mp, []byte("some avg10=65.00 avg60=60.00 total=100\nfull avg10=65.00 avg60=60.00 total=100\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"), []byte("high 10\nmax 0\n"), 0o644)
			t.Cleanup(func() { _ = os.Chmod(mp, 0o644) })

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			for i := 1; i <= 4; i++ {
				_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"),
					[]byte(fmt.Sprintf("high %d\nmax 0\n", 10+i*10)), 0o644)
				ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			}
			eventually(t, 5*time.Second, 100*time.Millisecond, "initial event fired", func() error {
				if len(api.getEvents()) < 1 {
					return fmt.Errorf("no event")
				}
				return nil
			})
			before := len(api.getEvents())
			// Corrupt memory.pressure -> inconclusive for >=2 cycles; restore -> must NOT re-emit.
			_ = os.WriteFile(mp, []byte("corrupt"), 0o644)
			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)

			_ = os.WriteFile(mp, []byte("some avg10=65.00 avg60=60.00 total=100\nfull avg10=65.00 avg60=60.00 total=100\n"), 0o644)
			_ = os.WriteFile(filepath.Join(sliceDir, "memory.events"), []byte("high 100\nmax 0\n"), 0o644)
			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			ra.waitNextWorkerHygieneCycle(t, "cgroup-pod-throttle", 5*time.Second)
			if after := len(api.getEvents()); after != before {
				t.Fatalf("episode dedup flapped on unreadable pressure: before=%d after=%d", before, after)
			}
		})

		t.Run("CgroupV1MissingKubepodsDegradesGracefully", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f24-t2-5", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "300ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f24-t2-5",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "missing kubepods degrades cleanly", func() error {
				if code, _ := reqHTTPGet(t, ra.healthzURL()); code != http.StatusOK {
					return fmt.Errorf("healthz=%d", code)
				}
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="cgroup-pod-throttle"`, `result="abort"`)
				if !ok || v < 1 {
					return fmt.Errorf("abort ok=%v v=%v", ok, v)
				}
				return nil
			})
		})
	})

	t.Run("F26_ContainerdShimStaleMountBoundary", func(t *testing.T) {
		t.Run("APIUnreachableFailsClosed", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.podsStatusCode = http.StatusInternalServerError
			api.setNode(makeNode("f26-t2-1", "10.244.0.0/24"))

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "350ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f26-t2-1",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			deadMount := filepath.Join(sb.kubeletPods, "dead-api-down", "volumes", "kubernetes.io~empty-dir", "c")
			_ = os.MkdirAll(deadMount, 0o755)
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_MOUNTINFO_FILE"],
				[]byte(fmt.Sprintf("210 1 8:1 / %s rw - tmpfs tmpfs rw\n", deadMount)), 0o644)

			_, pinPID := spawnDummySleep(t, 30)
			sid := strings.Repeat("a", 64)
			writeProcTask(t, sb.proc, pinPID, "containerd-shim", "S", 0,
				"0::/system.slice/k0sworker.service\n",
				[]string{"containerd-shim-runc-v2", "-namespace", "k8s.io", "-id", sid, "-address", sb.envMap["NODE_HOST_AGENT_CONTAINERD_SOCKET"]},
				10*time.Minute)
			_ = os.WriteFile(filepath.Join(sb.proc, strconv.Itoa(pinPID), "mountinfo"),
				[]byte(fmt.Sprintf("210 1 8:1 / %s rw - tmpfs tmpfs rw\n", deadMount)), 0o644)
			_ = os.Symlink(deadMount, filepath.Join(sb.proc, strconv.Itoa(pinPID), "fd", "4"))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "3 cycles while API unreachable", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="mountinfo-hygiene"`)
				if !ok || v < 3 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
			if !pidAlive(pinPID) {
				t.Fatalf("PID killed while API unreachable (must fail closed)")
			}
		})

		t.Run("MaintenanceHoldSuppressesDestructiveHeal", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			n := makeNode("f26-t2-2", "10.244.0.0/24")
			n.Annotations["passiontech.dev/cluster-maintenance-until"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
			api.setNode(n)

			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "350ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f26-t2-2",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			deadMount := filepath.Join(sb.kubeletPods, "dead-maint", "volumes", "kubernetes.io~empty-dir", "c")
			_ = os.MkdirAll(deadMount, 0o755)
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_MOUNTINFO_FILE"],
				[]byte(fmt.Sprintf("211 1 8:1 / %s rw - tmpfs tmpfs rw\n", deadMount)), 0o644)

			_, pinPID := spawnDummySleep(t, 30)
			sid := strings.Repeat("b", 64)
			writeProcTask(t, sb.proc, pinPID, "containerd-shim", "S", 0,
				"0::/system.slice/k0sworker.service\n",
				[]string{"containerd-shim-runc-v2", "-namespace", "k8s.io", "-id", sid, "-address", sb.envMap["NODE_HOST_AGENT_CONTAINERD_SOCKET"]},
				10*time.Minute)
			_ = os.WriteFile(filepath.Join(sb.proc, strconv.Itoa(pinPID), "mountinfo"),
				[]byte(fmt.Sprintf("211 1 8:1 / %s rw - tmpfs tmpfs rw\n", deadMount)), 0o644)
			_ = os.Symlink(deadMount, filepath.Join(sb.proc, strconv.Itoa(pinPID), "fd", "4"))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "3 cycles under maintenance hold", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="mountinfo-hygiene"`)
				if !ok || v < 3 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
			if !pidAlive(pinPID) {
				t.Fatalf("destructive kill fired during active maintenance hold")
			}
		})

		t.Run("EscapedMountPathOctal040", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f26-t2-3", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "350ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f26-t2-3",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			deadMount := filepath.Join(sb.kubeletPods, "dead-octal", "volumes", "kubernetes.io~empty-dir", "my dir")
			escaped := strings.ReplaceAll(deadMount, " ", `\040`)
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_MOUNTINFO_FILE"],
				[]byte(fmt.Sprintf("212 1 8:1 / %s rw - tmpfs tmpfs rw\n", escaped)), 0o644)

			_, liveInitPID := spawnDummySleep(t, 60)
			sid := strings.Repeat("c", 64)
			writeLiveCtrTaskDir(t, sb.ctrTaskRoot, sid, liveInitPID)
			_, pinPID := spawnDummySleep(t, 30)
			writeProcTask(t, sb.proc, pinPID, "containerd-shim", "S", 0,
				"0::/system.slice/k0sworker.service\n",
				[]string{"containerd-shim-runc-v2", "-namespace", "k8s.io", "-id", sid, "-address", sb.envMap["NODE_HOST_AGENT_CONTAINERD_SOCKET"]},
				10*time.Minute)
			_ = os.WriteFile(filepath.Join(sb.proc, strconv.Itoa(pinPID), "mountinfo"),
				[]byte(fmt.Sprintf("212 1 8:1 / %s rw - tmpfs tmpfs rw\n", escaped)), 0o644)
			_ = os.Symlink(deadMount, filepath.Join(sb.proc, strconv.Itoa(pinPID), "fd", "4"))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "K3 decodes octal \\040 mount path", func() error {
				logBytes, _ := os.ReadFile(sb.logFile)
				cleanedLog := strings.ToLower(strings.ReplaceAll(string(logBytes), sb.root, ""))
				toolBytes, _ := os.ReadFile(sb.toolLog)
				if strings.Contains(cleanedLog, "ebusy") || strings.Contains(string(toolBytes), "umount") || !pidAlive(pinPID) {
					return nil
				}
				return fmt.Errorf("K3 octal escaped mount wedge not handled")
			})
		})

		t.Run("UnreadableProcFDErrorsFailClosed", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f26-t2-4", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "350ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f26-t2-4",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			_, pinPID := spawnDummySleep(t, 30)
			sid := strings.Repeat("d", 64)
			writeProcTask(t, sb.proc, pinPID, "containerd-shim", "S", 0,
				"0::/system.slice/k0sworker.service\n",
				[]string{"containerd-shim-runc-v2", "-namespace", "k8s.io", "-id", sid, "-address", sb.envMap["NODE_HOST_AGENT_CONTAINERD_SOCKET"]},
				10*time.Minute)
			fdDir := filepath.Join(sb.proc, strconv.Itoa(pinPID), "fd")
			_ = os.Chmod(fdDir, 0o000)
			t.Cleanup(func() { _ = os.Chmod(fdDir, 0o755) })

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "agent healthy on unreadable proc fd", func() error {
				if code, _ := reqHTTPGet(t, ra.healthzURL()); code != http.StatusOK {
					return fmt.Errorf("healthz=%d", code)
				}
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="mountinfo-hygiene"`)
				if !ok || v < 2 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
		})

		t.Run("DStateShimHoldingDeadPodMountEscalatesWithoutHanging", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f26-t2-5", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "350ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f26-t2-5",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			deadMount := filepath.Join(sb.kubeletPods, "dead-dstate", "volumes", "kubernetes.io~empty-dir", "c")
			_ = os.MkdirAll(deadMount, 0o755)
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_MOUNTINFO_FILE"],
				[]byte(fmt.Sprintf("214 1 8:1 / %s rw - tmpfs tmpfs rw\n", deadMount)), 0o644)

			// Create a valid live task dir for sid so M2 ctr-tasks does NOT misclassify
			// PID 515151 as an orphan shim and write state-pod-teardown-wedged.
			_, liveInitPID := spawnDummySleep(t, 60)
			sid := strings.Repeat("e", 64)
			taskDir := filepath.Join(sb.ctrTaskRoot, sid)
			_ = os.MkdirAll(taskDir, 0o755)
			_ = os.WriteFile(filepath.Join(taskDir, "init.pid"), []byte(strconv.Itoa(liveInitPID)+"\n"), 0o644)
			_ = os.WriteFile(filepath.Join(taskDir, "log.json"), []byte("{}\n"), 0o644)
			_ = os.WriteFile(filepath.Join(taskDir, "config.json"), []byte(`{"annotations":{}}`), 0o644)

			writeProcTask(t, sb.proc, 515151, "containerd-shim", "D", 0,
				"0::/system.slice/k0sworker.service\n",
				nil, 10*time.Minute)
			_ = os.Symlink(filepath.Join(taskDir, "work"), filepath.Join(sb.proc, "515151", "fd", "3"))
			_ = os.Symlink(deadMount, filepath.Join(sb.proc, "515151", "fd", "4"))
			_ = os.WriteFile(filepath.Join(sb.proc, "515151", "mountinfo"),
				[]byte(fmt.Sprintf("214 1 8:1 / %s rw - tmpfs tmpfs rw\n", deadMount)), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "K3 D-state shim dead-pod mount wedge escalates without hanging", func() error {
				if code, _ := reqHTTPGet(t, ra.healthzURL()); code != http.StatusOK {
					return fmt.Errorf("healthz=%d", code)
				}
				logBytes, _ := os.ReadFile(sb.logFile)
				cleanedLog := strings.ToLower(strings.ReplaceAll(string(logBytes), sb.root, ""))
				m := ra.scrapeMetrics(t)
				if strings.Contains(cleanedLog, "ebusy") ||
					(strings.Contains(cleanedLog, "mount") && strings.Contains(cleanedLog, "dead-dstate")) ||
					strings.Contains(strings.ToLower(m), "ebusy") {
					return nil
				}
				return fmt.Errorf("expected K3 EBUSY / dead-dstate mount escalation signal for D-state shim")
			})
		})
	})

	t.Run("F28Agent_CgroupV2AndKubeletBoundary", func(t *testing.T) {
		t.Run("MissingK0sUnitAndConfigDegradesCleanly", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTMETRICS": "true",
				"NODE_HOST_AGENT_NODE_NAME":          "f28-t2-1",
			})
			_ = os.WriteFile(filepath.Join(sb.cgroup, "cgroup.controllers"), []byte("cpu memory\n"), 0o644)
			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			m := ra.scrapeMetrics(t)
			if strings.Contains(m, "node_k0s_config_drift{") {
				t.Fatalf("worker without k0scontroller.service emitted controller drift:\n%s", m)
			}
		})

		t.Run("UnparseableK0sYamlFailsSafe", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTMETRICS": "true",
				"NODE_HOST_AGENT_NODE_NAME":          "f28-t2-2",
			})
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_K0S_CONFIG"], []byte(":::bad yaml [[[\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_k0s_config_drift", `reason="unreadable"`, `key="k0s.yaml"`)
			if !ok || v != 1 {
				t.Fatalf("expected unreadable drift=1, got ok=%v v=%v", ok, v)
			}
		})

		t.Run("StandaloneModeHonorsTextfileReadiness", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTMETRICS": "true",
				"NODE_HOST_AGENT_TEXTFILE_INTERVAL":  "300ms",
				"NODE_HOST_AGENT_NODE_NAME":          "f28-t2-3",
			})
			ra := startReqAgent(t, bin, sb.envSlice(), "--standalone")
			defer ra.stopAndWait(t)

			prom := filepath.Join(sb.textfile, "node-watchdog.prom")
			eventually(t, 6*time.Second, 100*time.Millisecond, "standalone writes node-watchdog.prom", func() error {
				b, err := os.ReadFile(prom)
				if err != nil {
					return err
				}
				if !strings.Contains(string(b), "node_watchdog_state") && !strings.Contains(string(b), "node_host_agent") {
					return fmt.Errorf("unexpected prom content:\n%s", string(b))
				}
				return nil
			})
		})

		t.Run("RapidScrapesUseSnapshotCacheWithoutError", func(t *testing.T) {
			t.Parallel()
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HOSTMETRICS": "true",
				"NODE_HOST_AGENT_NODE_NAME":          "f28-t2-4",
			})
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_K0S_CONFIG"], []byte(cleanK0sYAML()), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			for i := 0; i < 10; i++ {
				if i == 5 {
					_ = os.WriteFile(sb.envMap["NODE_HOST_AGENT_K0S_CONFIG"], []byte(cleanK0sYAML()+"# touch\n"), 0o644)
				}
				m := ra.scrapeMetrics(t)
				if !strings.Contains(m, "node_k0s_config_drift") {
					t.Fatalf("scrape %d missing node_k0s_config_drift", i)
				}
			}
		})

		t.Run("NoNodeConditionChurnWhenSteady", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f28-t2-5", "10.244.0.0/24"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_REPORTER":   "true",
				"NODE_HOST_AGENT_REPORTER_INTERVAL": "250ms",
				"NODE_HOST_AGENT_NODE_NAME":         "f28-t2-5",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "initial condition sync patch and cycle", func() error {
				if api.countRequests(http.MethodPatch, "/api/v1/nodes/f28-t2-5/status") < 1 {
					return fmt.Errorf("no initial status patch yet")
				}
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_nodereporter_cycles_total", `result="ok"`)
				if !ok || v < 1 {
					return fmt.Errorf("nodereporter cycles ok=%v v=%v", ok, v)
				}
				return nil
			})
			countAtSteady := api.countRequests(http.MethodPatch, "/api/v1/nodes/f28-t2-5/status")
			cyclesAtSteady, _ := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_nodereporter_cycles_total", `result="ok"`)
			eventually(t, 5*time.Second, 50*time.Millisecond, "nodereporter advances 3 steady cycles", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_nodereporter_cycles_total", `result="ok"`)
				if !ok || v < cyclesAtSteady+3 {
					return fmt.Errorf("nodereporter cycles ok=%v v=%v want >= %.0f", ok, v, cyclesAtSteady+3)
				}
				return nil
			})
			countLater := api.countRequests(http.MethodPatch, "/api/v1/nodes/f28-t2-5/status")
			if countLater != countAtSteady {
				t.Fatalf("nodereporter churned PATCH /status during steady state: %d -> %d", countAtSteady, countLater)
			}
		})
	})

	t.Run("F31Agent_StaleUDPConntrackBoundary", func(t *testing.T) {
		t.Run("EmptyNodesListAbortsFailClosed", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "300ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f31-t2-1",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "empty nodes list aborts fail closed", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="udp-stale-socket"`, `result="abort"`)
				if !ok || v < 1 {
					return fmt.Errorf("abort ok=%v v=%v", ok, v)
				}
				return nil
			})
		})

		t.Run("NodesList500ErrorAbortsFailClosed", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.nodesStatusCode = http.StatusInternalServerError
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "300ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f31-t2-2",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "nodes 500 aborts without EndpointSlices query", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="udp-stale-socket"`, `result="abort"`)
				if !ok || v < 1 {
					return fmt.Errorf("abort ok=%v v=%v", ok, v)
				}
				return nil
			})
			if n := api.countRequests(http.MethodGet, "/apis/discovery.k8s.io/v1/endpointslices"); n != 0 {
				t.Fatalf("unexpected EndpointSlices query (%d) when Nodes failed", n)
			}
		})

		t.Run("PodsList500ErrorAbortsBeforeUDPCheck", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.podsStatusCode = http.StatusInternalServerError
			api.setNode(makeNode("f31-t2-3", "10.244.0.0/16"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "300ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f31-t2-3",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "pods 500 aborts udp-stale-socket", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="udp-stale-socket"`, `result="abort"`)
				if !ok || v < 1 {
					return fmt.Errorf("abort ok=%v v=%v", ok, v)
				}
				return nil
			})
		})

		t.Run("InvalidPodCIDROverrideWarnsAndFallsBackOrAborts", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f31-t2-4", ""))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":      "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL":    "300ms",
				"NODE_HOST_AGENT_UDP_STALE_POD_CIDRS": "not-a-cidr",
				"NODE_HOST_AGENT_NODE_NAME":           "f31-t2-4",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "invalid pod CIDR override handled safely", func() error {
				if code, _ := reqHTTPGet(t, ra.healthzURL()); code != http.StatusOK {
					return fmt.Errorf("healthz=%d", code)
				}
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="udp-stale-socket"`)
				if !ok || v < 1 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
		})

		t.Run("EndpointSlicesNotQueriedWhenNoUDPCandidates", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			api.setNode(makeNode("f31-t2-5", "10.244.0.0/16"))
			sb := newReqSandbox(t, map[string]string{
				"NODE_HOST_AGENT_ENABLE_HYGIENE":   "true",
				"NODE_HOST_AGENT_HYGIENE_INTERVAL": "300ms",
				"NODE_HOST_AGENT_NODE_NAME":        "f31-t2-5",
			})
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0sworker.service"), []byte("[Unit]\n"), 0o644)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "3 ok udp-stale-socket cycles", func() error {
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_workerhygiene_cycles_total", `check="udp-stale-socket"`, `result="ok"`)
				if !ok || v < 3 {
					return fmt.Errorf("ok=%v v=%v", ok, v)
				}
				return nil
			})
			if n := api.countRequests(http.MethodGet, "/apis/discovery.k8s.io/v1/endpointslices"); n != 0 {
				t.Fatalf("lazy EndpointSlices fetch violated: expected 0 requests, got %d", n)
			}
		})
	})

	t.Run("F33_KMSv2EncryptionBoundary", func(t *testing.T) {
		t.Run("KMSv2RestartGateHonorsSig13AutofixOff", func(t *testing.T) {
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
				"NODE_HOST_AGENT_CONTROLLER_INTERVAL":      "300ms",
				"NODE_HOST_AGENT_CONTROLLER_INSECURE_TLS":  "true",
				"NODE_HOST_AGENT_SIG13_AUTOFIX":            "off",
				"NODE_HOST_AGENT_API_SELF":                 strings.TrimPrefix(srv.URL, "https://"),
			})
			sb.ensureShortHostRoot(t)
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			writeKubeconfigFile(t, filepath.Join(sb.k0s, "pki", "admin.conf"), srv.URL, certPEM, keyPEM, caPEM)
			startMockUnixEchoServer(t, filepath.Join(sb.hostroot, "run", "k0s", "kms.sock"))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "K10 latches without restarting when sig13 autofix=off", func() error {
				latches, _ := filepath.Glob(filepath.Join(sb.state, "state-*kms*"))
				if len(latches) == 0 {
					return fmt.Errorf("expected KMSv2 latch")
				}
				return nil
			})
			toolBytes, _ := os.ReadFile(sb.toolLog)
			if strings.Contains(string(toolBytes), "restart k0scontroller") {
				t.Fatalf("restarted k0scontroller despite SIG13_AUTOFIX=off:\n%s", string(toolBytes))
			}
		})

		t.Run("KMSv2RestartGateHonorsDryRun", func(t *testing.T) {
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
				"NODE_HOST_AGENT_CONTROLLER_INTERVAL":      "300ms",
				"NODE_HOST_AGENT_CONTROLLER_INSECURE_TLS":  "true",
				"NODE_HOST_AGENT_SIG13_AUTOFIX":            "dry-run",
				"NODE_HOST_AGENT_API_SELF":                 strings.TrimPrefix(srv.URL, "https://"),
			})
			sb.ensureShortHostRoot(t)
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			writeKubeconfigFile(t, filepath.Join(sb.k0s, "pki", "admin.conf"), srv.URL, certPEM, keyPEM, caPEM)
			startMockUnixEchoServer(t, filepath.Join(sb.hostroot, "run", "k0s", "kms.sock"))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "K10 latches in dry-run mode", func() error {
				latches, _ := filepath.Glob(filepath.Join(sb.state, "state-*kms*"))
				if len(latches) == 0 {
					return fmt.Errorf("expected KMSv2 latch")
				}
				return nil
			})
			toolBytes, _ := os.ReadFile(sb.toolLog)
			if strings.Contains(string(toolBytes), "restart k0scontroller") {
				t.Fatalf("real restart fired under SIG13_AUTOFIX=dry-run:\n%s", string(toolBytes))
			}
		})

		t.Run("KMSv2EnforceRespectsMaintenanceHold", func(t *testing.T) {
			t.Parallel()
			api := newFakeE2EAPIServer(t)
			n := makeNode("f33-t2-3", "10.244.0.0/24")
			n.Annotations["passiontech.dev/cluster-maintenance-until"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
			api.setNode(n)

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
				"NODE_HOST_AGENT_CONTROLLER_INTERVAL":      "300ms",
				"NODE_HOST_AGENT_CONTROLLER_INSECURE_TLS":  "true",
				"NODE_HOST_AGENT_SIG13_AUTOFIX":            "enforce",
				"NODE_HOST_AGENT_API_SELF":                 strings.TrimPrefix(srv.URL, "https://"),
				"NODE_HOST_AGENT_NODE_NAME":                "f33-t2-3",
			})
			sb.ensureShortHostRoot(t)
			kc := filepath.Join(sb.root, "kubeconfig")
			api.writeKubeconfig(t, kc)
			sb.envMap["KUBECONFIG"] = kc
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			writeKubeconfigFile(t, filepath.Join(sb.k0s, "pki", "admin.conf"), srv.URL, certPEM, keyPEM, caPEM)
			startMockUnixEchoServer(t, filepath.Join(sb.hostroot, "run", "k0s", "kms.sock"))

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 6*time.Second, 100*time.Millisecond, "K10 latches while maintenance hold suppresses restart", func() error {
				latches, _ := filepath.Glob(filepath.Join(sb.state, "state-*kms*"))
				if len(latches) == 0 {
					return fmt.Errorf("expected KMSv2 latch")
				}
				return nil
			})
			toolBytes, _ := os.ReadFile(sb.toolLog)
			if strings.Contains(string(toolBytes), "restart k0scontroller") {
				t.Fatalf("restarted controller during active maintenance hold:\n%s", string(toolBytes))
			}
		})

		t.Run("KMSv2MissingSocketFileDoesNotPanic", func(t *testing.T) {
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
				"NODE_HOST_AGENT_CONTROLLER_INTERVAL":      "300ms",
				"NODE_HOST_AGENT_CONTROLLER_INSECURE_TLS":  "true",
				"NODE_HOST_AGENT_API_SELF":                 strings.TrimPrefix(srv.URL, "https://"),
			})
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			writeKubeconfigFile(t, filepath.Join(sb.k0s, "pki", "admin.conf"), srv.URL, certPEM, keyPEM, caPEM)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "readyz 200 and zero subsystem restarts", func() error {
				if code, _ := reqHTTPGet(t, ra.readyzURL()); code != http.StatusOK {
					return fmt.Errorf("readyz=%d", code)
				}
				v, ok := parseMetricValue(ra.scrapeMetrics(t), "node_host_agent_controllerhygiene_cycles_total")
				if !ok || v < 2 {
					return fmt.Errorf("cycles=%v", v)
				}
				return nil
			})
		})

		t.Run("KMSv2OversizeHealthzResponseBounded", func(t *testing.T) {
			t.Parallel()
			bigBody := strings.Repeat("K", 3<<20)
			srv, certPEM, keyPEM, caPEM := newSelfSignedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/api/v1/namespaces/default/services":
					_, _ = w.Write([]byte(`{"metadata":{"resourceVersion":"100"},"items":[]}`))
				case r.URL.Path == "/api/v1/namespaces/default/endpoints/kubernetes":
					_, _ = w.Write([]byte(`{"subsets":[{"addresses":[{"ip":"127.0.0.1"}]}]}`))
				case strings.HasPrefix(r.URL.Path, "/healthz/kms-provider-"):
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(bigBody))
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
			_ = os.WriteFile(filepath.Join(sb.hostroot, "etc", "systemd", "system", "k0scontroller.service"), []byte("[Unit]\n"), 0o644)
			writeKubeconfigFile(t, filepath.Join(sb.k0s, "pki", "admin.conf"), srv.URL, certPEM, keyPEM, caPEM)

			ra := startReqAgent(t, bin, sb.envSlice())
			defer ra.stopAndWait(t)

			eventually(t, 5*time.Second, 100*time.Millisecond, "oversize healthz response bounded cleanly", func() error {
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
	})
}

var _ = json.Marshal
var _ = exec.Command
