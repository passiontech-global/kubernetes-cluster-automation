// wiring_test.go — wiring-descriptor coverage: shared clientset, standalone flips, kinedb/hubsync gating.

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// stubKubeClient swaps the package-level client factory for a counter
// stub — csOnce's shared-build behaviour is only observable through it.
func stubKubeClient(t *testing.T,
	fn func() (kubernetes.Interface, error)) *int {
	t.Helper()
	calls := new(int)
	orig := kubeClient
	kubeClient = func() (kubernetes.Interface, error) {
		(*calls)++
		return fn()
	}
	t.Cleanup(func() { kubeClient = orig })
	return calls
}

// enableBothKubeConsumers is the env set where sweeper AND
// workerhygiene each reach their csOnce call.
func enableBothKubeConsumers(t *testing.T) {
	t.Helper()
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	t.Setenv("KUBECONFIG", "")
	disableAllSubsystems(t)
	t.Setenv(envnames.EnvEnableSweeper, "true")
	t.Setenv(envnames.EnvEnableHygiene, "true")
}

// TestCsOnceSharesOneClientset: sweeper and workerhygiene both consume
// csOnce — the clientset is built exactly once for the process.
func TestCsOnceSharesOneClientset(t *testing.T) {
	calls := stubKubeClient(t, func() (kubernetes.Interface, error) {
		return testutil.FakeKube(), nil
	})
	enableBothKubeConsumers(t)

	cfg, _ := testBuildAgentConfig("node-a", "p", false)

	if *calls != 1 {
		t.Fatalf("kubeClient calls=%d want 1 (shared clientset)", *calls)
	}
	names := []string{}
	for _, s := range cfg.Subsystems {
		names = append(names, s.Name())
	}
	if len(names) != 3 || names[0] != "sweeper" || names[1] != "workerhygiene" ||
		names[2] != "hubsync" {
		t.Fatalf("subsystems=%v want [sweeper workerhygiene hubsync]", names)
	}
}

// TestCsOnceErrorRetried: only a successful build is cached — each
// consumer re-attempts after a failure so one transient error cannot
// disable every kube subsystem for the process lifetime (and neither
// subsystem aborts the agent).
func TestCsOnceErrorRetried(t *testing.T) {
	calls := stubKubeClient(t, func() (kubernetes.Interface, error) {
		return nil, errors.New("no config")
	})
	enableBothKubeConsumers(t)

	cfg, _ := testBuildAgentConfig("node-a", "p", false)

	// sweeper + workerhygiene + hubsync each re-attempt once.
	if *calls != 3 {
		t.Fatalf("kubeClient calls=%d want 3 (error retried per consumer)", *calls)
	}
	if len(cfg.Subsystems) != 0 {
		t.Fatalf("subsystems=%d want 0 (client build failed)", len(cfg.Subsystems))
	}
}

// --- standalone mode ---

// TestStandaloneDefaultFlips verifies the standalone enable-set
// inversion: with a working kube client stub and a node name, pod
// mode builds the kube-dependent subsystems by default while
// standalone does not — and an explicit env override still wins.
func TestStandaloneDefaultFlips(t *testing.T) {
	stubKubeClient(t, func() (kubernetes.Interface, error) {
		return testutil.FakeKube(), nil
	})
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	t.Setenv("KUBECONFIG", "")
	t.Setenv(envnames.EnvNodeName, "node-a")
	t.Setenv(envnames.EnvWatchdogConf,
		filepath.Join(t.TempDir(), "absent.conf"))
	t.Setenv(envnames.EnvAPIGuardConf,
		filepath.Join(t.TempDir(), "absent-guard.conf"))
	t.Setenv(envnames.EnvHostconfigVarsDir, t.TempDir())
	t.Setenv(envnames.EnvConvergeSSHKey,
		filepath.Join(t.TempDir(), "absent-key"))
	t.Setenv(envnames.EnvEnableKinedb, "false")
	t.Setenv(envnames.EnvEnableControllerhygiene, "false")
	t.Setenv(envnames.EnvEnableHostconfig, "false")

	t.Run("standalone flips kube-dependent defaults off", func(t *testing.T) {
		cfg, _ := testBuildAgentConfig("node-a", "p", true)
		names := subsystemNames(cfg)
		want := map[string]bool{
			"apiprober": true, "hostmetrics": true,
			"hostmetrics-textfile": true,
			"nethealth":            true, "janitor": true,
		}
		for _, n := range names {
			if !want[n] {
				t.Fatalf("standalone subsystem %q not in want-set %v", n, names)
			}
			delete(want, n)
		}
		if len(want) != 0 {
			t.Fatalf("standalone missing subsystems %v (got %v)", want, names)
		}
	})

	t.Run("pod mode keeps kube-dependent defaults on", func(t *testing.T) {
		cfg, _ := testBuildAgentConfig("node-a", "p", false)
		got := map[string]bool{}
		for _, n := range subsystemNames(cfg) {
			got[n] = true
		}
		for _, n := range []string{
			"sweeper", "concourse-cache", "workerhygiene", "nodereporter",
		} {
			if !got[n] {
				t.Fatalf("pod mode missing %q (got %v)", n, subsystemNames(cfg))
			}
		}
		if got["hostmetrics-textfile"] {
			t.Fatal("hostmetrics-textfile must not run in pod mode")
		}
	})

	t.Run("env override still wins in standalone", func(t *testing.T) {
		t.Setenv(envnames.EnvEnableHygiene, "true")
		cfg, _ := testBuildAgentConfig("node-a", "p", true)
		got := map[string]bool{}
		for _, n := range subsystemNames(cfg) {
			got[n] = true
		}
		if !got["workerhygiene"] {
			t.Fatalf("ENABLE_HYGIENE=true ignored in standalone (got %v)",
				subsystemNames(cfg))
		}
	})

	t.Run("NODE_HOST_AGENT_STANDALONE env selects standalone", func(t *testing.T) {
		t.Setenv(envnames.EnvStandalone, "1")
		cfg, _ := testBuildAgentConfig("node-a", "p", false)
		got := map[string]bool{}
		for _, n := range subsystemNames(cfg) {
			got[n] = true
		}
		if got["sweeper"] || got["workerhygiene"] || got["nodereporter"] {
			t.Fatalf("STANDALONE=1 did not flip defaults (got %v)",
				subsystemNames(cfg))
		}
		if !got["hostmetrics-textfile"] {
			t.Fatal("STANDALONE=1 did not enable the textfile writer")
		}
	})
}

// --- kinedb / hubsync gating ---

func writeEd25519Key(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestKineDBGating(t *testing.T) {
	disableAllSubsystems(t)
	sandboxed := t.TempDir()
	t.Setenv(envnames.EnvWatchdogConf, filepath.Join(sandboxed, "no.conf"))
	t.Setenv(envnames.EnvAPIGuardConf, filepath.Join(sandboxed, "no.conf"))
	t.Setenv(envnames.EnvHostconfigVarsDir, sandboxed)
	t.Setenv(envnames.EnvConvergeSSHKey, filepath.Join(sandboxed, "no-key"))
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	t.Setenv("KUBECONFIG", "")

	t.Run("auto + no detect → off", func(t *testing.T) {
		cfg, _ := testBuildAgentConfig("n", "p", false)
		for _, n := range subsystemNames(cfg) {
			if n == "kinedb" {
				t.Fatal("kinedb enabled without Detect match")
			}
		}
	})
	t.Run("true forces on", func(t *testing.T) {
		t.Setenv(envnames.EnvEnableKinedb, "true")
		cfg, _ := testBuildAgentConfig("n", "p", false)
		got := subsystemNames(cfg)
		if len(got) != 1 || got[0] != "kinedb" {
			t.Fatalf("subsystems=%v want [kinedb]", got)
		}
	})
}

func TestHubsyncGating(t *testing.T) {
	disableAllSubsystems(t)
	sandboxed := t.TempDir()
	t.Setenv(envnames.EnvWatchdogConf, filepath.Join(sandboxed, "no.conf"))
	t.Setenv(envnames.EnvAPIGuardConf, filepath.Join(sandboxed, "no.conf"))
	t.Setenv(envnames.EnvHostconfigVarsDir, sandboxed)
	t.Setenv(envnames.EnvEnableKinedb, "false")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	t.Setenv("KUBECONFIG", "")

	t.Run("no key → registered, polls for key", func(t *testing.T) {
		stubKubeClient(t, func() (kubernetes.Interface, error) {
			return testutil.FakeKube(), nil
		})
		t.Setenv(envnames.EnvConvergeSSHKey,
			filepath.Join(sandboxed, "absent"))
		cfg, _ := testBuildAgentConfig("n", "pod-a", false)
		// The absent key is NOT a permanent gate — the secret mounts
		// optional:true and may land after pod start; the Syncer
		// re-checks on every trigger (skip-cycle-and-poll).
		got := subsystemNames(cfg)
		if len(got) != 1 || got[0] != "hubsync" {
			t.Fatalf("subsystems=%v want [hubsync] (key-waiting mode)", got)
		}
	})

	t.Run("key + kube client → on", func(t *testing.T) {
		stubKubeClient(t, func() (kubernetes.Interface, error) {
			return testutil.FakeKube(), nil
		})
		t.Setenv(envnames.EnvConvergeSSHKey, writeEd25519Key(t))
		cfg, _ := testBuildAgentConfig("n", "pod-a", false)
		got := subsystemNames(cfg)
		if len(got) != 1 || got[0] != "hubsync" {
			t.Fatalf("subsystems=%v want [hubsync]", got)
		}
	})

	t.Run("key + client error → skipped not fatal", func(t *testing.T) {
		stubKubeClient(t, func() (kubernetes.Interface, error) {
			return nil, errors.New("no config")
		})
		t.Setenv(envnames.EnvConvergeSSHKey, writeEd25519Key(t))
		cfg, _ := testBuildAgentConfig("n", "pod-a", false)
		for _, n := range subsystemNames(cfg) {
			if n == "hubsync" {
				t.Fatal("hubsync enabled despite client error")
			}
		}
	})

	t.Run("standalone never runs hubsync", func(t *testing.T) {
		stubKubeClient(t, func() (kubernetes.Interface, error) {
			return testutil.FakeKube(), nil
		})
		t.Setenv(envnames.EnvConvergeSSHKey, writeEd25519Key(t))
		cfg, _ := testBuildAgentConfig("n", "pod-a", true)
		for _, n := range subsystemNames(cfg) {
			if n == "hubsync" {
				t.Fatal("hubsync ran in standalone mode")
			}
		}
	})
}
