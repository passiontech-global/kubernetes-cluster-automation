package nodereporter

import (
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("NODE_HOST_AGENT_REPORTER_INTERVAL", "45s")
	t.Setenv("NODE_HOST_AGENT_EVENT_NAMESPACE", "node-ops")

	cs := fake.NewSimpleClientset()
	cfg := ConfigFromEnv(EnvDeps{
		Client:           cs,
		NodeName:         "node-1",
		WatchdogStateDir: "/host/var/lib/node-watchdog",
		WatchdogLogFile:  "/host/var/log/node-watchdog.log",
	})
	if cfg.Client != cs {
		t.Fatal("ConfigFromEnv did not pass the client through")
	}
	if cfg.NodeName != "node-1" {
		t.Fatalf("NodeName=%q", cfg.NodeName)
	}
	if cfg.WatchdogStateDir != "/host/var/lib/node-watchdog" {
		t.Fatalf("WatchdogStateDir=%q", cfg.WatchdogStateDir)
	}
	if cfg.WatchdogLogFile != "/host/var/log/node-watchdog.log" {
		t.Fatalf("WatchdogLogFile=%q", cfg.WatchdogLogFile)
	}
	if cfg.Interval != 45*time.Second {
		t.Fatalf("Interval=%v", cfg.Interval)
	}
	if cfg.EventNamespace != "node-ops" {
		t.Fatalf("EventNamespace=%q", cfg.EventNamespace)
	}
}
