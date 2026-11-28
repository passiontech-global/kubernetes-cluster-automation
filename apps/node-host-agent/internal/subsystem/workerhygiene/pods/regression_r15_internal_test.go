package pods

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR15ProxyAgentHostStat0000NeverOpensEnvironFIFO(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	f := wdepstest.New(t)
	d := &wdeps.Deps{Cfg: f.Cfg, Proc: procfs.New(f.Cfg.ProcRoot)}

	pdir := filepath.Join(f.ProcDir, "6210")
	statPath := filepath.Join(pdir, "stat")
	wdepstest.WriteFile(t, statPath,
		"6210 (proxy-agent) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")
	envFIFO := filepath.Join(pdir, "environ")
	if err := unix.Mkfifo(envFIFO, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if fp, err := os.OpenFile(envFIFO, os.O_RDWR, 0); err == nil {
			_ = fp.Close()
		}
	})
	if err := os.Chmod(statPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(statPath, 0o644) })

	for _, argv := range [][]string{
		{"/proxy-agent", "--proxy-server-host=1.2.3.4"},
		{"/proxy-agent", "--agent-identifiers=host=10.9.9.9"},
	} {
		type res struct {
			host string
			inc  bool
		}
		ch := make(chan res, 1)
		go func(a []string) {
			h, inc := proxyAgentHostChecked(d, 6210, a)
			ch <- res{host: h, inc: inc}
		}(argv)
		select {
		case r := <-ch:
			if !r.inc || r.host != "" {
				t.Fatalf("proxyAgentHostChecked(%v)=(%q,%v) want (\"\",true)", argv, r.host, r.inc)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("proxyAgentHostChecked(%v) blocked opening FIFO environ on 0o000 stat", argv)
		}
	}

	// ENOENT stat (synthetic stat-less fixture) still reads environ NODE_IP.
	wdepstest.WriteFile(t, filepath.Join(f.ProcDir, "6211", "environ"), "NODE_IP=10.1.2.3\x00")
	if h, inc := proxyAgentHostChecked(d, 6211, []string{"/proxy-agent"}); inc || h != "10.1.2.3" {
		t.Fatalf("ENOENT stat proxyAgentHostChecked=(%q,%v) want (10.1.2.3,false)", h, inc)
	}
	if h := proxyAgentHost(d, 6211, []string{"/proxy-agent"}); h != "10.1.2.3" {
		t.Fatalf("proxyAgentHost=%q want 10.1.2.3", h)
	}
	if h := proxyAgentHost(d, 6210, []string{"/proxy-agent"}); h != "" {
		t.Fatalf("stat 0o000 proxyAgentHost=%q want \"\"", h)
	}
}

func TestKonnCheckUnknownCommDStateStatsOnceIsInconclusive(t *testing.T) {
	f := wdepstest.New(t)
	f.Cfg.ApplyDefaults()
	d := &wdeps.Deps{Cfg: f.Cfg, Proc: procfs.New(f.Cfg.ProcRoot)}
	d.State = subframe.StoreAt(f.Cfg.WatchdogStateDir, f.Cfg.WatchdogLogFile,
		f.Cfg.Seams.Host.Clock, func() *slog.Logger {
			return slog.New(slog.NewTextHandler(io.Discard, nil))
		})
	d.Cycles, d.Actions = subframe.Counters("pods-test", "c", "a")
	f.Bind(d)
	wdepstest.WriteFile(t, f.Cfg.K0sWorkerUnitFile,
		"[Service]\nExecStart=/usr/bin/k0s worker --kubelet-extra-args=\"--node-ip=10.0.0.1\"\n")
	// Stale proxy-agent PID 6220 plus an unknown-comm D-state PID 6221.
	f.MkProc(t, 6220, "S", "/proxy-agent\x00--proxy-server-host=1.2.3.4\x00", "NODE_IP=10.0.0.99\x00")
	wdepstest.WriteFile(t, filepath.Join(f.ProcDir, "6220", "stat"),
		"6220 (proxy-agent) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")
	// Malformed stat missing '(' yields HasComm=false with state=D.
	wdepstest.WriteFile(t, filepath.Join(f.ProcDir, "6221", "stat"),
		"6221 ) D 1 1 1 0\n")

	kc := NewKonn(d)
	kc.Run(context.Background(), &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		PidsOnce:     func() []int { return []int{6220, 6221} },
		StatsOnce: func() map[int]procfs.Stat {
			return map[int]procfs.Stat{
				6220: {Comm: "proxy-agent", HasComm: true, Fields: []string{"S"}},
				6221: {HasComm: false, Fields: []string{"D"}},
			}
		},
	})
	if kc.Fails != 0 {
		t.Fatalf("unknown-comm D-state PID must abort konnectivity check without incrementing Fails, got Fails=%d", kc.Fails)
	}
}
