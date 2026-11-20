package pods

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
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
