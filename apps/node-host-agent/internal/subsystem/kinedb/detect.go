// detect.go — kine-DB-VM detection: the env-file fast path plus the
// node_exporter_extra_hosts kine_db:true match against this host's
// hostname/IPs (name = hostname or ip = local address, the contract
// hub_converge.yaml used).
package kinedb

import (
	"net"
	"os"
	"path/filepath"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

// Detect reports whether this host looks like the kine DB VM: either
// the postgres stack env file exists under hostRoot, or cluster.yaml
// in varsDir carries a `kine_db: true` node_exporter_extra_hosts
// entry matching this host (name = hostname or ip = local address).
// hostRoot "" means "/" (already on the host).
func Detect(hostRoot, varsDir string) bool {
	if hostRoot == "" {
		hostRoot = "/"
	}
	envPath := filepath.Join(hostRoot, strings.TrimPrefix(kdeps.DefaultEnvFile, "/"))
	if _, err := os.Stat(envPath); err == nil {
		return true
	}
	if varsDir == "" {
		return false
	}
	entries := readExtraHosts(filepath.Join(varsDir, "cluster.yaml"))
	if len(entries) == 0 {
		return false
	}
	return matchKineDBHost(entries, hostHostname(hostRoot), hostIPs())
}

type extraHost struct {
	Name   string `yaml:"name"`
	IP     string `yaml:"ip"`
	KineDB bool   `yaml:"kine_db"`
}

// readExtraHosts parses node_exporter_extra_hosts out of cluster.yaml.
// Returns nil on any read/parse failure (detection stays fail-quiet).
func readExtraHosts(path string) []extraHost {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		ExtraHosts []extraHost `yaml:"node_exporter_extra_hosts"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	return doc.ExtraHosts
}

// matchKineDBHost reports whether any kine_db:true extra-host entry
// names this host or carries one of its IPs.
func matchKineDBHost(entries []extraHost, hostname string, ips map[string]bool) bool {
	for _, e := range entries {
		if !e.KineDB {
			continue
		}
		if hostname != "" && e.Name == hostname {
			return true
		}
		if e.IP != "" && ips[e.IP] {
			return true
		}
	}
	return false
}

func hostHostname(hostRoot string) string {
	if data, err := os.ReadFile(filepath.Join(hostRoot, "etc/hostname")); err == nil {
		if h := strings.TrimSpace(string(data)); h != "" {
			return h
		}
	}
	h, _ := os.Hostname()
	return h
}

// hostIPs returns this host's interface IPs as a set — used to match
// a kine_db extra-host entry to the local machine.
func hostIPs() map[string]bool {
	out := map[string]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a.String())
		if err != nil {
			continue
		}
		out[ip.String()] = true
	}
	return out
}
