// thp_vars.go — stat-gated VarsDir loader for Wave-4 #9 THP targets
// (host_thp_enabled / host_thp_defrag), keeping hostmetrics/kernelfail
// aligned with hostconfig's Config/env > VarsDir > default precedence
// across runtime ConfigMap updates.
package kernelfail

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/topology"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
)

var thpVarsFiles = []string{
	"defaults.yaml",
	"cluster.yaml",
	"interdc_nodes.yaml",
	"interdc_dns_zone.yaml",
}

// thpVarsCache caches the last good VarsDir THP target resolution keyed
// by the combined fsx.FileStatKey fingerprint of the vars files. Guarded
// by mu so concurrent readers (e.g. THPTargets() / collectKernelDrift())
// stay race-free under live VarsDir updates.
type thpVarsCache struct {
	mu       sync.Mutex
	varsDir  string
	nodeName string
	okKey    string
	enabled  string
	defrag   string
	loadErr  bool
}

func (c *thpVarsCache) get(varsDir, nodeName string, clock *timex.Cell) (enabled, defrag string) {
	if varsDir == "" {
		return "", ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.varsDir != varsDir || c.nodeName != nodeName {
		c.varsDir = varsDir
		c.nodeName = nodeName
		c.okKey = ""
		c.enabled = ""
		c.defrag = ""
		c.loadErr = false
	}

	key, statComplete := thpVarsStatKey(varsDir)
	if statComplete && key == c.okKey && !c.loadErr {
		return c.enabled, c.defrag
	}

	en, df, err := loadTHPVars(varsDir, nodeName, clock)
	if err != nil {
		if !c.loadErr {
			c.loadErr = true
			logger().Warn("hostmetrics: THP vars load failed — keeping last good values",
				"varsDir", varsDir, "error", err)
		}
		return c.enabled, c.defrag
	}
	c.loadErr = false
	c.enabled = en
	c.defrag = df
	if statComplete {
		c.okKey = key
	} else {
		c.okKey = ""
	}
	return c.enabled, c.defrag
}

func thpVarsStatKey(varsDir string) (string, bool) {
	var b strings.Builder
	for _, name := range thpVarsFiles {
		p := filepath.Join(varsDir, name)
		sk, err := fsx.FileStatKey(p)
		if err == nil {
			b.WriteString(name)
			b.WriteByte('=')
			b.WriteString(sk)
			b.WriteByte(';')
		} else if os.IsNotExist(err) {
			b.WriteString(name)
			b.WriteString("=absent;")
		} else {
			return "", false
		}
	}
	return b.String(), true
}

func loadTHPVars(varsDir, nodeName string, clock *timex.Cell) (enabled, defrag string, err error) {
	if t, loadErr := topology.Load(topology.Config{
		VarsDir:  varsDir,
		NodeName: nodeName,
		Clock:    clock,
	}); loadErr == nil {
		for _, e := range t.Errors {
			if strings.HasPrefix(e, "defaults.yaml:") {
				return "", "", errors.New(e)
			}
		}
		return strings.TrimSpace(t.Vars.StrDef("host_thp_enabled", "")),
			strings.TrimSpace(t.Vars.StrDef("host_thp_defrag", "")),
			nil
	}
	return loadRawTHPVars(varsDir, clock)
}

// loadRawTHPVars handles partial VarsDir layouts (e.g. defaults.yaml
// alone without interdc_nodes.yaml or cluster.yaml), preserving the
// defaults.yaml -> cluster.yaml override order and lazy Jinja evaluation.
func loadRawTHPVars(varsDir string, clock *timex.Cell) (enabled, defrag string, err error) {
	raw := jinja.NewOMap()
	for _, name := range []string{"defaults.yaml", "cluster.yaml"} {
		p := filepath.Join(varsDir, name)
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			if os.IsNotExist(rerr) {
				continue
			}
			return "", "", fmt.Errorf("read %s: %w", p, rerr)
		}
		if len(bytes.TrimSpace(data)) == 0 {
			continue
		}
		decoded, derr := jinja.DecodeYAML(data)
		if derr != nil {
			return "", "", fmt.Errorf("%s: %w", name, derr)
		}
		if decoded == nil {
			continue
		}
		m, ok := decoded.(*jinja.OMap)
		if !ok {
			return "", "", fmt.Errorf("%s: top level is not a mapping", name)
		}
		for _, k := range m.Keys() {
			vv, _ := m.Get(k)
			raw.Set(k, vv)
		}
	}

	env := topology.NewEnv(varsDir, clock)
	resolved := map[string]any{}
	resolving := map[string]bool{}
	var evalErr error
	var lookup func(string) any
	lookup = func(k string) any {
		if x, ok := resolved[k]; ok {
			return x
		}
		if resolving[k] {
			if evalErr == nil {
				evalErr = fmt.Errorf("var %s: reference cycle", k)
			}
			return jinja.NewUndefined(k + "(cycle)")
		}
		rv, ok := raw.Get(k)
		if !ok {
			return jinja.NewUndefined(k)
		}
		resolving[k] = true
		defer delete(resolving, k)
		val := rv
		if s, ok := rv.(string); ok && (strings.Contains(s, "{{") || strings.Contains(s, "{%") || strings.Contains(s, "{#")) {
			out, rerr := jinja.RenderScoped(s, env, lookup)
			if rerr != nil {
				if evalErr == nil {
					evalErr = fmt.Errorf("var %s: %w", k, rerr)
				}
				return jinja.NewUndefined(k)
			}
			val = out
		}
		resolved[k] = val
		return val
	}

	getStr := func(k string) string {
		s := strings.TrimSpace(jinja.Stringify(lookup(k)))
		if s == "None" {
			return ""
		}
		return s
	}

	en := getStr("host_thp_enabled")
	df := getStr("host_thp_defrag")
	if evalErr != nil {
		return "", "", evalErr
	}
	return en, df, nil
}
