// group_coredns_zonefile.go — the CoreDNS zone-file render
// pass: renderZoneFile walks the pin records into the zone
// body, zoneSerial stamps the SOA serial and jsonPlain
// normalizes config values for it. Split out of
// group_coredns.go — that file keeps install/config.

package hostconfig

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
)

// renderZoneFile builds db.<zone> for hub nodes — hub_converge.yaml
// inline template parity (SOA/NS/A, service + node records, flat
// schema {zone, ttl, records:{name:{ip|node}}, node_records}).
func (c *cyc) renderZoneFile() ([]byte, error) {
	t, zone := c.t, c.zoneName()
	ttl := "60"
	if tv, ok := t.Zone.Get("ttl"); ok && tv != nil {
		ttl = fmt.Sprint(tv)
	}
	var hubs []string
	for _, k := range t.Nodes.Keys() {
		nv, _ := t.Nodes.Get(k)
		om, _ := nv.(*jinja.OMap)
		if om == nil {
			continue
		}
		if hv, ok := om.Get("hub"); ok {
			if b, _ := hv.(bool); b {
				nm := nodeIPStr(om, "name")
				// A hub without a registry marker would render
				// `nsN IN A ` with empty rdata and coredns rejects
				// the whole zone — pinZoneRecords guard parity.
				if nm == "" || t.Markers[nm] == "" {
					continue
				}
				hubs = append(hubs, nm)
			}
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "$TTL %s\n", ttl)
	fmt.Fprintf(&b, "@   IN SOA ns1.%s. admin.%s. (\n        %d ; serial=hash(records), changes only when content changes\n        60 15 604800 30 )\n",
		zone, zone, c.zoneSerial())
	b.WriteString("\n") // {% set _hubs %} line
	for i := range hubs {
		fmt.Fprintf(&b, "\n    IN NS ns%d.%s.\n", i+1, zone)
	}
	b.WriteString("\n") // {% endfor %}
	for i, h := range hubs {
		fmt.Fprintf(&b, "\n%-30s IN A %s\n", fmt.Sprintf("ns%d", i+1), t.Markers[h])
	}
	b.WriteString("\n") // {% endfor %}
	b.WriteString("; service records: interdc_dns_zone.yaml\n")
	b.WriteString("; (do NOT use '#' — the coredns/miekg zone parser does not accept\n")
	b.WriteString("; '#' as a comment, only ';' — \"not a TTL\" crashloop 2026-09-16)\n")
	c.eachZoneRecord(func(name, ip string) {
		b.WriteString("\n\n")
		fmt.Fprintf(&b, "%-30s IN A %s\n", name, ip)
		b.WriteString("\n")
	})
	b.WriteString("\n") // {% endfor %}
	b.WriteString("; node records: <tinc_name>.node.<zone> -> marker\n")
	if c.zoneNodeRecords() {
		b.WriteString("\n") // {% if node_records %}
		for _, k := range t.Nodes.Keys() {
			nv, _ := t.Nodes.Get(k)
			om, _ := nv.(*jinja.OMap)
			if om == nil {
				continue
			}
			nm := nodeIPStr(om, "name")
			if nm == "" || t.Markers[nm] == "" {
				continue
			}
			fmt.Fprintf(&b, "\n%-30s IN A %s\n", nm+".node", t.Markers[nm])
		}
		b.WriteString("\n") // {% endfor %}
	}
	return []byte(b.String()), nil
}

// zoneSerial — ansible: (interdc_nodes|to_json ~ interdc_dns_zone|to_json)
// | hash('sha256') | int(0,16) % 4294967295. Changes only when the
// inputs change (no DNS blip on every converge).
func (c *cyc) zoneSerial() int64 {
	nj, _ := json.Marshal(topologyPlain(c.t.Nodes))
	zj, _ := json.Marshal(topologyPlain(c.t.Zone))
	h := sha256.Sum256(append(nj, zj...))
	i := new(big.Int).SetBytes(h[:])
	i.Mod(i, big.NewInt(4294967295))
	return i.Int64()
}
