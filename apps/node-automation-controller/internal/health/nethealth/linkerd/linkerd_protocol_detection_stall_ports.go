// linkerd_protocol_detection_stall_ports.go — the port arithmetic of
// the linkerd-protocol-detection-stall check (linkerd-protocol-detection-stall): the
// well-known binary/stateful port table, the linkerd port-annotation
// parser ("6379,8000-8010" ranges included), and the
// missingBinaryPorts audit across opaque-ports / skip-inbound-ports /
// skip-outbound-ports.
package linkerd

import (
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// linkerdBinaryPorts are the well-known binary/stateful server
// ports Linkerd protocol detection cannot classify — a meshed pod
// exposing one of these without an opaque/skip annotation stalls on
// every new connection (the stateful-masterless-services linkerd port lists live in
// check-linkerd-stateful-ports; this is the pod-level audit mirror).
var linkerdBinaryPorts = map[int]bool{
	3306: true, 5432: true, 6379: true, 27017: true, 9042: true,
	4369: true, 25672: true, 7000: true, 7001: true, 9999: true,
	// server-speaks-first-ports: server-speaks-first protocols the proxy cannot
	// classify — NATS client/leaf ports and RabbitMQ AMQP — matching
	// the static gate and VAP port tables 1:1.
	4222: true, 5672: true, 6222: true,
}

// parsePortSet parses a linkerd port annotation
// ("6379,8000-8010") into a set of concrete ports. Ranges are
// expanded — annotation values are small.
func parsePortSet(s string) map[int]bool {
	out := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			l, err1 := strconv.Atoi(strings.TrimSpace(lo))
			h, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || h < l || h-l > 1024 {
				continue
			}
			for p := l; p <= h; p++ {
				out[p] = true
			}
			continue
		}
		if n, err := strconv.Atoi(part); err == nil {
			out[n] = true
		}
	}
	return out
}

// portSetString renders a port set back as a sorted
// comma-separated annotation value.
func portSetString(set map[int]bool) string {
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	return joinPorts(ports)
}

// joinPorts renders an already-sorted port list as a
// comma-separated annotation value.
func joinPorts(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, ",")
}

// missingBinaryPorts returns the sorted well-known binary ports
// the pod's containers expose that are covered by NONE of
// opaque-ports, skip-inbound-ports or skip-outbound-ports — each
// annotation makes the proxy treat the port as opaque TCP in the
// direction it governs (skip-outbound is the client-side escape a
// meshed pod INITIATING to MySQL/Postgres/Redis needs; the static
// gate and the VAP accept it, so the runtime audit must too —
// template-patch-stamp, or every skip-outbound workload gets patched +
// re-rolled every 30m).
func missingBinaryPorts(pod *corev1.Pod) []int {
	covered := parsePortSet(pod.Annotations[linkerdOpaquePortsAnno])
	for p := range parsePortSet(pod.Annotations[linkerdSkipInboundAnno]) {
		covered[p] = true
	}
	for p := range parsePortSet(pod.Annotations[linkerdSkipOutboundAnno]) {
		covered[p] = true
	}
	seen := map[int]bool{}
	var missing []int
	for _, c := range pod.Spec.Containers {
		for _, port := range c.Ports {
			if port.Protocol != "" && port.Protocol != corev1.ProtocolTCP {
				continue
			}
			n := int(port.ContainerPort)
			if linkerdBinaryPorts[n] && !covered[n] && !seen[n] {
				seen[n] = true
				missing = append(missing, n)
			}
		}
	}
	sort.Ints(missing)
	return missing
}
