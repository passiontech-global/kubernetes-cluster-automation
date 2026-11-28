// service_cidr_exhaustion_guard.go — health check "service-cidr-exhaustion-guard":
// detect-only guard monitoring Service ClusterIP CIDR and NodePort pool
// occupancy against warning (default 80%) and critical (default 90%) thresholds.
//
// Auto-discovers Service ClusterIP CIDRs from networking.k8s.io/v1 ServiceCIDR
// objects (Kubernetes 1.33+ GA), gracefully handling 403/404 and falling back
// to NODE_AUTOMATION_SERVICE_CLUSTER_CIDRS when ServiceCIDRs are absent or
// empty. Counts unique allocated ClusterIPs per CIDR and unique NodePorts in
// NODE_AUTOMATION_SERVICE_NODEPORT_RANGE (default 30000-32767), surfacing the
// top-3 consuming namespaces per saturated pool.
package nethealth

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// CheckNameServiceCIDRExhaustionGuard is the registry check name for service-cidr-exhaustion-guard.
	CheckNameServiceCIDRExhaustionGuard = "service-cidr-exhaustion-guard"

	svcCIDRDefaultNodePortRange = "30000-32767"
	svcCIDRDefaultWarnPct       = 80
	svcCIDRDefaultCritPct       = 90
	svcCIDREventReason          = "ServicePoolExhaustion"
	svcCIDREventCooldown        = 30 * time.Minute
	svcCIDRTopNamespacesLimit   = 3
)

var svcCIDRExhaustionGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_service_cidr_exhaustion",
	Help: "1 while a Service ClusterIP CIDR or NodePort pool meets or exceeds the configured warning or critical occupancy threshold.",
}, []string{"pool_type", "pool", "severity"})

func init() {
	ctrlmetrics.Registry.MustRegister(svcCIDRExhaustionGauge)
}

type svcCIDRCheck struct {
	*probefw.Deps

	fallbackCIDRs []string
	nodePortMin   int
	nodePortMax   int
	nodePortLabel string
	warnPct       int
	critPct       int

	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
}

// NewServiceCIDRExhaustionGuardCheck constructs the service-cidr-exhaustion-guard check.
func NewServiceCIDRExhaustionGuardCheck(d *probefw.Deps) probefw.Check {
	fallbackRaw := envx.Getenv("NODE_AUTOMATION_SERVICE_CLUSTER_CIDRS", "")
	var fallback []string
	if fallbackRaw != "" {
		for part := range strings.SplitSeq(fallbackRaw, ",") {
			if p := strings.TrimSpace(part); p != "" {
				fallback = append(fallback, p)
			}
		}
	}

	npRangeRaw := envx.Getenv("NODE_AUTOMATION_SERVICE_NODEPORT_RANGE", svcCIDRDefaultNodePortRange)
	npMin, npMax, ok := svcCIDRParsePortRange(npRangeRaw)
	if !ok {
		envx.Warnf("invalid NODE_AUTOMATION_SERVICE_NODEPORT_RANGE, using default",
			"key", "NODE_AUTOMATION_SERVICE_NODEPORT_RANGE",
			"value", npRangeRaw, "default", svcCIDRDefaultNodePortRange)
		npMin, npMax, _ = svcCIDRParsePortRange(svcCIDRDefaultNodePortRange)
		npRangeRaw = svcCIDRDefaultNodePortRange
	} else {
		npRangeRaw = fmt.Sprintf("%d-%d", npMin, npMax)
	}

	warnPct := envx.GetenvIntMin("NODE_AUTOMATION_SERVICE_CIDR_WARN_PCT", svcCIDRDefaultWarnPct, 1)
	if warnPct > 100 {
		envx.Warnf("NODE_AUTOMATION_SERVICE_CIDR_WARN_PCT > 100, clamping to 100",
			"key", "NODE_AUTOMATION_SERVICE_CIDR_WARN_PCT", "value", warnPct)
		warnPct = 100
	}
	critPct := envx.GetenvIntMin("NODE_AUTOMATION_SERVICE_CIDR_CRIT_PCT", svcCIDRDefaultCritPct, 1)
	if critPct > 100 {
		envx.Warnf("NODE_AUTOMATION_SERVICE_CIDR_CRIT_PCT > 100, clamping to 100",
			"key", "NODE_AUTOMATION_SERVICE_CIDR_CRIT_PCT", "value", critPct)
		critPct = 100
	}
	if critPct < warnPct {
		critPct = warnPct
	}

	return &svcCIDRCheck{
		Deps:          d,
		fallbackCIDRs: fallback,
		nodePortMin:   npMin,
		nodePortMax:   npMax,
		nodePortLabel: npRangeRaw,
		warnPct:       warnPct,
		critPct:       critPct,
	}
}

type svcCIDRPool struct {
	prefix    netip.Prefix
	label     string
	capacity  uint64
	unbounded bool
	usedIPs   map[netip.Addr]bool
	nsCounts  map[string]int
}

func (c *svcCIDRCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, svcCIDREventCooldown)

	var rep probefw.SweepReport

	prefixes, discoverErr := c.svcCIDRDiscoverPrefixes(ctx, log)
	if discoverErr != nil {
		rep.InfraErr(discoverErr)
	}

	svcs, err := c.AllServices(ctx)
	if err != nil {
		for k, lv := range c.emitted.Last() {
			rep.Carry(k, lv)
		}
		rep.InfraErr(fmt.Errorf("list services: %w", err))
		return rep.Result(&c.emitted, svcCIDRExhaustionGauge.DeleteLabelValues,
			"service pool exhaustion: ", ", ")
	}

	pools := make([]*svcCIDRPool, 0, len(prefixes))
	for _, pfx := range prefixes {
		capVal, unbounded := svcCIDRUsableCapacity(pfx)
		pools = append(pools, &svcCIDRPool{
			prefix:    pfx,
			label:     pfx.String(),
			capacity:  capVal,
			unbounded: unbounded,
			usedIPs:   make(map[netip.Addr]bool),
			nsCounts:  make(map[string]int),
		})
	}

	usedNodePorts := make(map[int32]bool)
	nodePortNSCounts := make(map[string]int)

	for i := range svcs {
		svc := &svcs[i]
		if svc.DeletionTimestamp != nil {
			continue
		}
		svcIPs := svcCIDRExtractClusterIPs(svc)
		for _, addr := range svcIPs {
			for _, pool := range pools {
				if pool.prefix.Contains(addr) && !pool.usedIPs[addr] {
					pool.usedIPs[addr] = true
					pool.nsCounts[svc.Namespace]++
				}
			}
		}

		svcPorts := svcCIDRExtractNodePorts(svc, c.nodePortMin, c.nodePortMax)
		for _, port := range svcPorts {
			if !usedNodePorts[port] {
				usedNodePorts[port] = true
				nodePortNSCounts[svc.Namespace]++
			}
		}
	}

	for _, pool := range pools {
		if pool.unbounded || pool.capacity == 0 {
			continue
		}
		used := uint64(len(pool.usedIPs))
		pct := float64(used) * 100.0 / float64(pool.capacity)
		severity := svcCIDRClassifySeverity(pct, c.warnPct, c.critPct)
		if severity == "" {
			continue
		}
		topNS := svcCIDRFormatTopNamespaces(pool.nsCounts, svcCIDRTopNamespacesLimit)
		key := "cluster_ip/" + pool.label + "/" + severity
		detail := fmt.Sprintf("cluster_ip %s %.1f%% (%d/%d) [%s] top=%s",
			pool.label, pct, used, pool.capacity, severity, topNS)
		rep.Emit(svcCIDRExhaustionGauge, key, []string{"cluster_ip", pool.label, severity}, detail)
		c.svcCIDREmitWarning(ctx, log, now, "cluster_ip", pool.label, severity, pct, used, pool.capacity, topNS)
	}

	nodePortCap := uint64(c.nodePortMax - c.nodePortMin + 1)
	if nodePortCap > 0 {
		usedNP := uint64(len(usedNodePorts))
		pct := float64(usedNP) * 100.0 / float64(nodePortCap)
		severity := svcCIDRClassifySeverity(pct, c.warnPct, c.critPct)
		if severity != "" {
			topNS := svcCIDRFormatTopNamespaces(nodePortNSCounts, svcCIDRTopNamespacesLimit)
			key := "nodeport/" + c.nodePortLabel + "/" + severity
			detail := fmt.Sprintf("nodeport %s %.1f%% (%d/%d) [%s] top=%s",
				c.nodePortLabel, pct, usedNP, nodePortCap, severity, topNS)
			rep.Emit(svcCIDRExhaustionGauge, key, []string{"nodeport", c.nodePortLabel, severity}, detail)
			c.svcCIDREmitWarning(ctx, log, now, "nodeport", c.nodePortLabel, severity, pct, usedNP, nodePortCap, topNS)
		}
	}

	return rep.Result(&c.emitted, svcCIDRExhaustionGauge.DeleteLabelValues,
		"service pool exhaustion: ", ", ")
}

func (c *svcCIDRCheck) svcCIDRDiscoverPrefixes(ctx context.Context, log logr.Logger) ([]netip.Prefix, error) {
	var rawCIDRs []string
	var listErr error

	if c.CS != nil {
		items, err := kube.ListAll(ctx,
			metav1.ListOptions{
				Limit:           kube.DefaultListPageSize,
				ResourceVersion: "0",
			},
			svcCIDRPageFunc(c.CS))
		switch {
		case err == nil:
			for i := range items {
				if items[i].DeletionTimestamp != nil {
					continue
				}
				rawCIDRs = append(rawCIDRs, items[i].Spec.CIDRs...)
			}
		case apierrors.IsForbidden(err) || kube.IsCRDAbsent(err):
			log.V(1).Info("ServiceCIDR list skipped; using env fallback if configured", "error", err)
		default:
			listErr = fmt.Errorf("list servicecidrs: %w", err)
		}
	}

	if len(rawCIDRs) == 0 {
		rawCIDRs = c.fallbackCIDRs
	}

	seen := make(map[netip.Prefix]bool, len(rawCIDRs))
	var out []netip.Prefix
	for _, raw := range rawCIDRs {
		pfx, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			log.V(1).Info("invalid Service CIDR skipped", "cidr", raw, "error", err)
			continue
		}
		pfx = pfx.Masked()
		if !seen[pfx] {
			seen[pfx] = true
			out = append(out, pfx)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].String() < out[j].String()
	})
	return out, listErr
}

func svcCIDRPageFunc(cs kubernetes.Interface) kube.PageFunc[networkingv1.ServiceCIDR] {
	return func(ctx context.Context, o metav1.ListOptions) ([]networkingv1.ServiceCIDR, string, error) {
		page, err := cs.NetworkingV1().ServiceCIDRs().List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return page.Items, page.GetContinue(), nil
	}
}

// svcCIDRUsableCapacity computes usable host addresses for pfx without int64 overflow.
// IPv6 prefixes shorter than /112 (> 65536 addresses) are treated as virtually unbounded.
func svcCIDRUsableCapacity(pfx netip.Prefix) (capacity uint64, unbounded bool) {
	bits := pfx.Bits()
	if pfx.Addr().Is4() {
		if bits < 0 || bits > 32 {
			return 0, false
		}
		hostBits := 32 - bits
		if bits < 31 {
			return (uint64(1) << hostBits) - 2, false
		}
		if bits == 31 {
			return 2, false
		}
		return 1, false
	}

	if bits < 0 || bits > 128 {
		return 0, false
	}
	if bits < 112 {
		return 0, true
	}
	hostBits := 128 - bits
	return uint64(1) << hostBits, false
}

func svcCIDRExtractClusterIPs(svc *corev1.Service) []netip.Addr {
	seen := make(map[netip.Addr]bool, 2)
	var out []netip.Addr
	add := func(raw string) {
		if raw == "" || raw == corev1.ClusterIPNone {
			return
		}
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return
		}
		if !seen[addr] {
			seen[addr] = true
			out = append(out, addr)
		}
	}
	add(svc.Spec.ClusterIP)
	for _, ip := range svc.Spec.ClusterIPs {
		add(ip)
	}
	return out
}

func svcCIDRExtractNodePorts(svc *corev1.Service, minPort, maxPort int) []int32 {
	seen := make(map[int32]bool)
	var out []int32
	add := func(port int32) {
		if port <= 0 || int(port) < minPort || int(port) > maxPort {
			return
		}
		if !seen[port] {
			seen[port] = true
			out = append(out, port)
		}
	}
	for i := range svc.Spec.Ports {
		add(svc.Spec.Ports[i].NodePort)
	}
	add(svc.Spec.HealthCheckNodePort)
	return out
}

func svcCIDRParsePortRange(raw string) (minPort, maxPort int, ok bool) {
	a, b, found := strings.Cut(strings.TrimSpace(raw), "-")
	if !found {
		return 0, 0, false
	}
	lo, err1 := strconv.Atoi(strings.TrimSpace(a))
	hi, err2 := strconv.Atoi(strings.TrimSpace(b))
	if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, false
	}
	return lo, hi, true
}

func svcCIDRClassifySeverity(pct float64, warnPct, critPct int) string {
	switch {
	case pct >= float64(critPct):
		return "critical"
	case pct >= float64(warnPct):
		return "warning"
	default:
		return ""
	}
}

func svcCIDRFormatTopNamespaces(counts map[string]int, limit int) string {
	if len(counts) == 0 {
		return "none"
	}
	type nsCount struct {
		ns    string
		count int
	}
	items := make([]nsCount, 0, len(counts))
	for ns, count := range counts {
		items = append(items, nsCount{ns: ns, count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].ns < items[j].ns
	})
	if len(items) > limit {
		items = items[:limit]
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, fmt.Sprintf("%s(%d)", item.ns, item.count))
	}
	return strings.Join(parts, ",")
}

func (c *svcCIDRCheck) svcCIDREmitWarning(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	poolType string,
	poolLabel string,
	severity string,
	pct float64,
	used uint64,
	capacity uint64,
	topNS string,
) {
	cooldownKey := "svc-pool." + poolType + "." + poolLabel + "." + severity
	if c.eventCooldown.CooledDown(cooldownKey, svcCIDREventCooldown, now) {
		return
	}
	note := fmt.Sprintf("Service %s pool %s is at %.1f%% capacity (%d/%d allocated, severity=%s); top namespaces: %s",
		poolType, poolLabel, pct, used, capacity, severity, topNS)

	if err := kube.EmitWarningEvent(ctx, c.CS, kube.WarningEvent{
		Name:      kube.TruncatedEventName(cooldownKey, cooldownKey, now),
		Namespace: "kube-system",
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Namespace",
			Name:       "kube-system",
		},
		Reason:            svcCIDREventReason,
		Note:              note,
		ReportingInstance: c.Name,
		Now:               now,
	}); err != nil {
		log.Info("WARN: ServicePoolExhaustion event create failed (RBAC?)", "pool", poolLabel, "error", err)
		return
	}
	c.eventCooldown.Stamp(cooldownKey, now)
	log.Info("EVENT: ServicePoolExhaustion", "poolType", poolType, "pool", poolLabel, "severity", severity)
}
