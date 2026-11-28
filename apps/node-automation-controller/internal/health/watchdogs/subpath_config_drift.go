// subpath_config_drift.go — the subpath-config-drift check
// (P1.10): a pod that mounts a ConfigMap/Secret key via subPath
// gets a plain file bind — the kubelet does NOT propagate ConfigMap
// updates into it, and the container never reloads.
//
// Detection runs on a 30m heavy-scan cadence: targeted ConfigMap/Secret
// Gets (bounded concurrency via errgroup.SetLimit(4)) feed SHA-256 content
// digests per workload; changes persisting >=15m trigger restart nudges.
//
// File layout: this file holds the check struct, constants, Run sweep loop,
// and content-hash evaluation; subpath_config_drift_heal.go holds mount
// resolution, fresh-pod checks, restart-template patches, and Warning Events.
package watchdogs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

type subpathConfigDriftCheck struct {
	*probefw.Deps

	emitted     state.GaugeLedger[string]
	eventHealed state.CooldownSet
	reloadHeals state.CooldownSet
	hashes      map[string]string
	driftSince  map[string]time.Time
	lastScan    time.Time
}

// NewSubPathConfigDriftCheck builds the check.
func NewSubPathConfigDriftCheck(d *probefw.Deps) probefw.Check {
	return &subpathConfigDriftCheck{
		Deps:       d,
		hashes:     map[string]string{},
		driftSince: map[string]time.Time{},
	}
}

const (
	CheckNameSubPathConfigDrift = "subpath-config-drift"

	subPathScanInterval      = 30 * time.Minute
	subPathDriftMinAge       = 15 * time.Minute
	subPathEventCooldown     = time.Hour
	subPathReloadCooldown    = time.Hour
	subPathMaxReloadsPerScan = 8
)

var subPathConfigDriftGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_subpath_config_drift",
	Help: "1 while a workload's subPath-mounted ConfigMap/Secret keys drifted past the settle window — subpath-config-drift.",
}, []string{"namespace", "name", "kind"})

func init() {
	ctrlmetrics.Registry.MustRegister(subPathConfigDriftGauge)
}

var subPathSystemNamespaces = map[string]bool{
	"kube-system":      true,
	"kube-public":      true,
	"kube-node-lease":  true,
	"flux-system":      true,
	"node-ops":         true,
	"cert-manager":     true,
	"linkerd":          true,
	"linkerd-cni":      true,
	"external-secrets": true,
}

var subPathDBQuorumLabels = []string{
	"cnpg.io/cluster",
	"postgres-operator.crunchydata.com/cluster",
	"pgv2.percona.com/cluster",
	"everest.percona.com/cluster",
	"pxc.percona.com/cluster",
	"psmdb.percona.com/cluster",
	"scylla.scylladb.com/cluster",
	"apps.rabbitmq.com/cluster",
	"dragonflydb.io/cluster",
	"nats_cluster",
}

func isSubPathDBQuorumWorkload(templateLabels map[string]string) bool {
	for _, k := range subPathDBQuorumLabels {
		if templateLabels[k] != "" {
			return true
		}
	}
	for _, k := range []string{"app.kubernetes.io/name", "app.kubernetes.io/part-of", "app.kubernetes.io/managed-by"} {
		v := strings.ToLower(templateLabels[k])
		if strings.Contains(v, "dragonfly") || strings.Contains(v, "percona") ||
			v == "nats" || strings.HasPrefix(v, "nats-") {
			return true
		}
	}
	return false
}

type subPathWorkload struct {
	kind     string
	ns, name string
	podSpec  *corev1.PodSpec
	template map[string]string
	annos    map[string]string
	obj      metav1.Object
}

func subPathDrifted(ns string, templateLabels, annos map[string]string) bool {
	if subPathSystemNamespaces[ns] || isSubPathDBQuorumWorkload(templateLabels) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(annos[kube.AnnoSubPathReloadOptOut])) {
	case "true", "1", "yes":
		return false
	}
	return true
}

func allMounts(podSpec *corev1.PodSpec) []corev1.VolumeMount {
	var out []corev1.VolumeMount
	for _, c := range podSpec.InitContainers {
		out = append(out, c.VolumeMounts...)
	}
	for _, c := range podSpec.Containers {
		out = append(out, c.VolumeMounts...)
	}
	return out
}

func (p *subpathConfigDriftCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	p.eventHealed.PruneExpired(now, subPathEventCooldown)
	p.reloadHeals.PruneExpired(now, subPathReloadCooldown)
	var rep probefw.SweepReport

	if now.Sub(p.lastScan) < subPathScanInterval && !p.lastScan.IsZero() {
		for k, lv := range p.emitted.Last() {
			rep.Find(k)
			rep.Carry(k, lv)
		}
		return rep.Result(&p.emitted, subPathConfigDriftGauge.DeleteLabelValues,
			"subpath config drift: ", ", ")
	}

	var workloads []subPathWorkload

	deps, err := p.AllDeployments(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list deployments: %w", err)}
	}
	for i := range deps {
		d := &deps[i]
		workloads = append(workloads, subPathWorkload{
			kind: "Deployment", ns: d.Namespace, name: d.Name,
			podSpec:  &d.Spec.Template.Spec,
			template: d.Spec.Template.Labels,
			annos:    kube.EffectiveAnnos(ctx, d),
			obj:      d,
		})
	}
	sts, err := p.AllStatefulSets(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list statefulsets: %w", err)}
	}
	for i := range sts {
		s := &sts[i]
		workloads = append(workloads, subPathWorkload{
			kind: "StatefulSet", ns: s.Namespace, name: s.Name,
			podSpec:  &s.Spec.Template.Spec,
			template: s.Spec.Template.Labels,
			annos:    kube.EffectiveAnnos(ctx, s),
			obj:      s,
		})
	}
	dss, err := p.AllDaemonSets(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list daemonsets: %w", err)}
	}
	for i := range dss {
		d := &dss[i]
		workloads = append(workloads, subPathWorkload{
			kind: "DaemonSet", ns: d.Namespace, name: d.Name,
			podSpec:  &d.Spec.Template.Spec,
			template: d.Spec.Template.Labels,
			annos:    kube.EffectiveAnnos(ctx, d),
			obj:      d,
		})
	}

	type objRef struct{ ns, name string }
	needCMs := map[objRef]bool{}
	needSecs := map[objRef]bool{}
	var active []subPathWorkload
	for _, w := range workloads {
		if !subPathDrifted(w.ns, w.template, w.annos) {
			continue
		}
		cms, secs := subPathReferencedObjects(w.podSpec)
		if len(cms) == 0 && len(secs) == 0 {
			continue
		}
		active = append(active, w)
		for _, n := range cms {
			needCMs[objRef{w.ns, n}] = true
		}
		for _, n := range secs {
			needSecs[objRef{w.ns, n}] = true
		}
	}

	cmData := map[string]map[string]string{}
	secretData := map[string]map[string][]byte{}
	var fetchMu sync.Mutex
	eg, egctx := errgroup.WithContext(ctx)
	eg.SetLimit(4)
	for ref := range needCMs {
		eg.Go(func() error {
			cm, gerr := p.CS.CoreV1().ConfigMaps(ref.ns).Get(egctx, ref.name, metav1.GetOptions{})
			if apierrors.IsNotFound(gerr) {
				return nil
			}
			if gerr != nil {
				return fmt.Errorf("get configmap %s/%s: %w", ref.ns, ref.name, gerr)
			}
			merged := make(map[string]string, len(cm.Data)+len(cm.BinaryData))
			for k, v := range cm.Data {
				merged[k] = v
			}
			for k, v := range cm.BinaryData {
				merged[k] = string(v)
			}
			fetchMu.Lock()
			cmData[ref.ns+"/"+ref.name] = merged
			fetchMu.Unlock()
			return nil
		})
	}
	for ref := range needSecs {
		eg.Go(func() error {
			sec, gerr := p.CS.CoreV1().Secrets(ref.ns).Get(egctx, ref.name, metav1.GetOptions{})
			if apierrors.IsNotFound(gerr) {
				return nil
			}
			if gerr != nil {
				return fmt.Errorf("get secret %s/%s: %w", ref.ns, ref.name, gerr)
			}
			fetchMu.Lock()
			secretData[ref.ns+"/"+ref.name] = sec.Data
			fetchMu.Unlock()
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return probefw.Result{Infra: err}
	}

	seenKeys := map[string]bool{}
	flaggedKeys := map[string]bool{}
	reloads := 0
	podsByNS := map[string][]*corev1.Pod{}
	for _, w := range active {
		key := w.kind + "/" + w.ns + "/" + w.name
		sig := p.subPathContentHash(w.podSpec, w.ns, cmData, secretData)
		if sig == "" {
			continue
		}
		seenKeys[key] = true
		base, seen := p.hashes[key]
		if !seen {
			p.hashes[key] = sig
			continue
		}
		if sig == base {
			delete(p.driftSince, key)
			continue
		}
		if _, ok := p.driftSince[key]; !ok {
			p.driftSince[key] = now
		}
		if now.Sub(p.driftSince[key]) < subPathDriftMinAge {
			continue
		}
		flaggedKeys[key] = true
		rep.Flag(subPathConfigDriftGauge, key,
			[]string{w.ns, w.name, w.kind})
		rep.Find(key)
		mayPatch := reloads < subPathMaxReloadsPerScan
		pods, ok := podsByNS[w.ns]
		if !ok {
			pods, err = p.PodsIn(ctx, w.ns)
			if err != nil {
				for k, lv := range p.emitted.Last() {
					if !flaggedKeys[k] {
						rep.Carry(k, lv)
					}
				}
				rep.InfraErr(fmt.Errorf("list pods: %w", err))
				return rep.Result(&p.emitted, subPathConfigDriftGauge.DeleteLabelValues,
					"subpath config drift: ", ", ")
			}
			podsByNS[w.ns] = pods
		}
		resolved, spent := p.reloadWorkload(ctx, log, w, pods,
			p.driftSince[key], now, mayPatch)
		if spent {
			reloads++
		}
		if resolved {
			p.hashes[key] = sig
			delete(p.driftSince, key)
		}
	}
	for k := range p.hashes {
		if !seenKeys[k] {
			delete(p.hashes, k)
			delete(p.driftSince, k)
		}
	}
	p.lastScan = now
	p.emitDriftEvent(ctx, log, rep.Findings(), now)
	return rep.Result(&p.emitted, subPathConfigDriftGauge.DeleteLabelValues,
		"subpath config drift: ", ", ")
}

func (p *subpathConfigDriftCheck) subPathContentHash(podSpec *corev1.PodSpec,
	ns string, cmData map[string]map[string]string,
	secretData map[string]map[string][]byte) string {

	type src struct {
		kind string
		name string
		keys map[string]string
	}
	byName := map[string]src{}
	for _, v := range podSpec.Volumes {
		s := src{keys: map[string]string{}}
		switch {
		case v.ConfigMap != nil:
			s.kind, s.name = "configmap", v.ConfigMap.Name
			for _, it := range v.ConfigMap.Items {
				s.keys[it.Path] = it.Key
			}
		case v.Secret != nil:
			s.kind, s.name = "secret", v.Secret.SecretName
			for _, it := range v.Secret.Items {
				s.keys[it.Path] = it.Key
			}
		default:
			continue
		}
		byName[v.Name] = s
	}
	var tuples []string
	for _, m := range allMounts(podSpec) {
		if m.SubPath == "" {
			continue
		}
		s, ok := byName[m.Name]
		if !ok {
			continue
		}
		key := m.SubPath
		if k, found := s.keys[m.SubPath]; found {
			key = k
		}
		objKey := ns + "/" + s.name
		content := "<absent>"
		if s.kind == "configmap" {
			if data, ok := cmData[objKey]; ok {
				if v, ok := data[key]; ok {
					content = v
				}
			}
		} else {
			if data, ok := secretData[objKey]; ok {
				if v, ok := data[key]; ok {
					content = string(v)
				}
			}
		}
		tuples = append(tuples, s.kind+"/"+objKey+"/"+key+"="+
			fmt.Sprintf("%x", sha256.Sum256([]byte(content))))
	}
	if len(tuples) == 0 {
		return ""
	}
	sort.Strings(tuples)
	sum := sha256.Sum256([]byte(strings.Join(tuples, "\n")))
	return hex.EncodeToString(sum[:])
}
