// kms_secret_canary_guard.go — health check "kms-secret-canary-guard":
// active canary Secret round-trip probe verifying KMS / encryption-at-rest
// write+read health without churning kine (rate-limited via CooldownSet to
// NODE_AUTOMATION_KMS_CANARY_INTERVAL, default 5m).
//
// Gracefully skips 403 Forbidden (RBAC not granted for canary Secret). On an
// HTTP 500 / decrypt / KMS error, triggers a bounded per-namespace LIST Secrets
// (Limit: 50, max 20 active namespaces per sweep) isolation fallback to pinpoint
// affected namespaces and emit a high-severity Warning Event.
package watchdogs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// CheckNameKMSCanaryGuard is the registry check name for kms-secret-canary-guard.
	CheckNameKMSCanaryGuard = "kms-secret-canary-guard"

	kmsCanarySecretName      = "node-automation-kms-canary"
	kmsCanaryDataKey         = "canary"
	kmsCanaryDefaultNS       = "node-ops"
	kmsCanaryDefaultInterval = 5 * time.Minute
	kmsCanaryEventReason     = "KMSSecretCanaryFailed"
	kmsCanaryEventCooldown   = 30 * time.Minute
	kmsCanaryMaxIsolationNS  = 20
	kmsCanaryListPageLimit   = int64(50)

	kmsCanaryReasonDecrypt  = "kms_decrypt_error"
	kmsCanaryReasonMismatch = "roundtrip_mismatch"
	kmsCanaryReasonNS500    = "namespace_secret_list_500"
)

var kmsCanaryUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_kms_secret_canary_unhealthy",
	Help: "1 while the KMS encryption-at-rest canary round-trip fails or namespaces fail Secrets LIST with 500/KMS error.",
}, []string{"namespace", "reason"})

func init() {
	ctrlmetrics.Registry.MustRegister(kmsCanaryUnhealthyGauge)
}

type kmsCanaryCheck struct {
	*probefw.Deps

	canaryNS string
	interval time.Duration
	seq      uint64

	runCooldown   state.CooldownSet
	eventCooldown state.CooldownSet
	emitted       state.GaugeLedger[string]
	lastFindings  []string
}

// NewKMSCanaryGuardCheck constructs the kms-secret-canary-guard check.
func NewKMSCanaryGuardCheck(d *probefw.Deps) probefw.Check {
	ns := envx.Getenv("NODE_AUTOMATION_KMS_CANARY_NAMESPACE", "")
	if ns == "" {
		ns = envx.Getenv("POD_NAMESPACE", kmsCanaryDefaultNS)
	}
	interval := envx.GetenvDuration("NODE_AUTOMATION_KMS_CANARY_INTERVAL", kmsCanaryDefaultInterval)

	return &kmsCanaryCheck{
		Deps:     d,
		canaryNS: ns,
		interval: interval,
	}
}

func (c *kmsCanaryCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, kmsCanaryEventCooldown)

	var rep probefw.SweepReport

	if c.runCooldown.CooledDown("canary", c.interval, now) {
		for k, lv := range c.emitted.Last() {
			rep.Carry(k, lv)
		}
		for _, f := range c.lastFindings {
			rep.Find(f)
		}
		return rep.Result(&c.emitted, kmsCanaryUnhealthyGauge.DeleteLabelValues,
			"kms secret canary failed: ", ", ")
	}

	c.runCooldown.Stamp("canary", now)
	c.seq++
	nonce := fmt.Sprintf("%d-%d", now.UnixNano(), c.seq)
	wantBytes := []byte(nonce)

	canaryErr := c.kmsCanaryWriteAndRead(ctx, wantBytes)
	switch {
	case canaryErr == nil:
		c.lastFindings = nil
		return rep.Result(&c.emitted, kmsCanaryUnhealthyGauge.DeleteLabelValues,
			"kms secret canary failed: ", ", ")

	case apierrors.IsForbidden(canaryErr):
		log.V(1).Info("KMS secret canary skipped (403 Forbidden)", "namespace", c.canaryNS, "error", canaryErr)
		c.lastFindings = nil
		return rep.Result(&c.emitted, kmsCanaryUnhealthyGauge.DeleteLabelValues,
			"kms secret canary failed: ", ", ")

	case errors.Is(canaryErr, errKMSCanaryMismatch):
		detail := fmt.Sprintf("%s/%s (%s: %v)", c.canaryNS, kmsCanarySecretName, kmsCanaryReasonMismatch, canaryErr)
		rep.Emit(kmsCanaryUnhealthyGauge, c.canaryNS+"/"+kmsCanaryReasonMismatch,
			[]string{c.canaryNS, kmsCanaryReasonMismatch}, detail)
		c.kmsCanaryEmitWarning(ctx, log, now, detail)
		c.lastFindings = slices.Clone(rep.Findings())
		return rep.Result(&c.emitted, kmsCanaryUnhealthyGauge.DeleteLabelValues,
			"kms secret canary failed: ", ", ")

	case kmsCanaryIsKMSError(canaryErr):
		brokenNS := c.kmsCanaryIsolateNamespaces(ctx, log)
		for _, ns := range brokenNS {
			nsDetail := ns + " (LIST Secrets 500/KMS error)"
			rep.Emit(kmsCanaryUnhealthyGauge, ns+"/"+kmsCanaryReasonNS500,
				[]string{ns, kmsCanaryReasonNS500}, nsDetail)
		}
		canaryDetail := fmt.Sprintf("%s/%s (%s: %v)", c.canaryNS, kmsCanarySecretName, kmsCanaryReasonDecrypt, canaryErr)
		if len(brokenNS) > 0 {
			canaryDetail = fmt.Sprintf("%s/%s (%s: %v; affected namespaces=[%s])",
				c.canaryNS, kmsCanarySecretName, kmsCanaryReasonDecrypt, canaryErr, strings.Join(brokenNS, ","))
		}
		rep.Emit(kmsCanaryUnhealthyGauge, c.canaryNS+"/"+kmsCanaryReasonDecrypt,
			[]string{c.canaryNS, kmsCanaryReasonDecrypt}, canaryDetail)
		c.kmsCanaryEmitWarning(ctx, log, now, canaryDetail)
		c.lastFindings = slices.Clone(rep.Findings())
		return rep.Result(&c.emitted, kmsCanaryUnhealthyGauge.DeleteLabelValues,
			"kms secret canary failed: ", ", ")

	default:
		for k, lv := range c.emitted.Last() {
			rep.Carry(k, lv)
		}
		rep.InfraErr(fmt.Errorf("kms canary %s/%s: %w", c.canaryNS, kmsCanarySecretName, canaryErr))
		return rep.Result(&c.emitted, kmsCanaryUnhealthyGauge.DeleteLabelValues,
			"kms secret canary failed: ", ", ")
	}
}

var errKMSCanaryMismatch = errors.New("quorum read payload mismatch")

func (c *kmsCanaryCheck) kmsCanaryWriteAndRead(ctx context.Context, payload []byte) error {
	secrets := c.CS.CoreV1().Secrets(c.canaryNS)
	writeErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		existing, err := secrets.Get(ctx, kmsCanarySecretName, metav1.GetOptions{ResourceVersion: ""})
		switch {
		case apierrors.IsNotFound(err):
			sec := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: c.canaryNS,
					Name:      kmsCanarySecretName,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					kmsCanaryDataKey: payload,
				},
			}
			_, cerr := secrets.Create(ctx, sec, metav1.CreateOptions{})
			if apierrors.IsAlreadyExists(cerr) {
				return apierrors.NewConflict(corev1.Resource("secrets"), kmsCanarySecretName, cerr)
			}
			return cerr
		case err != nil:
			return err
		default:
			uerr := kmsCanaryUpdateSecret(ctx, secrets, existing, payload)
			if apierrors.IsNotFound(uerr) {
				// Secret was deleted between Get and Update; trigger retry to re-create.
				return apierrors.NewConflict(corev1.Resource("secrets"), kmsCanarySecretName, uerr)
			}
			return uerr
		}
	})
	if writeErr != nil {
		return writeErr
	}

	got, err := secrets.Get(ctx, kmsCanarySecretName, metav1.GetOptions{ResourceVersion: ""})
	if err != nil {
		return err
	}
	if !bytes.Equal(got.Data[kmsCanaryDataKey], payload) {
		return fmt.Errorf("%w: got %d bytes, want %d", errKMSCanaryMismatch, len(got.Data[kmsCanaryDataKey]), len(payload))
	}
	return nil
}

func kmsCanaryUpdateSecret(
	ctx context.Context,
	secrets interface {
		Update(ctx context.Context, secret *corev1.Secret, opts metav1.UpdateOptions) (*corev1.Secret, error)
	},
	existing *corev1.Secret,
	payload []byte,
) error {
	updated := existing.DeepCopy()
	if updated.Data == nil {
		updated.Data = make(map[string][]byte, 1)
	}
	updated.Data[kmsCanaryDataKey] = payload
	_, err := secrets.Update(ctx, updated, metav1.UpdateOptions{})
	return err
}

func (c *kmsCanaryCheck) kmsCanaryIsolateNamespaces(ctx context.Context, log logr.Logger) []string {
	namespaces, err := c.AllNamespaces(ctx)
	if err != nil {
		log.V(1).Info("KMS canary isolation namespace list failed", "error", err)
		return nil
	}
	active := make([]string, 0, len(namespaces))
	for i := range namespaces {
		ns := &namespaces[i]
		if ns.DeletionTimestamp != nil || ns.Status.Phase == corev1.NamespaceTerminating {
			continue
		}
		active = append(active, ns.Name)
	}
	sort.Strings(active)
	if len(active) > kmsCanaryMaxIsolationNS {
		active = active[:kmsCanaryMaxIsolationNS]
	}

	var broken []string
	for _, ns := range active {
		if ctx.Err() != nil {
			break
		}
		_, listErr := c.CS.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{
			Limit: kmsCanaryListPageLimit,
		})
		if listErr == nil || apierrors.IsForbidden(listErr) {
			continue
		}
		if kmsCanaryIsKMSError(listErr) {
			broken = append(broken, ns)
		}
	}
	return broken
}

func kmsCanaryIsKMSError(err error) bool {
	if err == nil {
		return false
	}
	if apierrors.IsInternalError(err) {
		return true
	}
	var statusErr apierrors.APIStatus
	if errors.As(err, &statusErr) {
		if statusErr.Status().Code == http.StatusInternalServerError {
			return true
		}
	}
	lower := strings.ToLower(err.Error())
	for _, tok := range []string{"kms", "decrypt", "unable to transform", "data encryption key", "envelope"} {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

func (c *kmsCanaryCheck) kmsCanaryEmitWarning(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	note string,
) {
	cooldownKey := "kms-canary." + c.canaryNS
	probefw.EmitWarningDeduped(ctx, c.CS, log, &c.eventCooldown, cooldownKey, kmsCanaryEventCooldown, now, kube.WarningEvent{
		Namespace: c.canaryNS,
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Secret",
			Namespace:  c.canaryNS,
			Name:       kmsCanarySecretName,
		},
		Reason:            kmsCanaryEventReason,
		Note:              note,
		ReportingInstance: c.Name,
	})
}
