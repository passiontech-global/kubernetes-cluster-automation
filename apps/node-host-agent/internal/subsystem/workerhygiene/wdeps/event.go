// event.go — the events.v1 Warning scaffold the check emitters
// share. Every emitter in the tree builds the same shape — Reason
// doubling as Action, the node-host-agent reporting identity, a
// microsecond EventTime off the seams clock, a
// "<regarding>.<hex-nanos>" name and a Node-or-Pod ObjectReference
// — and every emitter logs the same "suspect: <reason> event
// create failed" line on a Create error. This file owns that
// scaffold once; the callers keep their per-event names, notes,
// budgets and ACTION lines.
package wdeps

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CheckEvent is one events.v1 emission — the fields that vary
// between the check emitters. Reason doubles as Action (all
// current emitters set them identically); When overrides the
// EventTime for back-dated events (the OOM victim's kernel epoch —
// zero means the seams clock now); Owner is the suffix of the
// create-failure suspect line ("pod kube-system/x", "node n1")
// and stays empty for node-scoped emitters that never carried one.
type CheckEvent struct {
	Name      string
	Namespace string
	Reason    string
	Note      string
	When      time.Time
	Regarding corev1.ObjectReference
	Owner     string
}

// ErrNoEventClient reports the nil-client seam — callers that
// must distinguish "event created" from "never attempted" (the
// SystemOOMVictim dedup marker) branch on it; the rest just
// ignore the return.
var ErrNoEventClient = errors.New("node-host-agent: no events client")

// EmitCheckEvent builds the shared events.v1 Warning and creates
// it through the client seam. A nil client returns ErrNoEventClient
// without logging — several callers gate on it themselves, the
// localpv emitter never did, and an event is best-effort telemetry
// either way. A create failure appends the shared suspect line and
// returns the error so callers can hold their dedup markers (the
// SystemOOMVictim contract); success returns nil.
func (d *Deps) EmitCheckEvent(ctx context.Context, ev CheckEvent) error {
	if d.Cfg.Client == nil {
		return ErrNoEventClient
	}
	now := d.Cfg.Seams.Host.Clock.Now()
	when := now
	if !ev.When.IsZero() {
		when = ev.When
	}
	e := &eventsv1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ev.Name,
			Namespace: ev.Namespace,
		},
		EventTime:           metav1.NewMicroTime(when),
		Reason:              ev.Reason,
		Note:                ev.Note,
		Type:                corev1.EventTypeWarning,
		ReportingController: "node-host-agent",
		ReportingInstance:   d.Cfg.NodeName,
		Action:              ev.Reason,
		Regarding:           ev.Regarding,
	}
	if _, err := d.Cfg.Client.EventsV1().Events(ev.Namespace).
		Create(ctx, e, metav1.CreateOptions{}); err != nil {
		owner := ""
		if ev.Owner != "" {
			owner = " for " + ev.Owner
		}
		d.State.AppendLog(fmt.Sprintf(
			"suspect: %s event create failed%s: %v", ev.Reason, owner, err))
		return err
	}
	return nil
}

// EmitPodEvent builds and emits a pod-scoped Warning event using the
// standard `<pod>.<suffix>.<hex-nanos>` name and `pod <ns>/<name>`
// owner convention.
func (d *Deps) EmitPodEvent(ctx context.Context, p *corev1.Pod,
	suffix, reason, note string) error {
	now := d.Cfg.Seams.Host.Clock.Now()
	name := fmt.Sprintf("%s.%x", p.Name, now.UnixNano())
	if suffix != "" {
		name = fmt.Sprintf("%s.%s.%x", p.Name, suffix, now.UnixNano())
	}
	return d.EmitCheckEvent(ctx, CheckEvent{
		Name:      name,
		Namespace: p.Namespace,
		Reason:    reason,
		Note:      note,
		When:      now,
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Pod",
			Namespace:  p.Namespace,
			Name:       p.Name,
			UID:        p.UID,
		},
		Owner: "pod " + p.Namespace + "/" + p.Name,
	})
}
