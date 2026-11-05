package shared

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestUIDDeleteOptions(t *testing.T) {
	opts := UIDDeleteOptions("abc-123", metav1.DeletePropagationBackground)
	if opts.Preconditions == nil || opts.Preconditions.UID == nil ||
		*opts.Preconditions.UID != "abc-123" {
		t.Fatal("UID precondition not set")
	}
	if opts.PropagationPolicy == nil ||
		*opts.PropagationPolicy != metav1.DeletePropagationBackground {
		t.Fatal("propagation policy not set")
	}

	opts = UIDDeleteOptions("x", "")
	if opts.Preconditions == nil || *opts.Preconditions.UID != "x" {
		t.Fatal("UID precondition not set")
	}
	if opts.PropagationPolicy != nil {
		t.Fatal("empty propagation should leave the policy unset")
	}
}
