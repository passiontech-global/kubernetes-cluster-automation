package shared

import (
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestConfirmAbsent(t *testing.T) {
	notFound := apierrors.NewNotFound(
		schema.GroupResource{Group: "", Resource: "services"}, "svc")
	unavailable := apierrors.NewServiceUnavailable("etcd: leader changed")

	tests := []struct {
		name     string
		getErr   error
		wantGone bool
		wantErr  bool
	}{
		{"NotFound confirms absence — delete proceeds", notFound, true, false},
		{"confirm failed — fail closed, keep the object", unavailable, false, true},
		{"Get succeeded — snapshot was stale", nil, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gone, err := ConfirmAbsent(tt.getErr)
			if gone != tt.wantGone {
				t.Fatalf("gone = %v, want %v", gone, tt.wantGone)
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != tt.getErr {
				t.Fatal("a confirm failure should pass the Get error through verbatim")
			}
		})
	}
}
