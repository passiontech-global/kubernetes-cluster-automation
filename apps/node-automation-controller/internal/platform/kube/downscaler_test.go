package kube

import (
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func i32(v int32) *int32 { return &v }

func TestIsIntentionallyDownscaled(t *testing.T) {
	cases := []struct {
		name        string
		annotations map[string]string
		replicas    *int32
		want        bool
	}{
		{"zero replicas + uptime annotation", map[string]string{"downscaler/uptime": "Mon-Fri 08:00-18:00"}, i32(0), true},
		{"zero replicas + downtime-replicas", map[string]string{"downscaler/downtime-replicas": "0"}, i32(0), true},
		{"zero replicas + force-downtime", map[string]string{"downscaler/force-downtime": "true"}, i32(0), true},
		{"zero replicas, no annotations", map[string]string{}, i32(0), false},
		{"zero replicas, nil annotations", nil, i32(0), false},
		{"zero replicas, unrelated annotation", map[string]string{"app/version": "1.2"}, i32(0), false},
		{"nonzero replicas + annotation", map[string]string{"downscaler/uptime": "x"}, i32(3), false},
		{"nil replicas + annotation (default 1)", map[string]string{"downscaler/uptime": "x"}, nil, false},
		{"nil replicas, nil annotations", nil, nil, false},
		{"annotation key with prefix only", map[string]string{"downscaler/": ""}, i32(0), true},
		{"similar-but-not-downscaler prefix", map[string]string{"downscalers/uptime": "x"}, i32(0), false},
		// Opt-out annotations are config, not sleep evidence — a zero
		// on an excluded workload is a crash, not the downscaler.
		{"exclude true vetoes", map[string]string{"downscaler/exclude": "true"}, i32(0), false},
		{"exclude true case/space-insensitive", map[string]string{"downscaler/exclude": " True "}, i32(0), false},
		{"force-uptime true vetoes", map[string]string{"downscaler/force-uptime": "true"}, i32(0), false},
		{"exclude-until alone is config", map[string]string{"downscaler/exclude-until": "2026-01-01T00:00:00Z"}, i32(0), false},
		{"exclude with duration value is config", map[string]string{"downscaler/exclude": "2h"}, i32(0), false},
		{"uptime + exclude true → awake on purpose", map[string]string{"downscaler/uptime": "Mon-Fri 08:00-18:00", "downscaler/exclude": "true"}, i32(0), false},
		{"uptime + force-uptime true → awake on purpose", map[string]string{"downscaler/uptime": "Mon-Fri 08:00-18:00", "downscaler/force-uptime": "TRUE"}, i32(0), false},
		{"uptime + exclude-until → still downscaled", map[string]string{"downscaler/uptime": "Mon-Fri 08:00-18:00", "downscaler/exclude-until": "2026-01-01T00:00:00Z"}, i32(0), true},
		{"grace-period counts as schedule evidence", map[string]string{"downscaler/grace-period": "10m"}, i32(0), true},
	}
	for _, c := range cases {
		if got := IsIntentionallyDownscaled(c.annotations, c.replicas); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDownscaledClusterCRs(t *testing.T) {
	items := []unstructured.Unstructured{
		{Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace":   "ns1",
				"name":        "df-parked",
				"annotations": map[string]interface{}{"downscaler/uptime": "Mon-Fri 08:00-18:00"},
			},
			"spec": map[string]interface{}{"replicas": int64(0)},
		}},
		{Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace":   "ns1",
				"name":        "df-live",
				"annotations": map[string]interface{}{"downscaler/uptime": "Mon-Fri 08:00-18:00"},
			},
			"spec": map[string]interface{}{"replicas": int64(3)},
		}},
	}

	got, err := DownscaledClusterCRs(items, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got["ns1/df-parked"] || got["ns1/df-live"] || len(got) != 1 {
		t.Fatalf("unexpected downscaled map: %v", got)
	}

	// NotFound and NoMatchError are treated as "none parked".
	for _, listErr := range []error{
		apierrors.NewNotFound(schema.GroupResource{Group: "g", Resource: "r"}, "x"),
		&meta.NoResourceMatchError{PartialResource: schema.GroupVersionResource{Resource: "r"}},
	} {
		got, err := DownscaledClusterCRs(nil, listErr)
		if err != nil || len(got) != 0 {
			t.Fatalf("expected empty map and nil err for %v, got %v, %v", listErr, got, err)
		}
	}

	// Other errors propagate.
	if _, err := DownscaledClusterCRs(nil, errors.New("apiserver down")); err == nil {
		t.Fatal("expected error to propagate")
	}
}

func TestOwnsOrdinalPodAndDownscaledMemberPod(t *testing.T) {
	cases := []struct {
		cr, pod string
		want    bool
	}{
		{"db", "db-0", true},
		{"db", "db-12", true},
		{"db", "db-server-0", true},
		{"db", "db-cache-0", false},
		{"db", "other-0", false},
		{"db", "db-server-abc", false},
	}
	for _, tc := range cases {
		if got := OwnsOrdinalPod(tc.cr, tc.pod); got != tc.want {
			t.Errorf("OwnsOrdinalPod(%q, %q) = %v, want %v", tc.cr, tc.pod, got, tc.want)
		}
	}

	downscaled := map[string]bool{
		"ns1/db": true,
		"badkey": true,
	}
	if !DownscaledMemberPod("ns1", "db-server-1", downscaled) {
		t.Error("expected ns1/db-server-1 to match ns1/db")
	}
	if DownscaledMemberPod("ns2", "db-0", downscaled) {
		t.Error("expected ns2/db-0 not to match ns1/db")
	}
}
