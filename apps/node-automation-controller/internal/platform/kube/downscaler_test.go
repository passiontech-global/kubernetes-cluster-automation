package kube

import "testing"

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
	}
	for _, c := range cases {
		if got := IsIntentionallyDownscaled(c.annotations, c.replicas); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
