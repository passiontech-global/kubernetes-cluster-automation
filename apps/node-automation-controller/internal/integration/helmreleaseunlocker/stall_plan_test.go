// stall_plan_test.go — coverage for the stall-plan pure helpers:
// the anti-affinity scheduling-deadlock signatures — only an
// affinity-shaped PodScheduled=False message proves the surge pod
// is wedged BY anti-affinity (cpu/taints/image failures read false),
// and only a required term whose selector matches the NEW labels is
// the deadlock (preferred terms and unparseable selectors never count).
package helmreleaseunlocker

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// podBlockedByTruthy builds a pod carrying one PodScheduled
// condition — status "" leaves the condition absent where the
// table needs it.
func podScheduledCond(status corev1.ConditionStatus, msg string) *corev1.Pod {
	return &corev1.Pod{
		Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{
			Type: corev1.PodScheduled, Status: status, Message: msg}}},
	}
}

func TestPodBlockedByAffinity(t *testing.T) {
	cases := []struct {
		name string
		pod  *corev1.Pod
		want bool
	}{
		{"no conditions is not blocked", &corev1.Pod{}, false},
		{"scheduled pod is not blocked",
			podScheduledCond(corev1.ConditionTrue, ""), false},
		{"existing-pods anti-affinity message is the wedge",
			podScheduledCond(corev1.ConditionFalse,
				"0/5 nodes are available: didn't satisfy existing pods anti-affinity rules"), true},
		{"pod anti-affinity rules message is the wedge",
			podScheduledCond(corev1.ConditionFalse,
				"1/3 nodes are available: didn't match pod anti-affinity rules"), true},
		{"insufficient cpu is a different failure",
			podScheduledCond(corev1.ConditionFalse,
				"0/5 nodes are available: Insufficient cpu"), false},
		{"untolerated taint is a different failure",
			podScheduledCond(corev1.ConditionFalse,
				"0/5 nodes are available: untolerated taint"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := podBlockedByAffinity(tc.pod); got != tc.want {
				t.Fatalf("podBlockedByAffinity = %v, want %v", got, tc.want)
			}
		})
	}
}

func tplWithAntiAffinity(terms ...corev1.PodAffinityTerm) *corev1.PodTemplateSpec {
	return &corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			Affinity: &corev1.Affinity{
				PodAntiAffinity: &corev1.PodAntiAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: terms,
				},
			},
		},
	}
}

func TestRequiredAntiAffinityMatches(t *testing.T) {
	matching := metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "web"}}
	other := metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "db"}}
	invalid := metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "app", Operator: "NotAnOperator"}}}
	labels := map[string]string{"app": "web"}

	cases := []struct {
		name string
		tpl  *corev1.PodTemplateSpec
		want bool
	}{
		{"nil affinity never blocks", &corev1.PodTemplateSpec{}, false},
		{"nil anti-affinity never blocks", &corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{Affinity: &corev1.Affinity{}}}, false},
		{"nil term selector selects all pods — blocking by definition",
			tplWithAntiAffinity(corev1.PodAffinityTerm{}), true},
		{"selector matching the new labels is the deadlock",
			tplWithAntiAffinity(corev1.PodAffinityTerm{LabelSelector: &matching}), true},
		{"selector against other labels is no deadlock",
			tplWithAntiAffinity(corev1.PodAffinityTerm{LabelSelector: &other}), false},
		{"an unparseable selector is skipped, not counted",
			tplWithAntiAffinity(corev1.PodAffinityTerm{LabelSelector: &invalid}), false},
		{"preferred terms never count", &corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{Affinity: &corev1.Affinity{
				PodAntiAffinity: &corev1.PodAntiAffinity{
					PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
						Weight: 100,
						PodAffinityTerm: corev1.PodAffinityTerm{
							LabelSelector: &matching}},
					}}}}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := requiredAntiAffinityMatches(tc.tpl, labels); got != tc.want {
				t.Fatalf("requiredAntiAffinityMatches = %v, want %v", got, tc.want)
			}
		})
	}
}
