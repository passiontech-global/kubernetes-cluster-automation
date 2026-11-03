package deschedulerstormgate

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

var ctx = context.Background()

func deschedulerDeploy(replicas int32, annos map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "descheduler", Namespace: "kube-system", Annotations: annos,
		},
		Spec: appsv1.DeploymentSpec{Replicas: &replicas},
	}
}

func getDeschedulerReplicas(t *testing.T, cs *fake.Clientset) int32 {
	t.Helper()
	d, err := cs.AppsV1().Deployments("kube-system").
		Get(ctx, "descheduler", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return *d.Spec.Replicas
}
