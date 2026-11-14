// helmprune_test.go — unit tests for the shared superseded Helm release
// secret prune (both typed and PartialObjectMetadata read paths).
package helmprune

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	metadatafake "k8s.io/client-go/metadata/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

func helmSecret(ns, name, release string, version int, status string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			UID:       types.UID("uid-" + ns + "-" + name),
			Labels: map[string]string{
				"owner":   "helm",
				"name":    release,
				"version": strconv.Itoa(version),
				"status":  status,
			},
		},
		Type: corev1.SecretType(helmReleaseSecretType),
		Data: map[string][]byte{"release": []byte("compressed-chart")},
	}
}

func TestPruneSupersededHelmSecrets_TypedSelectionAndHooks(t *testing.T) {
	t.Parallel()

	// Release "app" in "ns1": versions 1, 2, 3, 4 (all superseded) +
	// unversioned + non-superseded + Opaque decoy + unlabeled release.
	// With maxSuperseded=2, excess=2, deletes v1 and v2 (oldest); keeps v3 and v4.
	objs := []runtime.Object{
		helmSecret("ns1", "sh.helm.release.v1.app.v1", "app", 1, "superseded"),
		helmSecret("ns1", "sh.helm.release.v1.app.v2", "app", 2, "superseded"),
		helmSecret("ns1", "sh.helm.release.v1.app.v3", "app", 3, "superseded"),
		helmSecret("ns1", "sh.helm.release.v1.app.v4", "app", 4, "superseded"),
		// Unversioned secret — ignored for pruning but returned in helmTyped.
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "ns1",
				Name:      "sh.helm.release.v1.app.unversioned",
				Labels:    map[string]string{"owner": "helm", "name": "app", "status": "superseded", "version": "abc"},
			},
			Type: corev1.SecretType(helmReleaseSecretType),
		},
		// Non-superseded status — ignored for pruning.
		helmSecret("ns1", "sh.helm.release.v1.app.v5", "app", 5, "deployed"),
		// Opaque decoy — filtered out by listHelmSecretsTyped.
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "ns1",
				Name:      "opaque-decoy",
				Labels:    map[string]string{"owner": "helm", "name": "app", "status": "superseded", "version": "0"},
			},
			Type: corev1.SecretTypeOpaque,
		},
		// Missing "name" label — not grouped into any release.
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "ns1",
				Name:      "no-name-label",
				Labels:    map[string]string{"owner": "helm", "status": "superseded", "version": "1"},
			},
			Type: corev1.SecretType(helmReleaseSecretType),
		},
	}
	cs := fake.NewClientset(objs...)

	var excessCalls []string
	var preDeleteVers []int
	var deletedVers []int
	var deleteUIDs []types.UID
	cs.PrependReactor("delete", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		da := action.(k8stesting.DeleteAction)
		if da.GetDeleteOptions().Preconditions != nil && da.GetDeleteOptions().Preconditions.UID != nil {
			deleteUIDs = append(deleteUIDs, *da.GetDeleteOptions().Preconditions.UID)
		}
		return false, nil, nil
	})

	listed, err := PruneSupersededHelmSecrets(context.Background(), cs, 2, HelmSecretPruneHooks{
		Excess: func(ns, release string, superseded, cap int) {
			excessCalls = append(excessCalls, ns+"/"+release+":"+strconv.Itoa(superseded)+"/"+strconv.Itoa(cap))
		},
		PreDelete: func(s *corev1.Secret, version, supersededTotal int) {
			preDeleteVers = append(preDeleteVers, version)
		},
		Deleted: func(s *corev1.Secret, version int) {
			deletedVers = append(deletedVers, version)
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// All 6 matching helm-typed secrets (label selector filters status=superseded) should be returned, with Data cleared.
	if len(listed) != 6 {
		t.Fatalf("expected 6 helm-typed secrets, got %d", len(listed))
	}
	for _, s := range listed {
		if s.Data != nil {
			t.Errorf("expected Data=nil on %s, got %v", s.Name, s.Data)
		}
	}
	if !slices.Equal(excessCalls, []string{"ns1/app:4/2"}) {
		t.Errorf("unexpected Excess calls: %v", excessCalls)
	}
	if !slices.Equal(preDeleteVers, []int{1, 2}) {
		t.Errorf("unexpected PreDelete versions: %v", preDeleteVers)
	}
	if !slices.Equal(deletedVers, []int{1, 2}) {
		t.Errorf("unexpected Deleted versions: %v", deletedVers)
	}
	if len(deleteUIDs) != 2 || deleteUIDs[0] != "uid-ns1-sh.helm.release.v1.app.v1" || deleteUIDs[1] != "uid-ns1-sh.helm.release.v1.app.v2" {
		t.Errorf("unexpected delete UID preconditions: %v", deleteUIDs)
	}
}

func TestPruneSupersededHelmSecrets_NeverDeletesHighest(t *testing.T) {
	t.Parallel()

	// Even with maxSuperseded=0, the highest superseded revision (v2) is preserved.
	cs := fake.NewClientset(
		helmSecret("ns1", "rel-v1", "rel", 1, "superseded"),
		helmSecret("ns1", "rel-v2", "rel", 2, "superseded"),
	)
	var deleted []int
	_, err := PruneSupersededHelmSecrets(context.Background(), cs, 0, HelmSecretPruneHooks{
		Deleted: func(_ *corev1.Secret, v int) { deleted = append(deleted, v) },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Equal(deleted, []int{1}) {
		t.Fatalf("expected only v1 deleted, got %v", deleted)
	}
}

func TestPruneSupersededHelmSecrets_DeleteNotFoundAndErrors(t *testing.T) {
	t.Parallel()

	// 4 superseded secrets, maxSuperseded=1 => excess=3 (candidates v1, v2, v3; v4 is highest).
	// v1 returns NotFound (counts toward toDelete, no DeleteFailed/Deleted).
	// v2 returns InternalError (triggers DeleteFailed, does NOT decrement toDelete, tries v3).
	// v3 succeeds (Deleted fires).
	cs := fake.NewClientset(
		helmSecret("ns1", "rel-v1", "rel", 1, "superseded"),
		helmSecret("ns1", "rel-v2", "rel", 2, "superseded"),
		helmSecret("ns1", "rel-v3", "rel", 3, "superseded"),
		helmSecret("ns1", "rel-v4", "rel", 4, "superseded"),
	)
	cs.PrependReactor("delete", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		name := action.(k8stesting.DeleteAction).GetName()
		switch name {
		case "rel-v1":
			return true, nil, apierrors.NewNotFound(corev1.Resource("secrets"), name)
		case "rel-v2":
			return true, nil, apierrors.NewInternalError(errors.New("boom"))
		}
		return false, nil, nil
	})

	var deleted []int
	var failed []string
	_, err := PruneSupersededHelmSecrets(context.Background(), cs, 1, HelmSecretPruneHooks{
		Deleted:      func(_ *corev1.Secret, v int) { deleted = append(deleted, v) },
		DeleteFailed: func(s *corev1.Secret, _ error) { failed = append(failed, s.Name) },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Equal(failed, []string{"rel-v2"}) {
		t.Errorf("expected DeleteFailed for rel-v2, got %v", failed)
	}
	if !slices.Equal(deleted, []int{3}) {
		t.Errorf("expected Deleted for v3, got %v", deleted)
	}
}

func TestPruneSupersededHelmSecrets_TypedListBadRequestRetryAndError(t *testing.T) {
	t.Parallel()

	cs := fake.NewClientset(helmSecret("ns1", "rel-v1", "rel", 1, "superseded"))
	calls := 0
	cs.PrependReactor("list", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		if calls == 1 {
			return true, nil, apierrors.NewBadRequest("field selector unsupported")
		}
		return false, nil, nil
	})

	listed, err := PruneSupersededHelmSecrets(context.Background(), cs, 1, HelmSecretPruneHooks{})
	if err != nil {
		t.Fatalf("expected BadRequest retry to succeed, got %v", err)
	}
	if calls != 2 || len(listed) != 1 {
		t.Fatalf("expected 2 list calls and 1 secret, got calls=%d len=%d", calls, len(listed))
	}

	// Non-BadRequest list error is returned directly.
	csErr := fake.NewClientset()
	csErr.PrependReactor("list", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, &apierrors.StatusError{ErrStatus: metav1.Status{
			Status:  metav1.StatusFailure,
			Code:    http.StatusForbidden,
			Reason:  metav1.StatusReasonForbidden,
			Message: "forbidden",
		}}
	})
	if _, err := PruneSupersededHelmSecrets(context.Background(), csErr, 1, HelmSecretPruneHooks{}); err == nil {
		t.Fatal("expected forbidden list error")
	}
}

func TestPruneSupersededHelmSecretsMeta_PartialReadAndRetry(t *testing.T) {
	t.Parallel()

	s1 := helmSecret("ns1", "rel-v1", "rel", 1, "superseded")
	s2 := helmSecret("ns1", "rel-v2", "rel", 2, "superseded")
	s3 := helmSecret("ns1", "rel-v3", "rel", 3, "superseded")

	meta := testhelp.NewMetaClient(
		testhelp.MetaObj("v1", "Secret", s1.ObjectMeta),
		testhelp.MetaObj("v1", "Secret", s2.ObjectMeta),
		testhelp.MetaObj("v1", "Secret", s3.ObjectMeta),
	)
	// Inject a BadRequest on the first metadata list to cover the retry branch.
	metaCalls := 0
	meta.(*metadatafake.FakeMetadataClient).PrependReactor("list", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		metaCalls++
		if metaCalls == 1 {
			return true, nil, apierrors.NewBadRequest("field selector not supported")
		}
		return false, nil, nil
	})

	cs := fake.NewClientset(s1, s2, s3)
	var deleted []int
	listed, err := PruneSupersededHelmSecretsMeta(context.Background(), meta, cs, nil, 1, HelmSecretPruneHooks{
		Deleted: func(_ *corev1.Secret, v int) { deleted = append(deleted, v) },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if metaCalls != 2 {
		t.Errorf("expected 2 metadata list calls (retry on BadRequest), got %d", metaCalls)
	}
	if len(listed) != 3 {
		t.Errorf("expected 3 secrets projected, got %d", len(listed))
	}
	if !slices.Equal(deleted, []int{1, 2}) {
		t.Errorf("expected v1 and v2 deleted, got %v", deleted)
	}

	// Non-BadRequest metadata list error propagates.
	metaErr := testhelp.NewMetaClient()
	metaErr.(*metadatafake.FakeMetadataClient).PrependReactor("list", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewInternalError(errors.New("meta fail"))
	})
	if _, err := listHelmSecretsPartial(context.Background(), metaErr, cs, nil, metav1.ListOptions{}); err == nil {
		t.Fatal("expected error from listHelmSecretsPartial")
	}
}
