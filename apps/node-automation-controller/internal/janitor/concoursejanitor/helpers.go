// helpers.go — the janitor's small helpers: the ATC credential read
// and baseline-annotation patch plus the bash-style ${VAR:-?}
// formatting fallbacks (split out of concourse_janitor.go — see its
// header for the module contract).
package concoursejanitor

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// atcCredentials reads the break-glass local user from the
// concourse-web/local-users Secret (ES-managed): first line is
// "user:password", split on the FIRST colon (the password itself may
// contain colons).
func (j *concourseWorkdirJanitor) atcCredentials(ctx context.Context) (string, string, error) {
	cctx, cancel := context.WithTimeout(ctx, j.reqTimeout)
	defer cancel()
	sec, err := j.cs.CoreV1().Secrets(cjNamespace).Get(cctx, cjSecretName, metav1.GetOptions{})
	if err != nil {
		return "", "", err
	}
	line, _, _ := strings.Cut(string(sec.Data[cjSecretKey]), "\n")
	// Trim a possible CRLF — a stray \r inside the password would 401
	// every login and silently degrade the whole module to
	// delete-only mode.
	line = strings.TrimRight(line, "\r\n")
	user, pass, ok := strings.Cut(line, ":")
	if !ok || user == "" {
		return "", "", fmt.Errorf("secret %s key %s has no \"user:password\" first line",
			cjSecretName, cjSecretKey)
	}
	return user, pass, nil
}

// annotateBaseline merge-patches baseline-nodefs-gib=<nodefsGiB> onto
// the pod (kubectl annotate --overwrite). The annotation is what the
// next run subtracts from nodefs to get the work-dir usage.
func (j *concourseWorkdirJanitor) annotateBaseline(ctx context.Context, pod string, nodefsGiB int64) error {
	cctx, cancel := context.WithTimeout(ctx, j.reqTimeout)
	defer cancel()
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": map[string]string{
			cjBaselineAnno: strconv.FormatInt(nodefsGiB, 10),
		}},
	})
	if err != nil {
		return err
	}
	_, err = j.cs.CoreV1().Pods(cjNamespace).Patch(cctx, pod,
		types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}

// ---------------------------------------------------------------------------
// Small formatting helpers (bash's ${VAR:-?} fallback).
// ---------------------------------------------------------------------------

func strOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// intOr prints the number or "?" — used for both GiB and % fields
// (bash's ${VAR:-?} fallback).
func intOr(v int64, ok bool) string {
	if !ok {
		return "?"
	}
	return strconv.FormatInt(v, 10)
}
