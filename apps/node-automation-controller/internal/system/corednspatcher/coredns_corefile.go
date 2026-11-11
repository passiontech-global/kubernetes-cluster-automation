// coredns_corefile.go — the Corefile negative-cache reconcile
// (negative-cache-guard): reads kube-system/coredns's ConfigMap and caps
// NXDOMAIN negative caching at 5s. split from coredns_patcher.go (see its
// header for the module contract).
package corednspatcher

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// ---------------------------------------------------------------------------
// Corefile negative-cache reconcile (negative-cache-guard)
// ---------------------------------------------------------------------------

const (
	corednsConfigNS   = "kube-system"
	corednsConfigName = "coredns"
	corednsCorefile   = "Corefile"
	// corefileDenialDirective is the injected negative-cache cap —
	// 9984 entries at 5s TTL (a bare `cache 30` negative-caches
	// NXDOMAIN for the full SOA TTL and kills fresh-deploy Jobs).
	corefileDenialDirective = "denial 9984 5"
	corefileSuccessLine     = "success 9984 30"
)

// reconcileCorefile reads kube-system/coredns's Corefile and merge-
// patches it when a cache directive lacks a denial cap (see the
// header note). A missing ConfigMap/Corefile is tolerated — the k0s
// stack applier owns the object and re-creates it; a patch or get
// failure surfaces so the reconcile retries on the apiserver's
// backoff instead of silently leaving a 30s NXDOMAIN cache live.
func (r *corednsPatcher) reconcileCorefile(ctx context.Context) error {
	cm, err := r.cs.CoreV1().ConfigMaps(corednsConfigNS).
		Get(ctx, corednsConfigName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return nil
	case err != nil:
		return fmt.Errorf("get configmap %s/%s: %w",
			corednsConfigNS, corednsConfigName, err)
	}
	corefile := cm.Data[corednsCorefile]
	if corefile == "" {
		return nil
	}
	rewritten, changed := corefileDenialCap(corefile)
	if !changed {
		return nil
	}
	payload, err := json.Marshal(map[string]any{
		"data": map[string]any{corednsCorefile: rewritten},
	})
	if err != nil {
		return fmt.Errorf("marshal coredns corefile patch: %w", err)
	}
	if _, err := r.cs.CoreV1().ConfigMaps(corednsConfigNS).Patch(ctx,
		corednsConfigName, types.MergePatchType, payload,
		metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("patch configmap %s/%s: %w",
			corednsConfigNS, corednsConfigName, err)
	}
	logf.FromContext(ctx).Info("PATCH: Corefile cache directive gains a 5s denial cap " +
		"(NXDOMAIN no longer negative-caches for the full SOA TTL)")
	return nil
}

// corefileDenialCap rewrites every cache directive in the Corefile
// that carries no denial directive. Bare `cache 30` (optionally with
// zone args) expands to the success+denial block; an already-braced
// `cache 30 { ... }` block keeps its contents and only gains the
// denial line it lacks. A block that already declares denial is
// untouched — idempotent by construction. Returns (rewritten, changed).
//
// The parser is a line scan, not a Corefile grammar: `cache` is the
// only directive the rewrite touches, brace depth tracks the block
// it opens, and comment lines (#…) can never satisfy or break the
// denial check.
//
// Comments are stripped BEFORE any brace counting or slicing: a `#`
// inside a Corefile line comments out the rest of the line, so a
// brace (or a whole directive) inside a comment must never open,
// close, or depth-count a block — `cache 30 { # ops note }` opens a
// MULTI-line block (the `}` lives in the comment), and `# }` in a
// block body must not close it.
func corefileDenialCap(corefile string) (string, bool) {
	lines := strings.Split(corefile, "\n")
	changed := false
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		fields := strings.Fields(trimmed)
		if len(fields) == 0 || fields[0] != "cache" {
			continue
		}
		indent := lines[i][:len(lines[i])-len(strings.TrimLeft(lines[i], " \t"))]
		// Code-only view of the line: everything up to the first `#`.
		// A prefix of the original line, so indices into it index the
		// original too.
		code := strings.TrimSpace(stripCorefileComment(trimmed))
		open := strings.Index(code, "{")
		switch {
		case open < 0:
			// Bare form: `cache 30 [zones...]` → replace with the
			// braced success+denial block, keeping the args and the
			// line's own indentation. A trailing comment is carried
			// INSIDE the braces — appended after the `{` it would be
			// commented out of the Corefile entirely.
			comment := ""
			if hash := strings.Index(lines[i], "#"); hash >= 0 {
				if c := strings.TrimSpace(lines[i][hash:]); c != "" {
					comment = " " + c
				}
			}
			lines[i] = indent + code + " {" + comment + "\n" +
				indent + "    " + corefileSuccessLine + "\n" +
				indent + "    " + corefileDenialDirective + "\n" +
				indent + "}"
			changed = true
		case strings.LastIndex(code, "}") > open:
			// Inline single-line block `cache 30 { denial 9984 5 }`:
			// a denial inside already satisfies; without one, inject
			// before the closing brace. `code` is a prefix of
			// `lines[i]` minus the indent, so code indices shift by
			// len(indent) onto the original line — and a `}` inside a
			// trailing comment is never the injection point.
			inner := code[open+1 : strings.LastIndex(code, "}")]
			if !corefileBlockHasDenial(inner) {
				last := len(indent) + strings.LastIndex(code, "}")
				lines[i] = lines[i][:last] + " " + corefileDenialDirective + " }" +
					lines[i][last+len("}"):]
				changed = true
			}
		default:
			// Braced multi-line block: find the matching close and
			// inject denial before it when absent. Depth counts
			// comment-stripped braces only — `# }` never closes, and a
			// `{` or `}` inside a trailing comment never nests.
			depth := strings.Count(code, "{") - strings.Count(code, "}")
			hasDenial := false
			closeIdx := -1
			for j := i + 1; j < len(lines) && depth > 0; j++ {
				t := strings.TrimSpace(stripCorefileComment(lines[j]))
				depth += strings.Count(t, "{") - strings.Count(t, "}")
				if t != "" && strings.Fields(t)[0] == "denial" {
					hasDenial = true
				}
				if depth == 0 {
					closeIdx = j
				}
			}
			if !hasDenial && closeIdx >= 0 {
				lines[closeIdx] = indent + "    " + corefileDenialDirective +
					"\n" + lines[closeIdx]
				changed = true
				i = closeIdx // skip past the handled block
			} else if closeIdx >= 0 {
				i = closeIdx
			}
		}
	}
	if !changed {
		return corefile, false
	}
	return strings.Join(lines, "\n"), true
}

// stripCorefileComment cuts a Corefile line at its first `#` —
// everything from there on is a comment (coredns has no escape for a
// literal # in directive syntax, so the cut is unconditional).
func stripCorefileComment(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		return line[:i]
	}
	return line
}

// corefileBlockHasDenial reports whether an inline cache block body
// already declares a denial directive. Separators inside the braces
// are optional (`{ success 9984 30  denial 9984 5 }` is what our own
// injector emits on a separator-less input), so the scan is for a
// bare `denial` token anywhere in the body — a zone arg such as
// `denial.example.com` lands as a single field and cannot collide.
func corefileBlockHasDenial(inner string) bool {
	for _, f := range strings.Fields(inner) {
		if f == "denial" {
			return true
		}
	}
	return false
}
