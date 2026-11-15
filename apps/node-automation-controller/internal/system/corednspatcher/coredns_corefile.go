// coredns_corefile.go — the Corefile cache-block reconcile
// (negative-cache-guard/serve-stale): reads kube-system/coredns's
// ConfigMap and heals every cache directive — caps NXDOMAIN negative
// caching at 5s (denial 9984 5) and, when configured, injects
// `serve_stale <dur> immediate` so a CoreDNS backend loss during an
// API/apiserver storm does not turn into a DNS outage for the whole
// cluster. split from coredns_patcher.go (see its header for the
// module contract).
package corednspatcher

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
)

// ---------------------------------------------------------------------------
// Corefile cache-block reconcile (negative-cache-guard / serve-stale)
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
// patches it when a cache directive lacks the denial cap or the
// configured serve_stale window (see the header note). A missing
// ConfigMap/Corefile is tolerated — the k0s stack applier owns the
// object and re-creates it; a patch or get failure surfaces so the
// reconcile retries on the apiserver's backoff instead of silently
// leaving a 30s NXDOMAIN cache live.
//
// The patch goes through heal.FluxPatchGate: the ConfigMap is
// k0s/GitOps-owned, so a Git source that pins the Corefile would
// otherwise ping-pong this reconcile every requeue forever — the
// gate skips the write once the same object has been re-patched
// inside the conflict window and reports the loop instead.
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
	rewritten, changed := corefileCacheHeal(corefile, r.serveStale)
	if !changed {
		return nil
	}
	if !heal.FluxPatchGate("configmap", cm,
		corednsConfigNS+"/"+corednsConfigName, time.Now()) {
		logf.FromContext(ctx).Info("SKIP: Corefile cache heal patch — " +
			"Flux Heal-Revert Loop (Git owns this ConfigMap; fix the source)")
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
	logf.FromContext(ctx).Info("PATCH: Corefile cache directive gains a 5s denial cap" +
		" and serve_stale window " +
		"(NXDOMAIN no longer negative-caches for the full SOA TTL)")
	return nil
}

// corefileCacheHeal rewrites every cache directive in the Corefile
// that is missing a directive it should carry. Bare `cache 30`
// (optionally with zone args) expands to the success+denial block;
// an already-braced `cache 30 { ... }` block keeps its contents and
// only gains the directives it lacks — denial 9984 5 always, plus
// `serve_stale <dur> immediate` when serveStale is non-empty. A block
// that already declares a directive is untouched for it —
// idempotent by construction. Returns (rewritten, changed).
//
// The parser is a line scan, not a Corefile grammar: `cache` is the
// only directive the rewrite touches, brace depth tracks the block
// it opens, and comment lines (#…) can never satisfy or break the
// directive checks.
//
// Comments are stripped BEFORE any brace counting or slicing: a `#`
// inside a Corefile line comments out the rest of the line, so a
// brace (or a whole directive) inside a comment must never open,
// close, or depth-count a block — `cache 30 { # ops note }` opens a
// MULTI-line block (the `}` lives in the comment), and `# }` in a
// block body must not close it.
func corefileCacheHeal(corefile, serveStale string) (string, bool) {
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
			// braced success+denial(+serve_stale) block, keeping the
			// args and the line's own indentation. A trailing comment
			// is carried INSIDE the braces — appended after the `{`
			// it would be commented out of the Corefile entirely.
			comment := ""
			if hash := strings.Index(lines[i], "#"); hash >= 0 {
				if c := strings.TrimSpace(lines[i][hash:]); c != "" {
					comment = " " + c
				}
			}
			lines[i] = indent + code + " {" + comment + "\n" +
				indent + "    " + corefileSuccessLine + "\n" +
				indent + "    " + corefileDenialDirective + "\n" +
				serveStaleLines(indent, serveStale) +
				indent + "}"
			changed = true
		case strings.LastIndex(code, "}") > open:
			// Inline single-line block `cache 30 { denial 9984 5 }`:
			// directives inside already satisfy; whatever is missing
			// is injected before the closing brace. `code` is a
			// prefix of `lines[i]` minus the indent, so code indices
			// shift by len(indent) onto the original line — and a `}`
			// inside a trailing comment is never the injection point.
			inner := code[open+1 : strings.LastIndex(code, "}")]
			missing := cacheBlockMissing(inner, serveStale)
			if len(missing) > 0 {
				last := len(indent) + strings.LastIndex(code, "}")
				lines[i] = lines[i][:last] + " " + strings.Join(missing, " ") +
					" }" + lines[i][last+len("}"):]
				changed = true
			}
		default:
			// Braced multi-line block: find the matching close and
			// inject the missing directives before it. Depth counts
			// comment-stripped braces only — `# }` never closes, and
			// a `{` or `}` inside a trailing comment never nests.
			depth := strings.Count(code, "{") - strings.Count(code, "}")
			missing := cacheBlockMissingBody()
			if serveStale != "" {
				missing.serveStale = true
			}
			closeIdx := -1
			for j := i + 1; j < len(lines) && depth > 0; j++ {
				t := strings.TrimSpace(stripCorefileComment(lines[j]))
				depth += strings.Count(t, "{") - strings.Count(t, "}")
				if t != "" {
					f := strings.Fields(t)[0]
					if f == "denial" {
						missing.denial = false
					} else if f == "serve_stale" {
						missing.serveStale = false
					}
				}
				if depth == 0 {
					closeIdx = j
				}
			}
			if closeIdx >= 0 && (missing.denial || missing.serveStale) {
				inject := ""
				if missing.denial {
					inject += indent + "    " + corefileDenialDirective + "\n"
				}
				if missing.serveStale {
					inject += serveStaleLines(indent, serveStale)
				}
				lines[closeIdx] = inject + lines[closeIdx]
				changed = true
			}
			if closeIdx >= 0 {
				i = closeIdx // skip past the handled block
			}
		}
	}
	if !changed {
		return corefile, false
	}
	return strings.Join(lines, "\n"), true
}

// cacheBlockMissingBody seeds the multi-line scan's missing-directive
// set: denial is always expected, serve_stale only when the knob is
// on (the caller flips the flag before the body scan).
type cacheBlockMissingSet struct {
	denial     bool
	serveStale bool
}

func cacheBlockMissingBody() cacheBlockMissingSet {
	return cacheBlockMissingSet{denial: true}
}

// cacheBlockMissing lists the directive strings an inline cache
// block body lacks, in stable emission order (denial, then
// serve_stale).
func cacheBlockMissing(inner, serveStale string) []string {
	missing := cacheBlockMissingBody()
	if serveStale != "" {
		missing.serveStale = true
	}
	for f := range strings.FieldsSeq(inner) {
		if f == "denial" {
			missing.denial = false
		} else if f == "serve_stale" {
			missing.serveStale = false
		}
	}
	var out []string
	if missing.denial {
		out = append(out, corefileDenialDirective)
	}
	if missing.serveStale {
		out = append(out, "serve_stale "+serveStale+" immediate")
	}
	return out
}

// serveStaleLines renders the serve_stale directive as indented
// Corefile lines (each ending in \n) for the bare and multi-line
// forms, or "" when the knob is off.
func serveStaleLines(indent, serveStale string) string {
	if serveStale == "" {
		return ""
	}
	return indent + "    serve_stale " + serveStale + " immediate\n"
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
