#!/bin/sh
# gen-envdoc.sh — regenerate ENV.md, the operator-facing inventory of
# every NODE_HOST_AGENT_* knob the binary reads. The doc is derived,
# never hand-edited — entirely by internal/envdoc/cmd/genenvdoc now
# (AST scans of internal/envnames + every call site + the Descriptor
# registry; the rg|sed|awk pipeline this script used to splice is
# gone). Kept as a wrapper so `moon run node-host-agent:envdoc` and
# every doc workflow keeps working.
set -eu
cd "$(dirname "$0")/.."
go run ./internal/envdoc/cmd/genenvdoc -write ENV.md
