// Package concourseinit is the Go port of the bash + awk the
// concourse-worker-init-rm initContainer and the /concourse-runc/runc
// shell wrapper used to run — both lived inline in
// infrastructure/base/helm/helm-releases/concourse/values.yaml
// (worker.extraInitContainers[concourse-worker-init-rm], the `bash -ce`
// block under `command:`/`args:`).
//
// Two subcommand entrypoints replace it:
//
//   - WorkerInit — the init container half: btrfs subvolume cleanup,
//     selective wipe of /concourse-work-dir (shared-cache survives and,
//     inside it, the 14 PersistentCacheDirs), recreation of the
//     20-entry ScaffoldCacheDirs layout owned by uid/gid 4294967294
//     mode 0777, then installation of runc.real + the wrapper binary
//     into the concourse-runc emptyDir.
//   - RunRuncWrapper — installed as /concourse-runc/runc and mounted
//     over /usr/local/concourse/bin/runc inside the worker container
//     via a subPath volumeMount: on `runc create` it injects a bind
//     mount of /concourse-work-dir/shared-cache at /shared-cache into
//     unprivileged task containers (linux.uidMappings hostID
//     4294967294 + a /scratch mount present + no /shared-cache mount
//     yet), then syscall.Exec's runc.real. Fail-open on every error.
//
// The CLI integrator wires `concourse-worker-init` → WorkerInit and
// `concourse-runc-wrapper` (or an argv[0] basename of "runc", since the
// wrapper is a copy of this same binary) → RuncWrapper.
package concourseinit

import "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/concourse"

const (
	// DefaultWorkDir is the concourse worker work dir the init wipes —
	// the chart mounts the PVC here.
	DefaultWorkDir = "/concourse-work-dir"
	// DefaultRuncDir is the emptyDir shared between the init container
	// (writer) and the worker container (reader); the worker also
	// mounts <DefaultRuncDir>/runc over RuncSource via subPath.
	DefaultRuncDir = "/concourse-runc"
	// DefaultRuncSource is the real runc inside the concourse image —
	// copied to runc.real by the init.
	DefaultRuncSource = "/usr/local/concourse/bin/runc"
	// DefaultRuncReal is where the wrapper execs the real binary.
	DefaultRuncReal = DefaultRuncDir + "/runc.real"

	sharedCacheName   = concourse.SharedCacheName
	sharedCacheSource = DefaultWorkDir + "/" + sharedCacheName
	cacheOwner        = concourse.CacheOwner
	cachePerm         = concourse.CachePerm
)

// PersistentCacheDirs is the keep-list under shared-cache — the 14
// caches expensive enough to rebuild (go-mod ~1.4GB, toolchains,
// scanner DBs, package caches) that the wipe preserves. Every other
// first-level entry is removed; the script's case-list verbatim.
var PersistentCacheDirs = []string{
	"go-mod", "mise", "ci-tool", "node-deps", "bun", "uv", "pip",
	"trivy", "sonar", "golangci-lint", "nx", "moon", "bin", "py-tools",
}

// ScaffoldCacheDirs is the mkdir -p list — the 20 shared-cache
// subdirs recreated every init (a superset of PersistentCacheDirs;
// the difference — go-build, go, affected, build, coverage, ytt —
// is wiped and rebuilt empty each restart). Script order preserved.
var ScaffoldCacheDirs = []string{
	"go-mod", "go-build", "go", "mise", "bun", "uv", "pip", "affected",
	"golangci-lint", "build", "coverage", "ci-tool", "ytt", "node-deps",
	"trivy", "sonar", "nx", "moon", "bin", "py-tools",
}

// persistentSet is PersistentCacheDirs as a lookup map for the wipe.
var persistentSet = func() map[string]bool {
	m := make(map[string]bool, len(PersistentCacheDirs))
	for _, d := range PersistentCacheDirs {
		m[d] = true
	}
	return m
}()
