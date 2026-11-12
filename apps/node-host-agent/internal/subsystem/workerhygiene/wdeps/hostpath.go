// hostpath.go — agent-view → host-view path normalization shared by
// the workerhygiene domain packages (ctr mountinfo/task-rootfs
// handling, runtime snapshot scans). The DaemonSet mounts the host
// filesystem at /host; standalone mode mounts it at / (paths already
// host-side). Every place that compares an agent config path against
// a host-reported path (mountinfo fields, umount args, socket
// addresses) must strip the /host prefix — with a "/" boundary
// check, because strings.TrimPrefix(p, "/host") also mangles
// legitimate paths like "/hostname/...".
//
// The implementation lives in platform/hostutil.HostSidePath (the
// shared leaf sweeper and friends also use); this wrapper keeps the
// wdeps call sites unchanged.
package wdeps

import "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"

// HostSidePath maps an in-pod /host-mounted path back to the path a
// host process reports — see hostutil.HostSidePath.
func HostSidePath(p string) string { return hostutil.HostSidePath(p) }
