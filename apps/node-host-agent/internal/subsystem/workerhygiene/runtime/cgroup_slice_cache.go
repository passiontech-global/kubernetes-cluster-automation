// cgroup_slice_cache.go — consume-once pod-slice directory cache
// shared between CgroupThrottleCheck and SubprocOOMCheck within a
// single workerhygiene cycle.
package runtime

import (
	"os"
	"runtime"
	"sync"
	"weak"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

type cachedDirRead struct {
	ents []os.DirEntry
	err  error
}

type podSliceCacheEntry struct {
	kubepods string
	dirs     []string
	dirEnts  map[string]cachedDirRead
}

var (
	podSliceCacheMu  sync.Mutex
	podSliceCache    = map[weak.Pointer[wdeps.Deps]]podSliceCacheEntry{}
	podSliceCleanups = map[weak.Pointer[wdeps.Deps]]bool{}
)

func putPodSliceCache(d *wdeps.Deps, kubepods string, dirs []string, dirEnts map[string]cachedDirRead) {
	if d == nil {
		return
	}
	wp := weak.Make(d)
	podSliceCacheMu.Lock()
	if !podSliceCleanups[wp] {
		podSliceCleanups[wp] = true
		runtime.AddCleanup(d, func(k weak.Pointer[wdeps.Deps]) {
			podSliceCacheMu.Lock()
			delete(podSliceCache, k)
			delete(podSliceCleanups, k)
			podSliceCacheMu.Unlock()
		}, wp)
	}
	podSliceCache[wp] = podSliceCacheEntry{
		kubepods: kubepods,
		dirs:     dirs,
		dirEnts:  dirEnts,
	}
	podSliceCacheMu.Unlock()
}

func clearPodSliceCache(d *wdeps.Deps) {
	if d == nil {
		return
	}
	wp := weak.Make(d)
	podSliceCacheMu.Lock()
	delete(podSliceCache, wp)
	podSliceCacheMu.Unlock()
}

func takePodSliceCache(d *wdeps.Deps, kubepods string) (podSliceCacheEntry, bool) {
	if d == nil {
		return podSliceCacheEntry{}, false
	}
	wp := weak.Make(d)
	podSliceCacheMu.Lock()
	ent, ok := podSliceCache[wp]
	if ok {
		delete(podSliceCache, wp)
	}
	podSliceCacheMu.Unlock()
	if !ok || ent.kubepods != kubepods {
		return podSliceCacheEntry{}, false
	}
	return ent, true
}
