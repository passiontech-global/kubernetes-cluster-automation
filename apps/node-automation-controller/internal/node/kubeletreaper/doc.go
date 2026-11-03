// Package kubeletreaper is the kubelet-liveness-reaper module:
// quarantines nodes whose kubelet reports Ready but fails its healthz
// probe (the "fake Ready" gray failure).
package kubeletreaper
