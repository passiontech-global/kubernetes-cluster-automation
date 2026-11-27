// Package calicocontrollerspatcher is the calico-controllers-patcher module:
// keeps the kube-system calico-kube-controllers Deployment's readinessProbe
// pinned (timeoutSeconds: 5, failureThreshold: 6) against k0s stack reverts.
package calicocontrollerspatcher
