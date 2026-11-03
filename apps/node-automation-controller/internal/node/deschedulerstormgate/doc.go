// Package deschedulerstormgate is the descheduler-storm-gate module:
// scales the descheduler Deployment to 0 during node storms, taints or
// maintenance (cordon, kured lock, autopilot plans) and restores it
// when clear.
package deschedulerstormgate
