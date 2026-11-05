// Package datastore holds the datastore operator-health checks riding
// the cluster-health sweep: scylla-cluster-health,
// rabbitmq-quorum-health, rabbitmq-suspended-listener,
// dragonfly-replica-sync-storm, percona-cluster-quorum,
// stateful-masterless-services and olm-subscription-health. Each
// reports on the shared kuberhealthy_check series under its own check
// name.
package datastore
