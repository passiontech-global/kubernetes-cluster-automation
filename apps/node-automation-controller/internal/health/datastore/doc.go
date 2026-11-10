// Package datastore holds the datastore operator-health checks riding
// the cluster-health sweep plus the helpers several product families
// share (downscaler awareness, split-brain/site-skew census, the
// db-operator heal table): rabbitmq-quorum-health,
// rabbitmq-suspended-listener, dragonfly-replica-sync-storm and
// stateful-masterless-services live here; the self-contained product
// checks moved to subpackages — nats (nats-jetstream-health), scylla
// (scylla-cluster-health, scylla-compaction-schema-guard), percona
// (percona-cluster-quorum), postgres (postgres-wal-archive-guard +
// the CNPG signatures), olm (olm-subscription-health) and pvc
// (pvc-resize-stall-guard). Each reports on the shared
// kuberhealthy_check series under its own check name.
package datastore
