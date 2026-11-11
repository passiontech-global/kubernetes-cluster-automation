// Package datastore holds the datastore operator-health checks riding
// the cluster-health sweep plus the helpers several product families
// share (downscaler awareness, split-brain/site-skew census, the
// db-operator heal table): stateful-masterless-services lives here —
// its dragonfly auto-heals included (dragonfly_heals.go); the
// self-contained product checks moved to subpackages — nats
// (nats-jetstream-health), scylla (scylla-cluster-health,
// scylla-compaction-schema-guard), percona (percona-cluster-quorum),
// postgres (postgres-wal-archive-guard + the CNPG signatures), olm
// (olm-subscription-health), pvc (pvc-resize-stall-guard), rabbitmq
// (rabbitmq-quorum-health, rabbitmq-suspended-listener) and dragonfly
// (dragonfly-replica-sync-storm). Each reports on the shared
// kuberhealthy_check series under its own check name.
package datastore
