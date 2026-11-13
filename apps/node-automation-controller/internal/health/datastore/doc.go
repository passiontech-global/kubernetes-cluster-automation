// Package datastore holds the datastore operator-health checks riding
// the cluster-health sweep plus the helpers several product families
// share (downscaler awareness, split-brain/site-skew census, the
// db-operator heal table): stateful-masterless-services lives here —
// its dragonfly auto-heals included (stateful_masterless_heals.go); the
// self-contained product checks moved to subpackages — nats
// (nats-jetstream-health), scylla (scylla-cluster-health,
// scylla-compaction-schema-guard), percona (percona-cluster-quorum),
// postgres (postgres-wal-archive-guard + the CNPG signatures), rabbitmq
// (rabbitmq-quorum-health, rabbitmq-suspended-listener) and dragonfly
// (dragonfly-replica-sync-storm). The PV/PVC checks live under
// health/storage and the OLM checks under health/gitops/olm. Each
// reports on the shared kuberhealthy_check series under its own check
// name.
package datastore
