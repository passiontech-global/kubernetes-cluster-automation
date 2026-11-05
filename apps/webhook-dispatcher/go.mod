module github.com/passiontech-global/kubernetes-cluster-automation/apps/webhook-dispatcher

go 1.27.3

require (
	github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit v0.0.0
	github.com/prometheus/client_golang v1.25.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pandatix/go-abnf v0.5.5 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.73.1 // indirect
	github.com/prometheus/procfs v0.23.0 // indirect
	go.yaml.in/yaml/v2 v2.4.5 // indirect
	go.yaml.in/yaml/v3 v3.0.6 // indirect
	golang.org/x/sys v0.49.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit => ../../libs/hostkit
