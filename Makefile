GO ?= go
GOBIN := bin/themis
ifeq ($(OS),Windows_NT)
GOBIN := bin/themis.exe
endif

.PHONY: build controller kube-runner chaosmesh-planner postgres-runner fmt fmt-check vet test race fuzz check

build:
	$(GO) build -trimpath -o $(GOBIN) ./cmd/themis

controller:
	$(GO) build -trimpath -o bin/ ./cmd/themis-controller

kube-runner:
	$(GO) build -trimpath -o bin/ ./cmd/themis-kube ./cmd/themis-kube-fixture

chaosmesh-planner:
	$(GO) build -trimpath -o bin/ ./cmd/themis-chaosmesh

postgres-runner:
	$(GO) build -trimpath -o bin/ ./cmd/themis-postgres

fmt:
	$(GO) fmt ./...

# gofmt emits nothing on success. This target requires a POSIX shell.
fmt-check:
	@files="$$(gofmt -l cmd internal api examples test)" || exit 1; test -z "$$files" || (printf '%s\n' "$$files"; exit 1)

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

fuzz:
	$(GO) test ./internal/contract -run '^$$' -fuzz '^FuzzParse$$' -fuzztime 10s
	$(GO) test ./internal/result -run '^$$' -fuzz '^FuzzAggregateNeverFalsePass$$' -fuzztime 10s
	$(GO) test ./internal/run -run '^$$' -fuzz '^FuzzReplay$$' -fuzztime 10s
	$(GO) test ./internal/experiment -run '^$$' -fuzz '^FuzzReplayExperiment$$' -fuzztime 10s
	$(GO) test ./internal/kube -run '^$$' -fuzz '^FuzzDryRunSpec$$' -fuzztime 10s
	$(GO) test ./internal/kubeexperiment -run '^$$' -fuzz '^FuzzKubernetesJournalNeverTrustsPASS$$' -fuzztime 10s
	$(GO) test ./internal/kubeexperiment -run '^$$' -fuzz '^FuzzCoordinationIndexNeverAuthenticatesExecution$$' -fuzztime 10s
	$(GO) test ./internal/chaosmesh -run '^$$' -fuzz '^FuzzExternalPlanCannotAuthorizeFault$$' -fuzztime 10s
	$(GO) test ./internal/postgres -run '^$$' -fuzz '^FuzzContract$$' -fuzztime 10s
	$(GO) test ./internal/postgres -run '^$$' -fuzz '^FuzzDurableContract$$' -fuzztime 10s
	$(GO) test ./internal/postgres -run '^$$' -fuzz '^FuzzPITRUntrustedRecoveryData$$' -fuzztime 10s

check: fmt-check vet test build controller kube-runner
