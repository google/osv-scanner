export PATH := $(PATH):$(shell go env GOPATH)/bin

# Default - run help
.DEFAULT_GOAL := help

# Defaults for test
SHORT ?= true
SNAPS ?= false
ACC ?= false
VCR ?= ReplayWithNewEpisodes

## Show this help message
help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } \
		/^## / { printf "  %-20s %s\n", "", substr($$0, 4) }' $(MAKEFILE_LIST)

## Prevents make from trying to interpret the targets as files
.PHONY: build scanner lint lint-fix format clean local-docs test update-snapshots refresh-all help

## Build scanner
build:
	scripts/build.sh

## Run scanner (Usage: make scanner ARGS="<args>")
scanner:
	go run ./cmd/osv-scanner $(ARGS)

## Run lints
lint:
	scripts/run_lints.sh

## Run lints and fix
lint-fix:
	scripts/run_lints.sh --fix

## Run formatters
format:
	scripts/run_formatters.sh

## Clean build artifacts
clean:
	rm -f osv-scanner
	rm -f cmd/osv-scanner/scan/image/testdata/test-*.tar

## Run local docs
local-docs:
	scripts/run_local_docs.sh

## Run tests
test:
##  Options:
##    SNAPS=true   Update snapshots (Default: false)
##    ACC=true     Run acceptance tests (Default: false)
##    SHORT=false  Run full tests (Default: true)
##    VCR=mode     VCR mode (Default: ReplayWithNewEpisodes):
##      - 0|RecordOnly:            Record new cassettes
##      - 1|ReplayOnly:            Replay cassettes, error if missing
##      - 2|ReplayWithNewEpisodes: Replay, record if missing
##      - 3|RecordOnce:            Record if missing
##      - 4|Passthrough:           Disable VCR
	@export TEST_VCR_MODE=$(VCR); \
	if [ "$(SNAPS)" = "true" ]; then export UPDATE_SNAPS=true; fi; \
	if [ "$(ACC)" = "true" ]; then export TEST_ACCEPTANCE=true; fi; \
	ARGS=""; \
	if [ "$(SHORT)" = "true" ]; then ARGS="$$ARGS -short"; fi; \
	scripts/run_tests.sh $$ARGS

## Update all snapshots (Equivalent to make test SNAPS=true SHORT=false)
update-snapshots:
	$(MAKE) test SNAPS=true SHORT=false

## Refresh all snaps, matching CI test (Usage: make refresh-all REBUILD_IMAGES=true)
refresh-all:
	@if [ "$(REBUILD_IMAGES)" = "true" ]; then $(MAKE) clean; fi
	$(MAKE) test ACC=true SHORT=false VCR=RecordOnly SNAPS=true
