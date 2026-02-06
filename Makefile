export PATH := $(PATH):$(shell go env GOPATH)/bin

# Default - run help
.DEFAULT_GOAL := help

# Defaults for test
SHORT ?= true
SNAPS ?= false
ACC ?= false
VCR ?= ReplayWithNewEpisodes

help: ## Show this help message
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } \
		/^## / { printf "  %-20s %s\n", "", substr($$0, 4) }' $(MAKEFILE_LIST)

## Prevents make from trying to interpret the targets as files
.PHONY: build scanner lint lint-fix format clean local-docs test update-snapshots refresh-all help

build: ## Build scanner
	scripts/build.sh

scanner: ## Run scanner (Usage: make scanner ARGS="<args>")
	go run ./cmd/osv-scanner $(ARGS)

lint: ## Run lints
	scripts/run_lints.sh

lint-fix: ## Run lints and fix
	scripts/run_lints.sh --fix

format: ## Run formatters
	scripts/run_formatters.sh

clean: ## Clean build artifacts
	rm -f osv-scanner
	rm -f cmd/osv-scanner/scan/image/testdata/test-*.tar

local-docs: ## Run local docs
	scripts/run_local_docs.sh

test: ## Run tests
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

update-snapshots: ## Update snapshots (Equivalent to make test SNAPS=true)
	$(MAKE) test SNAPS=true

refresh-all: ## Refresh all snaps, matching CI test (Usage: make refresh-all REBUILD_IMAGES=true)
	@if [ "$(REBUILD_IMAGES)" = "true" ]; then $(MAKE) clean; fi
	$(MAKE) test ACC=true SHORT=false VCR=RecordOnly SNAPS=true
