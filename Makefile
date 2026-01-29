export PATH := $(PATH):$(shell go env GOPATH)/bin

scanner:
	scripts/build.sh

lint:
	scripts/run_lints.sh

lint-fix:
	scripts/run_lints.sh --fix

format:
	scripts/run_formatters.sh

test-short:
	scripts/run_tests.sh -short

test:
	scripts/run_tests.sh


clean:
	rm -f osv-scanner
	rm -r cmd/osv-scanner/scan/image/testdata/test-*.tar

update-snapshots:
	UPDATE_SNAPS=true scripts/run_tests.sh

local-docs:
	scripts/run_local_docs.sh
