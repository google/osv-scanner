export PATH := $(PATH):$(shell go env GOPATH)/bin

scanner:
	scripts/build.sh

lint:
	scripts/run_lints.sh

format:
	scripts/run_formatters.sh

test:
	scripts/run_tests.sh

clean:
	rm -f osv-scanner
