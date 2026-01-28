.PHONY: all prepare test test-js webapp static-webapp help

all: prepare test ## Prepare circuits and run all tests

prepare: ## Compile default circuits and install tools
	./prepare-circuit.sh

test: prepare ## Run all tests (Go tests)
	./prepare-circuit.sh test/ballot_checker_test.circom
	./prepare-circuit.sh test/ballot_cipher_test.circom
	go test -v ./test/...

test-js: ## Run JS package tests
	cd js && npm install && npm test

webapp: prepare ## Start the Proof Generator React Webapp (dev mode)
	cp artifacts/ballot_proof.wasm webapp/public/
	cp artifacts/ballot_proof_pkey.zkey webapp/public/
	cp artifacts/ballot_proof_vkey.json webapp/public/
	cd webapp && npm install && npm run dev

static-webapp: prepare ## Build the webapp for production
	cp artifacts/ballot_proof.wasm webapp/public/
	cp artifacts/ballot_proof_pkey.zkey webapp/public/
	cp artifacts/ballot_proof_vkey.json webapp/public/
	cd webapp && npm install && npm run build

help: ## Display this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
