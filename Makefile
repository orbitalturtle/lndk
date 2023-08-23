# This Makefile is used to compile an LND binary for the integration tests.

GO_BUILD := go build
CARGO_TEST := cargo test
LND_PKG := github.com/lightningnetwork/lnd

itest:
	@$(call print, "Building lnd for itests.")
	$(GO_BUILD) -tags="peersrpc signrpc dev" -o /tmp/lndk-tests/bin/lnd-itest$(EXEC_SUFFIX) $(LND_PKG)/cmd/lnd
	$(CARGO_TEST) -- --test-threads=1 --nocapture
