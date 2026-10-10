# Quality gates and builds for conductor-provisioner.
# GOWORK=off by default: the module is checked on its own, against the
# versions go.mod pins (what CI and release builds use), not through a
# family go.work; `make check GOWORK=$PWD/../go.work` checks it against
# local copies of the sibling modules instead.
export GOWORK ?= off
# Gate tools, pinned (the same versions as CI) and built into
# .tools/<go version>/, so a stale or mismatched binary on $GOPATH/bin
# never runs the gates. staticcheck v0.8.1 pins golang.org/x/tools v0.44,
# which cannot read the export data version 5 written by Go 1.27.2, so it
# is built against XTOOLS_VERSION until a staticcheck release carries it.
STATICCHECK_VERSION := v0.8.1
XTOOLS_VERSION := v0.51.0
GOVULNCHECK_VERSION := v1.8.0
TOOLS_DIR := $(CURDIR)/.tools/$(shell go env GOVERSION)
STATICCHECK := $(TOOLS_DIR)/staticcheck-$(STATICCHECK_VERSION)-xtools-$(XTOOLS_VERSION)
GOVULNCHECK := $(TOOLS_DIR)/govulncheck-$(GOVULNCHECK_VERSION)
VERSION ?= $(shell git describe --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
FUZZTIME ?= 20s
LAB_PKGS := $(wildcard ./internal/labtest)

.PHONY: build test check fmt vet staticcheck vulncheck fuzz lab-test tools

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/conductor-provisioner ./cmd/conductor-provisioner

test:
	go test -race ./...

check: fmt vet staticcheck vulncheck test

fmt:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...
	$(if $(LAB_PKGS),go vet -tags lab $(LAB_PKGS))

staticcheck: tools
	$(STATICCHECK) ./...
	$(if $(LAB_PKGS),$(STATICCHECK) -tags lab $(LAB_PKGS))

vulncheck: tools
	$(GOVULNCHECK) ./...

# Short fuzz run of the protocol decoder (requests, responses and the
# parameters of the plan operations).
fuzz:
	go test -run XXX -fuzz FuzzDecodeRequest -fuzztime $(FUZZTIME) ./provapi/
	go test -run XXX -fuzz FuzzReadMessage -fuzztime $(FUZZTIME) ./provapi/
	go test -run XXX -fuzz FuzzPlanParams -fuzztime $(FUZZTIME) ./provapi/

# Integration test against the Samba lab (environment in
# internal/labtest/lab_test.go).
lab-test:
	go test -tags lab -count=1 -v ./internal/labtest/

tools: $(STATICCHECK) $(GOVULNCHECK)

$(STATICCHECK):
	@mkdir -p $(TOOLS_DIR)
	tmp="$$(mktemp -d)" && trap 'rm -rf "$$tmp"' EXIT && cd "$$tmp" && \
		go mod init gatetools >/dev/null 2>&1 && \
		go get honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) golang.org/x/tools@$(XTOOLS_VERSION) && \
		go build -o $@ honnef.co/go/tools/cmd/staticcheck

$(GOVULNCHECK):
	@mkdir -p $(TOOLS_DIR)
	tmp="$$(mktemp -d)" && trap 'rm -rf "$$tmp"' EXIT && \
		GOBIN="$$tmp" go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) && \
		mv "$$tmp/govulncheck" $@
