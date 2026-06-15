.PHONY: all build test vet lint vuln tidy clean

GO ?= go

all: build vet test

build:
	$(GO) build ./...

test:
	$(GO) test -race -cover ./...

vet:
	$(GO) vet ./...

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found; skipping"; \
	fi

vuln:
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not found; install with: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	fi

tidy:
	$(GO) mod tidy

clean:
	$(GO) clean ./...
