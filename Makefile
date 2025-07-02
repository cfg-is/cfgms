.PHONY: build test proto lint clean

# Build settings
GO_BUILD_FLAGS=-trimpath -ldflags="-s -w"

# Binary names
STEWARD_BINARY=cfgms-steward
CONTROLLER_BINARY=controller
CLI_BINARY=cfgctl

# Protocol buffer variables
PROTO_DIR=pkg/api/proto
PROTO_FILES=$(shell find $(PROTO_DIR) -name "*.proto")
PROTO_INCLUDES=-I$(PROTO_DIR)

# Check for required tools
.PHONY: check-proto-tools
check-proto-tools:
	@which protoc > /dev/null || { \
		echo "Error: protoc is not installed..."; \
		exit 1; \
	}
	@which protoc-gen-go > /dev/null || { \
		echo "Error: protoc-gen-go is not installed..."; \
		exit 1; \
	}
	@which protoc-gen-go-grpc > /dev/null || { \
		echo "Error: protoc-gen-go-grpc is not installed..."; \
		exit 1; \
	}

# Generate Go code from proto files
.PHONY: proto
proto: check-proto-tools
	@echo "Generating proto files..."
	@for file in $(PROTO_FILES); do \
		protoc $(PROTO_INCLUDES) \
			--go_out=. --go_opt=paths=source_relative \
			--go-grpc_out=. --go-grpc_opt=paths=source_relative \
			$$file; \
	done

# Build all binaries
.PHONY: build
build: build-steward build-controller build-cli

# Build individual binaries
.PHONY: build-steward build-controller build-cli
build-steward:
	go build ${GO_BUILD_FLAGS} -o bin/${STEWARD_BINARY} ./cmd/steward

build-controller:
	go build ${GO_BUILD_FLAGS} -o bin/${CONTROLLER_BINARY} ./cmd/controller

build-cli:
	go build ${GO_BUILD_FLAGS} -o bin/${CLI_BINARY} ./cmd/cfgctl

test:
	go test -v -race -cover ./...

lint:
	golangci-lint run

clean:
	rm -rf bin/
	go clean -testcache
