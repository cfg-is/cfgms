.PHONY: build test proto lint clean

# Build settings
BINARY_NAME=cfgms
CONTROLLER_BINARY=controller
STEWARD_BINARY=steward
GO_BUILD_FLAGS=-trimpath -ldflags="-s -w"

# Protocol buffer variables
PROTO_DIR=pkg/api/proto
PROTO_FILES=$(shell find $(PROTO_DIR) -name "*.proto")
PROTO_INCLUDES=-I$(PROTO_DIR)

# Check for required tools
.PHONY: check-proto-tools
check-proto-tools:
	@which protoc > /dev/null || { \
		echo "Error: protoc is not installed. Please install Protocol Buffers:"; \
		echo "  Ubuntu/Debian: sudo apt install protobuf-compiler"; \
		echo "  macOS: brew install protobuf"; \
		echo "  Other: visit https://github.com/protocolbuffers/protobuf/releases"; \
		exit 1; \
	}
	@which protoc-gen-go > /dev/null || { \
		echo "Error: protoc-gen-go is not installed. Please install:"; \
		echo "  go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"; \
		exit 1; \
	}
	@which protoc-gen-go-grpc > /dev/null || { \
		echo "Error: protoc-gen-go-grpc is not installed. Please install:"; \
		echo "  go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"; \
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

build: build-controller build-steward

build-controller:
	go build ${GO_BUILD_FLAGS} -o bin/${CONTROLLER_BINARY} ./cmd/controller

build-steward:
	go build ${GO_BUILD_FLAGS} -o bin/${STEWARD_BINARY} ./cmd/steward

test:
	go test -v -race -cover ./...

lint:
	golangci-lint run

clean:
	rm -rf bin/
	go clean -testcache 