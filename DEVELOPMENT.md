# CFGMS Development Guide

This guide provides instructions for setting up a local CFGMS development environment and building the project from source.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Building from Source](#building-from-source)
- [Running Tests](#running-tests)
- [Development Workflow](#development-workflow)
- [Troubleshooting](#troubleshooting)
- [IDE Setup](#ide-setup)

## Prerequisites

### Required Tools

- **Go 1.25.0 or later** - [Download](https://go.dev/dl/)
- **Git** - Version control
- **Make** - Build automation
- **Protocol Buffers Compiler** - For proto file generation
  ```bash
  # Ubuntu/Debian
  sudo apt-get install protobuf-compiler

  # macOS
  brew install protobuf

  # Windows (using Chocolatey)
  choco install protoc
  ```

- **Go Protocol Buffer Plugins**:
  ```bash
  go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
  ```

### Optional Tools

- **Docker** - For integration tests and local deployment
- **golangci-lint** - Code linting
  ```bash
  # Install using go install
  go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
  ```

- **entr** - For watch mode during development
  ```bash
  # Ubuntu/Debian
  sudo apt-get install entr

  # macOS
  brew install entr
  ```

- **gitleaks** - Pre-commit secret scanning
  ```bash
  # Install from: https://github.com/gitleaks/gitleaks#installing
  ```

- **gosec** - Security scanning
  ```bash
  go install github.com/securego/gosec/v2/cmd/gosec@latest
  ```

### System Requirements

**For Building**:
- RAM: 4GB minimum, 8GB recommended
- Disk Space: 2GB free space
- OS: Linux, macOS, or Windows

**For Running Controller**:
- RAM: 2GB minimum, 4GB recommended
- Disk Space: 10GB minimum (for storage backend)
- OS: Linux (AMD64) or Windows (AMD64)

**For Running Steward**:
- RAM: 512MB minimum
- Disk Space: 500MB minimum
- OS: Linux (AMD64/ARM64), Windows (AMD64/ARM64), macOS (ARM64)

## Getting Started

### 1. Clone the Repository

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/cfgms.git
cd cfgms

# Add upstream remote
git remote add upstream https://github.com/cfg-is/cfgms.git
```

### 2. Install Dependencies

```bash
# Download Go module dependencies
go mod download

# Verify dependencies
go mod verify
```

### 3. Generate Protocol Buffer Files

```bash
# Generate Go code from .proto files
make proto
```

### 4. Verify Your Environment

```bash
# Run tests to verify everything is working
make test
```

If all tests pass, your development environment is ready!

## Building from Source

### Build All Components

```bash
# Build all binaries (controller, steward, CLI, cert-manager)
make build
```

Binaries will be created in the `bin/` directory:
- `bin/controller` - Controller server
- `bin/cfgms-steward` - Steward agent
- `bin/cfg` - Command-line interface
- `bin/cert-manager` - Certificate management utility

### Build Individual Components

```bash
# Build controller only
make build-controller

# Build steward only
make build-steward

# Build CLI only
make build-cli

# Build certificate manager only
make build-cert-manager
```

### Build with Commercial Features

```bash
# Build controller with commercial features (HA clustering)
make build-controller TAGS=commercial

# Or set TAGS for all builds
export TAGS=commercial
make build
```

### Cross-Platform Builds

```bash
# Build for specific platform
GOOS=linux GOARCH=amd64 make build-steward
GOOS=windows GOARCH=amd64 make build-steward
GOOS=darwin GOARCH=arm64 make build-steward

# Supported combinations:
# Linux: amd64, arm64
# Windows: amd64, arm64
# macOS: arm64
```

## Running Tests

### Quick Test (Smart Mode)

```bash
# Runs core tests + changed modules only
make test
```

This is the recommended command for daily development. It:
- Tests the framework (excluding modules)
- Tests core modules (file, directory, script)
- Tests any modules you've changed
- Validates both OSS and Commercial builds

### Unit Tests Only

```bash
# Fast unit tests with caching
make test-unit
```

Good for rapid feedback during development.

### Integration Tests

```bash
# Factory pattern integration tests
make test-integration-factory

# M365 integration tests (requires credentials)
make test-integration
```

**Note**: M365 integration tests require a `.env.local` file with valid Microsoft 365 credentials. See [docs/M365_INTEGRATION_GUIDE.md](docs/M365_INTEGRATION_GUIDE.md) for setup instructions.

### Watch Mode

```bash
# Automatically re-run tests on file changes
make test-watch
```

Requires `entr` to be installed. Great for TDD workflow.

### Pre-Commit Validation

```bash
# Run all validations before committing
make test-commit
```

This runs:
- All tests (unit + integration)
- Security scanning (gosec, gitleaks, staticcheck)
- Code linting (golangci-lint)
- M365 integration tests (if credentials available)

**CRITICAL**: This command must pass 100% before creating a pull request.

### CI-Level Testing

```bash
# Complete CI validation (8-12 minutes)
make test-ci
```

Runs the full test suite as it would run in GitHub Actions.

## Development Workflow

### Standard Workflow

1. **Create a feature branch**:
   ```bash
   git checkout develop
   git pull upstream develop
   git checkout -b feature/my-new-feature
   ```

2. **Make your changes** using TDD:
   ```bash
   # Write tests first
   # Run tests in watch mode
   make test-watch

   # Implement your feature
   # Tests should pass as you go
   ```

3. **Run pre-commit validation**:
   ```bash
   make test-commit
   ```

4. **Commit your changes**:
   ```bash
   git add .
   git commit -m "Add my new feature

   Brief explanation of the feature and why it was added.

   Fixes #issue_number"
   ```

5. **Push and create a pull request**:
   ```bash
   git push origin feature/my-new-feature
   # Create PR on GitHub
   ```

### Make Targets Reference

#### Building
- `make build` - Build all binaries
- `make build-controller` - Build controller only
- `make build-steward` - Build steward only
- `make build-cli` - Build CLI only
- `make proto` - Generate protocol buffer files

#### Testing
- `make test` - Smart test (recommended for development)
- `make test-unit` - Fast unit tests
- `make test-watch` - Watch mode for TDD
- `make test-integration` - M365 integration tests
- `make test-commit` - Pre-commit validation (blocking)
- `make test-ci` - Full CI test suite

#### Security
- `make security-scan` - Run all security scans
- `make security-precommit` - Pre-commit secret scanning
- `make security-check` - Security validation gate

#### Code Quality
- `make lint` - Run golangci-lint
- `make check-architecture` - Validate architecture compliance
- `make check-license-headers` - Verify license headers

#### Cleanup
- `make clean` - Remove built binaries

For a complete list of make targets, see [docs/development/commands-reference.md](docs/development/commands-reference.md).

## Troubleshooting

### Common Issues

#### "protoc: command not found"

Install the Protocol Buffers compiler:
```bash
# Ubuntu/Debian
sudo apt-get install protobuf-compiler

# macOS
brew install protobuf

# Verify installation
protoc --version
```

#### "protoc-gen-go: program not found"

Install the Go protocol buffer plugin:
```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

# Ensure $GOPATH/bin is in your PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

#### Tests Failing with "M365 credentials not found"

M365 integration tests require credentials. Either:

**Option 1**: Skip M365 tests (they're skipped automatically if no credentials)
```bash
make test  # M365 tests are skipped gracefully
```

**Option 2**: Set up credentials with OS keychain (REQUIRED - secure storage)
```bash
# 1. Create .env.local from example template
cp .env.local.example .env.local

# 2. Edit .env.local with your Azure App Registration details
#    - Fill in M365_CLIENT_ID, M365_TENANT_ID, M365_TENANT_DOMAIN
#    - Leave M365_CLIENT_SECRET=USE_KEYCHAIN (placeholder)

# 3. Store client secret securely in OS keychain
./scripts/migrate-credentials-to-keychain.sh

# 4. Load credentials for testing (config from file, secrets from keychain)
source ./scripts/load-credentials-from-keychain.sh

# 5. Run tests
make test
```

**IMPORTANT**: Client secrets are NEVER stored in plaintext files. The OS keychain provides encrypted storage that's automatically secured by your operating system.

See [docs/M365_INTEGRATION_GUIDE.md](docs/M365_INTEGRATION_GUIDE.md) for complete setup details.

#### "go.sum: checksum mismatch"

Clean and re-download dependencies:
```bash
go clean -modcache
go mod download
go mod verify
```

#### Build Fails with "cannot find package"

Ensure all dependencies are downloaded:
```bash
go mod download
go mod tidy
```

#### "permission denied" When Running Binaries

Make binaries executable:
```bash
chmod +x bin/*
```

### Getting Help

If you encounter issues not covered here:

1. **Check existing documentation**:
   - [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
   - [docs/development/](docs/development/) - Development guides
   - [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture

2. **Search GitHub Issues**:
   - [https://github.com/cfg-is/cfgms/issues](https://github.com/cfg-is/cfgms/issues)

3. **Ask in GitHub Discussions**:
   - [https://github.com/cfg-is/cfgms/discussions](https://github.com/cfg-is/cfgms/discussions)

4. **Create a new issue**:
   - Use the `question` label for general questions
   - Use the `bug` label for suspected bugs

## IDE Setup

### Visual Studio Code

Recommended extensions:
- **Go** (golang.go) - Official Go extension
- **Go Test Explorer** (premparihar.gotestexplorer) - Test UI
- **Protocol Buffers** (zxh404.vscode-proto3) - Proto syntax highlighting

Recommended settings (`.vscode/settings.json`):
```json
{
  "go.useLanguageServer": true,
  "go.lintTool": "golangci-lint",
  "go.lintOnSave": "workspace",
  "go.testFlags": ["-race", "-cover"],
  "go.testTimeout": "5m",
  "files.exclude": {
    "**/.git": true,
    "**/bin": true
  }
}
```

### GoLand / IntelliJ IDEA

1. Open the project directory
2. Enable Go Modules integration (enabled by default)
3. Configure test runner:
   - Run → Edit Configurations
   - Add "Go Test" configuration
   - Set flags: `-race -cover`

### Vim / Neovim

Recommended plugins:
- **vim-go** - Go development plugin
- **coc.nvim** + **coc-go** - Go language server

### Running Components Locally

CFGMS can be run in three modes. Start with the simplest:

#### Option A: Standalone Steward

**Perfect for**: Learning CFGMS, local development, single-server management

```bash
# Build steward
make build-steward

# Create local configuration
mkdir -p /etc/cfgms
cat > /etc/cfgms/config.yaml <<EOF
steward:
  id: dev-steward

resources:
  - name: hello-file
    module: file
    config:
      path: /tmp/hello-cfgms.txt
      content: "Hello from CFGMS standalone mode!"
      state: present

  - name: test-directory
    module: directory
    config:
      path: /tmp/cfgms-test
      state: present
      mode: "0755"
EOF

# Run steward in standalone mode
./bin/cfgms-steward -config /etc/cfgms/config.yaml

# Verify it worked
cat /tmp/hello-cfgms.txt
ls -la /tmp/cfgms-test
```

**No controller, no certificates, no network dependencies!**

---

#### Option B: Standalone Controller (Workflow Engine Only)

**Perfect for**: Cloud API automation, M365 management, no endpoint agents

```bash
# Build controller
make build-controller

# Run controller
./bin/controller
```

The controller will start on default ports:
- REST API: 9080
- gRPC-over-QUIC transport: 4433
- Internal services automatically configured

**Use it for M365/cloud workflows**:
```bash
# Build CLI
make build-cli

# Run a workflow
./bin/cfg workflow run examples/m365-user-provisioning.yaml
```

**No stewards needed for cloud-only automation!**

---

#### Option C: Controller + Stewards (Full Platform)

**Perfect for**: Fleet management, distributed systems

```bash
# 1. Start controller (auto-generates internal CA)
make build-controller
./bin/controller

# 2. On endpoint machines: register steward
make build-steward
./bin/cfgms-steward --controller https://localhost:9080 --register

# Certificates are auto-generated and auto-approved in development mode!

# 3. Use CLI to manage fleet
make build-cli
./bin/cfg steward list
./bin/cfg config apply fleet-config.yaml
```

**For production**: See [docs/development/local-development-setup.md](docs/development/local-development-setup.md) for proper certificate management.

## Next Steps

- **Read the contribution guidelines**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Understand the architecture**: [ARCHITECTURE.md](ARCHITECTURE.md)
- **Review the workflow**: [docs/development/story-checklist.md](docs/development/story-checklist.md)
- **Check the roadmap**: [docs/product/roadmap.md](docs/product/roadmap.md)
- **Find an issue to work on**: [GitHub Issues](https://github.com/cfg-is/cfgms/issues)

---

**Happy coding! We're excited to see your contributions to CFGMS.**
