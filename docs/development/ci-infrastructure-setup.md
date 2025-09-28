# CI Infrastructure Setup Guide

This guide ensures consistent and reliable test infrastructure setup for CFGMS CI/CD pipeline.

## Problem Solved

Previously, CI tests would fail inconsistently due to:
- Missing Docker test infrastructure
- Incorrect environment variable configuration
- Database connectivity issues in CI mode
- Inconsistent test environment setup between local and CI

## Solution Overview

We've implemented a robust infrastructure setup system that:
- ✅ **Automatically validates infrastructure availability**
- ✅ **Ensures consistent environment variables across all tests**
- ✅ **Provides clear error messages for missing components**
- ✅ **Works identically in local development and CI environments**

## Key Components

### 1. Infrastructure Runner Script (`scripts/test-with-infrastructure.sh`)

**Purpose**: Ensures all test infrastructure is available and properly configured before running tests.

**Features**:
- Loads test environment from `.env.test`
- Sets CI mode (`CI=1`) to enforce infrastructure requirements
- Validates PostgreSQL and Gitea availability
- Provides clear error messages for missing services
- Executes tests with proper environment variables

### 2. Updated Makefile Targets

**`test-infrastructure-required`**: New target that runs infrastructure-dependent tests with validation
**`test-ci`**: Updated to include infrastructure validation as a prerequisite
**`test-with-real-storage`**: Uses the infrastructure runner for consistent setup

### 3. Environment Configuration

The system relies on `.env.test` containing:
```bash
CFGMS_TEST_DB_HOST=localhost
CFGMS_TEST_DB_PORT=5433
CFGMS_TEST_DB_NAME=cfgms_test
CFGMS_TEST_DB_PASSWORD=<generated>
CFGMS_TEST_GITEA_URL=http://localhost:3001
CFGMS_TEST_GITEA_USER=cfgms_test
CFGMS_TEST_GITEA_PASSWORD=<generated>
```

## Usage Instructions

### For Developers

#### 1. Set Up Test Infrastructure (One-Time)
```bash
make test-integration-setup
```
This starts Docker containers for PostgreSQL, TimescaleDB, and Gitea.

#### 2. Run Infrastructure Tests
```bash
make test-infrastructure-required
```
This validates infrastructure and runs all integration tests.

#### 3. Run Individual Tests with Infrastructure
```bash
./scripts/test-with-infrastructure.sh go test -v ./pkg/testing/storage/
```

### For CI/CD Pipeline

The CI pipeline automatically includes infrastructure validation:
```bash
make test-ci
```

This runs the complete validation suite including:
1. Infrastructure validation (`test-infrastructure-required`)
2. Unit tests (`test`)
3. Linting (`lint`)
4. Security scanning (`security-scan`)
5. M365 integration tests
6. Complete integration tests

## Infrastructure Requirements

### Docker Services Required

1. **PostgreSQL Test Instance**
   - Container: `cfgms-postgres-test`
   - Port: `5433:5432`
   - Database: `cfgms_test`
   - Status check: `pg_isready`

2. **Gitea Test Instance**
   - Container: `cfgms-git-server-test`
   - Port: `3001:3000`
   - Status check: Health endpoint

3. **TimescaleDB Test Instance**
   - Container: `cfgms-timescaledb-test`
   - Port: `5434:5432`
   - Used for time-series logging tests

### Environment Variables

All tests that require infrastructure automatically inherit these variables:
- `CI=1` - Forces infrastructure requirement mode
- `CFGMS_TEST_INTEGRATION=1` - Enables integration test features
- Database connection parameters from `.env.test`
- Gitea connection parameters from `.env.test`

## Test Behavior

### Development Mode (Default)
- Infrastructure tests **skip** if Docker services unavailable
- Allows local development without full infrastructure setup
- Uses local filesystem fallbacks where possible
- Log message: `"Database provider not available in development environment"`

### CI Mode (`CI=1`)
- Infrastructure tests **HARD FAIL** if services unavailable
- Tests use `t.Fatalf()` instead of `t.Skipf()`
- Ensures production-like environment validation
- All storage providers must be functional
- Log message: `"REQUIRED INFRASTRUCTURE MISSING: Database provider is not available in CI/integration environment"`
- **Result**: `FAIL` with non-zero exit code (blocks CI/CD pipeline)

## Troubleshooting

### "Infrastructure Missing" Errors

**Error**: `REQUIRED INFRASTRUCTURE MISSING: Database provider is not available`

**Solutions**:
1. Start test infrastructure: `make test-integration-setup`
2. Verify containers are running: `docker ps`
3. Check service health: `./scripts/test-with-infrastructure.sh echo "Infrastructure check"`

### Database Connection Failures

**Error**: `dial tcp [::1]:5432: connect: connection refused`

**Solutions**:
1. Verify `.env.test` has correct port (5433, not 5432)
2. Check PostgreSQL container status: `docker exec cfgms-postgres-test pg_isready`
3. Regenerate test environment: `rm .env.test && make test-integration-setup`

### Gitea Connectivity Issues

**Error**: `Gitea test instance not available`

**Solutions**:
1. Check Gitea container: `docker logs cfgms-git-server-test`
2. Verify health endpoint: `curl http://localhost:3001/api/healthz`
3. Restart services: `make test-integration-setup`

## Integration with Existing Workflow

### Pre-Commit Validation
```bash
make test-commit  # Includes smart tests + quality gates (no infrastructure required)
```

### Full CI Validation
```bash
make test-ci      # Includes infrastructure validation + complete test suite
```

### Manual Infrastructure Testing
```bash
make test-with-real-storage  # Tests storage providers with real infrastructure
```

## Benefits

1. **Reliability**: Tests fail consistently and predictably when infrastructure is missing
2. **Clarity**: Clear error messages guide developers to correct setup
3. **Consistency**: Identical behavior in local development and CI environments
4. **Speed**: Infrastructure validation happens once at the beginning, not per test
5. **Flexibility**: Development mode allows local work without full infrastructure

## Future Enhancements

- GitHub Actions integration for automatic infrastructure setup
- Docker Compose health checks for more robust service validation
- Infrastructure caching for faster CI runs
- Support for alternative database providers (MySQL, SQLite)

---

**Note**: This infrastructure setup is critical for Epic 6 storage architecture testing and ensures all storage providers work correctly in production-like environments.