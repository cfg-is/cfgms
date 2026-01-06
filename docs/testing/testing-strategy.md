# CFGMS Testing Strategy

This document outlines the comprehensive testing strategy for CFGMS, designed to provide thorough validation while maintaining efficient development workflows.

## Testing Philosophy

CFGMS follows a **layered testing approach** that balances speed, coverage, and confidence:

1. **Fast Feedback**: Quick unit tests run on every change
2. **Integration Confidence**: Moderate-length integration tests validate component interactions
3. **Production Assurance**: Comprehensive validation ensures production readiness

## Test Suite Structure

### Layer 1: Fast Unit Tests (`make test`)

- **Runtime**: < 15 minutes
- **Scope**: Core functionality, individual components
- **Trigger**: Every push, pull request, development work
- **Coverage**: Unit tests with `-short` flag to skip long-running tests

```bash
make test
# Equivalent to: go test -v -race -cover -short ./...
```

### Layer 2: CI Validation (`make test-ci`)

- **Runtime**: < 15 minutes total
- **Scope**: Complete validation for CI/CD
- **Trigger**: CI on all branches, pre-merge validation
- **Coverage**: Unit tests + linting + security + M365 + storage integration

```bash
make test-ci
# Runs: test + lint + security-scan + test-m365-integration + test-integration-complete
```

### Layer 3: Full Production Validation (`make test-full`)

- **Runtime**: 60-90 minutes
- **Scope**: Complete system validation including load testing
- **Trigger**: Release preparation, comprehensive validation
- **Coverage**: Everything including Story #86 production readiness tests

```bash
make test-full
# Runs: test-fast + test-integration-comprehensive + test-story-86
```

## Test Categories

### Unit Tests (Fast)

- **Location**: `./features/...`, `./api/...`, `./cmd/...`
- **Duration**: Milliseconds to seconds per test
- **Focus**: Individual functions, modules, components
- **Examples**: DNA validation, module loading, configuration parsing

### Integration Tests (Moderate)

- **Location**: `./test/integration/...`, `./test/unit/...`
- **Duration**: Seconds to minutes per test
- **Focus**: Component interactions, service communication
- **Examples**: Controller-Steward communication, RBAC integration

### End-to-End Tests (Comprehensive)

- **Location**: `./test/e2e/...`
- **Duration**: Minutes per test
- **Focus**: Complete workflows, cross-feature scenarios
- **Examples**: Template deployment workflows, drift detection scenarios

### Production Readiness Tests (Thorough)

- **Location**: `./test/e2e/performance_test.go`, `./test/e2e/synthetic_monitoring_test.go`
- **Duration**: 5-45 minutes per test suite
- **Focus**: Production SLAs, load testing, security validation
- **Examples**: 100+ concurrent sessions, disaster recovery, security audit

## Testing Commands Reference

### Development Workflow

```bash
# Quick validation during development
make test                           # < 15 min - Unit tests only

# Pre-commit validation
make test-fast                      # < 10 min - Fast comprehensive
make test-commit                    # < 3 min - Recommended pre-commit
make test-ci                        # < 15 min - CI validation

# Specific test categories
make test-production-critical       # < 15 min - Core functionality
make test-integration              # < 20 min - Integration scenarios
```

### CI/CD Integration

```bash
# Cross-feature integration (chunked)
make test-cross-feature-integration # < 25 min - Cross-feature scenarios
make test-failure-propagation       # < 15 min - Failure recovery
make test-data-consistency         # < 15 min - Data consistency

# Production readiness (chunked)
make test-load-testing             # < 25 min - 100+ concurrent sessions
make test-performance-benchmarks   # < 15 min - SLA validation
make test-security-audit          # < 10 min - Security scanning
make test-disaster-recovery        # < 15 min - DR procedures
make test-monitoring-integration   # < 10 min - Monitoring validation
make test-synthetic-monitoring     # < 20 min - Ongoing monitoring
```

### Release Validation

```bash
# Complete Story #86 validation
make test-story-86                 # < 50 min - Full production readiness

# Complete system validation
make test-full                     # 60-90 min - Everything
```

## GitHub Actions Integration

The GitHub Actions workflow (`.github/workflows/test-suite.yml`) implements a **chunked testing strategy**:

### Automatic Triggers

- **Every Push/PR**: Unit tests only (< 15 min)
- **Main/Develop Branch**: Unit + Integration tests (< 30 min)
- **Main Branch Push**: + Production readiness tests (chunked, parallel)

### Manual Triggers

- **Fast**: Unit and integration tests
- **All**: + Cross-feature integration tests
- **Full**: + Production readiness and synthetic monitoring

### Chunking Strategy

Large test suites are split across parallel jobs:

```yaml
strategy:
  matrix:
    test-chunk: [
      "workflow-config",
      "dna-drift", 
      "template-rollback",
      "terminal-audit",
      "multi-tenant-saas"
    ]
```

## Performance Optimization

### Test Speed Optimization

1. **Short Flag**: `-short` skips long-running tests in unit test mode
2. **Timeouts**: Appropriate timeouts prevent hanging tests
3. **Parallel Execution**: Matrix jobs run production tests in parallel
4. **Caching**: Go module caching reduces setup time

### Resource Management

1. **CI Optimization**: Tests detect CI environment and reduce resource usage
2. **Session Limits**: Production tests use smaller session counts in CI
3. **Timeout Management**: Graduated timeouts based on test complexity

## Test Data Management

### Test Frameworks

- **E2E Framework**: `test/e2e/framework.go` - Comprehensive test infrastructure
- **Data Generation**: Realistic test data generation with multiple scenarios
- **State Management**: Clean setup/teardown for consistent test runs

### Environment Handling

- **CI Detection**: Tests automatically adapt to CI environments
- **Resource Constraints**: Reduced session counts and shorter durations in CI
- **Cleanup**: Proper resource cleanup prevents test interference

## Troubleshooting Test Issues

### Common Timeout Issues

```bash
# If tests timeout, try running specific categories:
make test-fast                    # Skip long-running tests
make test-production-critical     # Core functionality only

# For specific failing tests:
go test -v -timeout=30m ./test/e2e/... -run "TestSpecificTest"
```

### Memory/Resource Issues

```bash
# Run tests without race detection for lower memory usage:
go test -v -cover ./...

# Run specific packages:
go test -v ./features/controller/...
```

### CI Environment Issues

Tests automatically detect CI and adjust:

- Reduced concurrent session counts
- Shorter test durations
- Simplified resource requirements

## Best Practices

### For Developers

1. **Always run `make test`** before committing
2. **Use `make test-commit`** for significant changes
3. **Use `make test-ci`** for complete validation
4. **Run `make test-full`** before releases
5. **Write tests with appropriate timeouts**
6. **Use `-short` flag for development testing**

### For CI/CD

1. **Chunk long-running tests** into parallel jobs
2. **Set appropriate timeouts** for each test category
3. **Cache dependencies** to reduce setup time
4. **Upload test artifacts** for debugging
5. **Provide clear test summaries**

### For Production Validation

1. **Run full test suite** before deployments
2. **Validate all SLA requirements** with production readiness tests
3. **Test disaster recovery procedures** regularly
4. **Monitor synthetic test results** continuously

## Metrics and Monitoring

### Test Coverage Goals

- **Unit Tests**: > 80% coverage
- **Integration Tests**: > 90% critical path coverage
- **E2E Tests**: 100% user journey coverage
- **Production Tests**: 100% SLA validation coverage

### Performance Benchmarks

- **Unit Tests**: < 15 minutes total
- **Integration Tests**: < 30 minutes total
- **Production Tests**: < 90 minutes total
- **CI Pipeline**: < 45 minutes for standard validation

## Future Enhancements

### Planned Improvements

1. **Test Parallelization**: Further optimize test execution
2. **Smart Test Selection**: Run only tests affected by changes
3. **Performance Regression Detection**: Automated performance monitoring
4. **Chaos Testing**: Fault injection and resilience testing

### Monitoring Integration

1. **Test Result Metrics**: Export test results to monitoring systems
2. **Performance Tracking**: Track test execution time trends
3. **Failure Analysis**: Automated failure pattern detection
4. **SLA Monitoring**: Continuous SLA compliance validation

---

This testing strategy ensures CFGMS maintains high quality while providing fast feedback to developers and comprehensive validation for production deployments.
