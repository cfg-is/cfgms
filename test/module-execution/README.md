# Module Execution Test Workspace

This directory serves as the test workspace for module execution validation (Story 12.3).

## Purpose

This workspace is mounted into the `steward-standalone` Docker container at `/test-workspace` to enable validation of actual module execution in the containerized environment.

## Usage

The integration tests in `test/integration/transport/module_execution_test.go` use this workspace to:

1. **File Module Testing**: Verify that file modules create files with correct content and permissions
2. **Directory Module Testing**: Validate directory creation with proper permissions and structure
3. **Script Module Testing**: Execute scripts and verify output capture and exit codes

## Directory Structure

```
test/module-execution/
├── README.md          # This file
├── .gitkeep          # Ensures directory is tracked in Git
└── (test files)      # Created dynamically by tests, cleaned up after execution
```

## Docker Integration

This directory is mounted as a volume in `docker-compose.test.yml`:

```yaml
steward-standalone:
  volumes:
    - ./test/module-execution:/test-workspace:rw
```

## Cleanup

Test files created during test execution are automatically cleaned up by the test suite to ensure test isolation and repeatability.

## Security Note

This workspace is used exclusively for integration testing. It does not contain any production data or sensitive information.
