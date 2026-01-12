# GitHub Workflows Standards

This document defines standards and best practices for GitHub Actions workflows in the CFGMS repository.

## Workflow Organization

### Workflow Categories

1. **Critical Validation Workflows** (always run on PRs)
   - `test-suite.yml` - Unit and integration tests
   - `cross-platform-build.yml` - Build validation across platforms
   - `security-scan.yml` - Security vulnerability scanning
   - `codeql-analysis.yml` - Advanced SAST analysis

2. **Conditional Workflows** (run when specific files change)
   - `documentation.yml` - Documentation validation (docs/**, *.md)
   - `docker-security.yml` - Container security (Dockerfile*, go.mod, go.sum)
   - `license-check.yml` - License compliance (go.mod, go.sum)
   - `template-validation.yml` - Template validation (features/templates/**)

3. **Production Workflows** (run on main/releases)
   - `production-gates.yml` - Comprehensive production readiness validation
   - `release.yml` - Release automation
   - `release-automation.yml` - Automated release process

## Branch Protection & Required Checks

### Develop Branch

**Required Status Checks** (all must pass for merge):
- `unit-tests` - Core functionality validation (~3-5 min)
- `Build Gate` - Cross-platform compilation (~3-5 min)
- `security-deployment-gate` - Security vulnerability blocking (~6-10 min)

**Configuration**:
- No review requirements (solo-friendly)
- Squash merge only
- Strict up-to-date branch enforcement
- No admin bypass needed (tests provide sufficient protection)

### Main Branch

Protected for releases only. Merges come from `develop` via release PRs.

## Path Filtering Standards

### Code Changes (Run tests/builds/security)

Use this pattern for workflows that should run on code changes but skip docs-only:

```yaml
on:
  pull_request:
    branches: [main, develop]
    paths-ignore:
      - 'docs/**'
      - '*.md'
      - 'LICENSE'
      - '.gitignore'
      - '.editorconfig'
```

**Rationale**: Conservative approach - skips only pure documentation changes

### Documentation Changes Only

Use this pattern for workflows that only validate documentation:

```yaml
on:
  pull_request:
    branches: [main, develop]
    paths:
      - 'docs/**'
      - '*.md'
```

### Dependency Changes

Use this pattern for workflows triggered by dependency updates:

```yaml
on:
  pull_request:
    branches: [main, develop]
    paths:
      - 'go.mod'
      - 'go.sum'
      - 'vendor/**'
```

### Docker/Container Changes

Use this pattern for workflows triggered by container changes:

```yaml
on:
  pull_request:
    branches: [main, develop]
    paths:
      - '**/Dockerfile*'
      - 'docker-compose*.yml'
      - '.dockerignore'
      - 'go.mod'
      - 'go.sum'
```

## Stub Jobs for Docs-Only PRs

**Problem**: When docs-only PRs don't trigger code workflows, required checks never appear, blocking merge.

**Solution**: Add stub jobs to `documentation.yml` that provide required check names:

```yaml
# Stub job that satisfies "unit-tests" requirement
unit-tests:
  name: unit-tests
  runs-on: ubuntu-latest
  if: github.event_name == 'pull_request'
  steps:
    - run: echo "✅ Documentation-only PR, skipping unit tests"

# Stub job that satisfies "Build Gate" requirement
build-gate:
  name: Build Gate
  runs-on: ubuntu-latest
  if: github.event_name == 'pull_request'
  steps:
    - run: echo "✅ Documentation-only PR, skipping build validation"

# Stub job that satisfies "security-deployment-gate" requirement
security-deployment-gate:
  name: security-deployment-gate
  runs-on: ubuntu-latest
  if: github.event_name == 'pull_request'
  steps:
    - run: echo "✅ Documentation-only PR, skipping security scans"
```

**Key Points**:
- Job `name:` must match exactly with the required check name
- Only run on `pull_request` events (not push or workflow_dispatch)
- Instant pass (<10 seconds) allows fast docs-only PR merges
- Code PRs trigger real validation workflows which take precedence

## Job Naming Conventions

### Job IDs (Technical Names)

Use lowercase with hyphens:
```yaml
jobs:
  unit-tests:
  integration-tests:
  security-deployment-gate:
```

### Job Display Names

Use descriptive names for GitHub UI:
```yaml
jobs:
  integration-tests-controller:
    name: Controller Integration Tests (Linux)

  integration-tests-steward:
    name: Steward Integration Tests
```

## Common Patterns

### Environment Variables

Define common environment variables at workflow level:

```yaml
env:
  GO_VERSION: '1.23'
  NODE_VERSION: '20'
  CFGMS_TEST_INTEGRATION: '0'
```

### Dependency Caching

Use caching for faster workflow execution:

```yaml
- name: Cache Go modules
  uses: actions/cache@v3
  with:
    path: ~/go/pkg/mod
    key: ${{ runner.os }}-go-modules-${{ hashFiles('**/go.sum') }}
    restore-keys: |
      ${{ runner.os }}-go-modules-
```

### Timeout Management

Always set reasonable timeouts:

```yaml
jobs:
  unit-tests:
    runs-on: ubuntu-latest
    timeout-minutes: 15  # Prevents hung jobs
```

## Workflow Dependencies

### Using `needs:`

Establish clear job dependencies:

```yaml
jobs:
  unit-tests:
    # Runs first

  integration-tests:
    needs: unit-tests  # Waits for unit-tests

  deployment:
    needs: [unit-tests, integration-tests]  # Waits for both
```

### Conditional Dependencies

Run jobs only when dependencies succeed:

```yaml
integration-tests:
  needs: unit-tests
  if: needs.unit-tests.result == 'success'
```

## Security Best Practices

### Pinned Action Versions

Always pin action versions for security:

```yaml
# Good: Pinned to specific version
- uses: actions/checkout@v4

# Bad: Using latest
- uses: actions/checkout@latest
```

### Secrets Management

Never expose secrets in logs:

```yaml
# Good: Masked automatically
- run: echo "Token: ${{ secrets.GITHUB_TOKEN }}"

# Bad: Explicit secret exposure
- run: echo "Token: ${MY_SECRET}"
  env:
    MY_SECRET: ${{ secrets.MY_SECRET }}
```

### Permissions

Use least-privilege permissions:

```yaml
permissions:
  contents: read
  checks: read
  pull-requests: read
```

## Testing Workflows Locally

### Using act

Test workflows locally with `act`:

```bash
# Install act
brew install act  # macOS
# or
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Run workflow
act pull_request

# Run specific job
act pull_request -j unit-tests

# Dry run
act pull_request --dryrun
```

### Workflow Validation

Validate YAML syntax:

```bash
# Using GitHub CLI
gh workflow view test-suite.yml

# Using yamllint
yamllint .github/workflows/test-suite.yml
```

## Deprecated Patterns

### ❌ Merge Gate with workflow_run

**Don't use** `workflow_run` triggers for merge validation:

```yaml
# BAD: Race conditions and timing issues
on:
  workflow_run:
    workflows: ["Test Suite", "Build"]
    types: [completed]
```

**Problem**: Triggers when ANY workflow completes, not ALL. Can run multiple times.

**Solution**: Use direct required status checks in branch protection instead.

### ❌ Meta-Workflows

**Don't create** workflows that just check other workflows:

```yaml
# BAD: Meta-workflow that polls check status
jobs:
  check-all:
    steps:
      - name: Check if all workflows passed
        run: gh pr checks $PR_NUMBER
```

**Solution**: Use GitHub's native required status checks feature.

## Future Considerations

### GitHub Merge Queue

For multi-developer teams, consider GitHub Merge Queue:

```yaml
# In repository ruleset
{
  "type": "merge_queue",
  "parameters": {
    "check_response_timeout_minutes": 60,
    "grouping_strategy": "ALLGREEN",
    "merge_method": "SQUASH"
  }
}
```

**Benefits**:
- Tests actual merge commit
- Prevents "green-to-red" merges
- Intelligent PR queuing

**Cost**: Slightly longer merge times

### Workflow Consolidation

Consider consolidating related workflows into matrix jobs:

```yaml
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        go: ['1.22', '1.23']
    runs-on: ${{ matrix.os }}
```

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Workflow Syntax Reference](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions)
- [Branch Protection Rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [Repository Rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)

## Change History

- **2026-01-12**: Initial standards documentation
  - Removed problematic merge-gate workflow
  - Established direct required checks pattern
  - Documented stub job pattern for docs-only PRs
  - Defined path filtering standards
