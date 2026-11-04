# Development Documentation

This directory contains detailed development guides, standards, and workflows for CFGMS contributors.

## Quick Start for New Contributors

**Start with the root documentation first:**

1. [CONTRIBUTING.md](../../CONTRIBUTING.md) - Contributing guidelines and security practices
2. [DEVELOPMENT.md](../../DEVELOPMENT.md) - Local development environment setup
3. [ARCHITECTURE.md](../../ARCHITECTURE.md) - System architecture overview
4. [CLAUDE.md](../../CLAUDE.md) - AI assistant guidance for this codebase

## Development Workflow

### Story Development Process

- [Product Planning](product-planning.md) - Discovery, epic readiness, existing-work reconciliation and outcome evidence
- [Story Checklist](story-checklist.md) - Complete checklist for implementing stories
- [PR Review Methodology](pr-review-methodology.md) - 5-phase structured PR review process
- [Git Workflow](git-workflow.md) - GitFlow branching strategy and commit guidelines
- [Merge Protocol](merge-protocol.md) - Cross-cutting PR detection, rebase procedure, and merge serialization
- [Commands Reference](commands-reference.md) - Task map to current Makefile, CLI and operator owners
- [Commit & PR Standards](commit-and-pr-standards.md) - Commit message and PR description format (facts only)
- [Story Template](story-template.md) - Body template for pipeline stories
- [Issue Triage](issue-triage.md) - How issues are triaged and prioritized
- [External Contributors](external-contributors.md) - How the pipeline handles PRs from non-collaborators
- [Versioning Policy](versioning-policy.md) - Semantic versioning policy for releases
- [Branch Protection Rules](branch-protection-rules.md) - Active GitHub Rulesets configuration

### Development Guides

- [Autonomous Dev Team](autonomous-dev-team.md) - How the agent pipeline turns ideas into code
- [Agent Dispatch Reference](agent-dispatch.md) - Container infrastructure, credentials, troubleshooting
- [Acceptance Reviewer Verification](acceptance-reviewer-verification.md) - Code-reference verification model for acceptance checking
- [Complexity Report](complexity-gate.md) - `make complexity-report`: segments, metric file contract, baseline inventory
- [Code Navigation Tooling](code-navigation-tooling.md) - grep + Read navigation workflow and its measured failure modes
- [Documentation Boundaries](documentation-boundaries.md) - Product docs vs private-deployment docs
- [Steward runtime](../architecture/steward-operating-model.md) - Lifecycle, observation, convergence and local/managed entry paths

## Standards & Best Practices

### Code Quality

- [Go Coding Standards](standards/go-coding-standards.md) - Go code style and patterns
- [Casing Conventions](standards/casing-conventions.md) - snake_case config vs PascalCase PowerShell surfaces
- [Testing Standards](standards/testing-standards.md) - Testing requirements and patterns
- [Documentation Standards](standards/documentation-standards.md) - Documentation guidelines
- [Review Process](standards/documentation-standards.md#review-before-acceptance) - Code review standards

## Security Development

### Security Workflow

- [Security Setup](security-setup.md) - Development security configuration
- [Security Workflow Guide](security-workflow-guide.md) - Security-focused development process
- [Security Troubleshooting](security-troubleshooting.md) - Common security issues and solutions
- [Automated Remediation Guide](automated-remediation-guide.md) - Security automation

## Logging Development

### Logging System

- [Logging integration](logging-architecture-guide.md) - Initialization, injection, context and safe structured fields

## Infrastructure

### CI/CD & Testing

- [CI Infrastructure Setup](ci-infrastructure-setup.md) - GitHub Actions configuration
- [CI Runner GitHub App Setup](ci-runner-github-app-setup.md) - Self-hosted Hyper-V CI runner setup runbook
- [CI Test Tiers](ci-test-tiers.md) - Cost, value, and overlap audit of every CI workflow (proposal)
- [Project Management](project_management.md) - Project tracking and planning

## Slash Commands (Automated Workflow)

For automated development workflow, use the slash commands documented in `.claude/commands/`:

- `/story-start` - Begin new story with pre-flight checks
- `/story-commit` - Commit with validation and progress tracking
- `/story-complete` - Complete story with parallel team review and PR creation
- `/pr-review [number]` - Execute structured PR review

See [CLAUDE.md](../../CLAUDE.md) for complete slash command documentation.
