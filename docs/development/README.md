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

- [Story Checklist](story-checklist.md) - Complete checklist for implementing stories
- [PR Review Methodology](pr-review-methodology.md) - 5-phase structured PR review process
- [Git Workflow](git-workflow.md) - GitFlow branching strategy and commit guidelines
- [Commands Reference](commands-reference.md) - All available make commands and utilities

### Development Guides

- [Getting Started Guide](guides/getting-started.md) - Onboarding for new developers
- [Development Workflow](guides/development-workflow.md) - Daily development workflow
- [Standalone Steward Implementation](guides/standalone-steward-implementation.md) - Steward architecture guide

## Standards & Best Practices

### Code Quality

- [Go Coding Standards](standards/go-coding-standards.md) - Go code style and patterns
- [Testing Standards](standards/testing-standards.md) - Testing requirements and patterns
- [Documentation Standards](standards/documentation-standards.md) - Documentation guidelines
- [Review Process](standards/review-process.md) - Code review standards

## Security Development

### Security Workflow

- [Security Setup](security-setup.md) - Development security configuration
- [Security Workflow Guide](security-workflow-guide.md) - Security-focused development process
- [Security Troubleshooting](security-troubleshooting.md) - Common security issues and solutions
- [Automated Remediation Guide](automated-remediation-guide.md) - Security automation

## Logging Development

### Logging System

- [Module Logging Development Guide](module-logging-development-guide.md) - Implementing logging in modules
- [Logging Migration Standards](logging-migration-standards.md) - Migrating to new logging system
- [Logging Migration Summary](logging-migration-summary.md) - Migration progress tracking
- [Logging Interface Injection Implementation](logging-interface-injection-implementation-summary.md) - Dependency injection approach

## Infrastructure

### CI/CD & Testing

- [CI Infrastructure Setup](ci-infrastructure-setup.md) - GitHub Actions configuration
- [Test Cache Architecture](test-cache-architecture.md) - Test performance optimization
- [Project Management](project_management.md) - Project tracking and planning

## Slash Commands (Automated Workflow)

For automated development workflow, use the slash commands documented in `/.claude/slash-commands/`:

- `/story-start` - Begin new story with pre-flight checks
- `/story-commit` - Commit with validation and progress tracking
- `/story-complete` - Complete story with PR creation
- `/pr-review [number]` - Execute structured PR review
- `/dev-status` - Quick development environment status

See [CLAUDE.md](../../CLAUDE.md) for complete slash command documentation.

---

## Version Information

- **Document Version**: 2.0
- **Last Updated**: 2025-11-06
- **Status**: Active
- **Part of**: Story #228 - Documentation Cleanup & Creation

## Change History

| Date | Version | Description |
|------|---------|-------------|
| 2025-11-06 | 2.0 | Updated to lightweight index pointing to root docs and actual development files |
| 2024-04-04 | 1.0 | Initial documentation structure (deprecated) |
