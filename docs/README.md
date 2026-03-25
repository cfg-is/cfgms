# CFGMS Documentation

Welcome to the CFGMS (Configuration Management System) documentation. This documentation provides comprehensive information about the architecture, development, and usage of CFGMS.

## For Contributors (Start Here)

If you're new to the project, start with these essential documents:

- [Architecture](../ARCHITECTURE.md) - System design and architectural overview
- [Contributing Guidelines](../CONTRIBUTING.md) - How to contribute to the project
- [Development Setup](../DEVELOPMENT.md) - Local development environment setup
- [Code of Conduct](../CODE_OF_CONDUCT.md) - Community standards and expectations
- [Security Policy](../SECURITY.md) - Security practices and vulnerability reporting
- [Claude Code Integration](../CLAUDE.md) - AI assistant guidance for working with this codebase

## Architecture & Design

### Core Architecture

- [Architecture Document](architecture.md) - Detailed architecture documentation
- [Plugin Architecture](architecture/plugin-architecture.md) - Extensible module system design
- [Git Backend Design](architecture/git-backend-design.md) - GitOps storage backend
- [Hybrid Storage Solution](architecture/hybrid-storage-solution.md) - Flexible storage options
- [Communication Layer Migration](architecture/communication-layer-migration.md) - Transport architecture (gRPC-over-QUIC)
- [Rollback Design](architecture/rollback-design.md) - Configuration rollback system
- [Template Engine Design](architecture/template-engine-design.md) - Configuration templating
- [Workflow Debug System](architecture/workflow-debug-system.md) - Workflow debugging capabilities

### Module System

- [Module System Overview](architecture/modules/README.md) - Module architecture and design
- [Module Interface](architecture/modules/interface.md) - Module interface specifications
- [Script Module](modules/script-module.md) - Script execution module documentation

### Architecture Decisions

- [Architecture Decision Records](architecture/decisions/README.md) - Index of all ADRs
- [ADR-001: Central Provider Compliance Enforcement](architecture/decisions/001-central-provider-compliance-enforcement.md)

### High Availability & Commercial Split

- [HA Commercial Split](architecture/ha-commercial-split.md) - Open source vs commercial boundaries

### Historical Design Documents

- [gRPC Usage Analysis](architecture/grpc-usage-analysis.md) - Historical: Analysis that led to the gRPC-over-QUIC unified transport

## Development Guides

### Getting Started

- [Development Workflow](development/guides/development-workflow.md) - Daily development workflow
- [Getting Started Guide](development/guides/getting-started.md) - Onboarding for new developers
- [Standalone Steward Implementation](development/guides/standalone-steward-implementation.md)

### Development Standards

- [Go Coding Standards](development/standards/go-coding-standards.md) - Go code style and patterns
- [Testing Standards](development/standards/testing-standards.md) - Testing requirements and patterns
- [Documentation Standards](development/standards/documentation-standards.md) - Documentation guidelines
- [Review Process](development/standards/review-process.md) - Code review standards

### Development Workflow

- [Story Checklist](development/story-checklist.md) - Complete checklist for story implementation
- [PR Review Methodology](development/pr-review-methodology.md) - 5-phase structured PR review process
- [Git Workflow](development/git-workflow.md) - GitFlow branching strategy
- [Commands Reference](development/commands-reference.md) - All available make commands
- [Project Management](development/project_management.md) - Project tracking and planning

### Development Infrastructure

- [CI Infrastructure Setup](development/ci-infrastructure-setup.md) - GitHub Actions configuration
- [Test Cache Architecture](development/test-cache-architecture.md) - Test performance optimization

### Security Development

- [Security Setup](development/security-setup.md) - Development security configuration
- [Security Workflow Guide](development/security-workflow-guide.md) - Security-focused development process
- [Security Troubleshooting](development/security-troubleshooting.md) - Common security issues
- [Automated Remediation Guide](development/automated-remediation-guide.md) - Security automation

### Logging Development

- [Logging Architecture Guide](development/logging-architecture-guide.md) - CFGMS logging system architecture and usage
- [Logging Dependency Injection Guide](development/logging-dependency-injection-guide.md) - Module dependency injection patterns
- [Module Logging Development Guide](development/module-logging-development-guide.md) - Implementing logging in modules
- [Logging Migration Standards](development/logging-migration-standards.md) - Migrating to new logging system

## Security

### Security Architecture

- [Security Architecture](security/architecture.md) - System-wide security design
- [Zero Trust Security Analysis](security/zero_trust_security_analysis.md) - Zero-trust implementation analysis
- [Security Configuration](security/SECURITY_CONFIGURATION.md) - Secure configuration guidelines
- [Credential Setup](security/README.md) - Local credential management with OS keychain

### Security Audits

- [Audit Report 2025-10-17](security/audits/audit-report-2025-10-17.md) - Security audit findings
- [Remediation Plan 2025-10-17](security/audits/remediation-plan-2025-10-17.md) - Audit remediation strategy
- [Remediation Summary 2025-10-18](security/audits/remediation-summary-2025-10-18.md) - Remediation status
- [Sensitive Data Scan Results](security/sensitive-data-scan-results.md) - Repository security scan

## Product Information

### Vision & Strategy

- [Product Vision](product/vision.md) - Long-term product vision and strategy
- [Product Roadmap](product/roadmap.md) - Development roadmap and release planning
- [Feature Boundaries](product/feature-boundaries.md) - Open source vs commercial features
- [v0.7.0 Epic](product/v0.7.0-epic.md) - OSS launch preparation and business model

## Integration Guides

### Cloud Platform Integration

- [M365 Integration Guide](M365_INTEGRATION_GUIDE.md) - Microsoft 365 integration setup
- [CSP Sandbox Setup Guide](CSP_SANDBOX_SETUP_GUIDE.md) - Cloud Solution Provider testing environment

## Operations

### Production Operations

- [Production Runbooks](operations/production-runbooks.md) - Operational procedures and troubleshooting

### Monitoring & Observability

- [Monitoring Guide](monitoring.md) - Comprehensive monitoring setup
- [Test Coverage Analysis](testing/test_coverage_analysis.md) - Code coverage metrics

## Testing

- [Testing Strategy](testing/testing-strategy.md) - Overall testing approach and standards

## Deployment

- [Platform Support](deployment/platform-support.md) - Supported platforms and requirements
- [Registration Codes](deployment/registration-codes.md) - Steward registration system

## Configuration

- [Configuration Inheritance](guides/configuration-inheritance.md) - Hierarchical configuration system

## Examples

- [Logging Configuration](examples/logging-configuration.md) - Logging setup examples

## Reference

### Terminology

- [Terminology](terminology.md) - Standardized terminology and definitions

### GitHub Integration

- [GitHub Actions Fixes](github-actions-fixes.md) - CI/CD troubleshooting
- [GitHub CLI Reference](github-cli-reference.md) - Using gh CLI with CFGMS

## Documentation Review Status

- [Documentation Review Report](DOCUMENTATION_REVIEW_REPORT.md) - Comprehensive documentation audit (2025-10-23)
- [Documentation Review Status](DOCUMENTATION_REVIEW_STATUS.md) - Current progress on documentation cleanup

---

## Version Information

- **Document Version**: 2.0
- **Last Updated**: 2025-11-06
- **Status**: Active
- **Part of**: Story #228 - Documentation Cleanup & Creation

## Change History

| Date | Version | Description |
|------|---------|-------------|
| 2025-11-06 | 2.0 | Complete rewrite with accurate links and current structure |
| 2024-04-11 | 1.0 | Initial documentation structure (deprecated) |
