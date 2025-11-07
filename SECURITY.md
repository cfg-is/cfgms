# Security Policy

## Supported Versions

We take security seriously and provide security updates for the following versions of CFGMS:

| Version | Supported          |
| ------- | ------------------ |
| 0.7.x   | :white_check_mark: |
| < 0.7   | :x:                |

**Note**: As CFGMS is in active pre-1.0 development, we recommend always using the latest version from the `main` branch for production deployments.

## Reporting a Vulnerability

We appreciate responsible disclosure of security vulnerabilities. If you believe you've found a security issue in CFGMS, please report it to us privately.

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report security issues to:

**Email**: security@cfg.is

**PGP Key**: Available at [https://cfg.is/security/pgp-key.asc](https://cfg.is/security/pgp-key.asc) (if encryption is desired)

### What to Include

Please include as much of the following information as possible in your report:

- **Type of issue** (e.g., authentication bypass, SQL injection, cross-site scripting, etc.)
- **Affected component(s)** (controller, steward, API, specific feature)
- **Attack scenario** - Step-by-step instructions to reproduce the issue
- **Impact** - What can an attacker achieve?
- **Affected versions** - Which versions of CFGMS are vulnerable
- **Proof of concept** - Code, screenshots, or logs demonstrating the vulnerability
- **Suggested fix** (if you have one)

### What to Expect

After submitting a vulnerability report, you can expect:

1. **Acknowledgment within 48 hours** - We'll confirm receipt of your report
2. **Initial assessment within 5 business days** - We'll provide our initial evaluation of the severity and impact
3. **Regular updates** - We'll keep you informed as we investigate and develop a fix
4. **Credit** - With your permission, we'll credit you in the security advisory and release notes

### Our Commitment

- We will respond to your report promptly and keep you updated
- We will not take legal action against researchers who responsibly disclose vulnerabilities
- We will acknowledge your contribution (with your permission) in our security advisories
- We will work with you to understand and resolve the issue quickly

## Security Update Process

When a security vulnerability is confirmed:

1. **Triage**: We assess the severity and impact (Critical, High, Medium, Low)
2. **Fix Development**: We develop and test a patch in a private security branch
3. **Disclosure Coordination**: We coordinate disclosure timeline with the reporter
4. **Release**: We release a security update with:
   - Patched version(s)
   - Security advisory (GitHub Security Advisory)
   - CVE assignment (for Critical/High severity issues)
   - Public announcement
5. **Post-Release**: We update documentation and conduct a retrospective

### Disclosure Timeline

- **Critical vulnerabilities**: Patch released within 7 days
- **High vulnerabilities**: Patch released within 14 days
- **Medium vulnerabilities**: Patch released within 30 days
- **Low vulnerabilities**: Patch included in next regular release

We aim to publicly disclose vulnerabilities within 90 days of the initial report, or sooner once a patch is available.

## Security Best Practices

### For Deployment

When deploying CFGMS in production:

- **Use mutual TLS** - Enable mTLS for all steward-controller communication
- **Rotate certificates regularly** - Implement certificate rotation policies
- **Secure secret storage** - Use encrypted storage (SOPS) for sensitive configuration
- **Network segmentation** - Deploy controller in a secured network segment
- **Principle of least privilege** - Use RBAC to limit access appropriately
- **Keep updated** - Apply security updates promptly
- **Enable audit logging** - Monitor and review audit logs regularly
- **Secure API access** - Use strong API keys and rotate them regularly

### For Development

When contributing to CFGMS:

- **No Foot-guns in Development (CRITICAL PRINCIPLE)** - Never build insecure options for development convenience. If it requires durable storage in production, it MUST use durable storage in development. Insecure dev options inevitably leak into production.
- **No hardcoded secrets** - Never commit credentials, API keys, or secrets
- **Secure credential storage** - Secrets MUST use OS keychain or encrypted storage, never plaintext files
- **Input validation** - Validate and sanitize all user input
- **Parameterized queries** - Use parameterized SQL queries, never string concatenation
- **Secure defaults** - Choose secure defaults for all configuration options
- **No insecure documentation** - Never document unsafe alternatives, even as "quick start" options
- **Error handling** - Don't expose sensitive information in error messages
- **Dependency management** - Keep dependencies updated, review security advisories
- **Run security scans** - Use `make security-scan` before every commit

See [CONTRIBUTING.md](CONTRIBUTING.md) for complete security guidelines for contributors.

## Security Features

CFGMS includes the following security features:

### Authentication & Authorization
- Mutual TLS (mTLS) for all internal component communication
- Certificate-based steward authentication
- API key authentication for external API access
- Role-Based Access Control (RBAC) with hierarchical permissions
- Continuous authorization and Just-In-Time (JIT) access

### Data Protection
- Encrypted storage using SOPS (Secrets OPerationS)
- Secure secret management with pluggable backends
- TLS 1.3 for all network communication
- Certificate pinning for steward-controller connections

### Audit & Compliance
- Comprehensive audit logging of all system actions
- Tamper-evident audit trails
- Compliance reporting (CIS, HIPAA, PCI-DSS templates)
- Real-time security event monitoring

### Tenant Isolation
- Strict multi-tenant boundaries
- Resource isolation between tenants
- Hierarchical tenant model (MSP → Client → Group → Device)

## Known Security Limitations

As an early-stage project, please be aware of the following:

- **Pre-1.0 Software**: APIs and security models may change before v1.0 release
- **Active Development**: New features are added frequently; monitor security advisories
- **Community Review**: Security review is ongoing; additional issues may be discovered

## Security Advisories

Security advisories are published via:

- **GitHub Security Advisories**: [https://github.com/cfg-is/cfgms/security/advisories](https://github.com/cfg-is/cfgms/security/advisories)
- **Mailing List**: security-announce@cfg.is (subscribe at [https://cfg.is/security/](https://cfg.is/security/))
- **Release Notes**: Security fixes are highlighted in release notes

## Bug Bounty Program

CFGMS does not currently have a formal bug bounty program. However, we deeply appreciate security researchers who responsibly disclose vulnerabilities and will:

- Publicly acknowledge your contribution (with permission)
- Provide swag and recognition for significant findings
- Consider implementing a formal bounty program as the project matures

## Questions?

If you have questions about this security policy or CFGMS security in general:

- **General security questions**: security@cfg.is
- **Security policy questions**: conduct@cfg.is
- **Documentation issues**: Open an issue on GitHub with the `security` and `documentation` labels

## Attribution

This security policy is inspired by security policies from:
- [Kubernetes Security and Disclosure Information](https://kubernetes.io/docs/reference/issues-security/security/)
- [GitHub's Coordinated Disclosure of Security Vulnerabilities](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/about-coordinated-disclosure-of-security-vulnerabilities)

---

**Thank you for helping keep CFGMS and our community safe!**
