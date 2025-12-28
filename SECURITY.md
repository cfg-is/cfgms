# Security Policy

## Supported Versions

CFGMS follows [Semantic Versioning 2.0.0](https://semver.org/) with the following security support policy:

| Version | Status | Security Support |
|---------|--------|------------------|
| 0.8.x (Current) | Active Development | Full support with security patches |
| 0.7.x | Previous Minor | Security patches only (3 months) |
| < 0.7 | End of Life | No security patches |

**Pre-v1.0.0 Note**: During active development (0.x.x versions), we provide security patches for the current minor version only. Major security issues may be backported to the previous minor version on a case-by-case basis.

**Post-v1.0.0 Support Policy**:

- **Current Version**: Full support with bug fixes and security patches
- **Previous Minor Version (N-1)**: Security patches only for 3 months after new minor release
- **Long-Term Support (LTS)**: Even minor versions (v1.0, v1.2, v1.4) receive security patches for 18 months
- **End of Life**: Versions older than N-2 minor releases are unsupported

For complete versioning details, see [docs/development/versioning-policy.md](docs/development/versioning-policy.md).

## Reporting a Vulnerability

We appreciate responsible disclosure of security vulnerabilities. If you believe you've found a security issue in CFGMS, please report it to us privately.

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report security issues to:

**Email**: [security@cfg.is](mailto:security@cfg.is)

**Expected Response Time**: 48 hours for initial acknowledgment

**Disclosure Timeline**: We aim to publicly disclose vulnerabilities within 90 days of the initial report, or sooner once a patch is available.

**PGP Encrypted Email** (optional, for highly sensitive reports):

- **Public Key**: Available at <https://cfg.is/security/pgp-key.asc>
- **Note**: PGP encryption is optional; plaintext email to security@cfg.is is acceptable for most reports

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

Security patches are released following this timeline:

| Severity | Patch Timeline | Disclosure |
|----------|---------------|------------|
| **Critical** | Within 7 days | Immediate after patch |
| **High** | Within 14 days | Within 90 days |
| **Medium** | Within 30 days | Within 90 days |
| **Low** | Next regular release | Next release notes |

We aim to publicly disclose vulnerabilities within 90 days of the initial report, or sooner once a patch is available.

### CVE Assignment

Critical and High severity vulnerabilities will receive CVE (Common Vulnerabilities and Exposures) identifiers to ensure proper tracking and industry-wide awareness.

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
- **Configuration signing** - All configurations are cryptographically signed by the controller

### Configuration Signing

CFGMS implements cryptographic signing for all configurations sent from controller to steward:

- **Protection**: Prevents MITM attacks and ensures configuration integrity even with mTLS
- **Algorithms**: RSA-SHA256 or ECDSA-SHA256 (based on certificate type)
- **Key Management**: Controller signs with its mTLS certificate private key
- **Verification**: Steward verifies signatures using the controller's certificate
- **Enforcement**: Unsigned or invalid-signature configurations are rejected
- **Signature Format**: Embedded in YAML as `_signature` metadata field

This provides defense-in-depth beyond transport-layer security, ensuring that even if an attacker compromises the controller or performs a MITM attack, they cannot inject malicious configurations without the controller's private key.

### Explicit Environment Variable Policy

CFGMS enforces an explicit environment variable policy to prevent environment variable hijacking attacks:

**Policy**: Environment variables are only used when explicitly declared in configuration files using `${VAR}` or `${VAR:-default}` syntax.

**Why This Matters**:
- **Prevents Silent Hijacking**: An attacker with env var control cannot redirect the steward to a malicious controller without also modifying the configuration file
- **Defense in Depth**: Configuration files are protected by ACLs and cryptographic signatures (Story #250), so modifying config requires additional privileges
- **Audit Trail**: `cat config.yaml` shows exactly which values come from env vars
- **Fail-Safe**: Missing required env vars (without defaults) cause immediate startup failure

**How It Works**:
```yaml
# In config.yaml:
controller_url: ${CFGMS_CONTROLLER_URL:-https://controller.example.com:9080}
log_dir: ${CFGMS_LOG_DIR:-/var/log/cfgms}
db_password: ${CFGMS_DB_PASSWORD}  # Required - fails if not set
```

**Validation Behavior**:
- `${VAR:-default}` - Uses default if VAR is unset (safe for optional values)
- `${VAR}` without default - **Fails at startup** if VAR is not set (fail-safe for required values)

This approach ensures that environment variable usage is intentional, documented, and auditable.

### Configuration Signing

- All configurations are cryptographically signed by the controller
- Stewards verify signatures before applying ANY configuration changes
- Prevents MITM attacks and malicious configuration injection
- Uses RSA-SHA256 and ECDSA-SHA256 algorithms
- Signatures embedded in configuration YAML as `_signature` metadata

### Audit & Compliance
- Comprehensive audit logging of all system actions
- Tamper-evident audit trails
- Compliance reporting (CIS, HIPAA, PCI-DSS templates)
- Real-time security event monitoring

### Tenant Isolation
- Strict multi-tenant boundaries
- Resource isolation between tenants
- Hierarchical tenant model (MSP → Client → Group → Device)

## Out of Scope

The following are **not** considered security vulnerabilities for CFGMS:

### Infrastructure & Operations

- **Denial of Service (DoS)**: Network-level DoS attacks against CFGMS endpoints
- **Physical Security**: Physical access to systems running CFGMS
- **Social Engineering**: Attacks targeting users or administrators directly
- **Third-Party Services**: Vulnerabilities in external services CFGMS integrates with (M365, Active Directory, etc.)
- **End-of-Life Versions**: Vulnerabilities in unsupported versions (older than N-2 minor versions)

### Configuration & Deployment Issues

- **Misconfiguration**: Issues arising from insecure user configuration choices
- **Weak Credentials**: User-selected weak passwords or API keys
- **Insecure Infrastructure**: Underlying OS or network vulnerabilities
- **Public Exposure**: Services intentionally exposed to the public internet without proper network controls

### Known Limitations

- **Pre-1.0 Software**: APIs and security models may change before v1.0 release
- **Active Development**: New features are added frequently; monitor security advisories
- **Community Review**: Security review is ongoing; additional issues may be discovered
- **Browser-based Attacks**: XSS, CSRF in future Web UI (not yet implemented)

**Note**: While these are out of scope for security bounties, we still appreciate reports that help improve CFGMS security posture.

## Security Advisories

Stay informed about security updates through these channels:

- **GitHub Security Advisories**: [https://github.com/cfg-is/cfgms/security/advisories](https://github.com/cfg-is/cfgms/security/advisories)
- **GitHub Releases**: [https://github.com/cfg-is/cfgms/releases](https://github.com/cfg-is/cfgms/releases)
- **CHANGELOG.md**: Detailed version history with security notes
- **Mailing List**: security-announce@cfg.is (will be available when repository goes public)

## Hall of Fame

We recognize and thank security researchers who responsibly disclose vulnerabilities:

### Acknowledged Researchers

*(No vulnerabilities disclosed yet - project in active development)*

When security vulnerabilities are responsibly disclosed, we will credit researchers here (with their permission) and in GitHub Security Advisories.

## Bug Bounty Program

CFGMS does not currently have a formal bug bounty program. However, we deeply appreciate security researchers who responsibly disclose vulnerabilities and will:

- Publicly acknowledge your contribution (with permission)
- Provide recognition for significant findings
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
