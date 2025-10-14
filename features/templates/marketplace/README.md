# Template Marketplace

The CFGMS Template Marketplace provides a centralized repository for community-contributed configuration templates. This enables MSPs and system administrators to discover, share, and customize proven configuration patterns.

## Overview

The template marketplace implements:
- **Discovery & Search**: Browse templates by category, tags, and compliance frameworks
- **Semantic Versioning**: Track template versions and dependencies
- **Fork & Customize**: Create MSP-specific variations of community templates
- **Automated Validation**: CI/CD pipeline ensures template quality and security

## Directory Structure

```
features/templates/marketplace/
├── ssh-hardening/           # SSH security hardening template
│   ├── manifest.yaml        # Template metadata
│   ├── template.yaml        # Template content
│   └── README.md            # Documentation
├── baseline-security/       # Multi-module security baseline
│   ├── manifest.yaml
│   ├── template.yaml
│   └── README.md
└── backup-config/           # Automated backup configuration
    ├── manifest.yaml
    ├── template.yaml
    └── README.md
```

## Template Structure

Each template must include:

### 1. manifest.yaml (Required)
Template metadata and marketplace information:

```yaml
id: template-id
name: Template Name
version: 1.0.0
description: Detailed template description
author: Author Name
author_email: author@example.com (optional)
license: MIT
repository: https://github.com/... (optional)
category: security
keywords:
  - keyword1
  - keyword2
tags:
  - tag1
  - tag2
compliance_frameworks:  # optional
  - CIS
  - NIST
security_level: high    # optional: low, medium, high, critical
tested_platforms:       # optional
  - linux-ubuntu-20.04
  - linux-ubuntu-22.04
required_modules:       # optional
  - file
  - directory
dependencies:           # optional
  - template_id: other-template
    version: "1.0.0"
    required: true
```

### 2. template.yaml (Required)
The actual template content using CFGMS template syntax

### 3. README.md (Recommended)
Comprehensive documentation including:
- Features
- Configuration variables
- Usage examples
- Platform support
- Security notes
- Compliance information

## CI/CD Validation

Templates submitted to the marketplace undergo automated validation:

### Validation Checks
1. **Structure Validation**: Required files present (manifest.yaml, template.yaml)
2. **Manifest Validation**: All required fields present and valid
3. **Security Scanning**: No hardcoded secrets or insecure permissions
4. **Template Testing**: Templates render correctly with test data
5. **Documentation Quality**: README completeness and clarity
6. **Compliance Claims**: Validation of compliance framework tags

### Validation Workflow
Located in `.github/workflows-disabled/template-validation.yml` (will be enabled in v0.8.0)

The workflow performs:
- Structure and manifest validation
- Security scanning for secrets and permissions
- Template rendering tests
- Compliance framework validation
- Documentation quality checks

### Running Validation Locally

```bash
# Validate all templates
bash scripts/validate-templates.sh all

# Validate specific aspects
bash scripts/validate-templates.sh structure
bash scripts/validate-templates.sh manifests
bash scripts/validate-templates.sh security
bash scripts/validate-templates.sh examples
```

## Creating a New Template

1. **Create template directory**: `features/templates/marketplace/my-template/`

2. **Create manifest.yaml**:
```yaml
id: my-template
name: My Template Name
version: 1.0.0
description: What this template does (at least 20 characters)
author: Your Name
license: MIT
category: security  # or: compliance, backup, monitoring, networking, system, application
keywords:
  - relevant
  - keywords
```

3. **Create template.yaml**: Your template content using CFGMS syntax

4. **Create README.md**: Documentation with:
   - Features
   - Configuration variables table
   - Usage examples
   - Platform support
   - Security notes

5. **Validate locally**:
```bash
bash scripts/validate-templates.sh all
```

6. **Submit via Pull Request**: CI/CD will automatically validate

## Example Templates

### 1. SSH Hardening (`ssh-hardening/`)
- **Purpose**: CIS/NIST compliant SSH configuration
- **Modules**: file
- **Compliance**: CIS, NIST, SOC2
- **Platforms**: Linux (Ubuntu, Debian, RHEL, CentOS)

### 2. Baseline Security (`baseline-security/`)
- **Purpose**: Comprehensive endpoint security baseline
- **Modules**: file, directory, script
- **Compliance**: CIS, NIST, SOC2, PCI-DSS
- **Platforms**: Linux (Ubuntu, Debian, RHEL, CentOS)

### 3. Backup Configuration (`backup-config/`)
- **Purpose**: Automated backup with retention policies
- **Modules**: directory, script
- **Compliance**: SOC2, GDPR, HIPAA
- **Platforms**: Linux (Ubuntu, Debian, RHEL, CentOS)

## Template Categories

- **security**: Security hardening and controls
- **compliance**: Compliance framework implementations
- **backup**: Backup and disaster recovery
- **monitoring**: Monitoring and observability
- **networking**: Network configuration
- **system**: System configuration and tuning
- **application**: Application-specific configurations

## Contributing

1. Fork the repository
2. Create your template following the structure above
3. Run local validation
4. Submit a pull request
5. CI/CD will automatically validate your template
6. Community review and merge

## Compliance Frameworks

Templates can claim compliance with these frameworks:
- **CIS**: CIS Benchmarks (various distributions)
- **NIST**: NIST SP 800-53 controls
- **SOC2**: Service Organization Control 2
- **PCI-DSS**: Payment Card Industry Data Security Standard
- **HIPAA**: Health Insurance Portability and Accountability Act
- **GDPR**: General Data Protection Regulation

**Note**: Compliance claims are validated during CI/CD but require manual security review.

## Security

### Security Levels
- **low**: Basic configuration with minimal security impact
- **medium**: Standard security practices
- **high**: Hardened configuration following security best practices
- **critical**: Maximum security posture for sensitive environments

### Security Validation
All templates are scanned for:
- Hardcoded secrets (passwords, API keys, tokens)
- Insecure file permissions (777, 666)
- SQL injection vulnerabilities
- Command injection risks
- Information disclosure

## License

Templates in this marketplace are provided by the community under their specified licenses. Each template's license is specified in its manifest.yaml file.

Common licenses:
- MIT
- Apache 2.0
- GPL v3
- BSD 3-Clause

## Support

- **Documentation**: https://cfgms.io/docs/templates/marketplace
- **Issues**: https://github.com/cfg-is/cfgms/issues
- **Community**: https://discord.gg/cfgms

## Versioning

Templates follow semantic versioning (MAJOR.MINOR.PATCH):
- **MAJOR**: Breaking changes requiring configuration updates
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes and minor improvements

## Changelog

Maintain a changelog in your manifest.yaml:

```yaml
changelog:
  - version: 1.1.0
    date: 2025-10-15T00:00:00Z
    description: Added support for additional SSH ciphers
    breaking: false
    author: Author Name
  - version: 1.0.0
    date: 2025-10-13T00:00:00Z
    description: Initial release
    breaking: false
    author: Author Name
```
