# Security Audits Directory

This directory contains security audit reports with detailed vulnerability information.

**⚠️ IMPORTANT: This directory is gitignored and should NOT be committed to version control.**

## Purpose

Security audit reports contain sensitive information about vulnerabilities, including:
- Specific code locations of security issues
- Exploitation methods
- Unfixed vulnerability details
- Internal security architecture details

## When to Commit

Audit reports should only be added to version control AFTER:
1. All critical and high-severity vulnerabilities are fixed
2. Medium and low-severity issues are either fixed or accepted as risks
3. Report is sanitized to remove exploitation details
4. Public disclosure is approved

## Workflow

1. **During Audit**: Save full reports here (gitignored)
2. **During Remediation**: Reference reports for fixes
3. **After Fixes**: Create sanitized public version
4. **Before Release**: Move sanitized version to `docs/security/` for commit

## Current Reports

Check filenames in this directory for audit dates and scope.
