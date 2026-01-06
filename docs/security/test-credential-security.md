# Test Credential Security Guide

## Overview

CFGMS test infrastructure uses **dynamic credential generation** to eliminate hardcoded secrets and improve security posture during development and testing.

## 🔐 Security Improvements

### Before (❌ Security Issues)

```yaml
# Hardcoded in docker-compose.test.yml
POSTGRES_PASSWORD: cfgms_test_password
GITEA__admin__PASSWORD: cfgms_test_password
GITEA__security__SECRET_KEY: cfgms-test-secret-key-do-not-use-in-production
```

### After (✅ Secure)

```yaml
# Environment variables in docker-compose.test.yml
POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
GITEA__admin__PASSWORD: ${GITEA_ADMIN_PASSWORD}
GITEA__security__SECRET_KEY: ${GITEA_SECRET_KEY}
```

## 🛠️ Usage

### Automated Setup (Recommended)

```bash
# All-in-one secure setup
make test-integration-setup

# Run tests with generated credentials
make test-with-real-storage

# Clean up (removes credentials)
make test-integration-cleanup
```

### Manual Setup

```bash
# Generate secure credentials
./scripts/generate-test-credentials.sh

# Load credentials into environment
source .env.test

# Start services
docker-compose -f docker-compose.test.yml -f docker-compose.test.override.yml up -d

# Run tests
go test -v -tags=integration ./pkg/testing/storage/...
```

## 🔒 Security Features

### 1. **Cryptographically Secure Generation**

- Uses `openssl rand -base64 32` for password generation
- 32 bytes of entropy per credential
- Automatic cleanup of special characters

### 2. **Ephemeral Credentials**

- Generated fresh for each test session
- Automatically cleaned up after tests
- Never committed to version control

### 3. **Environment Isolation**

- Credentials stored in `.env.test` (gitignored)
- Docker override files (gitignored)
- No persistence between sessions

### 4. **Zero Hardcoded Secrets**

- Base configuration files contain only environment variable references
- Fallback secure generation in test fixtures
- No production credentials in test infrastructure

## 📁 Generated Files

### `.env.test` (Auto-generated, gitignored)

```bash
# CFGMS Test Environment - Generated 2024-01-15T10:30:00Z
CFGMS_TEST_DB_PASSWORD=a8K9mN4pQ7rS2vW5xZ3c
POSTGRES_PASSWORD=a8K9mN4pQ7rS2vW5xZ3c
CFGMS_TEST_GITEA_PASSWORD=b9L0oP5qR8sT3wX6yA4d
GITEA_ADMIN_PASSWORD=b9L0oP5qR8sT3wX6yA4d
GITEA_SECRET_KEY=c0M1pQ6rS9tU4xY7zA5eF8h2iL5nO8q
GITEA_INTERNAL_TOKEN=d1N2qR7sT0uV5yZ8aB6f
```

### `docker-compose.test.override.yml` (Auto-generated, gitignored)

```yaml
version: '3.8'
services:
  postgres-test:
    environment:
      POSTGRES_PASSWORD: a8K9mN4pQ7rS2vW5xZ3c
  git-server-test:
    environment:
      - GITEA__admin__PASSWORD=b9L0oP5qR8sT3wX6yA4d
```

## 🔍 Security Verification

### Check for Hardcoded Credentials

```bash
# Verify base configuration is secure
./scripts/generate-test-credentials.sh
# Output: ✅ Base configuration is secure

# Search for hardcoded secrets (should find none)
grep -r "cfgms_test_password\|cfgms-test-secret" docker-compose.test.yml
# No output = secure
```

### Credential Quality

```bash
# Example generated password
echo "a8K9mN4pQ7rS2vW5xZ3c" | wc -c
# 25 characters, high entropy

# Verify uniqueness across sessions
./scripts/generate-test-credentials.sh
cat .env.test | grep PASSWORD
# Different password each run
```

## 🚨 Security Requirements

### Development

- ✅ Never commit `.env.test` or `docker-compose.test.override.yml`
- ✅ Always use `make test-integration-cleanup` after testing
- ✅ Verify `.gitignore` contains credential files

### CI/CD

- ✅ Generate credentials in CI pipeline (not stored in repo)
- ✅ Use secrets management for production-like environments
- ✅ Rotate credentials for each build

### Production

- ✅ Never use test credential patterns in production
- ✅ Use proper secrets management (Vault, K8s secrets, etc.)
- ✅ Regular credential rotation

## 🔧 Migration Guide

### From Hardcoded Credentials

If you have existing hardcoded credentials:

1. **Remove hardcoded values**:

   ```bash
   ./scripts/remove-hardcoded-credentials.sh
   ```

2. **Update any scripts** that reference hardcoded values:

   ```bash
   # Replace hardcoded references
   sed -i 's/cfgms_test_password/${CFGMS_TEST_DB_PASSWORD}/g' your-script.sh
   ```

3. **Use new secure workflow**:

   ```bash
   make test-integration-setup
   make test-with-real-storage
   make test-integration-cleanup
   ```

## 🎯 Benefits

1. **Security**: No hardcoded credentials in version control
2. **Convenience**: Automated credential generation and cleanup
3. **Isolation**: Each test session uses unique credentials
4. **Compliance**: Meets security best practices for test environments
5. **Future-Proof**: Easy to extend for additional services

## ⚠️ Important Notes

- Generated credentials are **only for testing**
- Credentials are **NOT suitable for production**
- Always clean up test environments after use
- Monitor for accidental credential commits in PRs

This approach provides a secure foundation for CFGMS test infrastructure while maintaining developer productivity.
