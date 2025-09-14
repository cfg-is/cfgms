#!/bin/bash
# Secure test credential generation for CFGMS Docker integration testing
# Generates ephemeral credentials for each test run to eliminate hardcoded secrets

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🔐 Generating secure test credentials...${NC}"

# Generate random credentials (shorter, YAML-safe)
DB_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
TIMESCALEDB_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
GITEA_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
GITEA_SECRET_KEY=$(openssl rand -base64 48 | tr -d "=+/\n" | cut -c1-32)
GITEA_INTERNAL_TOKEN=$(openssl rand -base64 48 | tr -d "=+/\n" | cut -c1-32)
REDIS_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)

# Create environment file for test session
TEST_ENV_FILE=".env.test"
cat > "$TEST_ENV_FILE" <<EOF
# CFGMS Test Environment - Generated $(date)
# These credentials are ephemeral and only valid for this test session
# DO NOT commit this file to version control

# Database credentials
CFGMS_TEST_DB_PASSWORD=$DB_PASSWORD
POSTGRES_PASSWORD=$DB_PASSWORD

# TimescaleDB credentials
CFGMS_TEST_TIMESCALEDB=1
CFGMS_TEST_TIMESCALEDB_HOST=localhost
CFGMS_TEST_TIMESCALEDB_PORT=5434
CFGMS_TEST_TIMESCALEDB_PASSWORD=$TIMESCALEDB_PASSWORD
TIMESCALEDB_PASSWORD=$TIMESCALEDB_PASSWORD

# Gitea credentials
CFGMS_TEST_GITEA_PASSWORD=$GITEA_PASSWORD
GITEA_ADMIN_PASSWORD=$GITEA_PASSWORD
GITEA_SECRET_KEY=$GITEA_SECRET_KEY
GITEA_INTERNAL_TOKEN=$GITEA_INTERNAL_TOKEN

# Redis credentials
REDIS_PASSWORD=$REDIS_PASSWORD

# Service URLs (static)
CFGMS_TEST_DB_HOST=localhost
CFGMS_TEST_DB_PORT=5433
CFGMS_TEST_GITEA_URL=http://localhost:3001
CFGMS_TEST_GITEA_USER=cfgms_test

# Session info
CFGMS_TEST_SESSION_ID=$(uuidgen 2>/dev/null || echo "test-session-$(date +%s)")
CFGMS_TEST_SESSION_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF

# Create Docker Compose override with generated credentials
cat > "docker-compose.test.override.yml" <<EOF
# Docker Compose override with generated test credentials
# Generated $(date)
# DO NOT commit this file to version control

version: '3.8'

services:
  postgres-test:
    environment:
      POSTGRES_PASSWORD: $DB_PASSWORD

  timescaledb-test:
    environment:
      POSTGRES_PASSWORD: $TIMESCALEDB_PASSWORD

  git-server-test:
    environment:
      - GITEA__admin__PASSWORD=$GITEA_PASSWORD
      - GITEA__security__SECRET_KEY=$GITEA_SECRET_KEY
      - GITEA__security__INTERNAL_TOKEN=$GITEA_INTERNAL_TOKEN

  redis-test:
    command: redis-server --requirepass $REDIS_PASSWORD --appendonly no
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "$REDIS_PASSWORD", "ping"]
EOF

# Make sure .env.test and override files are in .gitignore
if [ -f .gitignore ]; then
    grep -q "^\.env\.test$" .gitignore || echo ".env.test" >> .gitignore
    grep -q "^docker-compose\.test\.override\.yml$" .gitignore || echo "docker-compose.test.override.yml" >> .gitignore
else
    cat > .gitignore <<EOF
.env.test
docker-compose.test.override.yml
EOF
fi

echo -e "${GREEN}✅ Test credentials generated successfully!${NC}"
echo ""
echo -e "${YELLOW}📋 Generated files:${NC}"
echo "   • .env.test - Environment variables for tests"
echo "   • docker-compose.test.override.yml - Docker override with credentials"
echo ""
echo -e "${YELLOW}🔧 Usage:${NC}"
echo "   # Source the environment"
echo "   source .env.test"
echo ""
echo "   # Start services with generated credentials"
echo "   docker-compose -f docker-compose.test.yml -f docker-compose.test.override.yml up -d"
echo ""
echo -e "${YELLOW}🔒 Security Notes:${NC}"
echo "   • Credentials are unique per test session"
echo "   • Files are automatically added to .gitignore"
echo "   • Clean up with: make test-integration-cleanup"
echo ""

# Verify no hardcoded credentials in base files
echo -e "${YELLOW}🔍 Verifying base configuration security...${NC}"
if grep -r "cfgms_test_password\|cfgms-test-secret\|cfgms-test-internal" docker-compose.test.yml >/dev/null 2>&1; then
    echo -e "${RED}⚠️  WARNING: Hardcoded credentials still found in docker-compose.test.yml${NC}"
    echo "   Run: ./scripts/remove-hardcoded-credentials.sh"
else
    echo -e "${GREEN}✅ Base configuration is secure${NC}"
fi