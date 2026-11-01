#!/bin/bash
set -euo pipefail

# CFGMS Test Infrastructure Runner
# Ensures consistent test environment setup for CI and development

echo "🐳 CFGMS Test Infrastructure Runner"
echo "===================================="

# Load test environment variables
if [[ -f .env.test ]]; then
    echo "📋 Loading test environment from .env.test..."
    set -a
    source .env.test
    set +a
    echo "✅ Test environment loaded"
else
    echo "❌ .env.test not found. Run 'make test-integration-setup' first"
    exit 1
fi

# Set CI mode to ensure infrastructure is required (AFTER sourcing .env.test)
export CI=1
export CFGMS_TEST_INTEGRATION=1

# Set default database name if not provided
export CFGMS_TEST_DB_NAME=${CFGMS_TEST_DB_NAME:-cfgms_test}

echo ""
echo "🔧 Test Environment Configuration:"
echo "  Database: ${CFGMS_TEST_DB_HOST}:${CFGMS_TEST_DB_PORT}/${CFGMS_TEST_DB_NAME}"
echo "  Gitea: ${CFGMS_TEST_GITEA_URL}"
echo "  Session: ${CFGMS_TEST_SESSION_ID}"

# Verify infrastructure is running
echo ""
echo "🔍 Verifying infrastructure availability..."

# Check PostgreSQL
if ! docker exec cfgms-postgres-test pg_isready -h localhost -p 5432 -U cfgms_test >/dev/null 2>&1; then
    echo "❌ PostgreSQL test instance not available"
    echo "   Run 'make test-integration-setup' to start infrastructure"
    exit 1
fi

# Check Gitea
if ! curl -s "${CFGMS_TEST_GITEA_URL}/api/healthz" >/dev/null; then
    echo "❌ Gitea test instance not available"
    echo "   Run 'make test-integration-setup' to start infrastructure"
    exit 1
fi

echo "✅ All infrastructure services are available"

# Run the specified test command
echo ""
echo "🧪 Running tests with infrastructure..."
echo "Command: $*"
echo ""

# Execute the test command with all environment variables
exec "$@"