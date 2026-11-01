#!/bin/bash
# Remove hardcoded credentials from CFGMS Docker test configuration
# Replaces hardcoded values with environment variable references

set -e

echo "🔒 Removing hardcoded credentials from Docker configuration..."

# Backup original file
cp docker-compose.test.yml docker-compose.test.yml.backup

# Replace hardcoded credentials with environment variables
sed -i 's/POSTGRES_PASSWORD: cfgms_test_password/POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}/' docker-compose.test.yml
sed -i 's/GITEA__admin__PASSWORD=cfgms_test_password/GITEA__admin__PASSWORD=${GITEA_ADMIN_PASSWORD}/' docker-compose.test.yml
sed -i 's/GITEA__security__SECRET_KEY=cfgms-test-secret-key-do-not-use-in-production/GITEA__security__SECRET_KEY=${GITEA_SECRET_KEY}/' docker-compose.test.yml
sed -i 's/GITEA__security__INTERNAL_TOKEN=cfgms-test-internal-token-do-not-use-in-production/GITEA__security__INTERNAL_TOKEN=${GITEA_INTERNAL_TOKEN}/' docker-compose.test.yml
sed -i 's/redis-server --requirepass cfgms_test_password/redis-server --requirepass ${REDIS_PASSWORD}/' docker-compose.test.yml
sed -i 's/"redis-cli", "-a", "cfgms_test_password"/"redis-cli", "-a", "${REDIS_PASSWORD}"/' docker-compose.test.yml

echo "✅ Hardcoded credentials removed from docker-compose.test.yml"
echo "📋 Backup saved as: docker-compose.test.yml.backup"
echo ""
echo "🔧 Next steps:"
echo "1. Run: ./scripts/generate-test-credentials.sh"
echo "2. Run: source .env.test"
echo "3. Run: make test-integration-setup"