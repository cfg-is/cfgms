#!/bin/bash
# Health check script for CFGMS test services
# Waits for all Docker services to be ready before running tests

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🐳 Waiting for CFGMS test services to be ready...${NC}"

# Configuration
POSTGRES_HOST="localhost"
POSTGRES_PORT="${CFGMS_TEST_DB_PORT:-5433}"
POSTGRES_USER="cfgms_test"
POSTGRES_DB="cfgms_test"
POSTGRES_PASSWORD="${CFGMS_TEST_DB_PASSWORD:-cfgms_test_password}"

TIMESCALEDB_HOST="localhost"
TIMESCALEDB_PORT="${CFGMS_TEST_TIMESCALEDB_PORT:-5434}"
TIMESCALEDB_USER="cfgms_test"  # Unified user for both logging and HA tests
TIMESCALEDB_DB="cfgms_ha_test"  # Unified database for both logging and HA tests
TIMESCALEDB_PASSWORD="${CFGMS_TEST_TIMESCALEDB_PASSWORD:-cfgms_test_password}"

GITEA_URL="http://localhost:3001"
GITEA_HEALTH_URL="http://localhost:3001/api/healthz"

MAX_WAIT=120  # Maximum wait time in seconds
WAIT_INTERVAL=5

# Function to check PostgreSQL
check_postgres() {
    echo -n "Checking PostgreSQL... "
    docker exec cfgms-postgres-test psql -U $POSTGRES_USER -d $POSTGRES_DB -c "SELECT 1;" > /dev/null 2>&1
}

# Function to check TimescaleDB
check_timescaledb() {
    echo -n "Checking TimescaleDB... "
    docker exec cfgms-timescaledb-test psql -U $TIMESCALEDB_USER -d $TIMESCALEDB_DB -c "SELECT extversion FROM pg_extension WHERE extname='timescaledb';" > /dev/null 2>&1
}

# Function to check Gitea
check_gitea() {
    echo -n "Checking Gitea... "
    curl -s -f "$GITEA_HEALTH_URL" > /dev/null 2>&1
}

# Function to wait for service
wait_for_service() {
    local service_name="$1"
    local check_function="$2"
    local elapsed=0
    
    while ! $check_function; do
        if [ $elapsed -ge $MAX_WAIT ]; then
            echo -e "${RED}❌ Timeout waiting for $service_name (${MAX_WAIT}s)${NC}"
            return 1
        fi
        
        echo -e "${YELLOW}⏳ Waiting for $service_name... (${elapsed}s/${MAX_WAIT}s)${NC}"
        sleep $WAIT_INTERVAL
        elapsed=$((elapsed + WAIT_INTERVAL))
    done
    
    echo -e "${GREEN}✅ $service_name is ready!${NC}"
    return 0
}

# Check if Docker Compose is running
echo "🔍 Checking Docker Compose services..."
if ! docker compose -f docker-compose.test.yml ps | grep -q "Up"; then
    echo -e "${RED}❌ Docker Compose test services are not running!${NC}"
    echo "Run: make test-integration-setup"
    exit 1
fi

# Wait for each service
echo ""
echo "🔄 Testing service connectivity..."

if wait_for_service "PostgreSQL" check_postgres; then
    echo "📊 Testing PostgreSQL functionality..."
    docker exec cfgms-postgres-test psql -U $POSTGRES_USER -d $POSTGRES_DB -c "
        SELECT
            'PostgreSQL' as service,
            version() as version,
            current_database() as database,
            current_user as user,
            now() as timestamp;
    " 2>/dev/null || echo -e "${YELLOW}⚠️  PostgreSQL basic query failed${NC}"
else
    exit 1
fi

if wait_for_service "TimescaleDB" check_timescaledb; then
    echo "⏰ Testing TimescaleDB functionality..."
    docker exec cfgms-timescaledb-test psql -U $TIMESCALEDB_USER -d $TIMESCALEDB_DB -c "
        SELECT
            'TimescaleDB' as service,
            extversion as version,
            current_database() as database,
            current_user as user,
            now() as timestamp
        FROM pg_extension WHERE extname='timescaledb';
    " 2>/dev/null || echo -e "${YELLOW}⚠️  TimescaleDB basic query failed${NC}"
else
    echo -e "${YELLOW}⚠️  TimescaleDB not available - logging tests will be skipped${NC}"
fi

if wait_for_service "Gitea" check_gitea; then
    echo "📁 Testing Gitea functionality..."
    
    # Test API access
    if curl -s "$GITEA_URL/api/v1/version" > /dev/null; then
        echo -e "${GREEN}   ✅ Gitea API accessible${NC}"
    else
        echo -e "${YELLOW}   ⚠️  Gitea API not accessible${NC}"
    fi
    
    # Check if test repositories exist
    if curl -s -u "cfgms_test:${CFGMS_TEST_GITEA_PASSWORD:-cfgms_test_password}" "$GITEA_URL/api/v1/user/repos" | grep -q "cfgms-test"; then
        echo -e "${GREEN}   ✅ Test repositories found${NC}"
    else
        echo -e "${YELLOW}   ⚠️  Test repositories not found - run setup script${NC}"
    fi
else
    exit 1
fi

echo ""
echo -e "${GREEN}🎉 All services are ready for testing!${NC}"
echo ""
echo "📋 Service Information:"
echo "   PostgreSQL:  localhost:5433 (user: cfgms_test, db: cfgms_test)"
echo "   TimescaleDB: localhost:5434 (user: cfgms_logger_test, db: cfgms_logs_test)"
echo "   Gitea:       http://localhost:3001 (user: cfgms_test)"
echo ""
echo "🧪 Ready to run integration tests:"
echo "   make test-with-real-storage"
echo ""