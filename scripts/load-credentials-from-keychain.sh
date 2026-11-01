#!/bin/bash
# Load credentials from .env.local and override secrets from OS keychain
# Usage: source ./scripts/load-credentials-from-keychain.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env.local"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Detect OS
OS=$(uname -s)

# Function to retrieve credential from keychain
get_credential() {
    local key=$1
    local service="cfgms-m365"

    if [ "$OS" = "Linux" ]; then
        secret-tool lookup service "$service" credential "$key" 2>/dev/null
    elif [ "$OS" = "Darwin" ]; then
        security find-generic-password -s "$service" -a "$key" -w 2>/dev/null
    fi
}

# Check if .env.local exists
if [ ! -f "$ENV_FILE" ]; then
    echo -e "${RED}❌ Error: .env.local not found at $ENV_FILE${NC}"
    echo ""
    echo "Setup instructions:"
    echo "  1. Copy the example: cp .env.local.example .env.local"
    echo "  2. Edit .env.local with your Azure tenant details"
    echo "  3. Run this script again to load credentials"
    return 1 2>/dev/null || exit 1
fi

# Check if keychain tool is available
if [ "$OS" = "Linux" ] && ! command -v secret-tool &> /dev/null; then
    echo -e "${RED}❌ Error: secret-tool not found${NC}"
    echo "Install with: sudo apt install libsecret-tools"
    return 1 2>/dev/null || exit 1
fi

if [ "$OS" = "Darwin" ] && ! command -v security &> /dev/null; then
    echo -e "${RED}❌ Error: security command not found${NC}"
    return 1 2>/dev/null || exit 1
fi

echo -e "${YELLOW}🔓 Loading credentials from .env.local + OS keychain...${NC}"
echo ""

# Step 1: Load all config from .env.local
set -a
source "$ENV_FILE"
set +a

echo -e "${GREEN}✅ Loaded configuration from .env.local${NC}"

# Step 2: Override secrets from keychain
M365_CLIENT_SECRET_FROM_KEYCHAIN=$(get_credential "M365_CLIENT_SECRET")
M365_MSP_CLIENT_SECRET_FROM_KEYCHAIN=$(get_credential "M365_MSP_CLIENT_SECRET")

if [ -n "$M365_CLIENT_SECRET_FROM_KEYCHAIN" ]; then
    export M365_CLIENT_SECRET="$M365_CLIENT_SECRET_FROM_KEYCHAIN"
    echo -e "${GREEN}✅ Loaded M365_CLIENT_SECRET from OS keychain${NC}"
else
    echo -e "${YELLOW}⚠️  M365_CLIENT_SECRET not found in keychain${NC}"
    echo "   Run: ./scripts/migrate-credentials-to-keychain.sh"
fi

if [ -n "$M365_MSP_CLIENT_SECRET_FROM_KEYCHAIN" ]; then
    export M365_MSP_CLIENT_SECRET="$M365_MSP_CLIENT_SECRET_FROM_KEYCHAIN"
    echo -e "${GREEN}✅ Loaded M365_MSP_CLIENT_SECRET from OS keychain${NC}"
else
    echo -e "${YELLOW}⚠️  M365_MSP_CLIENT_SECRET not found in keychain${NC}"
fi

echo ""
echo -e "${GREEN}✅ All credentials loaded successfully${NC}"
echo ""
echo "Environment variables set:"
echo "  ✓ M365_CLIENT_ID: $M365_CLIENT_ID"
echo "  ✓ M365_CLIENT_SECRET: ${M365_CLIENT_SECRET:0:10}... (${#M365_CLIENT_SECRET} chars)"
echo "  ✓ M365_TENANT_ID: $M365_TENANT_ID"
echo "  ✓ M365_TENANT_DOMAIN: $M365_TENANT_DOMAIN"
if [ -n "$M365_MSP_CLIENT_ID" ]; then
    echo "  ✓ M365_MSP_CLIENT_ID: $M365_MSP_CLIENT_ID"
    echo "  ✓ M365_MSP_CLIENT_SECRET: ${M365_MSP_CLIENT_SECRET:0:10}... (${#M365_MSP_CLIENT_SECRET} chars)"
    echo "  ✓ M365_MSP_TENANT_ID: $M365_MSP_TENANT_ID"
fi
echo ""
echo "💡 Config from .env.local, secrets from OS keychain (memory only)"
