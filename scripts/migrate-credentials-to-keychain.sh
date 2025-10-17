#!/bin/bash
# Migrate secrets from .env.local to OS keychain
# This script extracts ONLY secrets and stores them in encrypted OS keychain
# Non-secret config (client IDs, tenant IDs) remains in .env.local

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env.local"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🔐 CFGMS Secret Migration to OS Keychain${NC}"
echo "================================================"
echo ""
echo "This script will:"
echo "  1. Extract secrets from .env.local"
echo "  2. Store them in OS-encrypted keychain"
echo "  3. Replace secrets in .env.local with 'USE_KEYCHAIN' placeholder"
echo ""

# Check if .env.local exists
if [ ! -f "$ENV_FILE" ]; then
    echo -e "${RED}❌ Error: .env.local not found at $ENV_FILE${NC}"
    echo ""
    echo "First time setup:"
    echo "  1. Copy: cp .env.local.example .env.local"
    echo "  2. Edit .env.local with your Azure credentials"
    echo "  3. Run this script to migrate secrets to keychain"
    exit 1
fi

# Detect OS
OS=$(uname -s)
case "$OS" in
    Linux)
        KEYCHAIN_TOOL="secret-tool"
        ;;
    Darwin)
        KEYCHAIN_TOOL="security"
        ;;
    *)
        echo -e "${RED}❌ Unsupported OS: $OS${NC}"
        echo "This script supports Linux (secret-tool) and macOS (security)"
        exit 1
        ;;
esac

# Check if keychain tool is available
if ! command -v $KEYCHAIN_TOOL &> /dev/null; then
    echo -e "${RED}❌ Error: $KEYCHAIN_TOOL not found${NC}"
    if [ "$OS" = "Linux" ]; then
        echo "Install with: sudo apt install libsecret-tools"
    fi
    exit 1
fi

echo -e "${YELLOW}📋 Reading credentials from .env.local...${NC}"

# Parse .env.local
declare -A credentials
while IFS='=' read -r key value; do
    # Skip comments and empty lines
    [[ "$key" =~ ^#.*$ ]] && continue
    [[ -z "$key" ]] && continue

    # Trim whitespace
    key=$(echo "$key" | xargs)
    value=$(echo "$value" | xargs)

    credentials["$key"]="$value"
done < "$ENV_FILE"

echo -e "${GREEN}✅ Found ${#credentials[@]} configuration entries${NC}"
echo ""

# Function to store in keychain
store_credential() {
    local key=$1
    local value=$2
    local service="cfgms-m365"

    if [ "$OS" = "Linux" ]; then
        echo "$value" | secret-tool store --label="CFGMS - $key" service "$service" credential "$key"
    elif [ "$OS" = "Darwin" ]; then
        security add-generic-password -s "$service" -a "$key" -w "$value" -U
    fi
}

echo -e "${YELLOW}🔒 Storing secrets in OS keychain...${NC}"

# Store secrets in keychain
secret_count=0
for key in "${!credentials[@]}"; do
    value="${credentials[$key]}"

    # Only store secrets (CLIENT_SECRET, PASSWORD, API_KEY, etc.)
    if [[ "$key" == *"SECRET"* ]] || [[ "$key" == *"PASSWORD"* ]] || [[ "$key" == *"API_KEY"* ]]; then
        # Skip if already using keychain
        if [[ "$value" == "USE_KEYCHAIN" ]]; then
            echo -e "  ${YELLOW}Skipping${NC}: $key (already using keychain)"
            continue
        fi

        echo -e "  ${GREEN}Storing${NC}: $key (${#value} chars)"
        store_credential "$key" "$value"
        ((secret_count++))
    fi
done

echo ""

if [ $secret_count -eq 0 ]; then
    echo -e "${YELLOW}⚠️  No secrets found to migrate${NC}"
    echo "   All secrets may already be using keychain"
    echo ""
    exit 0
fi

echo -e "${GREEN}✅ $secret_count secret(s) stored in OS keychain${NC}"
echo ""

# Create backup before modifying .env.local
BACKUP_FILE="$ENV_FILE.backup.$(date +%Y%m%d_%H%M%S)"
echo -e "${YELLOW}📦 Creating backup: $BACKUP_FILE${NC}"
cp "$ENV_FILE" "$BACKUP_FILE"

# Update .env.local to replace secrets with USE_KEYCHAIN placeholder
echo -e "${YELLOW}📝 Updating .env.local to use keychain placeholders...${NC}"

temp_file=$(mktemp)
while IFS= read -r line; do
    # Check if line contains a secret
    if [[ "$line" =~ ^[[:space:]]*M365.*SECRET[[:space:]]*= ]]; then
        # Extract the key name
        key=$(echo "$line" | cut -d'=' -f1 | xargs)
        # Replace with USE_KEYCHAIN placeholder
        echo "${key}=USE_KEYCHAIN  # Actual secret stored in OS keychain"
    else
        # Keep the line as-is
        echo "$line"
    fi
done < "$ENV_FILE" > "$temp_file"

mv "$temp_file" "$ENV_FILE"

echo -e "${GREEN}✅ .env.local updated with keychain placeholders${NC}"
echo ""
echo -e "${GREEN}✅ Migration Complete!${NC}"
echo ""
echo "Summary:"
echo "  • $secret_count secret(s) stored in encrypted OS keychain"
echo "  • .env.local still contains non-secret config (IDs, domains)"
echo "  • Backup created: $BACKUP_FILE"
echo ""
echo "Next steps:"
echo "  1. Test: source ./scripts/load-credentials-from-keychain.sh"
echo "  2. Verify: go test ./features/modules/m365/..."
echo "  3. If working, delete backup: rm $BACKUP_FILE"
echo ""
echo "To restore if needed:"
echo "  cp $BACKUP_FILE .env.local"
echo ""
