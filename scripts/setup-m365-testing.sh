#!/bin/bash

# CFGMS M365 Testing Setup Script
# This script helps set up the environment for M365 delegated permissions testing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
CRED_PATH="./m365-test-creds"
BUILD_PATH="./bin/m365-test"

echo -e "${BLUE}🚀 CFGMS M365 Testing Setup${NC}"
echo -e "==============================="
echo

# Function to print colored output
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check if we're in the right directory
if [[ ! -f "go.mod" ]] || ! grep -q "github.com/cfgis/cfgms" go.mod; then
    print_error "This script must be run from the CFGMS root directory"
    exit 1
fi

print_success "Found CFGMS project root"

# Check Go installation
if ! command -v go &> /dev/null; then
    print_error "Go is not installed or not in PATH"
    print_info "Please install Go 1.21 or later: https://golang.org/dl/"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
print_success "Go version: $GO_VERSION"

# Build the M365 testing tool
print_info "Building M365 testing tool..."
if go build -o "$BUILD_PATH" ./cmd/m365-test; then
    print_success "Built M365 testing tool: $BUILD_PATH"
else
    print_error "Failed to build M365 testing tool"
    exit 1
fi

# Create credentials directory
if mkdir -p "$CRED_PATH"; then
    print_success "Created credentials directory: $CRED_PATH"
else
    print_error "Failed to create credentials directory"
    exit 1
fi

# Set secure permissions on credentials directory
chmod 700 "$CRED_PATH"
print_success "Set secure permissions on credentials directory"

# Check for environment variables
echo
print_info "Checking environment configuration..."

MISSING_VARS=()

if [[ -z "$M365_CLIENT_ID" ]]; then
    MISSING_VARS+=("M365_CLIENT_ID")
fi

if [[ -z "$M365_CLIENT_SECRET" ]]; then
    MISSING_VARS+=("M365_CLIENT_SECRET")
fi

if [[ -z "$M365_TENANT_ID" ]]; then
    MISSING_VARS+=("M365_TENANT_ID")
fi

if [[ ${#MISSING_VARS[@]} -gt 0 ]]; then
    print_warning "Missing environment variables: ${MISSING_VARS[*]}"
    echo
    echo -e "${YELLOW}To complete setup, set these environment variables:${NC}"
    echo
    for var in "${MISSING_VARS[@]}"; do
        echo "export $var=\"your-value-here\""
    done
    echo
    echo -e "${YELLOW}You can also create a .env file:${NC}"
    echo "cat > .env << EOF"
    echo "M365_CLIENT_ID=\"your-client-id\""
    echo "M365_CLIENT_SECRET=\"your-client-secret\""  
    echo "M365_TENANT_ID=\"your-tenant-id\""
    echo "EOF"
    echo
    echo -e "${YELLOW}Then source it: source .env${NC}"
else
    print_success "All required environment variables are set"
    echo "  M365_CLIENT_ID: ${M365_CLIENT_ID:0:8}..."
    echo "  M365_CLIENT_SECRET: [HIDDEN]"
    echo "  M365_TENANT_ID: ${M365_TENANT_ID:0:8}..."
fi

# Optional variables
echo
print_info "Optional environment variables:"
if [[ -n "$M365_TEST_USER_UPN" ]]; then
    print_success "M365_TEST_USER_UPN: $M365_TEST_USER_UPN"
else
    echo "  M365_TEST_USER_UPN: [Not set - will use interactive authentication]"
fi

if [[ -n "$M365_REDIRECT_URI" ]]; then
    print_success "M365_REDIRECT_URI: $M365_REDIRECT_URI"
else
    echo "  M365_REDIRECT_URI: [Not set - will use http://localhost:8080/callback]"
fi

# Test connection (if credentials are available)
echo
if [[ -n "$M365_CLIENT_ID" && -n "$M365_CLIENT_SECRET" && -n "$M365_TENANT_ID" ]]; then
    print_info "Testing basic connectivity..."
    
    # Run a quick non-interactive test
    if timeout 30s "$BUILD_PATH" -interactive=false -test-scopes=false -verbose=false &>/dev/null; then
        print_success "Basic connectivity test passed"
    else
        print_warning "Basic connectivity test failed (this may be normal if app permissions aren't configured)"
        print_info "Try running the full interactive test to verify setup"
    fi
fi

# Show next steps
echo
echo -e "${BLUE}📋 Next Steps:${NC}"
echo -e "=============="
echo

if [[ ${#MISSING_VARS[@]} -gt 0 ]]; then
    echo -e "${YELLOW}1. Complete Azure AD setup:${NC}"
    echo "   - Register an application in Azure Portal"
    echo "   - Configure redirect URI: http://localhost:8080/callback"
    echo "   - Add delegated permissions (see TESTING.md)"
    echo "   - Grant admin consent"
    echo "   - Create client secret"
    echo "   - Set environment variables"
    echo
    echo -e "${YELLOW}2. Run the test after setting variables:${NC}"
else
    echo -e "${GREEN}1. Run the interactive test:${NC}"
fi

echo "   $BUILD_PATH"
echo

echo -e "${BLUE}2. For detailed documentation:${NC}"
echo "   cat features/modules/m365/TESTING.md"
echo

echo -e "${BLUE}3. For non-interactive testing:${NC}"
echo "   $BUILD_PATH -interactive=false"
echo

echo -e "${BLUE}4. For verbose output:${NC}"
echo "   $BUILD_PATH -verbose=true"
echo

echo -e "${BLUE}5. Test results will be saved to:${NC}"
echo "   $CRED_PATH/test-results/"
echo "   $CRED_PATH/scenario-results/"
echo

# Show Azure AD setup reminder
echo -e "${YELLOW}📝 Azure AD Application Requirements:${NC}"
echo "=================================="
echo "Ensure your Azure AD application has:"
echo "• Redirect URI: http://localhost:8080/callback"
echo "• Delegated permissions: User.Read, Directory.Read.All, etc."
echo "• Application permissions: (optional, for fallback testing)"
echo "• Admin consent granted for all permissions"
echo "• Client secret created and not expired"
echo

echo -e "${GREEN}🎉 Setup complete!${NC}"
echo

# Final check
if [[ ${#MISSING_VARS[@]} -eq 0 ]]; then
    echo -e "${GREEN}Ready to test! Run: $BUILD_PATH${NC}"
else
    echo -e "${YELLOW}Set the missing environment variables, then run: $BUILD_PATH${NC}"
fi