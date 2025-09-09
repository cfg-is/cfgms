#!/bin/bash

# CFGMS MSP Test Server
# Tests multi-tenant app with local callback handling

set -e

echo "🚀 CFGMS MSP Test Server"
echo "========================"

# Check if .env.local exists
if [ ! -f ".env.local" ]; then
    echo "❌ .env.local not found!"
    echo "   Create .env.local with your M365 credentials:"
    echo "   M365_CLIENT_ID=your-client-id"
    echo "   M365_CLIENT_SECRET=your-client-secret"
    echo "   M365_TENANT_ID=your-tenant-id"
    echo "   M365_INTEGRATION_ENABLED=true"
    exit 1
fi

# Load environment variables
echo "📋 Loading credentials from .env.local..."
set -a
source .env.local
set +a

# Check for MSP credentials first, fallback to regular M365
CLIENT_ID=${M365_MSP_CLIENT_ID:-$M365_CLIENT_ID}
CLIENT_SECRET=${M365_MSP_CLIENT_SECRET:-$M365_CLIENT_SECRET}
TENANT_ID=${M365_MSP_TENANT_ID:-$M365_TENANT_ID}

if [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ] || [ -z "$TENANT_ID" ]; then
    echo "❌ Missing required M365 credentials in .env.local"
    echo "   For MSP testing, add: M365_MSP_CLIENT_ID, M365_MSP_CLIENT_SECRET, M365_MSP_TENANT_ID"
    echo "   Or use regular: M365_CLIENT_ID, M365_CLIENT_SECRET, M365_TENANT_ID"
    exit 1
fi

echo "✅ Credentials loaded"
echo "   Client ID: ${CLIENT_ID:0:8}..."
echo "   Tenant ID: $TENANT_ID"

# Show which credential set is being used
if [ -n "$M365_MSP_CLIENT_ID" ]; then
    echo "   Using: MSP multi-tenant credentials"
else
    echo "   Using: Regular M365 credentials (fallback)"
fi

# Build the test server
echo "🔨 Building test server..."
go build -o bin/msp-test-server ./cmd/msp-test-server

if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi

echo "✅ Build successful"

# Start server
echo "🚀 Starting MSP test server..."
echo ""
echo "📍 Server will start at: http://localhost:8080"
echo "🔧 Make sure your M365 app redirect URI is set to:"
echo "   http://localhost:8080/admin/callback"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

./bin/msp-test-server