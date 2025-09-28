#!/bin/bash
# Gitea initialization script for CFGMS test repositories
# Creates test repositories for git provider validation

set -e

echo "Setting up CFGMS test repositories in Gitea..."

# Wait for Gitea to be fully ready
echo "Waiting for Gitea to be ready..."
timeout=60
while ! curl -s http://localhost:3000/api/healthz > /dev/null 2>&1; do
    if [ $timeout -le 0 ]; then
        echo "Timeout waiting for Gitea to be ready"
        exit 1
    fi
    echo "Waiting for Gitea... ($timeout seconds remaining)"
    sleep 5
    timeout=$((timeout-5))
done

echo "Gitea is ready!"

# Gitea API credentials - use environment variables or secure defaults
GITEA_URL="http://localhost:3000"
USERNAME="${CFGMS_TEST_GITEA_USER:-cfgms_test}"
# Get password from Docker environment or fallback
PASSWORD="${CFGMS_TEST_GITEA_PASSWORD:-$GITEA__admin__PASSWORD}"
if [ -z "$PASSWORD" ]; then
    PASSWORD="cfgms_test_password"
fi

if [ "$PASSWORD" != "${CFGMS_TEST_GITEA_PASSWORD:-}" ]; then
    echo "⚠️  Warning: Using generated password. For production, set CFGMS_TEST_GITEA_PASSWORD"
fi

# Function to create repository via API
create_repo() {
    local repo_name="$1"
    local description="$2"
    
    echo "Creating repository: $repo_name"
    
    curl -X POST \
        -u "$USERNAME:$PASSWORD" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"$repo_name\",
            \"description\": \"$description\",
            \"private\": false,
            \"auto_init\": true,
            \"default_branch\": \"main\"
        }" \
        "$GITEA_URL/api/v1/user/repos" || echo "Repository $repo_name may already exist"
}

# Create test repositories for CFGMS git provider testing
create_repo "cfgms-test-global" "CFGMS test global configuration repository"
create_repo "cfgms-test-client-001" "CFGMS test client configuration repository"
create_repo "cfgms-test-scripts" "CFGMS test script module repository" 
create_repo "cfgms-test-templates" "CFGMS test configuration templates repository"

# Create initial commits with test data
setup_repo_content() {
    local repo_name="$1"
    local temp_dir="/tmp/cfgms-test-$repo_name"
    
    echo "Setting up content for repository: $repo_name"
    
    # Clone the repository (use external port 3001)
    git clone "http://localhost:3001/$USERNAME/$repo_name.git" "$temp_dir" || return 0
    cd "$temp_dir"
    
    # Configure git user
    git config user.name "CFGMS Test"
    git config user.email "test@cfgms.local"
    
    # Create test configuration files
    case $repo_name in
        "cfgms-test-global")
            mkdir -p configs/global
            echo '{"version": "1.0", "type": "global", "test": true}' > configs/global/test-config.json
            echo "# CFGMS Global Test Repository" > README.md
            ;;
        "cfgms-test-client-001")
            mkdir -p configs/clients/client-001
            echo '{"version": "1.0", "type": "client", "client_id": "001", "test": true}' > configs/clients/client-001/test-config.json
            echo "# CFGMS Client Test Repository" > README.md
            ;;
        "cfgms-test-scripts")
            mkdir -p scripts
            echo '#!/bin/bash\necho "CFGMS test script executed successfully"' > scripts/test-script.sh
            chmod +x scripts/test-script.sh
            echo "# CFGMS Scripts Test Repository" > README.md
            ;;
        "cfgms-test-templates")
            mkdir -p templates
            echo '{"template_version": "1.0", "variables": {"test_var": "$TEST_VALUE"}}' > templates/test-template.json
            echo "# CFGMS Templates Test Repository" > README.md
            ;;
    esac
    
    # Commit and push changes
    git add .
    git commit -m "Initial test configuration for $repo_name"
    git push origin main
    
    # Cleanup
    cd /
    rm -rf "$temp_dir"
}

# Set up content for each repository
setup_repo_content "cfgms-test-global"
setup_repo_content "cfgms-test-client-001" 
setup_repo_content "cfgms-test-scripts"
setup_repo_content "cfgms-test-templates"

echo "CFGMS test repositories setup completed successfully!"