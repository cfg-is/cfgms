#!/bin/bash
#
# Install Git Hooks for CFGMS Development
#
# This script installs mandatory git hooks that enforce:
# - Pre-push validation (runs make test before pushing)
# - Prevents broken tests from reaching remote branches
#
# Usage:
#   ./scripts/install-git-hooks.sh
#
# To uninstall:
#   rm .git/hooks/pre-push

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOOKS_DIR="$REPO_ROOT/.git/hooks"

echo "🔧 Installing CFGMS Git Hooks"
echo "=============================="
echo ""

# Check if we're in a git repository
if [ ! -d "$REPO_ROOT/.git" ]; then
    echo "❌ Error: Not in a git repository"
    echo "   Please run this script from the CFGMS repository root"
    exit 1
fi

# Create hooks directory if it doesn't exist
mkdir -p "$HOOKS_DIR"

# Install pre-push hook
echo "📦 Installing pre-push hook..."
cat > "$HOOKS_DIR/pre-push" << 'HOOK_EOF'
#!/bin/bash
#
# CFGMS Pre-Push Hook
#
# Enforces mandatory validation before pushing to remote:
# - Runs all unit tests with race detection
# - Runs security scans
# - Runs linting checks
#
# This prevents broken tests from reaching develop/main branches.
#
# To bypass in emergency (NOT RECOMMENDED):
#   git push --no-verify
#

set -e

echo ""
echo "🚦 CFGMS Pre-Push Validation"
echo "============================"
echo ""

# Get the branch being pushed
current_branch=$(git branch --show-current)

# Only run validation for feature/hotfix branches
if [[ ! $current_branch =~ ^(feature|hotfix)/ ]]; then
    echo "ℹ️  Skipping validation for non-feature branch: $current_branch"
    echo ""
    exit 0
fi

echo "📋 Branch: $current_branch"
echo ""

# Check if there are uncommitted changes
if [ -n "$(git status --porcelain)" ]; then
    echo "⚠️  WARNING: Uncommitted changes detected"
    echo "   Recommendation: Commit or stash changes before pushing"
    echo ""
    git status --short
    echo ""
    read -p "Continue with push? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Push cancelled"
        exit 1
    fi
fi

# Run validation
echo "🧪 Running Pre-Push Validation..."
echo ""
echo "This validates:"
echo "  ✓ Unit tests with race detection"
echo "  ✓ Security scanning (secrets, vulnerabilities)"
echo "  ✓ Code linting and quality checks"
echo ""
echo "⏱️  Estimated time: 2-5 minutes"
echo ""

# Run make test (fast validation)
if ! make test; then
    echo ""
    echo "❌ PRE-PUSH VALIDATION FAILED"
    echo ""
    echo "   Tests must pass before pushing to remote."
    echo ""
    echo "   Fix the issues and try again:"
    echo "   1. Review test failures above"
    echo "   2. Fix failing tests"
    echo "   3. Run: make test"
    echo "   4. Retry: git push"
    echo ""
    echo "   Emergency bypass (NOT RECOMMENDED):"
    echo "   git push --no-verify"
    echo ""
    exit 1
fi

echo ""
echo "✅ PRE-PUSH VALIDATION PASSED"
echo ""
echo "   All tests passing - safe to push to remote"
echo ""

exit 0
HOOK_EOF

# Make the hook executable
chmod +x "$HOOKS_DIR/pre-push"

echo "✅ Pre-push hook installed successfully"
echo ""
echo "📋 What This Hook Does:"
echo "   • Runs 'make test' before every push"
echo "   • Blocks push if tests fail"
echo "   • Prevents broken code from reaching remote branches"
echo "   • Skips validation for non-feature branches"
echo ""
echo "🚀 Hook Installation Complete!"
echo ""
echo "💡 Tips:"
echo "   • The hook runs automatically on 'git push'"
echo "   • Emergency bypass: git push --no-verify (NOT recommended)"
echo "   • Recommended: Use /story-commit for automatic validation"
echo ""
