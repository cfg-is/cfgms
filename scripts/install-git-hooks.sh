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

# Install pre-commit hook (artifact detection)
echo "📦 Installing pre-commit hook (artifact detection)..."
cat > "$HOOKS_DIR/pre-commit" << 'HOOK_EOF'
#!/bin/bash
#
# CFGMS Pre-Commit Hook — Test Artifact Detection
#
# Blocks commits that include files outside the allowed project directories.
# Catches test artifacts (tenant data, compiled binaries, log output) before
# they enter git history.
#
# To bypass in emergency: git commit --no-verify
#

# Allowed root-level directories
ALLOWED_DIRS="^(api|cmd|commercial|docs|examples|features|internal|pkg|scripts|templates|test|\.claude|\.devcontainer|\.github)/"

# Allowed root-level files (config, docs, build files)
ALLOWED_FILES="^(\.|CLAUDE|README|CHANGELOG|CONTRIBUTING|CONTRIBUTORS|CODE_OF_CONDUCT|CODEOWNERS|DEVELOPMENT|ARCHITECTURE|LICENSING|QUICK_START|SECURITY|LICENSE|Makefile|Dockerfile|docker-compose|go\.(mod|sum)|buf\.(gen\.)?yaml|staticcheck\.conf|windows-setup\.ps1|\.agent-dispatch\.yaml)"

blocked=0
blocked_files=""

while IFS= read -r file; do
    # Skip deletions
    status=$(git diff --cached --name-status -- "$file" | cut -f1)
    if [ "$status" = "D" ]; then
        continue
    fi

    # Check if file is in an allowed directory
    if echo "$file" | grep -qE "$ALLOWED_DIRS"; then
        continue
    fi

    # Check if file is an allowed root-level file
    if echo "$file" | grep -qE "$ALLOWED_FILES"; then
        continue
    fi

    # Block compiled binaries (any location)
    if file "$file" 2>/dev/null | grep -q "executable\|ELF\|Mach-O"; then
        blocked=1
        blocked_files="$blocked_files\n  BINARY: $file"
        continue
    fi

    # This file is outside allowed directories
    blocked=1
    blocked_files="$blocked_files\n  $file"
done < <(git diff --cached --name-only)

if [ $blocked -ne 0 ]; then
    echo ""
    echo "❌ COMMIT BLOCKED: Test artifacts or misplaced files detected"
    echo ""
    echo "The following staged files are outside allowed project directories:"
    echo -e "$blocked_files"
    echo ""
    echo "Allowed directories: api/ cmd/ commercial/ docs/ examples/ features/"
    echo "                     internal/ pkg/ scripts/ templates/ test/"
    echo ""
    echo "If these are test artifacts, unstage them:"
    echo "  git reset HEAD <file>"
    echo ""
    echo "If legitimate, bypass with: git commit --no-verify"
    echo ""
    exit 1
fi

exit 0
HOOK_EOF

chmod +x "$HOOKS_DIR/pre-commit"

echo "✅ Pre-commit hook installed successfully"
echo ""
echo "📋 What These Hooks Do:"
echo "   Pre-commit:"
echo "   • Blocks commits with files outside allowed project directories"
echo "   • Catches test artifacts (tenant data, binaries, log output)"
echo ""
echo "   Pre-push:"
echo "   • Runs 'make test' before every push"
echo "   • Blocks push if tests fail"
echo "   • Prevents broken code from reaching remote branches"
echo "   • Skips validation for non-feature branches"
echo ""
echo "🚀 Hook Installation Complete!"
echo ""
echo "💡 Tips:"
echo "   • Hooks run automatically on commit and push"
echo "   • Emergency bypass: --no-verify (NOT recommended)"
echo "   • Recommended: Use /story-commit for automatic validation"
echo ""
