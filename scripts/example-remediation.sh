#!/bin/bash

# Example: Automated Security Remediation Script
# This demonstrates how Claude Code can process the remediation report
# and automatically apply fixes for common security issues.

set -euo pipefail

echo "🤖 Example: Automated Security Remediation"
echo "==========================================="
echo ""

# Generate remediation report
echo "📋 Step 1: Generate remediation report"
make security-remediation-report

REPORT_FILE="/tmp/cfgms-security-remediation.json"

if [ ! -f "$REPORT_FILE" ]; then
    echo "✅ No security issues found. Exiting."
    exit 0
fi

echo ""
echo "📖 Step 2: Parse remediation report"
echo "Report contains $(jq '.remediation_suggestions | length' "$REPORT_FILE") categories of issues"

# Process each remediation suggestion by priority
jq -r '.remediation_suggestions | sort_by(.priority) | .[] | "\(.priority)|\(.tool)|\(.category)|\(.issues_count)|\(.auto_fixable)|\(.validation_command)"' "$REPORT_FILE" | while IFS='|' read -r priority tool category count auto_fixable validation_cmd; do
    echo ""
    echo "🔧 Processing: $tool ($category) - $count issues (Priority $priority)"
    
    case "$tool" in
        "trivy")
            echo "   Example fix for dependency vulnerabilities:"
            echo "   > Fix go-git vulnerability: go get github.com/go-git/go-git/v5@v5.13.0"
            echo "   > Update dependencies: go mod tidy"
            echo "   > Validate fix: $validation_cmd"
            
            # Show specific vulnerabilities
            echo "   Detailed vulnerabilities:"
            jq -r '.remediation_suggestions[] | select(.tool == "trivy") | .detailed_vulnerabilities[]? | "     • \(.VulnerabilityID) (\(.Severity)): \(.PkgName) \(.InstalledVersion) → \(.FixedVersion)"' "$REPORT_FILE"
            ;;
            
        "gosec")
            echo "   Example fixes for security patterns:"
            echo "   > Integer overflow (G115): Add bounds checking before type conversion"
            echo "   > Weak random (G404): Replace math/rand with crypto/rand"
            echo "   > TLS version (G402): Set MinVersion to TLS 1.2 or higher"
            echo "   > File permissions (G301/G302/G306): Use more restrictive permissions"
            echo "   > Validate fix: $validation_cmd"
            
            # Show pattern counts
            high_count=$(jq -r '.remediation_suggestions[] | select(.tool == "gosec") | .high_count // 0' "$REPORT_FILE")
            medium_count=$(jq -r '.remediation_suggestions[] | select(.tool == "gosec") | .medium_count // 0' "$REPORT_FILE")
            echo "     High severity: $high_count issues"
            echo "     Medium severity: $medium_count issues"
            ;;
            
        "staticcheck")
            echo "   Example fixes for code quality:"
            echo "   > Remove unused variables and functions"
            echo "   > Fix inefficient string concatenation"
            echo "   > Improve error handling patterns"
            echo "   > Note: These require manual review (auto_fixable: $auto_fixable)"
            echo "   > Validate fix: $validation_cmd"
            ;;
            
        "nancy")
            echo "   Example fix for Go dependency vulnerabilities:"
            echo "   > Update vulnerable packages identified by Nancy"
            echo "   > Use: go get package@safe-version"
            echo "   > Validate fix: $validation_cmd"
            ;;
    esac
done

echo ""
echo "🎯 Step 3: Remediation Priority Guide"
echo "====================================="
echo "1. Priority 1 (CRITICAL/HIGH CVEs): Fix immediately - deployment blocking"
echo "2. Priority 2 (Dependency vulnerabilities): Fix in same session"  
echo "3. Priority 3 (Security patterns): Fix high-severity first, then medium"
echo "4. Priority 4 (Code quality): Fix during cleanup/refactoring"

echo ""
echo "🔍 Step 4: Validation Workflow"
echo "=============================="
echo "After applying fixes:"
echo "1. Run specific tool validation: make security-[tool]"
echo "2. Run comprehensive scan: make security-scan"
echo "3. Run tests: make test"
echo "4. Run full validation: make test-with-security"

echo ""
echo "📚 Step 5: Reference Documentation"
echo "=================================="
echo "• Remediation guide: docs/development/automated-remediation-guide.md"
echo "• Security setup: docs/development/security-setup.md"  
echo "• CLAUDE.md workflow integration"

echo ""
echo "✨ Example completed! Use this pattern in Claude Code for automated remediation."