#!/bin/bash
# Template Validation Script for CFGMS
# Validates template marketplace contributions for CI/CD

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

# Template marketplace directory
TEMPLATE_DIR="features/templates/marketplace"

# Logging functions
log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
    ((PASS_COUNT++)) || true
}

log_error() {
    echo -e "${RED}✗${NC} $1"
    ((FAIL_COUNT++)) || true
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
    ((WARN_COUNT++)) || true
}

# Validation functions

validate_structure() {
    log_info "Validating template directory structure..."

    if [ ! -d "$TEMPLATE_DIR" ]; then
        log_error "Template marketplace directory not found: $TEMPLATE_DIR"
        return 1
    fi

    local templates_found=0
    for template_dir in "$TEMPLATE_DIR"/*/ ; do
        if [ -d "$template_dir" ]; then
            ((templates_found++)) || true
            local template_name=$(basename "$template_dir")
            log_info "Checking template: $template_name"

            # Check for required files
            if [ -f "$template_dir/manifest.yaml" ]; then
                log_success "$template_name: manifest.yaml found"
            else
                log_error "$template_name: manifest.yaml missing"
            fi

            if [ -f "$template_dir/template.yaml" ]; then
                log_success "$template_name: template.yaml found"
            else
                log_error "$template_name: template.yaml missing"
            fi

            if [ -f "$template_dir/README.md" ]; then
                log_success "$template_name: README.md found"
            else
                log_warning "$template_name: README.md recommended but not required"
            fi
        fi
    done

    if [ $templates_found -eq 0 ]; then
        log_error "No templates found in $TEMPLATE_DIR"
        return 1
    fi

    log_success "Found $templates_found templates"
    return 0
}

validate_manifests() {
    log_info "Validating template manifests..."

    for manifest in "$TEMPLATE_DIR"/*/manifest.yaml ; do
        if [ -f "$manifest" ]; then
            local template_dir=$(dirname "$manifest")
            local template_name=$(basename "$template_dir")

            log_info "Validating manifest for: $template_name"

            # Check required fields
            local required_fields=("id" "name" "version" "description" "author" "license" "category")

            for field in "${required_fields[@]}"; do
                if grep -q "^${field}:" "$manifest"; then
                    log_success "$template_name: Field '$field' present"
                else
                    log_error "$template_name: Required field '$field' missing"
                fi
            done

            # Validate semantic version format
            if grep -qE "^version: [0-9]+\.[0-9]+\.[0-9]+" "$manifest"; then
                log_success "$template_name: Valid semantic version"
            else
                log_error "$template_name: Invalid semantic version format"
            fi

            # Check for valid categories
            local valid_categories=("security" "compliance" "backup" "monitoring" "networking" "system" "application")
            local category=$(grep "^category:" "$manifest" | awk '{print $2}')

            if [[ " ${valid_categories[@]} " =~ " ${category} " ]]; then
                log_success "$template_name: Valid category: $category"
            else
                log_warning "$template_name: Unusual category: $category"
            fi
        fi
    done

    return 0
}

validate_security() {
    log_info "Checking template security..."

    # Check for hardcoded secrets patterns
    local secret_patterns=(
        "password.*=.*['\"].*['\"]"
        "api[_-]?key.*=.*['\"].*['\"]"
        "secret.*=.*['\"].*['\"]"
        "token.*=.*['\"].*['\"]"
        "AWS.*KEY"
        "AKIA[0-9A-Z]{16}"
    )

    for template_file in "$TEMPLATE_DIR"/*/*.yaml; do
        if [ -f "$template_file" ]; then
            local file_name=$(basename "$template_file")
            local template_name=$(basename "$(dirname "$template_file")")

            for pattern in "${secret_patterns[@]}"; do
                if grep -iE "$pattern" "$template_file" > /dev/null 2>&1; then
                    log_error "$template_name/$file_name: Possible hardcoded secret detected (pattern: $pattern)"
                fi
            done

            log_success "$template_name/$file_name: No obvious hardcoded secrets"
        fi
    done

    return 0
}

validate_permissions() {
    log_info "Validating file permissions in templates..."

    # Check for overly permissive file permissions (777, 666)
    for template_file in "$TEMPLATE_DIR"/*/*.yaml; do
        if [ -f "$template_file" ]; then
            local template_name=$(basename "$(dirname "$template_file")")

            if grep -E "mode:.*['\"]?0?777['\"]?" "$template_file" > /dev/null 2>&1; then
                log_error "$template_name: Overly permissive permissions (777) found"
            elif grep -E "mode:.*['\"]?0?666['\"]?" "$template_file" > /dev/null 2>&1; then
                log_error "$template_name: Overly permissive permissions (666) found"
            else
                log_success "$template_name: File permissions appear safe"
            fi
        fi
    done

    return 0
}

validate_secrets() {
    log_info "Checking for secrets in template content..."

    # Use grep to find potential secrets
    if grep -rE "(password|secret|key|token)" "$TEMPLATE_DIR" --include="*.yaml" | grep -vE "(# |description|comment|example)" | head -5; then
        log_warning "Potential secrets found in templates - manual review recommended"
    else
        log_success "No obvious secrets found in template files"
    fi

    return 0
}

validate_examples() {
    log_info "Validating example templates..."

    local required_examples=("ssh-hardening" "baseline-security" "backup-config")

    for example in "${required_examples[@]}"; do
        if [ -d "$TEMPLATE_DIR/$example" ]; then
            log_success "Example template found: $example"

            # Validate example has all required files
            if [ -f "$TEMPLATE_DIR/$example/manifest.yaml" ] && \
               [ -f "$TEMPLATE_DIR/$example/template.yaml" ] && \
               [ -f "$TEMPLATE_DIR/$example/README.md" ]; then
                log_success "$example: All required files present"
            else
                log_error "$example: Missing required files"
            fi
        else
            log_error "Required example template missing: $example"
        fi
    done

    return 0
}

validate_compliance() {
    log_info "Validating compliance framework tags..."

    local valid_frameworks=("CIS" "NIST" "SOC2" "PCI-DSS" "HIPAA" "GDPR")

    for manifest in "$TEMPLATE_DIR"/*/manifest.yaml ; do
        if [ -f "$manifest" ]; then
            local template_name=$(basename "$(dirname "$manifest")")

            if grep -q "compliance_frameworks:" "$manifest"; then
                log_info "$template_name: Checking compliance frameworks..."

                for framework in "${valid_frameworks[@]}"; do
                    if grep -A 5 "compliance_frameworks:" "$manifest" | grep -q "$framework"; then
                        log_success "$template_name: Valid framework tag: $framework"
                    fi
                done
            else
                log_info "$template_name: No compliance frameworks specified (optional)"
            fi
        fi
    done

    return 0
}

validate_cis_check() {
    log_info "Checking CIS benchmark alignment..."

    for template_dir in "$TEMPLATE_DIR"/*/ ; do
        if [ -d "$template_dir" ]; then
            local template_name=$(basename "$template_dir")
            local manifest="$template_dir/manifest.yaml"

            if grep -q "CIS" "$manifest" 2>/dev/null; then
                log_info "$template_name: Claims CIS compliance - manual review recommended"
                log_success "$template_name: CIS tag present in manifest"
            fi
        fi
    done

    return 0
}

validate_security_level() {
    log_info "Validating security level claims..."

    local valid_levels=("low" "medium" "high" "critical")

    for manifest in "$TEMPLATE_DIR"/*/manifest.yaml ; do
        if [ -f "$manifest" ]; then
            local template_name=$(basename "$(dirname "$manifest")")

            if grep -q "security_level:" "$manifest"; then
                local level=$(grep "security_level:" "$manifest" | awk '{print $2}')

                if [[ " ${valid_levels[@]} " =~ " ${level} " ]]; then
                    log_success "$template_name: Valid security level: $level"
                else
                    log_error "$template_name: Invalid security level: $level"
                fi
            else
                log_info "$template_name: No security level specified (optional)"
            fi
        fi
    done

    return 0
}

validate_readme() {
    log_info "Checking README completeness..."

    local required_sections=("Features" "Usage" "Configuration" "Platform Support")

    for readme in "$TEMPLATE_DIR"/*/README.md ; do
        if [ -f "$readme" ]; then
            local template_name=$(basename "$(dirname "$readme")")
            log_info "Checking README for: $template_name"

            for section in "${required_sections[@]}"; do
                set +e  # Temporarily disable exit on error for grep
                grep -qi "## $section\|# $section" "$readme"
                local grep_result=$?
                set -e  # Re-enable exit on error

                if [ $grep_result -eq 0 ]; then
                    log_success "$template_name: Section found: $section"
                else
                    log_warning "$template_name: Recommended section missing: $section"
                fi
            done

            # Check README length (should be substantial)
            local line_count=$(wc -l < "$readme")
            if [ "$line_count" -ge 50 ]; then
                log_success "$template_name: README has adequate documentation ($line_count lines)"
            else
                log_warning "$template_name: README may be too brief ($line_count lines)"
            fi
        fi
    done

    return 0
}

validate_manifest_complete() {
    log_info "Validating manifest completeness..."

    for manifest in "$TEMPLATE_DIR"/*/manifest.yaml ; do
        if [ -f "$manifest" ]; then
            local template_name=$(basename "$(dirname "$manifest")")

            # Check for recommended optional fields
            local optional_fields=("keywords" "homepage" "repository" "tested_platforms" "required_modules")

            local optional_count=0
            for field in "${optional_fields[@]}"; do
                if grep -q "^${field}:" "$manifest"; then
                    ((optional_count++)) || true
                fi
            done

            if [ $optional_count -ge 3 ]; then
                log_success "$template_name: Manifest has good metadata ($optional_count optional fields)"
            else
                log_warning "$template_name: Consider adding more metadata ($optional_count optional fields)"
            fi
        fi
    done

    return 0
}

validate_doc_sections() {
    log_info "Checking for required documentation sections..."

    for readme in "$TEMPLATE_DIR"/*/README.md ; do
        if [ -f "$readme" ]; then
            local template_name=$(basename "$(dirname "$readme")")

            # Check for usage examples
            if grep -qi "usage\|example" "$readme"; then
                log_success "$template_name: Usage examples found"
            else
                log_warning "$template_name: No usage examples found"
            fi

            # Check for platform support
            if grep -qi "platform\|tested on" "$readme"; then
                log_success "$template_name: Platform information found"
            else
                log_warning "$template_name: No platform information found"
            fi

            # Check for security notes
            if grep -qi "security\|important\|warning" "$readme"; then
                log_success "$template_name: Security notes found"
            else
                log_info "$template_name: Consider adding security notes"
            fi
        fi
    done

    return 0
}

validate_render() {
    local template_name="$1"
    log_info "Validating rendered output for: $template_name"

    if [ -d "$TEMPLATE_DIR/$template_name" ]; then
        log_success "$template_name: Template directory exists"
        # Additional rendering validation would go here
        # This is a placeholder for actual template rendering tests
    else
        log_error "$template_name: Template directory not found"
    fi

    return 0
}

generate_report() {
    log_info "Generating validation report..."

    echo "Template Validation Report"
    echo "=========================="
    echo ""
    echo "Summary:"
    echo "  ✓ Passed: $PASS_COUNT"
    echo "  ✗ Failed: $FAIL_COUNT"
    echo "  ⚠ Warnings: $WARN_COUNT"
    echo ""

    if [ $FAIL_COUNT -eq 0 ]; then
        echo "✅ All validation checks passed!"
        exit 0
    else
        echo "❌ Some validation checks failed. Please review and fix."
        exit 1
    fi
}

# Main execution
COMMAND="${1:-all}"

case "$COMMAND" in
    structure)
        validate_structure
        generate_report
        ;;
    manifests)
        validate_manifests
        generate_report
        ;;
    security)
        validate_security
        generate_report
        ;;
    secrets)
        validate_secrets
        generate_report
        ;;
    permissions)
        validate_permissions
        generate_report
        ;;
    examples)
        validate_examples
        generate_report
        ;;
    compliance)
        validate_compliance
        generate_report
        ;;
    cis-check)
        validate_cis_check
        generate_report
        ;;
    security-level)
        validate_security_level
        generate_report
        ;;
    readme)
        validate_readme
        generate_report
        ;;
    manifest-complete)
        validate_manifest_complete
        generate_report
        ;;
    doc-sections)
        validate_doc_sections
        generate_report
        ;;
    render)
        validate_render "${2:-}"
        generate_report
        ;;
    report)
        generate_report
        ;;
    all)
        validate_structure
        validate_manifests
        validate_security
        validate_permissions
        validate_examples
        validate_compliance
        validate_readme
        generate_report
        ;;
    *)
        echo "Usage: $0 {structure|manifests|security|secrets|permissions|examples|compliance|cis-check|security-level|readme|manifest-complete|doc-sections|render|report|all}"
        exit 1
        ;;
esac
