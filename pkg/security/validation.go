package security

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Validator provides comprehensive input validation for security-sensitive data
type Validator struct {
	// Configuration
	maxStringLength     int
	maxSliceLength      int
	allowedCharsets     map[string]*regexp.Regexp
	prohibitedPatterns  []*regexp.Regexp
}

// ValidationError represents a validation failure with context
type ValidationError struct {
	Field   string `json:"field"`
	Value   string `json:"value,omitempty"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

func (e *ValidationError) Error() string {
	if e.Value != "" {
		return fmt.Sprintf("validation failed for field '%s' with value '%s': %s (rule: %s)",
			e.Field, e.Value, e.Message, e.Rule)
	}
	return fmt.Sprintf("validation failed for field '%s': %s (rule: %s)",
		e.Field, e.Message, e.Rule)
}

// ValidationResult contains the results of validation
type ValidationResult struct {
	Valid  bool               `json:"valid"`
	Errors []*ValidationError `json:"errors,omitempty"`
}

func (vr *ValidationResult) AddError(field, value, rule, message string) {
	vr.Valid = false
	vr.Errors = append(vr.Errors, &ValidationError{
		Field:   field,
		Value:   value,
		Rule:    rule,
		Message: message,
	})
}

func (vr *ValidationResult) AddErrorf(field, value, rule, format string, args ...interface{}) {
	vr.AddError(field, value, rule, fmt.Sprintf(format, args...))
}

// NewValidator creates a new validator with secure defaults
func NewValidator() *Validator {
	v := &Validator{
		maxStringLength: 4096,  // 4KB max string length
		maxSliceLength:  1000,  // Max 1000 items in arrays/slices
		allowedCharsets: make(map[string]*regexp.Regexp),
		prohibitedPatterns: []*regexp.Regexp{
			// Common injection patterns
			regexp.MustCompile(`(?i)(script|javascript|vbscript|onload|onerror|onclick)`),
			regexp.MustCompile(`(?i)(<\s*script|<\s*iframe|<\s*object|<\s*embed)`),
			regexp.MustCompile(`(?i)(eval\s*\(|expression\s*\(|javascript:)`),
			// SQL injection patterns
			regexp.MustCompile(`(?i)(union\s+select|drop\s+table|delete\s+from|insert\s+into|update\s+set)`),
			regexp.MustCompile(`(?i)(\'\s*;\s*drop|\'\s*or\s*1\s*=\s*1|--\s*$)`),
			// Command injection patterns
			regexp.MustCompile(`(?i)(&&|\|\||;|`+"`"+`|\$\(|\${)`),
			// Path traversal patterns
			regexp.MustCompile(`\.\.[/\\]|[/\\]\.\.[/\\]|[/\\]\.\.$`),
			// LDAP injection patterns
			regexp.MustCompile(`(?i)(\*\)|\|\(|\&\(|!\()`),
		},
	}

	// Define allowed character sets
	v.allowedCharsets["alphanumeric"] = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	v.allowedCharsets["alphanumeric_dash"] = regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`)
	v.allowedCharsets["email"] = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	v.allowedCharsets["uuid"] = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	v.allowedCharsets["hostname"] = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	v.allowedCharsets["safe_text"] = regexp.MustCompile(`^[a-zA-Z0-9\s\.\-_,;:!?\(\)\[\]]+$`)
	v.allowedCharsets["base64"] = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)

	return v
}

// ValidateString validates a string field with comprehensive security checks
func (v *Validator) ValidateString(result *ValidationResult, field, value string, rules ...string) {
	if value == "" && v.hasRule(rules, "required") {
		result.AddError(field, value, "required", "field is required")
		return
	}

	if value == "" {
		return // Empty is OK if not required
	}

	// Check UTF-8 validity
	if !utf8.ValidString(value) {
		result.AddError(field, "", "utf8", "invalid UTF-8 encoding")
		return
	}

	// Length validation
	if len(value) > v.maxStringLength {
		result.AddErrorf(field, "", "max_length", "exceeds maximum length of %d characters", v.maxStringLength)
		return
	}

	// Minimum length check
	if minLen := v.getRuleInt(rules, "min_length"); minLen > 0 && len(value) < minLen {
		result.AddErrorf(field, "", "min_length", "minimum length is %d characters", minLen)
		return
	}

	// Check for prohibited patterns (injection attacks)
	for _, pattern := range v.prohibitedPatterns {
		if pattern.MatchString(value) {
			result.AddError(field, "", "security", "contains prohibited pattern")
			return
		}
	}

	// Character set validation
	if charset := v.getRuleString(rules, "charset"); charset != "" {
		if pattern, exists := v.allowedCharsets[charset]; exists {
			if !pattern.MatchString(value) {
				result.AddErrorf(field, "", "charset", "contains invalid characters for charset '%s'", charset)
				return
			}
		}
	}

	// Check for control characters
	if v.hasRule(rules, "no_control_chars") {
		for _, r := range value {
			if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
				result.AddError(field, "", "control_chars", "contains prohibited control characters")
				return
			}
		}
	}

	// Custom format validation
	if v.hasRule(rules, "email") {
		if !v.allowedCharsets["email"].MatchString(value) {
			result.AddError(field, "", "email", "invalid email format")
			return
		}
	}

	if v.hasRule(rules, "uuid") {
		if !v.allowedCharsets["uuid"].MatchString(value) {
			result.AddError(field, "", "uuid", "invalid UUID format")
			return
		}
	}

	if v.hasRule(rules, "hostname") {
		if !v.allowedCharsets["hostname"].MatchString(value) {
			result.AddError(field, "", "hostname", "invalid hostname format")
			return
		}
	}
}

// ValidateInteger validates an integer field
func (v *Validator) ValidateInteger(result *ValidationResult, field string, value int64, rules ...string) {
	if value == 0 && v.hasRule(rules, "required") {
		result.AddError(field, "0", "required", "field is required")
		return
	}

	if min := v.getRuleInt64(rules, "min"); min != 0 && value < min {
		result.AddErrorf(field, fmt.Sprintf("%d", value), "min", "minimum value is %d", min)
		return
	}

	if max := v.getRuleInt64(rules, "max"); max != 0 && value > max {
		result.AddErrorf(field, fmt.Sprintf("%d", value), "max", "maximum value is %d", max)
		return
	}

	if v.hasRule(rules, "positive") && value <= 0 {
		result.AddError(field, fmt.Sprintf("%d", value), "positive", "must be positive")
		return
	}
}

// ValidateSlice validates a slice/array field
func (v *Validator) ValidateSlice(result *ValidationResult, field string, length int, rules ...string) {
	if length == 0 && v.hasRule(rules, "required") {
		result.AddError(field, "[]", "required", "field is required")
		return
	}

	if length > v.maxSliceLength {
		result.AddErrorf(field, "", "max_length", "exceeds maximum length of %d items", v.maxSliceLength)
		return
	}

	if min := v.getRuleInt(rules, "min_items"); min > 0 && length < min {
		result.AddErrorf(field, "", "min_items", "minimum items is %d", min)
		return
	}

	if max := v.getRuleInt(rules, "max_items"); max > 0 && length > max {
		result.AddErrorf(field, "", "max_items", "maximum items is %d", max)
		return
	}
}

// ValidateIPAddress validates an IP address
func (v *Validator) ValidateIPAddress(result *ValidationResult, field, value string, rules ...string) {
	if value == "" && v.hasRule(rules, "required") {
		result.AddError(field, value, "required", "field is required")
		return
	}

	if value == "" {
		return
	}

	ip := net.ParseIP(value)
	if ip == nil {
		result.AddError(field, value, "ip", "invalid IP address format")
		return
	}

	if v.hasRule(rules, "no_private") {
		if ip.IsPrivate() {
			result.AddError(field, value, "no_private", "private IP addresses not allowed")
			return
		}
	}

	if v.hasRule(rules, "no_loopback") {
		if ip.IsLoopback() {
			result.AddError(field, value, "no_loopback", "loopback addresses not allowed")
			return
		}
	}

	if v.hasRule(rules, "ipv4_only") {
		if ip.To4() == nil {
			result.AddError(field, value, "ipv4_only", "only IPv4 addresses allowed")
			return
		}
	}
}

// ValidateURL validates a URL with security checks
func (v *Validator) ValidateURL(result *ValidationResult, field, value string, rules ...string) {
	if value == "" && v.hasRule(rules, "required") {
		result.AddError(field, value, "required", "field is required")
		return
	}

	if value == "" {
		return
	}

	// Basic URL format check (more permissive to allow localhost validation)
	urlPattern := regexp.MustCompile(`^https?://[a-zA-Z0-9.-]+[a-zA-Z0-9]+(:[0-9]+)?(/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]*)?$`)
	if !urlPattern.MatchString(value) {
		result.AddError(field, value, "url", "invalid URL format")
		return
	}

	if v.hasRule(rules, "https_only") {
		if !strings.HasPrefix(value, "https://") {
			result.AddError(field, value, "https_only", "only HTTPS URLs allowed")
			return
		}
	}

	// Check for prohibited URL components
	if strings.Contains(value, "localhost") || strings.Contains(value, "127.0.0.1") {
		if v.hasRule(rules, "no_localhost") {
			result.AddError(field, value, "no_localhost", "localhost URLs not allowed")
			return
		}
	}
}

// ValidateJSON validates JSON content for safety
func (v *Validator) ValidateJSON(result *ValidationResult, field, value string, rules ...string) {
	if value == "" && v.hasRule(rules, "required") {
		result.AddError(field, value, "required", "field is required")
		return
	}

	if value == "" {
		return
	}

	// Check for deeply nested structures (potential DoS)
	depth := 0
	maxDepth := 10
	for _, char := range value {
		if char == '{' || char == '[' {
			depth++
			if depth > maxDepth {
				result.AddError(field, "", "max_depth", "JSON structure too deeply nested")
				return
			}
		} else if char == '}' || char == ']' {
			depth--
		}
	}

	// Check for excessive string lengths in JSON
	stringPattern := regexp.MustCompile(`"([^"\\]|\\.)*"`)
	matches := stringPattern.FindAllString(value, -1)
	for _, match := range matches {
		if len(match) > 1000 { // Max 1KB per JSON string
			result.AddError(field, "", "json_string_length", "JSON contains oversized string values")
			return
		}
	}
}

// Helper methods for rule processing
func (v *Validator) hasRule(rules []string, rule string) bool {
	for _, r := range rules {
		if r == rule {
			return true
		}
	}
	return false
}

func (v *Validator) getRuleString(rules []string, prefix string) string {
	for _, rule := range rules {
		if strings.HasPrefix(rule, prefix+":") {
			return strings.TrimPrefix(rule, prefix+":")
		}
	}
	return ""
}

func (v *Validator) getRuleInt(rules []string, prefix string) int {
	if val := v.getRuleString(rules, prefix); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return 0
}

func (v *Validator) getRuleInt64(rules []string, prefix string) int64 {
	if val := v.getRuleString(rules, prefix); val != "" {
		if i, err := strconv.ParseInt(val, 10, 64); err == nil {
			return i
		}
	}
	return 0
}

// SecurityContext provides context for validation
type SecurityContext struct {
	UserID      string
	TenantID    string
	RemoteAddr  string
	UserAgent   string
	RequestPath string
}

// EnhancedValidator extends basic validation with security context
type EnhancedValidator struct {
	*Validator
	context *SecurityContext
}

// NewEnhancedValidator creates a validator with security context
func NewEnhancedValidator(ctx *SecurityContext) *EnhancedValidator {
	return &EnhancedValidator{
		Validator: NewValidator(),
		context:   ctx,
	}
}

// ValidateWithContext performs validation with security context awareness
func (ev *EnhancedValidator) ValidateWithContext(result *ValidationResult, field, value string, rules ...string) {
	// Perform standard validation
	ev.ValidateString(result, field, value, rules...)

	// Additional context-aware validation
	if ev.hasRule(rules, "tenant_scoped") && ev.context != nil {
		// Ensure the value doesn't reference other tenants
		if strings.Contains(value, "/tenant/") && !strings.Contains(value, ev.context.TenantID) {
			result.AddError(field, "", "tenant_scope", "cross-tenant reference not allowed")
		}
	}

	if ev.hasRule(rules, "rate_limit") && ev.context != nil {
		// This would integrate with rate limiting based on context
		// For now, we'll just validate the field isn't being used for abuse
		if len(value) > 100 && strings.Repeat("a", 50) == value[:50] {
			result.AddError(field, "", "rate_limit", "potential abuse pattern detected")
		}
	}
}