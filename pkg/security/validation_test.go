// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package security

import (
	"testing"
)

func TestValidator_ValidateString(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		field   string
		value   string
		rules   []string
		wantErr bool
		errRule string
	}{
		{
			name:    "valid alphanumeric string",
			field:   "test",
			value:   "hello123",
			rules:   []string{"charset:alphanumeric"},
			wantErr: false,
		},
		{
			name:    "invalid alphanumeric string",
			field:   "test",
			value:   "hello-123",
			rules:   []string{"charset:alphanumeric"},
			wantErr: true,
			errRule: "charset",
		},
		{
			name:    "string too long",
			field:   "test",
			value:   string(make([]byte, 5000)),
			rules:   []string{},
			wantErr: true,
			errRule: "max_length",
		},
		{
			name:    "required field empty",
			field:   "test",
			value:   "",
			rules:   []string{"required"},
			wantErr: true,
			errRule: "required",
		},
		{
			name:    "injection pattern detected",
			field:   "test",
			value:   "hello<script>alert('xss')</script>",
			rules:   []string{},
			wantErr: true,
			errRule: "security",
		},
		{
			name:    "SQL injection pattern detected",
			field:   "test",
			value:   "'; DROP TABLE users; --",
			rules:   []string{},
			wantErr: true,
			errRule: "security",
		},
		{
			name:    "valid email",
			field:   "email",
			value:   "user@example.com",
			rules:   []string{"email"},
			wantErr: false,
		},
		{
			name:    "invalid email",
			field:   "email",
			value:   "not-an-email",
			rules:   []string{"email"},
			wantErr: true,
			errRule: "email",
		},
		{
			name:    "valid UUID",
			field:   "id",
			value:   "550e8400-e29b-41d4-a716-446655440000",
			rules:   []string{"uuid"},
			wantErr: false,
		},
		{
			name:    "invalid UUID",
			field:   "id",
			value:   "not-a-uuid",
			rules:   []string{"uuid"},
			wantErr: true,
			errRule: "uuid",
		},
		{
			name:    "valid hostname",
			field:   "host",
			value:   "example.com",
			rules:   []string{"hostname"},
			wantErr: false,
		},
		{
			name:    "invalid hostname",
			field:   "host",
			value:   "invalid..hostname",
			rules:   []string{"hostname"},
			wantErr: true,
			errRule: "hostname",
		},
		{
			name:    "control characters",
			field:   "text",
			value:   "hello\x00world",
			rules:   []string{"no_control_chars"},
			wantErr: true,
			errRule: "control_chars",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ValidationResult{Valid: true}
			validator.ValidateString(result, tt.field, tt.value, tt.rules...)

			if tt.wantErr && result.Valid {
				t.Errorf("expected validation to fail but it passed")
			}
			if !tt.wantErr && !result.Valid {
				t.Errorf("expected validation to pass but it failed: %v", result.Errors)
			}
			if tt.wantErr && len(result.Errors) > 0 && result.Errors[0].Rule != tt.errRule {
				t.Errorf("expected error rule %s, got %s", tt.errRule, result.Errors[0].Rule)
			}
		})
	}
}

func TestValidator_ValidateInteger(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		field   string
		value   int64
		rules   []string
		wantErr bool
		errRule string
	}{
		{
			name:    "valid positive integer",
			field:   "count",
			value:   42,
			rules:   []string{"positive"},
			wantErr: false,
		},
		{
			name:    "invalid positive integer",
			field:   "count",
			value:   -1,
			rules:   []string{"positive"},
			wantErr: true,
			errRule: "positive",
		},
		{
			name:    "value within range",
			field:   "port",
			value:   8080,
			rules:   []string{"min:1", "max:65535"},
			wantErr: false,
		},
		{
			name:    "value too small",
			field:   "port",
			value:   0,
			rules:   []string{"min:1"},
			wantErr: true,
			errRule: "min",
		},
		{
			name:    "value too large",
			field:   "port",
			value:   70000,
			rules:   []string{"max:65535"},
			wantErr: true,
			errRule: "max",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ValidationResult{Valid: true}
			validator.ValidateInteger(result, tt.field, tt.value, tt.rules...)

			if tt.wantErr && result.Valid {
				t.Errorf("expected validation to fail but it passed")
			}
			if !tt.wantErr && !result.Valid {
				t.Errorf("expected validation to pass but it failed: %v", result.Errors)
			}
			if tt.wantErr && len(result.Errors) > 0 && result.Errors[0].Rule != tt.errRule {
				t.Errorf("expected error rule %s, got %s", tt.errRule, result.Errors[0].Rule)
			}
		})
	}
}

func TestValidator_ValidateIPAddress(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		field   string
		value   string
		rules   []string
		wantErr bool
		errRule string
	}{
		{
			name:    "valid IPv4",
			field:   "ip",
			value:   "192.168.1.1",
			rules:   []string{},
			wantErr: false,
		},
		{
			name:    "valid IPv6",
			field:   "ip",
			value:   "2001:db8::1",
			rules:   []string{},
			wantErr: false,
		},
		{
			name:    "invalid IP",
			field:   "ip",
			value:   "300.300.300.300",
			rules:   []string{},
			wantErr: true,
			errRule: "ip",
		},
		{
			name:    "private IP not allowed",
			field:   "ip",
			value:   "192.168.1.1",
			rules:   []string{"no_private"},
			wantErr: true,
			errRule: "no_private",
		},
		{
			name:    "loopback not allowed",
			field:   "ip",
			value:   "127.0.0.1",
			rules:   []string{"no_loopback"},
			wantErr: true,
			errRule: "no_loopback",
		},
		{
			name:    "IPv6 not allowed",
			field:   "ip",
			value:   "2001:db8::1",
			rules:   []string{"ipv4_only"},
			wantErr: true,
			errRule: "ipv4_only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ValidationResult{Valid: true}
			validator.ValidateIPAddress(result, tt.field, tt.value, tt.rules...)

			if tt.wantErr && result.Valid {
				t.Errorf("expected validation to fail but it passed")
			}
			if !tt.wantErr && !result.Valid {
				t.Errorf("expected validation to pass but it failed: %v", result.Errors)
			}
			if tt.wantErr && len(result.Errors) > 0 && result.Errors[0].Rule != tt.errRule {
				t.Errorf("expected error rule %s, got %s", tt.errRule, result.Errors[0].Rule)
			}
		})
	}
}

func TestValidator_ValidateURL(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		field   string
		value   string
		rules   []string
		wantErr bool
		errRule string
	}{
		{
			name:    "valid HTTP URL",
			field:   "url",
			value:   "http://example.com",
			rules:   []string{},
			wantErr: false,
		},
		{
			name:    "valid HTTPS URL",
			field:   "url",
			value:   "https://example.com/path?query=value",
			rules:   []string{},
			wantErr: false,
		},
		{
			name:    "invalid URL",
			field:   "url",
			value:   "not-a-url",
			rules:   []string{},
			wantErr: true,
			errRule: "url",
		},
		{
			name:    "HTTP not allowed",
			field:   "url",
			value:   "http://example.com",
			rules:   []string{"https_only"},
			wantErr: true,
			errRule: "https_only",
		},
		{
			name:    "localhost not allowed",
			field:   "url",
			value:   "https://localhost:8080",
			rules:   []string{"no_localhost"},
			wantErr: true,
			errRule: "no_localhost",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ValidationResult{Valid: true}
			validator.ValidateURL(result, tt.field, tt.value, tt.rules...)

			if tt.wantErr && result.Valid {
				t.Errorf("expected validation to fail but it passed")
			}
			if !tt.wantErr && !result.Valid {
				t.Errorf("expected validation to pass but it failed: %v", result.Errors)
			}
			if tt.wantErr && len(result.Errors) > 0 && result.Errors[0].Rule != tt.errRule {
				t.Errorf("expected error rule %s, got %s", tt.errRule, result.Errors[0].Rule)
			}
		})
	}
}

func TestValidator_ValidateJSON(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		field   string
		value   string
		rules   []string
		wantErr bool
		errRule string
	}{
		{
			name:    "valid simple JSON",
			field:   "data",
			value:   `{"key": "value"}`,
			rules:   []string{},
			wantErr: false,
		},
		{
			name:    "deeply nested JSON",
			field:   "data",
			value:   `{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":"too deep"}}}}}}}}}}`,
			rules:   []string{},
			wantErr: true,
			errRule: "max_depth",
		},
		{
			name:    "JSON with oversized string",
			field:   "data",
			value:   `{"key": "` + string(make([]byte, 1001)) + `"}`,
			rules:   []string{},
			wantErr: true,
			errRule: "json_string_length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ValidationResult{Valid: true}
			validator.ValidateJSON(result, tt.field, tt.value, tt.rules...)

			if tt.wantErr && result.Valid {
				t.Errorf("expected validation to fail but it passed")
			}
			if !tt.wantErr && !result.Valid {
				t.Errorf("expected validation to pass but it failed: %v", result.Errors)
			}
			if tt.wantErr && len(result.Errors) > 0 && result.Errors[0].Rule != tt.errRule {
				t.Errorf("expected error rule %s, got %s", tt.errRule, result.Errors[0].Rule)
			}
		})
	}
}

func TestEnhancedValidator_ValidateWithContext(t *testing.T) {
	ctx := &SecurityContext{
		UserID:   "user123",
		TenantID: "tenant456",
	}
	validator := NewEnhancedValidator(ctx)

	tests := []struct {
		name    string
		field   string
		value   string
		rules   []string
		wantErr bool
		errRule string
	}{
		{
			name:    "tenant scoped valid",
			field:   "resource",
			value:   "/tenant/tenant456/resource",
			rules:   []string{"tenant_scoped"},
			wantErr: false,
		},
		{
			name:    "tenant scoped invalid",
			field:   "resource",
			value:   "/tenant/other-tenant/resource",
			rules:   []string{"tenant_scoped"},
			wantErr: true,
			errRule: "tenant_scope",
		},
		{
			name:    "rate limit abuse detection",
			field:   "data",
			value:   string(make([]byte, 101)), // More than 100 chars of repeated pattern
			rules:   []string{"rate_limit"},
			wantErr: false, // Our simple pattern detection won't trigger on random bytes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ValidationResult{Valid: true}
			validator.ValidateWithContext(result, tt.field, tt.value, tt.rules...)

			if tt.wantErr && result.Valid {
				t.Errorf("expected validation to fail but it passed")
			}
			if !tt.wantErr && !result.Valid {
				t.Errorf("expected validation to pass but it failed: %v", result.Errors)
			}
			if tt.wantErr && len(result.Errors) > 0 && result.Errors[0].Rule != tt.errRule {
				t.Errorf("expected error rule %s, got %s", tt.errRule, result.Errors[0].Rule)
			}
		})
	}
}

func BenchmarkValidator_ValidateString(b *testing.B) {
	validator := NewValidator()
	result := &ValidationResult{Valid: true}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.Valid = true
		result.Errors = nil
		validator.ValidateString(result, "test", "hello123world", "charset:alphanumeric", "max_length:100")
	}
}

// Story #253: Additional tests for 90%+ coverage

func TestValidationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ValidationError
		contains []string
	}{
		{
			name: "error with value",
			err: &ValidationError{
				Field:   "email",
				Value:   "invalid",
				Rule:    "format",
				Message: "invalid email format",
			},
			contains: []string{"email", "invalid", "format", "invalid email format"},
		},
		{
			name: "error without value",
			err: &ValidationError{
				Field:   "password",
				Value:   "",
				Rule:    "required",
				Message: "field is required",
			},
			contains: []string{"password", "required", "field is required"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, substr := range tt.contains {
				if !contains(errStr, substr) {
					t.Errorf("expected error to contain '%s', got '%s'", substr, errStr)
				}
			}
		})
	}
}

func TestValidationResult_AddError(t *testing.T) {
	result := &ValidationResult{Valid: true}

	result.AddError("field1", "value1", "rule1", "message1")

	if result.Valid {
		t.Error("expected result.Valid to be false after adding error")
	}
	if len(result.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(result.Errors))
	}
	if result.Errors[0].Field != "field1" {
		t.Errorf("expected field 'field1', got '%s'", result.Errors[0].Field)
	}
}

func TestValidationResult_AddErrorf(t *testing.T) {
	result := &ValidationResult{Valid: true}

	result.AddErrorf("field1", "value1", "rule1", "formatted %s %d", "message", 42)

	if result.Valid {
		t.Error("expected result.Valid to be false after adding error")
	}
	if len(result.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(result.Errors))
	}
	if result.Errors[0].Message != "formatted message 42" {
		t.Errorf("expected formatted message, got '%s'", result.Errors[0].Message)
	}
}

func TestValidator_ValidateSlice(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		field   string
		length  int
		rules   []string
		wantErr bool
		errRule string
	}{
		{
			name:    "valid slice",
			field:   "items",
			length:  5,
			rules:   []string{},
			wantErr: false,
		},
		{
			name:    "empty slice required",
			field:   "items",
			length:  0,
			rules:   []string{"required"},
			wantErr: true,
			errRule: "required",
		},
		{
			name:    "slice exceeds max length",
			field:   "items",
			length:  1500,
			rules:   []string{},
			wantErr: true,
			errRule: "max_length",
		},
		{
			name:    "slice below min items",
			field:   "items",
			length:  2,
			rules:   []string{"min_items:5"},
			wantErr: true,
			errRule: "min_items",
		},
		{
			name:    "slice above max items",
			field:   "items",
			length:  20,
			rules:   []string{"max_items:10"},
			wantErr: true,
			errRule: "max_items",
		},
		{
			name:    "slice within range",
			field:   "items",
			length:  7,
			rules:   []string{"min_items:5", "max_items:10"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ValidationResult{Valid: true}
			validator.ValidateSlice(result, tt.field, tt.length, tt.rules...)

			if tt.wantErr && result.Valid {
				t.Errorf("expected validation to fail but it passed")
			}
			if !tt.wantErr && !result.Valid {
				t.Errorf("expected validation to pass but it failed: %v", result.Errors)
			}
			if tt.wantErr && len(result.Errors) > 0 && result.Errors[0].Rule != tt.errRule {
				t.Errorf("expected error rule %s, got %s", tt.errRule, result.Errors[0].Rule)
			}
		})
	}
}

func TestValidator_ValidateString_EdgeCases(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		field   string
		value   string
		rules   []string
		wantErr bool
		errRule string
	}{
		// Empty value (not required) should pass
		{
			name:    "empty non-required",
			field:   "optional",
			value:   "",
			rules:   []string{},
			wantErr: false,
		},
		// Invalid UTF-8
		{
			name:    "invalid UTF-8",
			field:   "text",
			value:   string([]byte{0xff, 0xfe, 0xfd}),
			rules:   []string{},
			wantErr: true,
			errRule: "utf8",
		},
		// Minimum length validation
		{
			name:    "below min length",
			field:   "password",
			value:   "abc",
			rules:   []string{"min_length:8"},
			wantErr: true,
			errRule: "min_length",
		},
		// Valid alphanumeric with dash
		{
			name:    "valid alphanumeric_dash",
			field:   "slug",
			value:   "my-slug_123",
			rules:   []string{"charset:alphanumeric_dash"},
			wantErr: false,
		},
		// Safe text charset
		{
			name:    "valid safe_text",
			field:   "description",
			value:   "Hello, World! This is a test.",
			rules:   []string{"charset:safe_text"},
			wantErr: false,
		},
		// Base64 charset
		{
			name:    "valid base64",
			field:   "encoded",
			value:   "SGVsbG8gV29ybGQ=",
			rules:   []string{"charset:base64"},
			wantErr: false,
		},
		// Path traversal detection
		{
			name:    "path traversal ../",
			field:   "path",
			value:   "../../../etc/passwd",
			rules:   []string{},
			wantErr: true,
			errRule: "security",
		},
		// Command injection
		{
			name:    "command injection &&",
			field:   "input",
			value:   "test && cat /etc/passwd",
			rules:   []string{},
			wantErr: true,
			errRule: "security",
		},
		// LDAP injection
		{
			name:    "LDAP injection",
			field:   "ldap",
			value:   "admin*)(|(objectclass=*)",
			rules:   []string{},
			wantErr: true,
			errRule: "security",
		},
		// Unicode handling
		{
			name:    "valid unicode",
			field:   "text",
			value:   "こんにちは世界",
			rules:   []string{},
			wantErr: false,
		},
		// Allowed control characters (tab, newline)
		{
			name:    "allowed control chars (tab, newline)",
			field:   "text",
			value:   "line1\tcolumn2\nline2",
			rules:   []string{"no_control_chars"},
			wantErr: false,
		},
		// XSS via expression
		{
			name:    "XSS expression",
			field:   "input",
			value:   "expression(alert('xss'))",
			rules:   []string{},
			wantErr: true,
			errRule: "security",
		},
		// Unknown charset (should pass, no validation)
		{
			name:    "unknown charset",
			field:   "data",
			value:   "anything goes",
			rules:   []string{"charset:nonexistent"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ValidationResult{Valid: true}
			validator.ValidateString(result, tt.field, tt.value, tt.rules...)

			if tt.wantErr && result.Valid {
				t.Errorf("expected validation to fail but it passed")
			}
			if !tt.wantErr && !result.Valid {
				t.Errorf("expected validation to pass but it failed: %v", result.Errors)
			}
			if tt.wantErr && len(result.Errors) > 0 && result.Errors[0].Rule != tt.errRule {
				t.Errorf("expected error rule %s, got %s", tt.errRule, result.Errors[0].Rule)
			}
		})
	}
}

func TestValidator_ValidateInteger_EdgeCases(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		field   string
		value   int64
		rules   []string
		wantErr bool
		errRule string
	}{
		{
			name:    "required zero",
			field:   "count",
			value:   0,
			rules:   []string{"required"},
			wantErr: true,
			errRule: "required",
		},
		{
			name:    "zero positive check",
			field:   "count",
			value:   0,
			rules:   []string{"positive"},
			wantErr: true,
			errRule: "positive",
		},
		{
			name:    "valid no rules",
			field:   "count",
			value:   42,
			rules:   []string{},
			wantErr: false,
		},
		{
			name:    "invalid min rule format (ignored)",
			field:   "count",
			value:   5,
			rules:   []string{"min:invalid"},
			wantErr: false, // Invalid rule format is ignored
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ValidationResult{Valid: true}
			validator.ValidateInteger(result, tt.field, tt.value, tt.rules...)

			if tt.wantErr && result.Valid {
				t.Errorf("expected validation to fail but it passed")
			}
			if !tt.wantErr && !result.Valid {
				t.Errorf("expected validation to pass but it failed: %v", result.Errors)
			}
			if tt.wantErr && len(result.Errors) > 0 && result.Errors[0].Rule != tt.errRule {
				t.Errorf("expected error rule %s, got %s", tt.errRule, result.Errors[0].Rule)
			}
		})
	}
}

func TestValidator_ValidateIPAddress_EdgeCases(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		field   string
		value   string
		rules   []string
		wantErr bool
		errRule string
	}{
		{
			name:    "empty not required",
			field:   "ip",
			value:   "",
			rules:   []string{},
			wantErr: false,
		},
		{
			name:    "empty required",
			field:   "ip",
			value:   "",
			rules:   []string{"required"},
			wantErr: true,
			errRule: "required",
		},
		{
			name:    "public IP passes no_private",
			field:   "ip",
			value:   "8.8.8.8",
			rules:   []string{"no_private"},
			wantErr: false,
		},
		{
			name:    "non-loopback passes no_loopback",
			field:   "ip",
			value:   "192.168.1.1",
			rules:   []string{"no_loopback"},
			wantErr: false,
		},
		{
			name:    "IPv4 passes ipv4_only",
			field:   "ip",
			value:   "10.0.0.1",
			rules:   []string{"ipv4_only"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ValidationResult{Valid: true}
			validator.ValidateIPAddress(result, tt.field, tt.value, tt.rules...)

			if tt.wantErr && result.Valid {
				t.Errorf("expected validation to fail but it passed")
			}
			if !tt.wantErr && !result.Valid {
				t.Errorf("expected validation to pass but it failed: %v", result.Errors)
			}
			if tt.wantErr && len(result.Errors) > 0 && result.Errors[0].Rule != tt.errRule {
				t.Errorf("expected error rule %s, got %s", tt.errRule, result.Errors[0].Rule)
			}
		})
	}
}

func TestValidator_ValidateURL_EdgeCases(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		field   string
		value   string
		rules   []string
		wantErr bool
		errRule string
	}{
		{
			name:    "empty not required",
			field:   "url",
			value:   "",
			rules:   []string{},
			wantErr: false,
		},
		{
			name:    "empty required",
			field:   "url",
			value:   "",
			rules:   []string{"required"},
			wantErr: true,
			errRule: "required",
		},
		{
			name:    "HTTPS URL with https_only passes",
			field:   "url",
			value:   "https://example.com",
			rules:   []string{"https_only"},
			wantErr: false,
		},
		{
			name:    "127.0.0.1 with no_localhost",
			field:   "url",
			value:   "https://127.0.0.1:8080",
			rules:   []string{"no_localhost"},
			wantErr: true,
			errRule: "no_localhost",
		},
		{
			name:    "URL with port",
			field:   "url",
			value:   "https://example.com:8443/path",
			rules:   []string{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ValidationResult{Valid: true}
			validator.ValidateURL(result, tt.field, tt.value, tt.rules...)

			if tt.wantErr && result.Valid {
				t.Errorf("expected validation to fail but it passed")
			}
			if !tt.wantErr && !result.Valid {
				t.Errorf("expected validation to pass but it failed: %v", result.Errors)
			}
			if tt.wantErr && len(result.Errors) > 0 && result.Errors[0].Rule != tt.errRule {
				t.Errorf("expected error rule %s, got %s", tt.errRule, result.Errors[0].Rule)
			}
		})
	}
}

func TestValidator_ValidateJSON_EdgeCases(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		field   string
		value   string
		rules   []string
		wantErr bool
		errRule string
	}{
		{
			name:    "empty not required",
			field:   "json",
			value:   "",
			rules:   []string{},
			wantErr: false,
		},
		{
			name:    "empty required",
			field:   "json",
			value:   "",
			rules:   []string{"required"},
			wantErr: true,
			errRule: "required",
		},
		{
			name:    "valid array",
			field:   "json",
			value:   `[1, 2, 3]`,
			rules:   []string{},
			wantErr: false,
		},
		{
			name:    "deeply nested arrays",
			field:   "json",
			value:   `[[[[[[[[[[["too deep"]]]]]]]]]]]`,
			rules:   []string{},
			wantErr: true,
			errRule: "max_depth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ValidationResult{Valid: true}
			validator.ValidateJSON(result, tt.field, tt.value, tt.rules...)

			if tt.wantErr && result.Valid {
				t.Errorf("expected validation to fail but it passed")
			}
			if !tt.wantErr && !result.Valid {
				t.Errorf("expected validation to pass but it failed: %v", result.Errors)
			}
			if tt.wantErr && len(result.Errors) > 0 && result.Errors[0].Rule != tt.errRule {
				t.Errorf("expected error rule %s, got %s", tt.errRule, result.Errors[0].Rule)
			}
		})
	}
}

func TestEnhancedValidator_NilContext(t *testing.T) {
	// Test with nil context
	validator := NewEnhancedValidator(nil)
	result := &ValidationResult{Valid: true}

	// Should not panic and should pass basic validation
	validator.ValidateWithContext(result, "field", "value", "tenant_scoped")

	// With nil context, tenant_scoped rule should be skipped
	if !result.Valid {
		t.Errorf("expected validation to pass with nil context, got errors: %v", result.Errors)
	}
}

func TestEnhancedValidator_RateLimitAbuse(t *testing.T) {
	ctx := &SecurityContext{
		UserID:   "user123",
		TenantID: "tenant456",
	}
	validator := NewEnhancedValidator(ctx)

	// Create an abusive pattern (101+ chars of repeated 'a')
	abusePattern := ""
	for i := 0; i < 101; i++ {
		abusePattern += "a"
	}

	result := &ValidationResult{Valid: true}
	validator.ValidateWithContext(result, "data", abusePattern, "rate_limit")

	// The rate limit check should detect the abuse pattern
	if result.Valid {
		t.Error("expected rate limit abuse to be detected")
	}
}

func TestValidator_getRuleString(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name     string
		rules    []string
		prefix   string
		expected string
	}{
		{
			name:     "found rule",
			rules:    []string{"charset:alphanumeric", "required"},
			prefix:   "charset",
			expected: "alphanumeric",
		},
		{
			name:     "not found",
			rules:    []string{"required", "min_length:5"},
			prefix:   "charset",
			expected: "",
		},
		{
			name:     "empty rules",
			rules:    []string{},
			prefix:   "charset",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.getRuleString(tt.rules, tt.prefix)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestValidator_getRuleInt(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name     string
		rules    []string
		prefix   string
		expected int
	}{
		{
			name:     "found valid int",
			rules:    []string{"min_length:10"},
			prefix:   "min_length",
			expected: 10,
		},
		{
			name:     "not found",
			rules:    []string{"required"},
			prefix:   "min_length",
			expected: 0,
		},
		{
			name:     "invalid int format",
			rules:    []string{"min_length:invalid"},
			prefix:   "min_length",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.getRuleInt(tt.rules, tt.prefix)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestValidator_getRuleInt64(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name     string
		rules    []string
		prefix   string
		expected int64
	}{
		{
			name:     "found valid int64",
			rules:    []string{"max:9223372036854775807"},
			prefix:   "max",
			expected: 9223372036854775807,
		},
		{
			name:     "not found",
			rules:    []string{"required"},
			prefix:   "max",
			expected: 0,
		},
		{
			name:     "invalid int64 format",
			rules:    []string{"max:invalid"},
			prefix:   "max",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.getRuleInt64(tt.rules, tt.prefix)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestValidator_hasRule(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name     string
		rules    []string
		rule     string
		expected bool
	}{
		{
			name:     "found",
			rules:    []string{"required", "email"},
			rule:     "required",
			expected: true,
		},
		{
			name:     "not found",
			rules:    []string{"required", "email"},
			rule:     "uuid",
			expected: false,
		},
		{
			name:     "empty rules",
			rules:    []string{},
			rule:     "required",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.hasRule(tt.rules, tt.rule)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// Helper function for string contains check
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
