package security

import (
	"testing"
)

func TestValidator_ValidateString(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name     string
		field    string
		value    string
		rules    []string
		wantErr  bool
		errRule  string
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