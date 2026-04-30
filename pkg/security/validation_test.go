// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package security

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
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
			name:    "valid email via charset",
			field:   "email",
			value:   "user@example.com",
			rules:   []string{"charset:email"},
			wantErr: false,
		},
		{
			name:    "invalid email via charset",
			field:   "email",
			value:   "not-an-email",
			rules:   []string{"charset:email"},
			wantErr: true,
			errRule: "charset",
		},
		{
			name:    "valid UUID via charset",
			field:   "id",
			value:   "550e8400-e29b-41d4-a716-446655440000",
			rules:   []string{"charset:uuid"},
			wantErr: false,
		},
		{
			name:    "invalid UUID via charset",
			field:   "id",
			value:   "not-a-uuid",
			rules:   []string{"charset:uuid"},
			wantErr: true,
			errRule: "charset",
		},
		{
			name:    "valid hostname via charset",
			field:   "host",
			value:   "example.com",
			rules:   []string{"charset:hostname"},
			wantErr: false,
		},
		{
			name:    "invalid hostname via charset",
			field:   "host",
			value:   "invalid..hostname",
			rules:   []string{"charset:hostname"},
			wantErr: true,
			errRule: "charset",
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
		{
			name:    "min:0 accepts zero",
			field:   "count",
			value:   0,
			rules:   []string{"min:0"},
			wantErr: false,
		},
		{
			name:    "min:0 rejects negative",
			field:   "count",
			value:   -1,
			rules:   []string{"min:0"},
			wantErr: true,
			errRule: "min",
		},
		{
			name:    "max:0 rejects positive",
			field:   "count",
			value:   1,
			rules:   []string{"max:0"},
			wantErr: true,
			errRule: "max",
		},
		{
			name:    "max:0 accepts zero",
			field:   "count",
			value:   0,
			rules:   []string{"max:0"},
			wantErr: false,
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

// TestValidator_ValidateIPAddress_ValueRedacted verifies that ValidationError.Value
// is always "" for IP address validation errors (F12 redaction).
func TestValidator_ValidateIPAddress_ValueRedacted(t *testing.T) {
	validator := NewValidator()

	cases := []struct {
		name  string
		value string
		rules []string
	}{
		{"invalid IP", "300.300.300.300", nil},
		{"private IP rejected", "192.168.1.1", []string{"no_private"}},
		{"loopback rejected", "127.0.0.1", []string{"no_loopback"}},
		{"IPv6 rejected by ipv4_only", "2001:db8::1", []string{"ipv4_only"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := &ValidationResult{Valid: true}
			validator.ValidateIPAddress(result, "ip", tc.value, tc.rules...)
			if result.Valid {
				t.Fatal("expected validation failure")
			}
			for _, e := range result.Errors {
				if e.Value != "" {
					t.Errorf("ValidationError.Value must be empty (redacted), got %q", e.Value)
				}
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
			value:   "http://1.1.1.1/",
			rules:   []string{},
			wantErr: false,
		},
		{
			name:    "valid HTTPS URL",
			field:   "url",
			value:   "https://8.8.8.8/path?query=value",
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
			value:   "http://1.1.1.1/",
			rules:   []string{"https_only"},
			wantErr: true,
			errRule: "https_only",
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

func TestValidator_ValidateURL_SSRF(t *testing.T) {
	validator := NewValidator()

	// All of these must be rejected regardless of which rule fires (ssrf or url).
	alwaysReject := []struct {
		name  string
		value string
	}{
		{"loopback IPv4", "http://127.0.0.1/"},
		{"loopback localhost", "http://localhost/"},
		{"loopback IPv6", "http://[::1]/"},
		{"unspecified IPv4", "http://0.0.0.0/"},
		{"unspecified IPv6", "http://[::]/"},
		{"link-local metadata endpoint", "http://169.254.169.254/"},
		{"private RFC1918 class C", "http://192.168.1.1/"},
		{"private RFC1918 class A", "http://10.0.0.1/"},
		{"private RFC1918 class B", "http://172.16.0.1/"},
		{"IPv4-mapped IPv6 loopback", "http://[::ffff:127.0.0.1]/"},
	}
	for _, tt := range alwaysReject {
		t.Run(tt.name, func(t *testing.T) {
			result := &ValidationResult{Valid: true}
			validator.ValidateURL(result, "url", tt.value)
			if result.Valid {
				t.Errorf("%s: expected SSRF rejection but URL was accepted", tt.value)
			}
		})
	}

	// Decimal and hex IP notation: must be rejected; the firing rule (url vs ssrf) is platform-dependent.
	for _, value := range []string{"http://2130706433/", "http://0x7f000001/"} {
		t.Run("numeric notation "+value, func(t *testing.T) {
			result := &ValidationResult{Valid: true}
			validator.ValidateURL(result, "url", value)
			if result.Valid {
				t.Errorf("%s: expected rejection but URL was accepted", value)
			}
		})
	}

	// allow_host bypasses IP-class rejection for the named host.
	t.Run("allow_host bypasses SSRF check", func(t *testing.T) {
		result := &ValidationResult{Valid: true}
		validator.ValidateURL(result, "url", "http://dev.local/", "allow_host:dev.local")
		if !result.Valid {
			t.Errorf("allow_host:dev.local should bypass SSRF check, got errors: %v", result.Errors)
		}
	})

	// allow_host matching is case-insensitive.
	t.Run("allow_host case-insensitive", func(t *testing.T) {
		result := &ValidationResult{Valid: true}
		validator.ValidateURL(result, "url", "http://Dev.Local/", "allow_host:dev.local")
		if !result.Valid {
			t.Errorf("allow_host case-insensitive match failed, got errors: %v", result.Errors)
		}
	})
}

func TestValidator_ValidateURL_DNSTimeout(t *testing.T) {
	t.Run("default dnsLookupTimeout is 5s", func(t *testing.T) {
		v := NewValidator()
		if v.dnsLookupTimeout != 5*time.Second {
			t.Errorf("expected dnsLookupTimeout 5s, got %s", v.dnsLookupTimeout)
		}
	})

	t.Run("DNS failure rejects URL with url rule", func(t *testing.T) {
		v := NewValidator()
		v.dnsLookupTimeout = 1 * time.Millisecond
		result := &ValidationResult{Valid: true}
		v.ValidateURL(result, "url", "http://cfgms-test-nonexistent.invalid/")
		if result.Valid {
			t.Error("expected DNS failure to reject URL")
		}
		if len(result.Errors) == 0 || result.Errors[0].Rule != "url" {
			t.Errorf("expected rule 'url', got errors: %v", result.Errors)
		}
	})

	// dnsLookupTimeout is enforced: a DNS lookup that hangs longer than the
	// configured timeout must be interrupted and the URL rejected.
	t.Run("dnsLookupTimeout interrupts hanging DNS lookup", func(t *testing.T) {
		v := NewValidator()
		v.dnsLookupTimeout = 50 * time.Millisecond
		// Inject a lookup that blocks until context deadline fires.
		v.dnsLookup = func(ctx context.Context, host string) ([]net.IPAddr, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(5 * time.Second):
				return nil, nil
			}
		}
		result := &ValidationResult{Valid: true}
		v.ValidateURL(result, "url", "http://cfgms-test-timeout.example/")
		if result.Valid {
			t.Error("expected DNS timeout to reject URL")
		}
		if len(result.Errors) == 0 || result.Errors[0].Rule != "url" {
			t.Errorf("expected rule 'url', got errors: %v", result.Errors)
		}
	})

	// A successful DNS lookup that returns zero IP addresses must be rejected.
	// This prevents a silent SSRF bypass when a resolver returns NOERROR with no records.
	t.Run("zero IPs returned by DNS rejects URL", func(t *testing.T) {
		v := NewValidator()
		v.dnsLookup = func(ctx context.Context, host string) ([]net.IPAddr, error) {
			return nil, nil // no addresses, no error
		}
		result := &ValidationResult{Valid: true}
		v.ValidateURL(result, "url", "http://cfgms-test-zero-ips.example/")
		if result.Valid {
			t.Error("expected zero-IPs response to reject URL")
		}
		if len(result.Errors) == 0 || result.Errors[0].Rule != "url" {
			t.Errorf("expected rule 'url', got errors: %v", result.Errors)
		}
	})

	// allow_host: is an unconditional bypass — it skips DNS lookup and IP-class
	// checks for the named host. The rules parameter must only contain
	// developer-controlled values; user-supplied input must never flow into rules.
	t.Run("allow_host with loopback IP literal is explicit bypass", func(t *testing.T) {
		v := NewValidator()
		result := &ValidationResult{Valid: true}
		v.ValidateURL(result, "url", "http://127.0.0.1/", "allow_host:127.0.0.1")
		if !result.Valid {
			t.Errorf("allow_host:127.0.0.1 is an explicit trust bypass and must be accepted: %v", result.Errors)
		}
	})
}

func TestValidator_getAllowedHosts(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name  string
		rules []string
		want  []string
	}{
		{"nil rules", nil, nil},
		{"no allow_host rules", []string{"required", "https_only"}, nil},
		{"single allow_host", []string{"allow_host:example.com"}, []string{"example.com"}},
		{"multiple allow_host", []string{"allow_host:a.com", "allow_host:b.com"}, []string{"a.com", "b.com"}},
		{"mixed rules", []string{"required", "allow_host:foo.internal", "https_only"}, []string{"foo.internal"}},
		{"empty value after prefix", []string{"allow_host:"}, []string{""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.getAllowedHosts(tt.rules)
			if len(got) != len(tt.want) {
				t.Fatalf("getAllowedHosts(%v) = %v, want %v", tt.rules, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("getAllowedHosts[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestContainsFold(t *testing.T) {
	tests := []struct {
		name  string
		slice []string
		s     string
		want  bool
	}{
		{"empty slice", nil, "foo", false},
		{"exact match", []string{"foo", "bar"}, "foo", true},
		{"case-insensitive match upper in slice", []string{"FOO", "bar"}, "foo", true},
		{"case-insensitive match upper in target", []string{"foo"}, "FOO", true},
		{"no match", []string{"foo", "bar"}, "baz", false},
		{"empty string in slice", []string{""}, "", true},
		{"empty string not in slice", []string{"foo"}, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsFold(tt.slice, tt.s)
			if got != tt.want {
				t.Errorf("containsFold(%v, %q) = %v, want %v", tt.slice, tt.s, got, tt.want)
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
			value:   `{"key": "` + strings.Repeat("a", 1001) + `"}`,
			rules:   []string{},
			wantErr: true,
			errRule: "json_string_length",
		},
		{
			name:    "brackets inside string do not count as depth",
			field:   "data",
			value:   `{"k":"[[[[[[[[[[["}`,
			rules:   []string{},
			wantErr: false,
		},
		{
			name:    "close brace inside string does not affect depth",
			field:   "data",
			value:   `{"k":"}"}`,
			rules:   []string{},
			wantErr: false,
		},
		{
			name:    "malformed JSON fails with json_syntax",
			field:   "data",
			value:   `{key: "value"}`,
			rules:   []string{},
			wantErr: true,
			errRule: "json_syntax",
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
				if !strings.Contains(errStr, substr) {
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
		// Unicode handling — no charset rule means no rejection
		{
			name:    "valid unicode no charset",
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
		// zero is a valid integer value; callers that need "non-zero" use min:1 or positive
		{
			name:    "zero is valid with no rules",
			field:   "count",
			value:   0,
			rules:   []string{},
			wantErr: false,
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
			value:   "https://8.8.8.8",
			rules:   []string{"https_only"},
			wantErr: false,
		},
		{
			name:    "URL with port",
			field:   "url",
			value:   "https://8.8.8.8:8443/path",
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

// TestValidator_hasRuleWithValue verifies the hasRuleWithValue helper used by
// ValidateInteger to distinguish "rule not present" from "rule present with value 0".
func TestValidator_hasRuleWithValue(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name   string
		rules  []string
		prefix string
		want   bool
	}{
		{"present with value", []string{"min:0"}, "min", true},
		{"present with non-zero value", []string{"min:5"}, "min", true},
		{"not present", []string{"positive"}, "min", false},
		{"empty rules", nil, "min", false},
		{"different prefix present", []string{"max:10"}, "min", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.hasRuleWithValue(tt.rules, tt.prefix)
			if got != tt.want {
				t.Errorf("hasRuleWithValue(%v, %q) = %v, want %v", tt.rules, tt.prefix, got, tt.want)
			}
		})
	}
}
