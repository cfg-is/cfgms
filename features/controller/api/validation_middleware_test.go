// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/security"
)

// hasContentTypeError reports whether the validation result contains a
// content-type rejection error.
func hasContentTypeError(result *security.ValidationResult) bool {
	for _, e := range result.Errors {
		if e.Field == "header.Content-Type" && e.Rule == "content_type" {
			return true
		}
	}
	return false
}

// TestValidateRequestHeaders_ContentType verifies that the validation
// middleware accepts JSON, form, and YAML content types (the steward config
// upload endpoint ingests application/yaml) and still rejects unsupported ones.
func TestValidateRequestHeaders_ContentType(t *testing.T) {
	s := &Server{}

	cases := []struct {
		name        string
		contentType string
		wantErr     bool
	}{
		{"json", "application/json", false},
		{"json with charset", "application/json; charset=utf-8", false},
		{"form urlencoded", "application/x-www-form-urlencoded", false},
		{"multipart", "multipart/form-data; boundary=abc", false},
		{"yaml", "application/yaml", false},
		{"x-yaml", "application/x-yaml", false},
		{"text yaml", "text/yaml", false},
		{"octet-stream binary upload", "application/octet-stream", false},
		{"empty", "", false},
		{"unsupported xml", "application/xml", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/api/v1/stewards/steward-1/config", nil)
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}

			validator := security.NewEnhancedValidator(nil)
			result := &security.ValidationResult{Valid: true}

			s.validateRequestHeaders(validator, result, req)

			assert.Equal(t, tc.wantErr, hasContentTypeError(result),
				"content type %q: unexpected content-type validation outcome", tc.contentType)
		})
	}
}

// TestValidateRequestBody_OctetStreamBypassesSizeLimit verifies that binary
// uploads larger than the 10MB JSON-body cap pass validation. The installer
// artifact upload endpoint accepts ~30MB steward binaries, and the validation
// middleware must not buffer them in memory.
func TestValidateRequestBody_OctetStreamBypassesSizeLimit(t *testing.T) {
	s := &Server{}

	// Build a body larger than the 10MB JSON cap.
	bigBody := bytes.Repeat([]byte{0xAB}, 12*1024*1024)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/installer/artifacts/linux/amd64",
		bytes.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/octet-stream")

	validator := security.NewEnhancedValidator(nil)
	result := &security.ValidationResult{Valid: true}

	err := s.validateRequestBody(validator, result, req)
	require.NoError(t, err)
	assert.True(t, result.Valid, "octet-stream upload must pass body validation, got errors: %+v", result.Errors)

	// The body must still be readable downstream (validation must not consume it).
	downstream, readErr := io.ReadAll(req.Body)
	require.NoError(t, readErr)
	assert.Len(t, downstream, len(bigBody), "request body must remain intact for handler streaming")
}

// TestValidateRequestBody_JSONStillSizeCapped verifies that JSON bodies remain
// subject to the 10MB cap — the octet-stream bypass is scoped to binary uploads.
func TestValidateRequestBody_JSONStillSizeCapped(t *testing.T) {
	s := &Server{}

	bigBody := bytes.Repeat([]byte{'x'}, 12*1024*1024)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards",
		bytes.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")

	validator := security.NewEnhancedValidator(nil)
	result := &security.ValidationResult{Valid: true}

	err := s.validateRequestBody(validator, result, req)
	require.NoError(t, err)
	assert.False(t, result.Valid, "JSON body >10MB must trigger validation error")

	foundSize := false
	for _, e := range result.Errors {
		if e.Rule == "max_size" {
			foundSize = true
			break
		}
	}
	assert.True(t, foundSize, "expected max_size rule violation; got %+v", result.Errors)
}

func TestRequestBodyLimitMiddleware_RejectsOversizedContentLengthBeforeHandler(t *testing.T) {
	s := &Server{}
	called := false
	handler := s.requestBodyLimitMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/register", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = maxStructuredRequestBodyBytes + 1
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	assert.False(t, called, "oversized body must be rejected before reaching a public handler")
}

func TestRequestBodyLimitMiddleware_RejectsOversizedChunkedBody(t *testing.T) {
	s := &Server{}
	called := false
	handler := s.requestBodyLimitMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))

	body := io.MultiReader(
		io.LimitReader(&zeroReader{}, maxStructuredRequestBodyBytes),
		strings.NewReader("x"),
	)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/register", body)
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = -1
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	assert.False(t, called, "chunked transfer encoding must not bypass the body limit")
}

func TestRequestBodyLimitMiddleware_BoundsBinaryStreams(t *testing.T) {
	s := &Server{}
	handler := s.requestBodyLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		var tooLarge *http.MaxBytesError
		if !assert.ErrorAs(t, err, &tooLarge) {
			return
		}
		assert.Equal(t, maxBinaryRequestBodyBytes, tooLarge.Limit)
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))

	body := io.MultiReader(
		io.LimitReader(&zeroReader{}, maxBinaryRequestBodyBytes),
		strings.NewReader("x"),
	)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/installer/artifacts/linux/amd64", body)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = -1
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

type zeroReader struct{}

func (*zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// TestValidateURLParameters_TenantPathWithSlash verifies that a route variable named
// "tenant_path" with a hierarchical value (e.g., "fleet-root/fleet-child-a") passes
// validation. Regression test for the tenant_path_id charset introduced in Issue #2098
// (validationMiddleware case "id" using charset:alphanumeric_dash incorrectly rejected
// tenant IDs that contain '/' path separators).
func TestValidateURLParameters_TenantPathWithSlash(t *testing.T) {
	s := &Server{}
	validator := security.NewEnhancedValidator(nil)

	tests := []struct {
		name      string
		varName   string
		value     string
		wantValid bool
	}{
		{
			name:      "hierarchical tenant path passes",
			varName:   "tenant_path",
			value:     "fleet-root/fleet-child-a",
			wantValid: true,
		},
		{
			name:      "deep hierarchical tenant path passes",
			varName:   "tenant_path",
			value:     "root/msp-a/client-1/servers",
			wantValid: true,
		},
		{
			name:      "tenant path with dot-dot segment rejected",
			varName:   "tenant_path",
			value:     "../etc/passwd",
			wantValid: false,
		},
		{
			name:      "tenant path exceeding global max rejected",
			varName:   "tenant_path",
			value:     strings.Repeat("a/", 2049),
			wantValid: false,
		},
		{
			name:      "plain id still rejects slash",
			varName:   "id",
			value:     "fleet-root/fleet-child-a",
			wantValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Use a safe placeholder in the URL; the actual variable value is injected
			// via mux.SetURLVars so the URL parser never sees unsafe characters.
			req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/placeholder/refresh-policy", nil)
			req = mux.SetURLVars(req, map[string]string{tc.varName: tc.value})
			result := &security.ValidationResult{Valid: true}
			s.validateURLParameters(validator, result, req)
			assert.Equal(t, tc.wantValid, result.Valid,
				"tenant_path=%q: expected valid=%v, errors=%v", tc.value, tc.wantValid, result.Errors)
		})
	}
}

// TestValidateQueryParameters_TenantIDWithSlash verifies that a query parameter named
// "tenant_id" with a hierarchical value (e.g., "fleet-root/fleet-child-b") passes
// validation via charset:tenant_path_id. Regression test for BUG 1 in Issue #2098
// where the default safe_text charset incorrectly rejected tenant IDs containing '/'.
func TestValidateQueryParameters_TenantIDWithSlash(t *testing.T) {
	s := &Server{}
	validator := security.NewEnhancedValidator(nil)

	tests := []struct {
		name      string
		queryKey  string
		queryVal  string
		wantValid bool
	}{
		{
			name:      "hierarchical tenant_id with slash passes",
			queryKey:  "tenant_id",
			queryVal:  "fleet-root/fleet-child-b",
			wantValid: true,
		},
		{
			name:      "deep hierarchical tenant_id passes",
			queryKey:  "tenant_id",
			queryVal:  "root/msp-a/client-1/servers",
			wantValid: true,
		},
		{
			name:      "tenant_id with dot-dot traversal rejected",
			queryKey:  "tenant_id",
			queryVal:  "../etc/passwd",
			wantValid: false,
		},
		{
			name:      "plain query param still uses safe_text (no slash allowed)",
			queryKey:  "action",
			queryVal:  "fleet-root/fleet-child-b",
			wantValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/refresh/pending?"+tc.queryKey+"="+tc.queryVal, nil)
			result := &security.ValidationResult{Valid: true}
			s.validateQueryParameters(validator, result, req)
			assert.Equal(t, tc.wantValid, result.Valid,
				"%s=%q: expected valid=%v, errors=%v", tc.queryKey, tc.queryVal, tc.wantValid, result.Errors)
		})
	}
}
