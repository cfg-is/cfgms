// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

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
