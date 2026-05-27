// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

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
		{"empty", "", false},
		{"unsupported xml", "application/xml", true},
		{"unsupported octet-stream", "application/octet-stream", true},
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
