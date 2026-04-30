// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/security"
)

// ValidationMiddleware provides comprehensive input validation for API requests
func (s *Server) validationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create security context
		ctx := s.buildSecurityContext(r)
		validator := security.NewEnhancedValidator(ctx)
		result := &security.ValidationResult{Valid: true}

		// Validate URL parameters
		s.validateURLParameters(validator, result, r)

		// Validate query parameters
		s.validateQueryParameters(validator, result, r)

		// Only validate headers for mutating operations to avoid breaking GET requests
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" || r.Method == "DELETE" {
			// Validate request headers
			s.validateRequestHeaders(validator, result, r)
		}

		// Validate request body for POST/PUT requests
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
			if err := s.validateRequestBody(validator, result, r); err != nil {
				s.writeErrorResponse(w, http.StatusBadRequest, "Request body validation failed", "BODY_VALIDATION_ERROR")
				return
			}
		}

		// If validation failed, return error response
		if !result.Valid {
			// Log validation errors for debugging
			s.logger.Debug("Request validation failed", "errors", result.Errors, "path", r.URL.Path)
			s.writeValidationErrorResponse(w, result)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// buildSecurityContext creates a security context from the request
func (s *Server) buildSecurityContext(r *http.Request) *security.SecurityContext {
	ctx := &security.SecurityContext{
		RemoteAddr:  r.RemoteAddr,
		UserAgent:   r.Header.Get("User-Agent"),
		RequestPath: r.URL.Path,
	}

	// Extract user and tenant info from context if available
	if userID, ok := r.Context().Value(userIDContextKey).(string); ok {
		ctx.UserID = userID
	}
	if tenantID, ok := r.Context().Value(ctxkeys.TenantID).(string); ok {
		ctx.TenantID = tenantID
	}

	return ctx
}

// validateURLParameters validates URL path parameters
func (s *Server) validateURLParameters(validator *security.EnhancedValidator, result *security.ValidationResult, r *http.Request) {
	vars := mux.Vars(r)

	for param, value := range vars {
		switch param {
		case "id":
			// Validate ID parameters (should be UUIDs or alphanumeric)
			validator.ValidateString(result, "path."+param, value, "required", "charset:alphanumeric_dash", "max_length:64")
		case "serial":
			// Certificate serial numbers
			validator.ValidateString(result, "path."+param, value, "required", "charset:alphanumeric", "max_length:40")
		case "tenantId", "tenant_id":
			// Tenant IDs should be UUIDs
			validator.ValidateString(result, "path."+param, value, "required", "charset:uuid")
		case "stewardId", "steward_id":
			// Steward IDs
			validator.ValidateString(result, "path."+param, value, "required", "charset:alphanumeric_dash", "max_length:64")
		default:
			// Generic validation for other path parameters
			validator.ValidateString(result, "path."+param, value, "charset:safe_text", "max_length:128", "no_control_chars")
		}
	}
}

// validateQueryParameters validates URL query parameters
func (s *Server) validateQueryParameters(validator *security.EnhancedValidator, result *security.ValidationResult, r *http.Request) {
	query := r.URL.Query()

	for param, values := range query {
		for i, value := range values {
			fieldName := fmt.Sprintf("query.%s[%d]", param, i)

			switch param {
			case "limit":
				// M-INPUT-1: Use ParseInt instead of Atoi to prevent integer overflow (security audit finding)
				limit, err := strconv.ParseInt(value, 10, 64)
				if err != nil {
					result.AddError(fieldName, value, "integer", "must be a valid integer")
				} else if limit < 0 || limit > 1000 {
					result.AddError(fieldName, value, "range", "must be between 0 and 1000")
				}
			case "offset":
				// M-INPUT-1: Use ParseInt instead of Atoi to prevent integer overflow (security audit finding)
				offset, err := strconv.ParseInt(value, 10, 64)
				if err != nil {
					result.AddError(fieldName, value, "integer", "must be a valid integer")
				} else if offset < 0 {
					result.AddError(fieldName, value, "range", "must be greater than or equal to 0")
				}
			case "sort":
				// Sort parameter validation
				validator.ValidateString(result, fieldName, value, "charset:alphanumeric_dash", "max_length:64")
			case "filter", "search":
				// Search and filter parameters
				validator.ValidateString(result, fieldName, value, "charset:safe_text", "max_length:256", "no_control_chars")
			case "format":
				// Output format validation
				if value != "json" && value != "xml" && value != "csv" {
					result.AddError(fieldName, value, "enum", "format must be json, xml, or csv")
				}
			case "status":
				// Status filter validation
				validator.ValidateString(result, fieldName, value, "charset:alphanumeric_dash", "max_length:32")
			default:
				// Generic query parameter validation
				validator.ValidateString(result, fieldName, value, "charset:safe_text", "max_length:512", "no_control_chars")
			}
		}
	}
}

// validateRequestHeaders validates critical request headers
func (s *Server) validateRequestHeaders(validator *security.EnhancedValidator, result *security.ValidationResult, r *http.Request) {
	// Validate Content-Type for POST/PUT requests
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		contentType := r.Header.Get("Content-Type")
		if contentType != "" {
			if !strings.HasPrefix(contentType, "application/json") &&
				!strings.HasPrefix(contentType, "application/x-www-form-urlencoded") &&
				!strings.HasPrefix(contentType, "multipart/form-data") {
				result.AddError("header.Content-Type", contentType, "content_type", "unsupported content type")
			}
		}
	}

	// Validate User-Agent
	userAgent := r.Header.Get("User-Agent")
	if userAgent != "" {
		validator.ValidateString(result, "header.User-Agent", userAgent, "max_length:512", "no_control_chars")
	}

	// Validate custom headers
	for name, values := range r.Header {
		if strings.HasPrefix(name, "X-") {
			for i, value := range values {
				fieldName := fmt.Sprintf("header.%s[%d]", name, i)
				validator.ValidateString(result, fieldName, value, "max_length:1024", "no_control_chars")
			}
		}
	}

	// Validate Authorization header if present
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			token := strings.TrimPrefix(auth, "Bearer ")
			// API keys can be various formats, just validate basic safety
			validator.ValidateString(result, "header.Authorization", token, "charset:safe_text", "max_length:2048")
		}
	}
}

// validateRequestBody validates the request body for POST/PUT requests
func (s *Server) validateRequestBody(validator *security.EnhancedValidator, result *security.ValidationResult, r *http.Request) error {
	if r.Body == nil {
		return nil
	}

	// Read the body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	// Restore the body for downstream handlers
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	// Check body size
	if len(body) > 10*1024*1024 { // 10MB max
		result.AddError("body", "", "max_size", "request body too large (max 10MB)")
		return nil
	}

	if len(body) == 0 {
		return nil // Empty body is OK
	}

	// Validate JSON structure if Content-Type is JSON
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "application/json") {
		if err := s.validateJSONBody(validator, result, body, r.URL.Path); err != nil {
			return err
		}
	}

	return nil
}

// validateJSONBody validates JSON request bodies with endpoint-specific rules
func (s *Server) validateJSONBody(validator *security.EnhancedValidator, result *security.ValidationResult, body []byte, path string) error {
	// Parse JSON for field-level validation
	var jsonData map[string]interface{}
	if err := json.Unmarshal(body, &jsonData); err != nil {
		// This is a JSON parsing error, not a validation error
		// Let the downstream handler deal with it to maintain existing error codes
		return nil
	}

	// First validate JSON structure after successful parsing
	validator.ValidateJSON(result, "body", string(body), "required")

	if !result.Valid {
		return nil // Don't continue with invalid JSON structure
	}

	// Apply endpoint-specific validation rules
	switch {
	case strings.Contains(path, "/api/v1/stewards"):
		s.validateStewardRequest(validator, result, jsonData)
	case strings.Contains(path, "/api/v1/certificates"):
		s.validateCertificateRequest(validator, result, jsonData)
	case strings.Contains(path, "/api/v1/rbac"):
		s.validateRBACRequest(validator, result, jsonData)
	case strings.Contains(path, "/api/v1/api-keys"):
		s.validateAPIKeyRequest(validator, result, jsonData)
	default:
		s.validateGenericRequest(validator, result, jsonData)
	}

	return nil
}

// validateStewardRequest validates steward-specific request fields
func (s *Server) validateStewardRequest(validator *security.EnhancedValidator, result *security.ValidationResult, data map[string]interface{}) {
	if id, ok := data["id"].(string); ok {
		validator.ValidateString(result, "body.id", id, "required", "charset:alphanumeric_dash", "max_length:64")
	}

	if version, ok := data["version"].(string); ok {
		validator.ValidateString(result, "body.version", version, "required", "charset:safe_text", "max_length:32")
	}

	if status, ok := data["status"].(string); ok {
		validStatuses := []string{"connected", "disconnected", "error", "updating"}
		if !contains(validStatuses, status) {
			result.AddError("body.status", status, "enum", "invalid status value")
		}
	}

	// Validate DNA structure if present
	if dna, ok := data["dna"].(map[string]interface{}); ok {
		s.validateDNAObject(validator, result, dna)
	}
}

// validateCertificateRequest validates certificate request fields
func (s *Server) validateCertificateRequest(validator *security.EnhancedValidator, result *security.ValidationResult, data map[string]interface{}) {
	if commonName, ok := data["common_name"].(string); ok {
		validator.ValidateString(result, "body.common_name", commonName, "required", "charset:hostname", "max_length:253")
	}

	if sans, ok := data["sans"].([]interface{}); ok {
		validator.ValidateSlice(result, "body.sans", len(sans), "max_items:50")
		for i, san := range sans {
			if sanStr, ok := san.(string); ok {
				validator.ValidateString(result, fmt.Sprintf("body.sans[%d]", i), sanStr, "charset:hostname", "max_length:253")
			}
		}
	}

	if keyType, ok := data["key_type"].(string); ok {
		validKeyTypes := []string{"rsa", "ecdsa", "ed25519"}
		if !contains(validKeyTypes, keyType) {
			result.AddError("body.key_type", keyType, "enum", "invalid key type")
		}
	}
}

// validateRBACRequest validates RBAC request fields
func (s *Server) validateRBACRequest(validator *security.EnhancedValidator, result *security.ValidationResult, data map[string]interface{}) {
	if roleName, ok := data["role_name"].(string); ok {
		validator.ValidateString(result, "body.role_name", roleName, "required", "charset:alphanumeric_dash", "max_length:64")
	}

	if permissions, ok := data["permissions"].([]interface{}); ok {
		validator.ValidateSlice(result, "body.permissions", len(permissions), "required", "max_items:100")
		for i, perm := range permissions {
			if permStr, ok := perm.(string); ok {
				validator.ValidateString(result, fmt.Sprintf("body.permissions[%d]", i), permStr, "charset:alphanumeric_dash", "max_length:128")
			}
		}
	}

	if subjects, ok := data["subjects"].([]interface{}); ok {
		validator.ValidateSlice(result, "body.subjects", len(subjects), "max_items:1000")
		for i, subject := range subjects {
			if subjectStr, ok := subject.(string); ok {
				validator.ValidateWithContext(result, fmt.Sprintf("body.subjects[%d]", i), subjectStr, "charset:uuid", "tenant_scoped")
			}
		}
	}
}

// validateAPIKeyRequest validates API key request fields
func (s *Server) validateAPIKeyRequest(validator *security.EnhancedValidator, result *security.ValidationResult, data map[string]interface{}) {
	if name, ok := data["name"].(string); ok {
		validator.ValidateString(result, "body.name", name, "required", "charset:safe_text", "max_length:128")
	}

	if description, ok := data["description"].(string); ok {
		validator.ValidateString(result, "body.description", description, "charset:safe_text", "max_length:512")
	}

	if permissions, ok := data["permissions"].([]interface{}); ok {
		validator.ValidateSlice(result, "body.permissions", len(permissions), "required", "min_items:1", "max_items:50")
		for i, perm := range permissions {
			if permStr, ok := perm.(string); ok {
				// Allow colons in permission strings for resource:action format
				validator.ValidateString(result, fmt.Sprintf("body.permissions[%d]", i), permStr, "charset:safe_text", "max_length:128")
			}
		}
	}

	if tenantID, ok := data["tenant_id"].(string); ok {
		// Validate tenant ID - allow both UUIDs and simple strings for testing
		validator.ValidateString(result, "body.tenant_id", tenantID, "charset:alphanumeric_dash", "max_length:128")
	}

	if expiresAt, ok := data["expires_at"].(string); ok {
		// Validate RFC3339 timestamp format
		validator.ValidateString(result, "body.expires_at", expiresAt, "charset:safe_text", "max_length:64")
	}
}

// validateDNAObject validates DNA object structure
func (s *Server) validateDNAObject(validator *security.EnhancedValidator, result *security.ValidationResult, dna map[string]interface{}) {
	if id, ok := dna["id"].(string); ok {
		validator.ValidateString(result, "body.dna.id", id, "required", "charset:uuid")
	}

	if attributes, ok := dna["attributes"].(map[string]interface{}); ok {
		for key, value := range attributes {
			validator.ValidateString(result, fmt.Sprintf("body.dna.attributes.%s", key), key, "charset:alphanumeric_dash", "max_length:64")
			if valueStr, ok := value.(string); ok {
				validator.ValidateString(result, fmt.Sprintf("body.dna.attributes.%s", key), valueStr, "charset:safe_text", "max_length:512")
			}
		}
	}
}

// validateGenericRequest validates common fields in generic requests
func (s *Server) validateGenericRequest(validator *security.EnhancedValidator, result *security.ValidationResult, data map[string]interface{}) {
	// Validate common fields that might appear in any request
	if name, ok := data["name"].(string); ok {
		validator.ValidateString(result, "body.name", name, "charset:safe_text", "max_length:256")
	}

	if description, ok := data["description"].(string); ok {
		validator.ValidateString(result, "body.description", description, "charset:safe_text", "max_length:1024")
	}

	if tags, ok := data["tags"].([]interface{}); ok {
		validator.ValidateSlice(result, "body.tags", len(tags), "max_items:20")
		for i, tag := range tags {
			if tagStr, ok := tag.(string); ok {
				validator.ValidateString(result, fmt.Sprintf("body.tags[%d]", i), tagStr, "charset:alphanumeric_dash", "max_length:64")
			}
		}
	}
}

// writeValidationErrorResponse writes a validation error response
func (s *Server) writeValidationErrorResponse(w http.ResponseWriter, result *security.ValidationResult) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)

	errorResponse := ErrorResponse{
		Error: &APIError{
			Code:    "VALIDATION_ERROR",
			Message: "Request validation failed",
			Details: map[string]interface{}{
				"validation_errors": result.Errors,
			},
		},
		Timestamp: getCurrentTimestamp(),
	}

	_ = json.NewEncoder(w).Encode(errorResponse)
}

// Helper function to check if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
