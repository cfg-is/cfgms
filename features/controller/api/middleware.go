package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	// Context keys
	apiKeyContextKey contextKey = "api_key"
	userIDContextKey contextKey = "user_id"
)

// loggingMiddleware logs HTTP requests
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap the response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Process request
		next.ServeHTTP(wrapped, r)

		// Log the request
		duration := time.Since(start)
		s.logger.Info("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.statusCode,
			"duration", duration,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.Header.Get("User-Agent"),
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// corsMiddleware handles CORS headers
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		w.Header().Set("Access-Control-Expose-Headers", "X-Total-Count")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// contentTypeMiddleware sets appropriate content type headers
func (s *Server) contentTypeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set default content type for API responses
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json")
		}

		next.ServeHTTP(w, r)
	})
}

// authenticationMiddleware validates API keys for protected endpoints
func (s *Server) authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract API key from header
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			// Also check Authorization header for Bearer token
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				apiKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if apiKey == "" {
			s.writeErrorResponse(w, http.StatusUnauthorized, "API key required", "MISSING_API_KEY")
			return
		}

		// Validate API key
		s.mu.RLock()
		keyInfo, exists := s.apiKeys[apiKey]
		s.mu.RUnlock()

		if !exists {
			s.writeErrorResponse(w, http.StatusUnauthorized, "Invalid API key", "INVALID_API_KEY")
			return
		}

		// Check if key is expired
		if keyInfo.ExpiresAt != nil && time.Now().After(*keyInfo.ExpiresAt) {
			s.writeErrorResponse(w, http.StatusUnauthorized, "API key expired", "EXPIRED_API_KEY")
			return
		}

		// Add key info to request context
		ctx := context.WithValue(r.Context(), apiKeyContextKey, keyInfo)
		ctx = context.WithValue(ctx, userIDContextKey, keyInfo.ID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// writeErrorResponse writes a standardized error response
func (s *Server) writeErrorResponse(w http.ResponseWriter, statusCode int, message, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	errorResponse := ErrorResponse{
		Error: &APIError{
			Code:    code,
			Message: message,
		},
		Timestamp: time.Now().UTC(),
	}

	json.NewEncoder(w).Encode(errorResponse)
}

// writeSuccessResponse writes a standardized success response
func (s *Server) writeSuccessResponse(w http.ResponseWriter, data interface{}) {
	s.writeResponse(w, http.StatusOK, data)
}

// writeResponse writes a standardized API response
func (s *Server) writeResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := APIResponse{
		Data:      data,
		Timestamp: time.Now().UTC(),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("Failed to encode response", "error", err)
	}
}

// getAPIKeyFromContext extracts the API key from request context
func (s *Server) getAPIKeyFromContext(ctx context.Context) *APIKey {
	if key, ok := ctx.Value(apiKeyContextKey).(*APIKey); ok {
		return key
	}
	return nil
}

// getUserIDFromContext extracts the user ID from request context
func (s *Server) getUserIDFromContext(ctx context.Context) string {
	if userID, ok := ctx.Value(userIDContextKey).(string); ok {
		return userID
	}
	return ""
}
