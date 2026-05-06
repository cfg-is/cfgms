// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package trigger

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/gorilla/mux"
	"golang.org/x/time/rate"

	"github.com/cfgis/cfgms/pkg/logging"
)

// errBearerAuthRateLimited is returned when the bearer token auth failure rate limit is exceeded.
var errBearerAuthRateLimited = errors.New("bearer auth rate limit exceeded")

// errBasicAuthUnauthorized is returned when Basic auth credentials are missing or invalid.
var errBasicAuthUnauthorized = errors.New("basic auth unauthorized")

// errPayloadValidationFailed is returned when a webhook payload fails schema or structural validation.
var errPayloadValidationFailed = errors.New("payload validation failed")

// HTTPWebhookHandler implements the WebhookHandler interface using HTTP endpoints
type HTTPWebhookHandler struct {
	logger              *logging.ModuleLogger
	triggerManager      TriggerManager
	workflowTrigger     WorkflowTrigger
	server              *http.Server
	router              *mux.Router
	webhooks            map[string]*Trigger
	pathToTrigger       map[string]string // Maps webhook paths to trigger IDs
	rateLimiters        map[string]*rate.Limiter
	authFailureLimiters map[string]*rate.Limiter
	mutex               sync.RWMutex
	running             bool
	address             string
	port                int
}

// NewHTTPWebhookHandler creates a new HTTP-based webhook handler
func NewHTTPWebhookHandler(triggerManager TriggerManager, workflowTrigger WorkflowTrigger, address string, port int) *HTTPWebhookHandler {
	logger := logging.ForModule("workflow.trigger.webhook").WithField("component", "http_handler")

	router := mux.NewRouter()
	handler := &HTTPWebhookHandler{
		logger:              logger,
		triggerManager:      triggerManager,
		workflowTrigger:     workflowTrigger,
		router:              router,
		webhooks:            make(map[string]*Trigger),
		pathToTrigger:       make(map[string]string),
		rateLimiters:        make(map[string]*rate.Limiter),
		authFailureLimiters: make(map[string]*rate.Limiter),
		address:             address,
		port:                port,
	}

	// Set up webhook routes
	handler.setupRoutes()

	return handler
}

// Start starts the webhook handler HTTP server
func (wh *HTTPWebhookHandler) Start(ctx context.Context) error {
	wh.mutex.Lock()
	defer wh.mutex.Unlock()

	if wh.running {
		return fmt.Errorf("webhook handler is already running")
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := wh.logger.WithTenant(tenantID)

	addr := fmt.Sprintf("%s:%d", wh.address, wh.port)
	wh.server = &http.Server{
		Addr:         addr,
		Handler:      wh.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	logger.InfoCtx(ctx, "Starting webhook handler server",
		"address", addr)

	go func() {
		if err := wh.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.ErrorCtx(ctx, "Webhook handler server error",
				"error", err.Error())
		}
	}()

	wh.running = true

	logger.InfoCtx(ctx, "Webhook handler started successfully",
		"address", addr)

	return nil
}

// Stop stops the webhook handler HTTP server
func (wh *HTTPWebhookHandler) Stop(ctx context.Context) error {
	wh.mutex.Lock()
	defer wh.mutex.Unlock()

	if !wh.running {
		return fmt.Errorf("webhook handler is not running")
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := wh.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Stopping webhook handler server")

	shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := wh.server.Shutdown(shutdownCtx); err != nil {
		logger.ErrorCtx(ctx, "Error during webhook handler shutdown",
			"error", err.Error())
		return err
	}

	wh.running = false

	logger.InfoCtx(ctx, "Webhook handler stopped successfully")

	return nil
}

// RegisterWebhook registers a webhook endpoint for a trigger
func (wh *HTTPWebhookHandler) RegisterWebhook(ctx context.Context, trigger *Trigger) error {
	wh.mutex.Lock()
	defer wh.mutex.Unlock()

	if trigger.Type != TriggerTypeWebhook || trigger.Webhook == nil {
		return fmt.Errorf("trigger %s is not a webhook trigger", trigger.ID)
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := wh.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Registering webhook endpoint",
		"trigger_id", trigger.ID,
		"path", trigger.Webhook.Path,
		"methods", trigger.Webhook.Method)

	// Store webhook configuration
	wh.webhooks[trigger.ID] = trigger

	// Store path-to-trigger mapping
	wh.pathToTrigger[trigger.Webhook.Path] = trigger.ID

	// Set up rate limiter if configured
	if trigger.Webhook.RateLimit != nil {
		rateLimit := rate.Limit(trigger.Webhook.RateLimit.RequestsPerMinute / 60.0) // Convert to requests per second
		burstSize := trigger.Webhook.RateLimit.BurstSize
		if burstSize <= 0 {
			burstSize = trigger.Webhook.RateLimit.RequestsPerMinute
		}
		wh.rateLimiters[trigger.ID] = rate.NewLimiter(rateLimit, burstSize)
	}

	logger.InfoCtx(ctx, "Webhook endpoint registered successfully",
		"trigger_id", trigger.ID,
		"path", trigger.Webhook.Path)

	return nil
}

// UnregisterWebhook removes a webhook endpoint
func (wh *HTTPWebhookHandler) UnregisterWebhook(ctx context.Context, triggerID string) error {
	wh.mutex.Lock()
	defer wh.mutex.Unlock()

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := wh.logger.WithTenant(tenantID)

	trigger, exists := wh.webhooks[triggerID]
	if !exists {
		logger.WarnCtx(ctx, "Attempted to unregister non-existent webhook",
			"trigger_id", triggerID)
		return fmt.Errorf("webhook trigger %s is not registered", triggerID)
	}

	delete(wh.webhooks, triggerID)
	delete(wh.rateLimiters, triggerID)
	delete(wh.authFailureLimiters, triggerID)

	// Clean up path mapping
	delete(wh.pathToTrigger, trigger.Webhook.Path)

	logger.InfoCtx(ctx, "Webhook endpoint unregistered successfully",
		"trigger_id", triggerID,
		"path", trigger.Webhook.Path)

	return nil
}

// HandleWebhook processes an incoming webhook request
func (wh *HTTPWebhookHandler) HandleWebhook(ctx context.Context, triggerID string, payload []byte, headers map[string]string) (*TriggerExecution, error) {
	wh.mutex.RLock()
	trigger, exists := wh.webhooks[triggerID]
	wh.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("webhook trigger %s not found", triggerID)
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := wh.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Processing webhook request",
		"trigger_id", triggerID,
		"payload_size", len(payload))

	// Create trigger execution record — store only sanitized headers to prevent
	// bearer tokens and credentials from leaking into persisted execution records.
	execution := &TriggerExecution{
		ID:        generateExecutionID(),
		TriggerID: triggerID,
		Status:    TriggerExecutionStatusPending,
		StartTime: time.Now(),
		TriggerData: map[string]interface{}{
			"trigger_type": "webhook",
			"trigger_id":   triggerID,
			"headers":      sanitizeHeaders(headers),
			"payload_size": len(payload),
		},
	}

	// Validate payload
	if err := wh.validatePayload(trigger.Webhook, payload); err != nil {
		execution.Status = TriggerExecutionStatusFailed
		execution.Error = fmt.Sprintf("payload validation failed: %v", err)
		endTime := time.Now()
		execution.EndTime = &endTime
		execution.Duration = execution.EndTime.Sub(execution.StartTime)

		logger.ErrorCtx(ctx, "Webhook payload validation failed",
			"trigger_id", triggerID,
			"error", err.Error())

		return execution, fmt.Errorf("%w: %v", errPayloadValidationFailed, err)
	}

	// Authenticate request
	if err := wh.authenticateRequest(trigger.Webhook, payload, headers, triggerID); err != nil {
		execution.Status = TriggerExecutionStatusFailed
		execution.Error = fmt.Sprintf("authentication failed: %v", err)
		endTime := time.Now()
		execution.EndTime = &endTime
		execution.Duration = execution.EndTime.Sub(execution.StartTime)

		logger.ErrorCtx(ctx, "Webhook authentication failed",
			"trigger_id", triggerID,
			"error", err.Error())

		return execution, err
	}

	// Parse payload and map to workflow variables
	workflowVariables, err := wh.mapPayloadToVariables(trigger, payload, headers)
	if err != nil {
		execution.Status = TriggerExecutionStatusFailed
		execution.Error = fmt.Sprintf("payload mapping failed: %v", err)
		endTime := time.Now()
		execution.EndTime = &endTime
		execution.Duration = execution.EndTime.Sub(execution.StartTime)

		logger.ErrorCtx(ctx, "Webhook payload mapping failed",
			"trigger_id", triggerID,
			"error", err.Error())

		return execution, err
	}

	// Add trigger data to variables — sanitize headers to prevent auth credentials
	// from reaching workflow steps via the webhook_headers variable.
	triggerData := map[string]interface{}{
		"trigger_type":    "webhook",
		"trigger_id":      triggerID,
		"webhook_headers": sanitizeHeaders(headers),
		"execution_id":    execution.ID,
	}

	// Merge variables
	for k, v := range triggerData {
		workflowVariables[k] = v
	}

	// Execute workflow asynchronously
	execution.Status = TriggerExecutionStatusRunning

	go func() {
		execCtx := context.WithValue(context.Background(), TenantIDContextKey, tenantID)
		if trigger.Timeout > 0 {
			var cancel context.CancelFunc
			execCtx, cancel = context.WithTimeout(execCtx, trigger.Timeout)
			defer cancel()
		}

		workflowExecution, err := wh.workflowTrigger.TriggerWorkflow(execCtx, trigger, workflowVariables)

		endTime := time.Now()
		execution.EndTime = &endTime
		execution.Duration = execution.EndTime.Sub(execution.StartTime)

		if err != nil {
			execution.Status = TriggerExecutionStatusFailed
			execution.Error = err.Error()

			logger.ErrorCtx(execCtx, "Failed to trigger workflow from webhook",
				"trigger_id", triggerID,
				"execution_id", execution.ID,
				"error", err.Error())
		} else {
			execution.Status = TriggerExecutionStatusSuccess
			execution.WorkflowExecutionID = workflowExecution.ID

			logger.InfoCtx(execCtx, "Workflow triggered successfully from webhook",
				"trigger_id", triggerID,
				"execution_id", execution.ID,
				"workflow_execution_id", workflowExecution.ID)
		}

		// Update webhook statistics
		wh.updateWebhookStatistics(triggerID, execution.Status == TriggerExecutionStatusSuccess, execution.Duration)
	}()

	logger.InfoCtx(ctx, "Webhook request accepted for processing",
		"trigger_id", triggerID,
		"execution_id", execution.ID)

	return execution, nil
}

// setupRoutes sets up the HTTP routes for webhook handling
func (wh *HTTPWebhookHandler) setupRoutes() {
	// Health check endpoint
	wh.router.HandleFunc("/health", wh.healthCheck).Methods("GET")

	// Generic webhook endpoint
	wh.router.HandleFunc("/webhook/{trigger_id}", wh.handleWebhookRequest)

	// Trigger-specific paths will be handled by the generic handler
	wh.router.PathPrefix("/triggers/").HandlerFunc(wh.handleWebhookRequest)
}

// healthCheck handles health check requests
func (wh *HTTPWebhookHandler) healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	}); err != nil {
		wh.logger.Error("Failed to encode health check response", "error", err.Error())
	}
}

// handleWebhookRequest handles incoming webhook HTTP requests
func (wh *HTTPWebhookHandler) handleWebhookRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// First try to resolve trigger ID by path (for webhook.Path-based routing)
	wh.mutex.RLock()
	triggerID, foundByPath := wh.pathToTrigger[r.URL.Path]
	wh.mutex.RUnlock()

	// If not found by path, extract trigger ID from URL
	if !foundByPath {
		vars := mux.Vars(r)
		triggerID = vars["trigger_id"]

		// If not found in vars, try to extract from path
		if triggerID == "" {
			path := r.URL.Path
			if strings.HasPrefix(path, "/triggers/webhook/") {
				triggerID = strings.TrimPrefix(path, "/triggers/webhook/")
			}
		}
	}

	if triggerID == "" {
		http.Error(w, "Trigger ID not found in request", http.StatusBadRequest)
		return
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := wh.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Received webhook request",
		"trigger_id", triggerID,
		"method", r.Method,
		"remote_addr", r.RemoteAddr,
		"user_agent", r.Header.Get("User-Agent"))

	// Get trigger configuration
	wh.mutex.RLock()
	trigger, exists := wh.webhooks[triggerID]
	wh.mutex.RUnlock()

	if !exists {
		logger.WarnCtx(ctx, "Webhook request for unknown trigger",
			"trigger_id", triggerID)
		http.Error(w, "Webhook trigger not found", http.StatusNotFound)
		return
	}

	// Check if webhook is enabled
	if !trigger.Webhook.Enabled {
		logger.WarnCtx(ctx, "Webhook request for disabled trigger",
			"trigger_id", triggerID)
		http.Error(w, "Webhook trigger is disabled", http.StatusServiceUnavailable)
		return
	}

	// Check HTTP method
	if !wh.isMethodAllowed(trigger.Webhook, r.Method) {
		logger.WarnCtx(ctx, "Webhook request with disallowed method",
			"trigger_id", triggerID,
			"method", r.Method,
			"allowed_methods", trigger.Webhook.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check IP allowlist
	if !wh.isIPAllowed(trigger.Webhook, r.RemoteAddr) {
		logger.WarnCtx(ctx, "Webhook request from disallowed IP",
			"trigger_id", triggerID,
			"remote_addr", r.RemoteAddr,
			"allowed_ips", trigger.Webhook.AllowedIPs)
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Check rate limit
	if !wh.checkRateLimit(triggerID) {
		logger.WarnCtx(ctx, "Webhook request rate limited",
			"trigger_id", triggerID,
			"remote_addr", r.RemoteAddr)
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Read payload
	payload, err := wh.readPayload(r, trigger.Webhook)
	if err != nil {
		logger.ErrorCtx(ctx, "Failed to read webhook payload",
			"trigger_id", triggerID,
			"error", err.Error())
		http.Error(w, "Failed to read payload", http.StatusBadRequest)
		return
	}

	// Extract headers
	headers := make(map[string]string)
	for name, values := range r.Header {
		if len(values) > 0 {
			headers[name] = values[0]
		}
	}

	// Process webhook
	execution, err := wh.HandleWebhook(ctx, triggerID, payload, headers)
	if err != nil {
		if errors.Is(err, errBearerAuthRateLimited) {
			logger.WarnCtx(ctx, "Webhook bearer auth rate limit exceeded",
				"trigger_id", triggerID,
				"remote_addr", r.RemoteAddr)
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		if errors.Is(err, errBasicAuthUnauthorized) {
			logger.WarnCtx(ctx, "Webhook basic auth failed",
				"trigger_id", triggerID,
				"remote_addr", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if errors.Is(err, errPayloadValidationFailed) {
			logger.WarnCtx(ctx, "Webhook payload validation failed",
				"trigger_id", triggerID,
				"remote_addr", r.RemoteAddr)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		logger.ErrorCtx(ctx, "Failed to process webhook",
			"trigger_id", triggerID,
			"error", err.Error())
		http.Error(w, "Failed to process webhook", http.StatusInternalServerError)
		return
	}

	// Return success response
	response := map[string]interface{}{
		"status":       "accepted",
		"execution_id": execution.ID,
		"trigger_id":   triggerID,
		"timestamp":    time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.ErrorCtx(ctx, "Failed to encode webhook response", "error", err.Error())
	}

	logger.InfoCtx(ctx, "Webhook request processed successfully",
		"trigger_id", triggerID,
		"execution_id", execution.ID)
}

// validatePayload validates the webhook payload
func (wh *HTTPWebhookHandler) validatePayload(webhook *WebhookConfig, payload []byte) error {
	if webhook.PayloadValidation == nil {
		return nil
	}

	validation := webhook.PayloadValidation

	// Check payload size
	if validation.MaxSize > 0 && int64(len(payload)) > validation.MaxSize {
		return fmt.Errorf("payload size %d exceeds maximum allowed size %d", len(payload), validation.MaxSize)
	}

	// Validate JSON structure if JSON schema is provided
	if validation.JSONSchema != "" {
		if err := validateJSONSchema(payload, validation.JSONSchema); err != nil {
			return err
		}
	}

	// Check required fields
	if len(validation.RequiredFields) > 0 {
		var jsonData map[string]interface{}
		if err := json.Unmarshal(payload, &jsonData); err != nil {
			return fmt.Errorf("cannot validate required fields: payload is not valid JSON: %w", err)
		}

		for _, field := range validation.RequiredFields {
			if _, exists := jsonData[field]; !exists {
				return fmt.Errorf("required field %s is missing from payload", field)
			}
		}
	}

	return nil
}

// authenticateRequest authenticates the webhook request
func (wh *HTTPWebhookHandler) authenticateRequest(webhook *WebhookConfig, payload []byte, headers map[string]string, triggerID string) error {
	if webhook.Authentication == nil || webhook.Authentication.Type == WebhookAuthNone {
		return nil
	}

	auth := webhook.Authentication

	switch auth.Type {
	case WebhookAuthHMAC:
		return wh.validateHMACSignature(auth, payload, headers)

	case WebhookAuthAPIKey:
		return wh.validateAPIKey(auth, headers)

	case WebhookAuthBearer:
		return wh.validateBearerToken(auth, headers, triggerID)

	case WebhookAuthBasic:
		return wh.validateBasicAuth(auth, headers)

	default:
		return fmt.Errorf("unsupported authentication type: %s", auth.Type)
	}
}

// validateHMACSignature validates HMAC signature
func (wh *HTTPWebhookHandler) validateHMACSignature(auth *WebhookAuth, payload []byte, headers map[string]string) error {
	if auth.Secret == "" {
		return fmt.Errorf("HMAC secret is required")
	}

	signatureHeader := auth.SignatureHeader
	if signatureHeader == "" {
		signatureHeader = "X-Signature-256"
	}

	signature, exists := headers[signatureHeader]
	if !exists {
		return fmt.Errorf("signature header %s not found", signatureHeader)
	}

	// Remove "sha256=" prefix if present
	signature = strings.TrimPrefix(signature, "sha256=")

	// Calculate expected signature
	mac := hmac.New(sha256.New, []byte(auth.Secret))
	mac.Write(payload)
	expectedSignature := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return fmt.Errorf("HMAC signature validation failed")
	}

	return nil
}

// validateAPIKey validates API key
func (wh *HTTPWebhookHandler) validateAPIKey(auth *WebhookAuth, headers map[string]string) error {
	if auth.APIKey == "" {
		return fmt.Errorf("API key is required")
	}

	keyHeader := auth.APIKeyHeader
	if keyHeader == "" {
		keyHeader = "X-API-Key"
	}

	// Try both the original header name and the canonical form
	providedKey, exists := headers[keyHeader]
	if !exists {
		// Try canonical header form (Go's http.Header canonicalizes headers)
		canonicalHeader := http.CanonicalHeaderKey(keyHeader)
		providedKey, exists = headers[canonicalHeader]
	}

	if !exists {
		return fmt.Errorf("API key header %s not found", keyHeader)
	}

	// Normalize both keys to prevent Unicode normalization attacks
	normalizedProvided := norm.NFC.String(providedKey)
	normalizedExpected := norm.NFC.String(auth.APIKey)

	// Use constant time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(normalizedProvided), []byte(normalizedExpected)) != 1 {
		return fmt.Errorf("invalid API key")
	}

	return nil
}

// getOrCreateAuthFailureLimiter lazily initializes and returns the auth failure limiter for a trigger.
func (wh *HTTPWebhookHandler) getOrCreateAuthFailureLimiter(triggerID string) *rate.Limiter {
	if wh.authFailureLimiters == nil {
		return nil
	}
	wh.mutex.RLock()
	limiter, exists := wh.authFailureLimiters[triggerID]
	wh.mutex.RUnlock()
	if exists {
		return limiter
	}
	wh.mutex.Lock()
	defer wh.mutex.Unlock()
	if limiter, exists = wh.authFailureLimiters[triggerID]; exists {
		return limiter
	}
	limiter = rate.NewLimiter(rate.Limit(10.0/60.0), 10)
	wh.authFailureLimiters[triggerID] = limiter
	return limiter
}

// validateBearerToken validates Bearer token using constant-time NFC-normalized comparison.
func (wh *HTTPWebhookHandler) validateBearerToken(auth *WebhookAuth, headers map[string]string, triggerID string) error {
	// Fail-closed: missing config rejects all requests without leaking config state.
	if auth.BearerToken == "" {
		return errors.New("invalid Bearer token")
	}

	authHeader, exists := headers["Authorization"]
	if !exists {
		return wh.bearerAuthFailure(triggerID)
	}

	// NFC-normalize both sides before comparison to prevent Unicode normalization attacks.
	// Keep "Bearer " prefix on both sides — equal padding is acceptable.
	normalizedReceived := norm.NFC.String(authHeader)
	normalizedExpected := norm.NFC.String("Bearer " + auth.BearerToken)

	if subtle.ConstantTimeCompare([]byte(normalizedReceived), []byte(normalizedExpected)) != 1 {
		return wh.bearerAuthFailure(triggerID)
	}

	return nil
}

// bearerAuthFailure records an auth failure and returns errBearerAuthRateLimited if exhausted.
func (wh *HTTPWebhookHandler) bearerAuthFailure(triggerID string) error {
	limiter := wh.getOrCreateAuthFailureLimiter(triggerID)
	if limiter != nil && !limiter.Allow() {
		return errBearerAuthRateLimited
	}
	return errors.New("invalid Bearer token")
}

// validateBasicAuth validates HTTP Basic authentication
func (wh *HTTPWebhookHandler) validateBasicAuth(auth *WebhookAuth, headers map[string]string) error {
	if auth.BasicAuth == nil {
		return fmt.Errorf("basic auth configuration is required")
	}

	authHeader, exists := headers["Authorization"]
	if !exists {
		return errBasicAuthUnauthorized
	}

	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return errBasicAuthUnauthorized
	}

	decoded, err := base64.StdEncoding.DecodeString(authHeader[len(prefix):])
	if err != nil {
		return errBasicAuthUnauthorized
	}

	// Split on the first colon only — passwords may contain colons (RFC 7617).
	colonIdx := strings.IndexByte(string(decoded), ':')
	if colonIdx < 0 {
		return errBasicAuthUnauthorized
	}

	username := string(decoded[:colonIdx])
	password := string(decoded[colonIdx+1:])

	usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(auth.BasicAuth.Username))
	passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(auth.BasicAuth.Password))

	// AND the results to prevent short-circuit timing differences.
	if usernameMatch&passwordMatch != 1 {
		return errBasicAuthUnauthorized
	}

	return nil
}

// blockedWebhookHeaders is the set of header names (lowercased) that must never appear
// in execution records or workflow variables to prevent credential leaks.
var blockedWebhookHeaders = map[string]struct{}{
	"authorization": {}, "cookie": {}, "x-api-key": {}, "x-auth-token": {},
}

// sanitizeHeaders returns a copy of headers with auth-related entries removed.
func sanitizeHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		if _, blocked := blockedWebhookHeaders[strings.ToLower(k)]; !blocked {
			out[k] = v
		}
	}
	return out
}

// validateJSONSchema validates a JSON payload against a JSON schema using basic structural
// validation (type, required, properties). Supports a subset of JSON Schema draft-07.
func validateJSONSchema(payload []byte, schema string) error {
	var payloadDoc interface{}
	if err := json.Unmarshal(payload, &payloadDoc); err != nil {
		return fmt.Errorf("invalid JSON payload: %w", err)
	}

	var schemaDoc map[string]interface{}
	if err := json.Unmarshal([]byte(schema), &schemaDoc); err != nil {
		return fmt.Errorf("invalid JSON schema: %w", err)
	}

	if err := applySchemaRules(payloadDoc, schemaDoc); err != nil {
		return fmt.Errorf("payload does not match JSON schema: %w", err)
	}
	return nil
}

// applySchemaRules recursively applies JSON schema rules (type, required, properties).
func applySchemaRules(value interface{}, schema map[string]interface{}) error {
	if schemaType, ok := schema["type"]; ok {
		typeName, ok := schemaType.(string)
		if !ok {
			return fmt.Errorf("schema 'type' must be a string")
		}
		if err := checkJSONType(value, typeName); err != nil {
			return err
		}
	}

	obj, isObj := value.(map[string]interface{})

	if required, ok := schema["required"]; ok {
		requiredFields, ok := required.([]interface{})
		if !ok {
			return fmt.Errorf("schema 'required' must be an array")
		}
		if !isObj {
			return fmt.Errorf("payload must be an object to validate required fields")
		}
		for _, f := range requiredFields {
			field, _ := f.(string)
			if _, exists := obj[field]; !exists {
				return fmt.Errorf("required field %q is missing", field)
			}
		}
	}

	if properties, ok := schema["properties"]; ok && isObj {
		propsMap, ok := properties.(map[string]interface{})
		if !ok {
			return fmt.Errorf("schema 'properties' must be an object")
		}
		for fieldName, fieldSchema := range propsMap {
			if fieldValue, exists := obj[fieldName]; exists {
				fieldSchemaMap, ok := fieldSchema.(map[string]interface{})
				if !ok {
					continue
				}
				if err := applySchemaRules(fieldValue, fieldSchemaMap); err != nil {
					return fmt.Errorf("field %q: %w", fieldName, err)
				}
			}
		}
	}

	return nil
}

// checkJSONType verifies that a JSON value matches the declared schema type.
func checkJSONType(value interface{}, schemaType string) error {
	switch schemaType {
	case "object":
		if _, ok := value.(map[string]interface{}); !ok {
			return fmt.Errorf("expected type object, got %T", value)
		}
	case "array":
		if _, ok := value.([]interface{}); !ok {
			return fmt.Errorf("expected type array, got %T", value)
		}
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("expected type string, got %T", value)
		}
	case "number":
		if _, ok := value.(float64); !ok {
			return fmt.Errorf("expected type number, got %T", value)
		}
	case "integer":
		f, ok := value.(float64)
		if !ok {
			return fmt.Errorf("expected type integer, got %T", value)
		}
		if f != float64(int64(f)) {
			return fmt.Errorf("expected integer value, got %v", f)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("expected type boolean, got %T", value)
		}
	case "null":
		if value != nil {
			return fmt.Errorf("expected null, got %T", value)
		}
	}
	return nil
}

// mapPayloadToVariables maps webhook payload to workflow variables
func (wh *HTTPWebhookHandler) mapPayloadToVariables(trigger *Trigger, payload []byte, headers map[string]string) (map[string]interface{}, error) {
	variables := make(map[string]interface{})

	// Start with trigger's default variables
	for k, v := range trigger.Variables {
		variables[k] = v
	}

	// Parse JSON payload
	var payloadData map[string]interface{}
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &payloadData); err != nil {
			// If not JSON, store as raw string
			variables["webhook_payload"] = string(payload)
		} else {
			// Apply payload mapping if configured
			if trigger.Webhook.PayloadMapping != nil {
				for workflowVar, payloadPath := range trigger.Webhook.PayloadMapping {
					if value, exists := payloadData[payloadPath]; exists {
						variables[workflowVar] = value
					}
				}
			} else {
				// If no mapping, include all payload data with "webhook_" prefix
				for k, v := range payloadData {
					variables["webhook_"+k] = v
				}
			}
		}
	}

	// Add headers as variables with "header_" prefix, excluding auth-related headers.
	for k, v := range headers {
		lk := strings.ToLower(k)
		if _, blocked := blockedWebhookHeaders[lk]; !blocked {
			variables["header_"+lk] = v
		}
	}

	return variables, nil
}

// isMethodAllowed checks if the HTTP method is allowed for the webhook
func (wh *HTTPWebhookHandler) isMethodAllowed(webhook *WebhookConfig, method string) bool {
	if len(webhook.Method) == 0 {
		// Default to POST if no methods specified
		return method == "POST"
	}

	for _, allowedMethod := range webhook.Method {
		if strings.EqualFold(allowedMethod, method) {
			return true
		}
	}

	return false
}

// isIPAllowed checks if the client IP is allowed
func (wh *HTTPWebhookHandler) isIPAllowed(webhook *WebhookConfig, remoteAddr string) bool {
	if len(webhook.AllowedIPs) == 0 {
		return true // No IP restrictions
	}

	clientIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		clientIP = remoteAddr // Fallback if no port
	}

	parsedIP := net.ParseIP(clientIP)
	if parsedIP == nil {
		return false // Invalid IP address
	}

	for _, allowedIP := range webhook.AllowedIPs {
		// Support CIDR notation
		_, cidr, err := net.ParseCIDR(allowedIP)
		if err == nil {
			// Prevent IPv4-mapped IPv6 addresses from bypassing IPv4 allowlists
			// Check if client IP is IPv4-mapped IPv6 and CIDR is IPv4
			if strings.Contains(clientIP, "::ffff:") && cidr.IP.To4() != nil {
				continue // Block IPv4-mapped IPv6 from matching IPv4 CIDRs
			}

			if cidr.Contains(parsedIP) {
				return true
			}
		} else {
			// Exact IP match
			allowedParsed := net.ParseIP(allowedIP)
			if allowedParsed != nil && parsedIP.Equal(allowedParsed) {
				return true
			}
		}
	}

	return false
}

// checkRateLimit checks if the request is within rate limits
func (wh *HTTPWebhookHandler) checkRateLimit(triggerID string) bool {
	wh.mutex.RLock()
	rateLimiter, exists := wh.rateLimiters[triggerID]
	wh.mutex.RUnlock()

	if !exists {
		return true // No rate limit configured
	}

	return rateLimiter.Allow()
}

// readPayload reads and validates the request payload
func (wh *HTTPWebhookHandler) readPayload(r *http.Request, webhook *WebhookConfig) ([]byte, error) {
	// Check content type if specified
	if webhook.ContentType != "" {
		contentType := r.Header.Get("Content-Type")
		if !strings.Contains(contentType, webhook.ContentType) {
			return nil, fmt.Errorf("unsupported content type: %s, expected: %s", contentType, webhook.ContentType)
		}
	}

	// Read payload with size limit
	maxSize := int64(10 * 1024 * 1024) // Default 10MB limit
	if webhook.PayloadValidation != nil && webhook.PayloadValidation.MaxSize > 0 {
		maxSize = webhook.PayloadValidation.MaxSize
	}

	body := http.MaxBytesReader(nil, r.Body, maxSize)
	payload, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	return payload, nil
}

// updateWebhookStatistics updates statistics for a webhook
func (wh *HTTPWebhookHandler) updateWebhookStatistics(triggerID string, success bool, duration time.Duration) {
	wh.mutex.Lock()
	defer wh.mutex.Unlock()

	trigger, exists := wh.webhooks[triggerID]
	if !exists {
		return
	}

	if trigger.Webhook.Statistics == nil {
		trigger.Webhook.Statistics = &WebhookStatistics{}
	}

	stats := trigger.Webhook.Statistics
	stats.TotalCalls++

	if success {
		stats.SuccessfulCalls++
	} else {
		stats.FailedCalls++
	}

	now := time.Now()
	stats.LastCall = &now

	// Update average response time (simple moving average)
	if stats.AverageResponseTime == 0 {
		stats.AverageResponseTime = duration
	} else {
		stats.AverageResponseTime = (stats.AverageResponseTime + duration) / 2
	}
}

// generateExecutionID generates a unique execution ID using cryptographically secure random
func generateExecutionID() string {
	// Generate cryptographically secure random bytes
	randBytes := make([]byte, 8)
	if _, err := rand.Read(randBytes); err != nil {
		// Fallback to timestamp only if crypto/rand fails
		return fmt.Sprintf("exec_%d", time.Now().UnixNano())
	}

	// Convert to uint64 for consistent formatting
	randValue := uint64(randBytes[0])<<56 | uint64(randBytes[1])<<48 |
		uint64(randBytes[2])<<40 | uint64(randBytes[3])<<32 |
		uint64(randBytes[4])<<24 | uint64(randBytes[5])<<16 |
		uint64(randBytes[6])<<8 | uint64(randBytes[7])

	return fmt.Sprintf("exec_%d_%d", time.Now().UnixNano(), randValue)
}

// GetWebhookStatistics returns statistics for all webhooks (for monitoring)
func (wh *HTTPWebhookHandler) GetWebhookStatistics() map[string]*WebhookStatistics {
	wh.mutex.RLock()
	defer wh.mutex.RUnlock()

	result := make(map[string]*WebhookStatistics)
	for id, trigger := range wh.webhooks {
		if trigger.Webhook.Statistics != nil {
			result[id] = trigger.Webhook.Statistics
		}
	}

	return result
}

// GetRegisteredWebhooks returns all registered webhooks (for monitoring)
func (wh *HTTPWebhookHandler) GetRegisteredWebhooks() map[string]*Trigger {
	wh.mutex.RLock()
	defer wh.mutex.RUnlock()

	result := make(map[string]*Trigger)
	for id, trigger := range wh.webhooks {
		result[id] = trigger
	}

	return result
}
