// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/features/config/signature"
	controllerrun "github.com/cfgis/cfgms/features/controller/run"
	cpInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// relayPrincipalKey is a private context key used by the relay handler to inject
// a pre-validated, scope-limited Principal, bypassing normal mTLS/API-key auth.
// It is only set by RelayHandler after grant validation — never from untrusted input.
type relayPrincipalContextKeyType struct{}

var relayPrincipalKey = relayPrincipalContextKeyType{}

// RelayHandler subscribes to EventRelayRequest events, validates the per-execution
// grant, routes the embedded HTTP request through the existing REST handler (using
// a scope-limited Principal), and sends back a CommandRelayResponse.
//
// The device identity is always taken from event.StewardID (mTLS-verified by the
// control plane transport) — never from any field in the relay message body.
type RelayHandler struct {
	controlPlane cpInterfaces.ControlPlaneProvider
	runManager   *controllerrun.Manager
	apiHandler   http.Handler
	signer       signature.Signer // optional; nil = unsigned commands (test mode)
	logger       logging.Logger
}

// NewRelayHandler creates a RelayHandler wired to the given control plane, run
// manager, and API HTTP handler. signer may be nil in test or unsecured mode.
func NewRelayHandler(
	controlPlane cpInterfaces.ControlPlaneProvider,
	runManager *controllerrun.Manager,
	apiHandler http.Handler,
	signer signature.Signer,
	logger logging.Logger,
) *RelayHandler {
	return &RelayHandler{
		controlPlane: controlPlane,
		runManager:   runManager,
		apiHandler:   apiHandler,
		signer:       signer,
		logger:       logger,
	}
}

// Start subscribes to EventRelayRequest events. Returns when ctx is cancelled.
func (h *RelayHandler) Start(ctx context.Context) error {
	return h.controlPlane.SubscribeEvents(ctx, &cpTypes.EventFilter{
		EventTypes: []cpTypes.EventType{cpTypes.EventRelayRequest},
	}, h.handleRelayEvent)
}

// handleRelayEvent processes a single EventRelayRequest:
//  1. Extracts deviceID (from event.StewardID — trusted) and executionID.
//  2. Validates the grant keyed on (deviceID, executionID).
//  3. Constructs a scoped, non-admin Principal from the grant.
//  4. Routes the embedded HTTP request through the REST handler.
//  5. Sends the response back as CommandRelayResponse.
func (h *RelayHandler) handleRelayEvent(ctx context.Context, event *cpTypes.Event) error {
	if event.Type != cpTypes.EventRelayRequest {
		return nil
	}

	// Device identity from mTLS-verified StewardID — never from the message body.
	deviceID := event.StewardID
	if deviceID == "" {
		h.logger.Warn("relay: received relay_request with empty steward_id — ignoring")
		return nil
	}

	if event.Details == nil {
		h.logger.Warn("relay: relay_request has no details", "device_id", logging.SanitizeLogValue(deviceID))
		return nil
	}

	executionID, _ := event.Details["execution_id"].(string)
	seq, _ := event.Details["sequence"].(float64)
	method, _ := event.Details["method"].(string)
	path, _ := event.Details["path"].(string)
	bodyB64, _ := event.Details["body"].(string)

	if executionID == "" || method == "" || path == "" {
		h.logger.Warn("relay: missing required fields in relay_request",
			"device_id", logging.SanitizeLogValue(deviceID),
			"execution_id", logging.SanitizeLogValue(executionID))
		return h.sendErrorResponse(ctx, deviceID, event.StewardID, executionID, seq, http.StatusBadRequest)
	}

	// Validate grant — keyed on (deviceID, executionID) so cross-device spoofing fails.
	grant, err := h.runManager.LookupGrant(deviceID, executionID)
	if err != nil {
		h.logger.Info("relay: grant not found or consumed",
			"device_id", logging.SanitizeLogValue(deviceID),
			"execution_id", logging.SanitizeLogValue(executionID),
			"error", err)
		return h.sendErrorResponse(ctx, deviceID, event.StewardID, executionID, seq, http.StatusForbidden)
	}

	// Construct scope-limited, non-admin Principal. TenantID comes from the grant
	// (set at dispatch time from device registration) — not from the event body.
	principal := &Principal{
		ID:          fmt.Sprintf("relay:%s:%s", deviceID, executionID),
		Name:        fmt.Sprintf("relay-script:%s", deviceID),
		IsAdmin:     false,
		Permissions: grant.Scope,
		TenantID:    grant.TenantID,
	}

	// Decode request body.
	body, _ := base64.StdEncoding.DecodeString(bodyB64)

	// Build the synthetic HTTP request.
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	} else {
		bodyReader = http.NoBody
	}
	req, err := http.NewRequestWithContext(ctx, method, path, bodyReader)
	if err != nil {
		h.logger.Error("relay: build request failed",
			"device_id", logging.SanitizeLogValue(deviceID),
			"path", logging.SanitizeLogValue(path),
			"error", err)
		return h.sendErrorResponse(ctx, deviceID, event.StewardID, executionID, seq, http.StatusInternalServerError)
	}

	// Copy only safe headers from the relay event. Auth tokens, correlation IDs, and
	// routing headers are stripped so a script cannot forge audit entries or widen scope.
	safeHeaders := map[string]bool{"content-type": true, "accept": true}
	if headers, ok := event.Details["headers"].(map[string]interface{}); ok {
		for k, v := range headers {
			if safeHeaders[strings.ToLower(k)] {
				if vs, ok := v.(string); ok {
					req.Header.Set(k, vs)
				}
			}
		}
	}

	// Inject the pre-built Principal into the request context so that
	// authenticationMiddleware bypasses normal credential checks.
	reqCtx := context.WithValue(req.Context(), relayPrincipalKey, principal)
	reqCtx = context.WithValue(reqCtx, principalContextKey, principal)
	reqCtx = context.WithValue(reqCtx, ctxkeys.UserIDKey, logging.SanitizeLogValue(principal.ID))
	reqCtx = context.WithValue(reqCtx, ctxkeys.TenantID, principal.TenantID)
	req = req.WithContext(reqCtx)

	// Route through the existing REST handler (requirePermission checks Permissions).
	rw := httptest.NewRecorder()
	h.apiHandler.ServeHTTP(rw, req)
	resp := rw.Result()
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)

	// Flatten response headers to map[string]interface{}.
	respHeaders := make(map[string]interface{}, len(resp.Header))
	for k, vs := range resp.Header {
		if len(vs) > 0 {
			respHeaders[k] = vs[0]
		}
	}

	return h.sendRelayResponse(ctx, deviceID, executionID, seq, resp.StatusCode, respHeaders, respBody)
}

// sendErrorResponse sends a CommandRelayResponse with the given HTTP status code
// and no body. Used for grant validation failures and malformed requests.
func (h *RelayHandler) sendErrorResponse(ctx context.Context, targetSteward, _, executionID string, seq float64, statusCode int) error {
	return h.sendRelayResponse(ctx, targetSteward, executionID, seq, statusCode, nil, []byte(http.StatusText(statusCode)))
}

// sendRelayResponse transmits a CommandRelayResponse to the target steward.
func (h *RelayHandler) sendRelayResponse(
	ctx context.Context,
	targetSteward, executionID string,
	seq float64,
	statusCode int,
	headers map[string]interface{},
	body []byte,
) error {
	if headers == nil {
		headers = map[string]interface{}{}
	}
	cmd := &cpTypes.Command{
		ID:        uuid.New().String(),
		Type:      cpTypes.CommandRelayResponse,
		StewardID: targetSteward,
		Timestamp: time.Now(),
		Params: map[string]interface{}{
			"execution_id": executionID,
			"sequence":     seq,
			"status":       float64(statusCode),
			"headers":      headers,
			"body":         base64.StdEncoding.EncodeToString(body),
		},
	}

	signed := &cpTypes.SignedCommand{Command: *cmd}
	if h.signer != nil {
		rawParams := cpTypes.InterfaceParamsToStringMap(cmd.Params)
		cmdBytes, err := cpTypes.CommandSigningBytes(cmd, rawParams)
		if err != nil {
			return fmt.Errorf("relay: sign response: %w", err)
		}
		sig, err := h.signer.Sign(cmdBytes)
		if err != nil {
			return fmt.Errorf("relay: sign response: %w", err)
		}
		signed.Signature = sig
	}

	if err := h.controlPlane.SendCommand(ctx, signed); err != nil {
		h.logger.Error("relay: failed to send relay response",
			"target_steward", logging.SanitizeLogValue(targetSteward),
			"execution_id", logging.SanitizeLogValue(executionID),
			"error", err)
		return fmt.Errorf("relay: send command: %w", err)
	}

	h.logger.Debug("relay: sent relay response",
		"target_steward", logging.SanitizeLogValue(targetSteward),
		"execution_id", logging.SanitizeLogValue(executionID),
		"status", statusCode)

	return nil
}
