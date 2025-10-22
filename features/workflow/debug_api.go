package workflow

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/cfgis/cfgms/pkg/logging"
)

// DebugAPI provides HTTP API endpoints for workflow debugging
type DebugAPI struct {
	debugEngine DebugEngine
	logger      *logging.ModuleLogger
}

// NewDebugAPI creates a new debug API instance
func NewDebugAPI(debugEngine DebugEngine, logger logging.Logger) *DebugAPI {
	debugLogger := logging.ForModule("workflow-debug").WithField("component", "api")
	return &DebugAPI{
		debugEngine: debugEngine,
		logger:      debugLogger,
	}
}

// Debug session management endpoints

// StartDebugSessionRequest represents the request to start a debug session
type StartDebugSessionRequest struct {
	ExecutionID string        `json:"execution_id"`
	Settings    DebugSettings `json:"settings"`
}

// StartDebugSessionResponse represents the response from starting a debug session
type StartDebugSessionResponse struct {
	Session *DebugSession `json:"session"`
}

// StartDebugSession handles POST /debug/sessions
func (api *DebugAPI) StartDebugSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := api.logger.WithTenant(tenantID)

	var req StartDebugSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("Failed to decode start debug session request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate request
	if req.ExecutionID == "" {
		http.Error(w, "execution_id is required", http.StatusBadRequest)
		return
	}

	// Set default settings if not provided
	if req.Settings.MaxHistorySize == 0 {
		req.Settings.MaxHistorySize = 1000
	}
	req.Settings.TenantIsolation = true // Always enforce tenant isolation

	session, err := api.debugEngine.StartDebugSession(ctx, req.ExecutionID, req.Settings)
	if err != nil {
		logger.Error("Failed to start debug session", "error", err, "execution_id", req.ExecutionID)
		http.Error(w, fmt.Sprintf("Failed to start debug session: %v", err), http.StatusInternalServerError)
		return
	}

	logger.InfoCtx(ctx, "Started debug session via API",
		"session_id", session.ID,
		"execution_id", req.ExecutionID)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(StartDebugSessionResponse{Session: session}); err != nil {
		logger.Error("Failed to encode response", "error", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// GetDebugSession handles GET /debug/sessions/{sessionId}
func (api *DebugAPI) GetDebugSession(w http.ResponseWriter, r *http.Request) {
	sessionID := extractSessionID(r)
	if sessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}

	session, err := api.debugEngine.GetDebugSession(sessionID)
	if err != nil {
		api.logger.Error("Failed to get debug session", "error", err, "session_id", sessionID)
		http.Error(w, fmt.Sprintf("Failed to get debug session: %v", err), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(session); err != nil {
		api.logger.Error("Failed to encode session response", "error", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// ListDebugSessions handles GET /debug/sessions
func (api *DebugAPI) ListDebugSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := api.debugEngine.ListDebugSessions()
	if err != nil {
		api.logger.Error("Failed to list debug sessions", "error", err)
		http.Error(w, fmt.Sprintf("Failed to list debug sessions: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"sessions": sessions,
	}); err != nil {
		api.logger.Error("Failed to encode sessions response", "error", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// StopDebugSession handles DELETE /debug/sessions/{sessionId}
func (api *DebugAPI) StopDebugSession(w http.ResponseWriter, r *http.Request) {
	sessionID := extractSessionID(r)
	if sessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}

	err := api.debugEngine.StopDebugSession(sessionID)
	if err != nil {
		api.logger.Error("Failed to stop debug session", "error", err, "session_id", sessionID)
		http.Error(w, fmt.Sprintf("Failed to stop debug session: %v", err), http.StatusInternalServerError)
		return
	}

	api.logger.Info("Stopped debug session via API", "session_id", sessionID)
	w.WriteHeader(http.StatusNoContent)
}

// Step execution control endpoints

// StepExecutionRequest represents a step execution command
type StepExecutionRequest struct {
	Action          DebugAction            `json:"action"`
	VariableUpdates map[string]interface{} `json:"variable_updates,omitempty"`
}

// StepExecution handles POST /debug/sessions/{sessionId}/step
func (api *DebugAPI) StepExecution(w http.ResponseWriter, r *http.Request) {
	sessionID := extractSessionID(r)
	if sessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}

	var req StepExecutionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.logger.Error("Failed to decode step execution request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Apply variable updates if provided
	if req.VariableUpdates != nil {
		for varName, value := range req.VariableUpdates {
			if err := api.debugEngine.UpdateVariable(sessionID, varName, value); err != nil {
				api.logger.Error("Failed to update variable", "error", err, "variable", varName)
				http.Error(w, fmt.Sprintf("Failed to update variable %s: %v", varName, err), http.StatusInternalServerError)
				return
			}
		}
	}

	err := api.debugEngine.StepExecution(sessionID, req.Action)
	if err != nil {
		api.logger.Error("Failed to execute debug step", "error", err, "session_id", sessionID, "action", req.Action)
		http.Error(w, fmt.Sprintf("Failed to execute debug step: %v", err), http.StatusInternalServerError)
		return
	}

	api.logger.Info("Executed debug step via API", "session_id", sessionID, "action", req.Action)
	w.WriteHeader(http.StatusOK)
}

// Breakpoint management endpoints

// SetBreakpointRequest represents a request to set a breakpoint
type SetBreakpointRequest struct {
	StepName  string     `json:"step_name"`
	Condition *Condition `json:"condition,omitempty"`
}

// SetBreakpoint handles POST /debug/sessions/{sessionId}/breakpoints
func (api *DebugAPI) SetBreakpoint(w http.ResponseWriter, r *http.Request) {
	sessionID := extractSessionID(r)
	if sessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}

	var req SetBreakpointRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.logger.Error("Failed to decode set breakpoint request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.StepName == "" {
		http.Error(w, "step_name is required", http.StatusBadRequest)
		return
	}

	breakpoint, err := api.debugEngine.SetBreakpoint(sessionID, req.StepName, req.Condition)
	if err != nil {
		api.logger.Error("Failed to set breakpoint", "error", err, "session_id", sessionID, "step_name", req.StepName)
		http.Error(w, fmt.Sprintf("Failed to set breakpoint: %v", err), http.StatusInternalServerError)
		return
	}

	api.logger.Info("Set breakpoint via API", "session_id", sessionID, "breakpoint_id", breakpoint.ID, "step_name", req.StepName)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(breakpoint); err != nil {
		api.logger.Error("Failed to encode breakpoint response", "error", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// ListBreakpoints handles GET /debug/sessions/{sessionId}/breakpoints
func (api *DebugAPI) ListBreakpoints(w http.ResponseWriter, r *http.Request) {
	sessionID := extractSessionID(r)
	if sessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}

	breakpoints, err := api.debugEngine.ListBreakpoints(sessionID)
	if err != nil {
		api.logger.Error("Failed to list breakpoints", "error", err, "session_id", sessionID)
		http.Error(w, fmt.Sprintf("Failed to list breakpoints: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"breakpoints": breakpoints,
	}); err != nil {
		api.logger.Error("Failed to encode breakpoints response", "error", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// RemoveBreakpoint handles DELETE /debug/sessions/{sessionId}/breakpoints/{breakpointId}
func (api *DebugAPI) RemoveBreakpoint(w http.ResponseWriter, r *http.Request) {
	sessionID := extractSessionID(r)
	breakpointID := extractBreakpointID(r)

	if sessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}
	if breakpointID == "" {
		http.Error(w, "breakpoint_id is required", http.StatusBadRequest)
		return
	}

	err := api.debugEngine.RemoveBreakpoint(sessionID, breakpointID)
	if err != nil {
		api.logger.Error("Failed to remove breakpoint", "error", err, "session_id", sessionID, "breakpoint_id", breakpointID)
		http.Error(w, fmt.Sprintf("Failed to remove breakpoint: %v", err), http.StatusInternalServerError)
		return
	}

	api.logger.Info("Removed breakpoint via API", "session_id", sessionID, "breakpoint_id", breakpointID)
	w.WriteHeader(http.StatusNoContent)
}

// Variable inspection endpoints

// InspectVariables handles GET /debug/sessions/{sessionId}/variables
func (api *DebugAPI) InspectVariables(w http.ResponseWriter, r *http.Request) {
	sessionID := extractSessionID(r)
	if sessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}

	variables, err := api.debugEngine.InspectVariables(sessionID)
	if err != nil {
		api.logger.Error("Failed to inspect variables", "error", err, "session_id", sessionID)
		http.Error(w, fmt.Sprintf("Failed to inspect variables: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"variables": variables,
	}); err != nil {
		api.logger.Error("Failed to encode variables response", "error", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// UpdateVariableRequest represents a request to update a variable
type UpdateVariableRequest struct {
	Value interface{} `json:"value"`
}

// UpdateVariable handles PUT /debug/sessions/{sessionId}/variables/{variableName}
func (api *DebugAPI) UpdateVariable(w http.ResponseWriter, r *http.Request) {
	sessionID := extractSessionID(r)
	variableName := extractVariableName(r)

	if sessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}
	if variableName == "" {
		http.Error(w, "variable_name is required", http.StatusBadRequest)
		return
	}

	var req UpdateVariableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.logger.Error("Failed to decode update variable request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err := api.debugEngine.UpdateVariable(sessionID, variableName, req.Value)
	if err != nil {
		api.logger.Error("Failed to update variable", "error", err, "session_id", sessionID, "variable_name", variableName)
		http.Error(w, fmt.Sprintf("Failed to update variable: %v", err), http.StatusInternalServerError)
		return
	}

	api.logger.Info("Updated variable via API", "session_id", sessionID, "variable_name", variableName)
	w.WriteHeader(http.StatusOK)
}

// WatchVariableRequest represents a request to watch a variable
type WatchVariableRequest struct {
	BreakOnChange bool       `json:"break_on_change"`
	Condition     *Condition `json:"condition,omitempty"`
}

// WatchVariable handles POST /debug/sessions/{sessionId}/variables/{variableName}/watch
func (api *DebugAPI) WatchVariable(w http.ResponseWriter, r *http.Request) {
	sessionID := extractSessionID(r)
	variableName := extractVariableName(r)

	if sessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}
	if variableName == "" {
		http.Error(w, "variable_name is required", http.StatusBadRequest)
		return
	}

	var req WatchVariableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.logger.Error("Failed to decode watch variable request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err := api.debugEngine.WatchVariable(sessionID, variableName, req.BreakOnChange, req.Condition)
	if err != nil {
		api.logger.Error("Failed to watch variable", "error", err, "session_id", sessionID, "variable_name", variableName)
		http.Error(w, fmt.Sprintf("Failed to watch variable: %v", err), http.StatusInternalServerError)
		return
	}

	api.logger.Info("Added variable watch via API", "session_id", sessionID, "variable_name", variableName)
	w.WriteHeader(http.StatusOK)
}

// UnwatchVariable handles DELETE /debug/sessions/{sessionId}/variables/{variableName}/watch
func (api *DebugAPI) UnwatchVariable(w http.ResponseWriter, r *http.Request) {
	sessionID := extractSessionID(r)
	variableName := extractVariableName(r)

	if sessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}
	if variableName == "" {
		http.Error(w, "variable_name is required", http.StatusBadRequest)
		return
	}

	err := api.debugEngine.UnwatchVariable(sessionID, variableName)
	if err != nil {
		api.logger.Error("Failed to unwatch variable", "error", err, "session_id", sessionID, "variable_name", variableName)
		http.Error(w, fmt.Sprintf("Failed to unwatch variable: %v", err), http.StatusInternalServerError)
		return
	}

	api.logger.Info("Removed variable watch via API", "session_id", sessionID, "variable_name", variableName)
	w.WriteHeader(http.StatusNoContent)
}

// History and inspection endpoints

// GetAPICallHistory handles GET /debug/sessions/{sessionId}/api-calls
func (api *DebugAPI) GetAPICallHistory(w http.ResponseWriter, r *http.Request) {
	sessionID := extractSessionID(r)
	if sessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}

	history, err := api.debugEngine.GetAPICallHistory(sessionID)
	if err != nil {
		api.logger.Error("Failed to get API call history", "error", err, "session_id", sessionID)
		http.Error(w, fmt.Sprintf("Failed to get API call history: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"api_calls": history,
	}); err != nil {
		api.logger.Error("Failed to encode API calls response", "error", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// ReplayAPICall handles POST /debug/sessions/{sessionId}/api-calls/{callId}/replay
func (api *DebugAPI) ReplayAPICall(w http.ResponseWriter, r *http.Request) {
	sessionID := extractSessionID(r)
	callID := extractCallID(r)

	if sessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}
	if callID == "" {
		http.Error(w, "call_id is required", http.StatusBadRequest)
		return
	}

	replayCall, err := api.debugEngine.ReplayAPICall(sessionID, callID)
	if err != nil {
		api.logger.Error("Failed to replay API call", "error", err, "session_id", sessionID, "call_id", callID)
		http.Error(w, fmt.Sprintf("Failed to replay API call: %v", err), http.StatusInternalServerError)
		return
	}

	api.logger.Info("Replayed API call via API", "session_id", sessionID, "call_id", callID, "replay_id", replayCall.ID)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(replayCall); err != nil {
		api.logger.Error("Failed to encode replay call response", "error", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// GetStepHistory handles GET /debug/sessions/{sessionId}/steps
func (api *DebugAPI) GetStepHistory(w http.ResponseWriter, r *http.Request) {
	sessionID := extractSessionID(r)
	if sessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}

	// Parse optional limit parameter
	limit := 100 // default
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	history, err := api.debugEngine.GetStepHistory(sessionID)
	if err != nil {
		api.logger.Error("Failed to get step history", "error", err, "session_id", sessionID)
		http.Error(w, fmt.Sprintf("Failed to get step history: %v", err), http.StatusInternalServerError)
		return
	}

	// Apply limit
	if len(history) > limit {
		history = history[len(history)-limit:]
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"steps": history,
		"total": len(history),
	}); err != nil {
		api.logger.Error("Failed to encode step history response", "error", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// Helper functions for extracting URL parameters

func extractSessionID(r *http.Request) string {
	// This would typically use a router like gorilla/mux to extract path parameters
	// For now, return a placeholder - in real implementation this would extract from URL path
	return r.Header.Get("X-Session-ID") // Temporary workaround
}

func extractBreakpointID(r *http.Request) string {
	return r.Header.Get("X-Breakpoint-ID") // Temporary workaround
}

func extractVariableName(r *http.Request) string {
	return r.Header.Get("X-Variable-Name") // Temporary workaround
}

func extractCallID(r *http.Request) string {
	return r.Header.Get("X-Call-ID") // Temporary workaround
}

// RegisterDebugRoutes registers all debug API routes with the given mux
// This is a placeholder - in real implementation would integrate with the actual router
func (api *DebugAPI) RegisterRoutes() {
	// POST /debug/sessions - Start debug session
	// GET /debug/sessions - List debug sessions
	// GET /debug/sessions/{sessionId} - Get debug session
	// DELETE /debug/sessions/{sessionId} - Stop debug session
	// POST /debug/sessions/{sessionId}/step - Execute debug step
	// POST /debug/sessions/{sessionId}/breakpoints - Set breakpoint
	// GET /debug/sessions/{sessionId}/breakpoints - List breakpoints
	// DELETE /debug/sessions/{sessionId}/breakpoints/{breakpointId} - Remove breakpoint
	// GET /debug/sessions/{sessionId}/variables - Inspect variables
	// PUT /debug/sessions/{sessionId}/variables/{variableName} - Update variable
	// POST /debug/sessions/{sessionId}/variables/{variableName}/watch - Watch variable
	// DELETE /debug/sessions/{sessionId}/variables/{variableName}/watch - Unwatch variable
	// GET /debug/sessions/{sessionId}/api-calls - Get API call history
	// POST /debug/sessions/{sessionId}/api-calls/{callId}/replay - Replay API call
	// GET /debug/sessions/{sessionId}/steps - Get step history
}
