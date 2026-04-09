// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"

	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/controller/ctxkeys"
	"github.com/cfgis/cfgms/features/controller/fleet"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Regex pattern for validating identifiers (prevents log injection)
var identifierRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// handleListStewards handles GET /api/v1/stewards
// Supports optional query parameters for filtered search: os, platform, arch, status, hostname,
// tag (repeatable). TenantID is always taken from the authenticated context, never from query params.
// When no query params are provided, the existing all-stewards behavior is preserved.
func (s *Server) handleListStewards(w http.ResponseWriter, r *http.Request) {
	// Extract tenant from authenticated context (same pattern as handleUpdateStewardConfig).
	tenantID := ""
	if tid, ok := r.Context().Value(ctxkeys.TenantID).(string); ok && tid != "" {
		tenantID = tid
	}

	// Build a filter from query params and authenticated tenant scope.
	filter, err := buildFleetFilter(r, tenantID)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_FILTER")
		return
	}

	// When a filter is specified, use FleetQuery for filtered results (connected stewards only).
	if !isEmptyFilter(filter) {
		results, err := s.fleetQuery.Search(r.Context(), filter)
		if err != nil {
			s.logger.Error("Fleet query failed", "error", err)
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to query fleet", "INTERNAL_ERROR")
			return
		}
		stewardList := make([]StewardInfo, 0, len(results))
		for _, res := range results {
			info := StewardInfo{
				ID:       res.ID,
				Status:   res.Status,
				LastSeen: res.LastHeartbeat,
			}
			if len(res.DNAAttributes) > 0 {
				info.DNA = &DNAInfo{
					Hostname:     res.Hostname,
					OS:           res.OS,
					Architecture: res.Architecture,
					Attributes:   res.DNAAttributes,
				}
			}
			stewardList = append(stewardList, info)
		}
		s.logger.Info("Listed stewards (filtered)", "count", len(stewardList))
		s.writeSuccessResponse(w, stewardList)
		return
	}

	// No filter: existing behavior — return all stewards including registered-but-not-connected.
	stewards := s.controllerService.GetAllStewards()

	stewardList := make([]StewardInfo, 0, len(stewards))
	seenStewards := make(map[string]bool)

	for _, steward := range stewards {
		info := StewardInfo{
			ID:          steward.ID,
			Version:     steward.Version,
			Status:      steward.Status,
			LastSeen:    steward.LastHeartbeat,
			ConnectedAt: steward.LastHeartbeat,
			Metrics:     steward.Metrics,
		}

		if steward.DNA != nil {
			info.DNA = &DNAInfo{
				Hostname:     steward.DNA.Attributes["hostname"],
				OS:           steward.DNA.Attributes["os"],
				Architecture: steward.DNA.Attributes["arch"],
				Attributes:   steward.DNA.Attributes,
			}
		}

		stewardList = append(stewardList, info)
		seenStewards[steward.ID] = true
	}

	s.mu.RLock()
	for stewardID, registered := range s.registeredStewards {
		if !seenStewards[stewardID] {
			info := StewardInfo{
				ID:          stewardID,
				Status:      registered.Status,
				ConnectedAt: registered.RegisteredAt,
				LastSeen:    registered.LastHeartbeat,
			}
			stewardList = append(stewardList, info)
		}
	}
	s.mu.RUnlock()

	s.logger.Info("Listed stewards", "count", len(stewardList))
	s.writeSuccessResponse(w, stewardList)
}

// buildFleetFilter constructs a fleet.Filter from HTTP query parameters.
// tenantID comes from the authenticated context, not from query params, to prevent
// cross-tenant enumeration. Recognized params: os, platform, arch, status, hostname,
// tag (repeatable).
//
// Validation rules:
//   - status must be "online", "offline", "any", or empty
//   - string fields are capped at 253 characters (max DNS hostname length)
func buildFleetFilter(r *http.Request, tenantID string) (fleet.Filter, error) {
	const maxFieldLen = 253
	q := r.URL.Query()

	status := q.Get("status")
	if status != "" && status != "online" && status != "offline" && status != "any" {
		return fleet.Filter{}, fmt.Errorf("invalid status %q: must be online, offline, or any", status)
	}

	os := q.Get("os")
	platform := q.Get("platform")
	arch := q.Get("arch")
	hostname := q.Get("hostname")

	for name, val := range map[string]string{"os": os, "platform": platform, "arch": arch, "hostname": hostname} {
		if len(val) > maxFieldLen {
			return fleet.Filter{}, fmt.Errorf("filter field %q exceeds maximum length of %d", name, maxFieldLen)
		}
	}

	return fleet.Filter{
		TenantID:     tenantID,
		OS:           os,
		Platform:     platform,
		Architecture: arch,
		Status:       status,
		Hostname:     hostname,
		Tags:         q["tag"],
	}, nil
}

// isEmptyFilter reports whether a filter has no criteria set.
func isEmptyFilter(f fleet.Filter) bool {
	return f.TenantID == "" &&
		f.OS == "" &&
		f.Platform == "" &&
		f.Architecture == "" &&
		f.Status == "" &&
		f.Hostname == "" &&
		len(f.Tags) == 0 &&
		len(f.DNAAttributes) == 0
}

// handleGetSteward handles GET /api/v1/stewards/{id}
func (s *Server) handleGetSteward(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	// Get steward from controller service using GetStewardInfo
	stewardInfo, exists := s.controllerService.GetStewardInfo(stewardID)
	if !exists {
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		return
	}

	apiStewardInfo := StewardInfo{
		ID:       stewardInfo.ID,
		Status:   stewardInfo.Status,
		LastSeen: stewardInfo.LastHeartbeat,
		Version:  stewardInfo.Version,
		Metrics:  stewardInfo.Metrics,
	}

	// Include DNA information if available
	if stewardInfo.DNA != nil {
		apiStewardInfo.DNA = DNAFromProto(stewardInfo.DNA)
	}

	s.writeSuccessResponse(w, apiStewardInfo)
}

// handleGetStewardDNA handles GET /api/v1/stewards/{id}/dna
func (s *Server) handleGetStewardDNA(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	stewardIDForLog := logging.SanitizeLogValue(stewardID)

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	// Create gRPC request
	req := &controller.StewardRequest{
		StewardId: stewardID,
	}

	// Call gRPC service
	dnaResp, err := s.controllerService.GetStewardDNA(context.Background(), req)
	if err != nil {
		s.logger.Error("Failed to get steward DNA", "steward_id", stewardIDForLog, "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get steward DNA", "INTERNAL_ERROR")
		return
	}

	// Convert to API response
	dnaInfo := DNAFromProto(dnaResp)
	if dnaInfo == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "DNA not found for steward", "DNA_NOT_FOUND")
		return
	}

	s.writeSuccessResponse(w, dnaInfo)
}

// handleGetStewardConfig handles GET /api/v1/stewards/{id}/config
func (s *Server) handleGetStewardConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	stewardIDForLog := logging.SanitizeLogValue(stewardID)

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	// Get modules filter from query params
	modules := r.URL.Query()["modules"]

	// Create gRPC request
	req := &controller.ConfigRequest{
		StewardId: stewardID,
		Modules:   modules,
	}

	// Call gRPC service
	configResp, err := s.configService.GetConfiguration(context.Background(), req)
	if err != nil {
		s.logger.Error("Failed to get steward configuration", "steward_id", stewardIDForLog, "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get configuration", "INTERNAL_ERROR")
		return
	}

	// Check response status
	if configResp.Status.Code != 0 {
		s.writeErrorResponse(w, http.StatusBadRequest, configResp.Status.Message, "CONFIG_ERROR")
		return
	}

	// Convert protobuf config to map for HTTP response
	protoConfig := configResp.Config.Config
	if protoConfig == nil {
		s.logger.Error("Configuration is nil")
		s.writeErrorResponse(w, http.StatusInternalServerError, "Configuration is nil", "INTERNAL_ERROR")
		return
	}

	// Convert protobuf to Go struct
	goConfig, err := stewardconfig.FromProto(protoConfig)
	if err != nil {
		s.logger.Error("Failed to convert protobuf to Go struct", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to convert configuration", "CONVERSION_ERROR")
		return
	}

	// Marshal Go struct to JSON for response
	jsonBytes, err := json.Marshal(goConfig)
	if err != nil {
		s.logger.Error("Failed to marshal configuration to JSON", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to marshal configuration", "MARSHAL_ERROR")
		return
	}

	// Parse into map for response
	var config map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &config); err != nil {
		s.logger.Error("Failed to parse configuration JSON", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to parse configuration", "PARSE_ERROR")
		return
	}

	// Create response
	configInfo := ConfigurationInfo{
		StewardID: stewardID,
		Version:   configResp.Version,
		Config:    config,
		UpdatedAt: getCurrentTimestamp(),
	}

	s.writeSuccessResponse(w, configInfo)
}

// handleUpdateStewardConfig handles PUT /api/v1/stewards/{id}/config
func (s *Server) handleUpdateStewardConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	// Validate steward ID format
	stewardIDForLog := logging.SanitizeLogValue(stewardID)
	if !identifierRegex.MatchString(stewardID) {
		s.logger.Warn("Invalid steward ID format in config update request")
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid steward ID format", "INVALID_STEWARD_ID")
		return
	}

	// Parse request body into StewardConfig
	// Support both JSON (legacy) and YAML (production .cfg format)
	var config stewardconfig.StewardConfig
	contentType := r.Header.Get("Content-Type")

	// Read body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Error("Failed to read request body", "error", err)
		s.writeErrorResponse(w, http.StatusBadRequest, "Failed to read request body", "READ_ERROR")
		return
	}

	// Parse based on Content-Type
	if strings.Contains(contentType, "yaml") || strings.Contains(contentType, "x-yaml") {
		// YAML format (production .cfg files)
		if err := yaml.Unmarshal(bodyBytes, &config); err != nil {
			s.logger.Error("Failed to decode config YAML", "error", err)
			s.writeErrorResponse(w, http.StatusBadRequest, "Invalid YAML body", "INVALID_YAML")
			return
		}
		s.logger.Info("Received configuration in YAML format", "steward_id", stewardIDForLog, "resources", len(config.Resources))
	} else {
		// JSON format (legacy/backward compatibility)
		if err := json.Unmarshal(bodyBytes, &config); err != nil {
			s.logger.Error("Failed to decode config JSON", "error", err)
			s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_YAML")
			return
		}
		s.logger.Info("Received configuration in JSON format", "steward_id", stewardIDForLog, "resources", len(config.Resources))
	}

	// Extract tenant from context or use default
	tenantID := "default"
	if tid, ok := r.Context().Value(ctxkeys.TenantID).(string); ok && tid != "" {
		tenantID = tid
	}

	tenantIDForLog := logging.SanitizeLogValue(tenantID)

	s.logger.Info("Configuration upload request received",
		"steward_id", stewardIDForLog,
		"tenant_id", tenantIDForLog,
		"resource_count", len(config.Resources))

	// Store configuration using V2 durable config service
	if err := s.configService.SetConfiguration(r.Context(), tenantID, stewardID, &config); err != nil {
		s.logger.Error("Failed to store configuration",
			"steward_id", stewardIDForLog,
			"tenant_id", tenantIDForLog,
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to store configuration", "STORAGE_ERROR")
		return
	}

	s.logger.Info("Configuration stored successfully",
		"steward_id", stewardIDForLog,
		"tenant_id", tenantIDForLog)

	s.writeSuccessResponse(w, map[string]any{
		"steward_id": stewardID,
		"tenant_id":  tenantID,
		"status":     "stored",
		"message":    "Configuration stored successfully",
	})
}

// handleValidateConfig handles POST /api/v1/stewards/{id}/config/validate
func (s *Server) handleValidateConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	stewardIDForLog := logging.SanitizeLogValue(stewardID)

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	// Parse request body
	var validationReq ConfigValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&validationReq); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	// Convert config to JSON bytes
	configBytes, err := json.Marshal(validationReq.Config)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid configuration format", "INVALID_CONFIG")
		return
	}

	// Create gRPC request
	req := &controller.ConfigValidationRequest{
		Config:  configBytes,
		Version: validationReq.Version,
	}

	// Call gRPC service
	validationResp, err := s.configService.ValidateConfig(context.Background(), req)
	if err != nil {
		s.logger.Error("Failed to validate configuration", "steward_id", stewardIDForLog, "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to validate configuration", "INTERNAL_ERROR")
		return
	}

	// Convert validation errors
	var validationErrors []ValidationError
	for _, err := range validationResp.Errors {
		validationErrors = append(validationErrors, ValidationErrorFromProto(err))
	}

	// Create response
	result := ConfigValidationResult{
		Valid:    validationResp.Status.Code == 0,
		Errors:   validationErrors,
		Metadata: validationResp.Metadata,
	}

	s.writeSuccessResponse(w, result)
}

// handleGetConfigStatus handles GET /api/v1/stewards/{id}/config/status
func (s *Server) handleGetConfigStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	// Get configuration status from the service
	// For now, we'll return a placeholder since we need to implement this in the service layer
	// TODO: Implement configuration status tracking in the service layer

	status := ConfigStatusInfo{
		StewardID:     stewardID,
		ConfigVersion: "unknown",
		Status:        "unknown",
		Modules:       []ModuleStatus{},
		UpdatedAt:     getCurrentTimestamp(),
	}

	s.writeSuccessResponse(w, status)
}

// handleGetEffectiveConfig handles GET /api/v1/stewards/{id}/config/effective
func (s *Server) handleGetEffectiveConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	stewardIDForLog := logging.SanitizeLogValue(stewardID)

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	// Extract tenant from context or use default
	tenantID := "default"
	if tid, ok := r.Context().Value(ctxkeys.TenantID).(string); ok && tid != "" {
		tenantID = tid
	}

	// Get effective configuration from the V2 configuration service (durable storage)
	effectiveConfig, err := s.configService.GetEffectiveConfiguration(r.Context(), tenantID, stewardID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			s.logger.Debug("No effective configuration found", "steward_id", stewardIDForLog)
			s.writeErrorResponse(w, http.StatusNotFound, "No effective configuration found for steward", "NOT_FOUND")
		} else {
			s.logger.Error("Failed to get effective configuration", "steward_id", stewardIDForLog, "error", err)
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve effective configuration", "INTERNAL_ERROR")
		}
		return
	}

	s.logger.Info("Retrieved effective configuration", "steward_id", stewardIDForLog)
	s.writeSuccessResponse(w, effectiveConfig)
}
