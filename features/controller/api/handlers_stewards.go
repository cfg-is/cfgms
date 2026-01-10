// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	controller "github.com/cfgis/cfgms/api/proto/controller"
)

// handleListStewards handles GET /api/v1/stewards
func (s *Server) handleListStewards(w http.ResponseWriter, r *http.Request) {
	// Get all stewards from the controller service
	stewards := s.controllerService.GetAllStewards()

	// Convert to API response format
	stewardList := make([]StewardInfo, 0, len(stewards))
	for _, steward := range stewards {
		info := StewardInfo{
			ID:          steward.ID,
			Version:     steward.Version,
			Status:      steward.Status,
			LastSeen:    steward.LastHeartbeat,
			ConnectedAt: steward.LastHeartbeat, // Using LastHeartbeat as ConnectedAt for now
			Metrics:     steward.Metrics,
		}

		// Convert DNA if available
		if steward.DNA != nil {
			info.DNA = &DNAInfo{
				Hostname:     steward.DNA.Attributes["hostname"],
				OS:           steward.DNA.Attributes["os"],
				Architecture: steward.DNA.Attributes["arch"],
				Attributes:   steward.DNA.Attributes,
			}
		}

		stewardList = append(stewardList, info)
	}

	s.logger.Info("Listed stewards", "count", len(stewardList))
	s.writeSuccessResponse(w, stewardList)
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
		s.logger.Error("Failed to get steward DNA", "steward_id", stewardID, "error", err)
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
		s.logger.Error("Failed to get steward configuration", "steward_id", stewardID, "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get configuration", "INTERNAL_ERROR")
		return
	}

	// Check response status
	if configResp.Status.Code != 0 {
		s.writeErrorResponse(w, http.StatusBadRequest, configResp.Status.Message, "CONFIG_ERROR")
		return
	}

	// Parse configuration JSON
	var config map[string]interface{}
	if err := json.Unmarshal(configResp.Config, &config); err != nil {
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

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	// Parse request body
	var configUpdate map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&configUpdate); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	// For now, return a method not implemented response
	// TODO: Implement configuration update when the backend supports it
	s.writeErrorResponse(w, http.StatusNotImplemented, "Configuration updates not yet implemented", "NOT_IMPLEMENTED")
}

// handleValidateConfig handles POST /api/v1/stewards/{id}/config/validate
func (s *Server) handleValidateConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

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
		s.logger.Error("Failed to validate configuration", "steward_id", stewardID, "error", err)
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

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	// Get effective configuration from the configuration service
	effectiveConfig, err := s.configService.GetEffectiveConfiguration(stewardID)
	if err != nil {
		s.logger.Error("Failed to get effective configuration", "steward_id", stewardID, "error", err)

		// Check if steward not found
		if err.Error() == fmt.Sprintf("steward not found: %s", stewardID) {
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
			return
		}

		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve effective configuration", "INTERNAL_ERROR")
		return
	}

	s.logger.Info("Retrieved effective configuration", "steward_id", stewardID, "resources_count", len(effectiveConfig.Resources))
	s.writeSuccessResponse(w, effectiveConfig)
}
