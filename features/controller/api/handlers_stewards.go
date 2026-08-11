// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"

	controller "github.com/cfgis/cfgms/api/proto/controller"
	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/controller/modules/resolution"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/fleet/selector"
	"github.com/cfgis/cfgms/pkg/logging"
	loggingInterfaces "github.com/cfgis/cfgms/pkg/logging/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Regex pattern for validating identifiers (prevents log injection)
var identifierRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// tenantPathRegex validates a tenant path: flat IDs (e.g. "corp") and slash-separated
// hierarchical paths (e.g. "msp-a/client-1"). Each component matches identifierRegex.
var tenantPathRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$`)

// stewardPageMaxLimit caps the limit query parameter on GET /api/v1/stewards (Issue #2489).
const stewardPageMaxLimit = 500

// StewardListPage is the paginated envelope returned by handleListStewards when
// the limit/offset query parameters are present. Total is the post-filter,
// pre-slice steward count so clients can compute page counts.
type StewardListPage struct {
	Stewards []StewardInfo `json:"stewards"`
	Total    int           `json:"total"`
	Limit    int           `json:"limit"`
	Offset   int           `json:"offset"`
}

// parseStewardPagination parses the optional limit/offset query parameters for
// GET /api/v1/stewards. Rules (pinned by Issue #2489):
//   - limit must be an integer in 1..stewardPageMaxLimit
//   - offset must be an integer >= 0
//   - limit present without offset implies offset=0
//   - offset present without limit is rejected (ambiguous page size)
//   - neither present => paginated=false (existing full-list behavior)
//
// Error messages reference the offending parameter NAME only — never the raw
// client-supplied value (no information disclosure in error responses).
func parseStewardPagination(q url.Values) (limit, offset int, paginated bool, err error) {
	limitStr := q.Get("limit")
	offsetStr := q.Get("offset")

	if limitStr == "" && offsetStr == "" {
		return 0, 0, false, nil
	}
	if limitStr == "" {
		return 0, 0, false, fmt.Errorf("offset requires limit to be set")
	}

	limit, convErr := strconv.Atoi(limitStr)
	if convErr != nil || limit < 1 || limit > stewardPageMaxLimit {
		return 0, 0, false, fmt.Errorf("limit must be an integer between 1 and %d", stewardPageMaxLimit)
	}

	if offsetStr != "" {
		offset, convErr = strconv.Atoi(offsetStr)
		if convErr != nil || offset < 0 {
			return 0, 0, false, fmt.Errorf("offset must be a non-negative integer")
		}
	}

	return limit, offset, true, nil
}

// paginateStewards sorts stewards by ID and slices the requested page window.
// The ID sort exists solely to make pagination deterministic — pages must be
// stable across requests even though the underlying sources iterate maps in
// random order. User-facing sort is explicitly out of scope (Issue #2489).
func paginateStewards(stewards []StewardInfo, limit, offset int) StewardListPage {
	sort.Slice(stewards, func(i, j int) bool { return stewards[i].ID < stewards[j].ID })
	total := len(stewards)
	start := min(offset, total)
	end := min(start+limit, total)
	return StewardListPage{
		Stewards: stewards[start:end],
		Total:    total,
		Limit:    limit,
		Offset:   offset,
	}
}

// handleListStewards handles GET /api/v1/stewards
// Supports optional query parameters for filtered search: os, platform, arch, status, hostname,
// tag (repeatable). TenantID is always taken from the authenticated context, never from query params.
//
// Optional pagination (Issue #2489): limit (1..500) and offset (>=0) select a page
// over a deterministic steward-ID-sorted order and switch the response payload to
// a StewardListPage envelope with total = post-filter, pre-slice count. Pagination
// applies on both the filtered and unfiltered code paths. When both params are
// absent, the existing full-list payload is returned unchanged (backward
// compatibility for cfg and existing clients).
func (s *Server) handleListStewards(w http.ResponseWriter, r *http.Request) {
	// Extract tenant from authenticated context (same pattern as handleUpdateStewardConfig).
	tenantID := ""
	if tid, ok := r.Context().Value(ctxkeys.TenantID).(string); ok && tid != "" {
		tenantID = tid
	}

	// Selector-based search path: when ?q=<selector> is present, parse the
	// expression and apply tenant-scope enforcement identical to handleResolveSelector
	// (handlers_fleet.go:51-64). The existing ?os, ?platform, ?arch, ?status, ?tag,
	// ?hostname params are unaffected — they remain active on the non-q path.
	if q := r.URL.Query().Get("q"); q != "" {
		s.logger.Debug("Steward list selector search",
			"q", logging.SanitizeLogValue(q))
		selectorFilter, parsedTenantPath, parseErr := selector.Parse(q)
		if parseErr != nil {
			s.logger.Info("Invalid selector expression in steward list",
				"q", logging.SanitizeLogValue(q), "error", logging.SanitizeLogValue(parseErr.Error()))
			s.writeErrorResponse(w, http.StatusBadRequest, "invalid selector expression", "INVALID_SELECTOR")
			return
		}
		// Enforce tenant subtree scope — must match handleResolveSelector exactly
		// (same grammar, same boundary, same 403 CROSS_TENANT response code).
		if parsedTenantPath != "" {
			if tenantID != "" && parsedTenantPath != tenantID && !strings.HasPrefix(parsedTenantPath, tenantID+"/") {
				s.logger.Info("Selector tenant outside caller subtree",
					"parsed_tenant", logging.SanitizeLogValue(parsedTenantPath),
					"caller_tenant", logging.SanitizeLogValue(tenantID))
				s.writeErrorResponse(w, http.StatusForbidden,
					"Target tenant is outside the caller's authorized subtree", "CROSS_TENANT")
				return
			}
			selectorFilter.TenantSubtree = parsedTenantPath
		} else if tenantID != "" {
			selectorFilter.TenantSubtree = tenantID
		}

		limit, offset, paginated, paginErr := parseStewardPagination(r.URL.Query())
		if paginErr != nil {
			s.logger.Warn("Rejected steward list pagination params",
				"limit", logging.SanitizeLogValue(r.URL.Query().Get("limit")),
				"offset", logging.SanitizeLogValue(r.URL.Query().Get("offset")),
				"error", logging.SanitizeLogValue(paginErr.Error()))
			s.writeErrorResponse(w, http.StatusBadRequest, paginErr.Error(), "INVALID_PAGINATION")
			return
		}

		results, searchErr := s.fleetQuery.Search(r.Context(), selectorFilter)
		if searchErr != nil {
			s.logger.Error("Fleet query failed", "error", searchErr)
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to query fleet", "INTERNAL_ERROR")
			return
		}
		stewardList := make([]StewardInfo, 0, len(results))
		for _, res := range results {
			info := StewardInfo{
				ID:       res.ID,
				TenantID: res.TenantID,
				Status:   res.Status,
				LastSeen: res.LastHeartbeat,
				Version:  res.DNAAttributes["steward.version"],
			}
			if len(res.DNAAttributes) > 0 {
				attrs := make(map[string]string, len(res.DNAAttributes)+1)
				for k, v := range res.DNAAttributes {
					attrs[k] = v
				}
				if res.TenantID != "" {
					attrs["tenant"] = res.TenantID
				}
				info.DNA = &DNAInfo{
					Hostname:     res.Hostname,
					OS:           res.OS,
					Architecture: res.Architecture,
					Attributes:   attrs,
				}
			}
			stewardList = append(stewardList, info)
		}
		if paginated {
			page := paginateStewards(stewardList, limit, offset)
			s.logger.Info("Listed stewards (selector, paginated)",
				"q", logging.SanitizeLogValue(q), "count", len(page.Stewards), "total", page.Total)
			s.writeSuccessResponse(w, page)
			return
		}
		s.logger.Info("Listed stewards (selector)",
			"q", logging.SanitizeLogValue(q), "count", len(stewardList))
		s.writeSuccessResponse(w, stewardList)
		return
	}

	// Build a filter from query params and authenticated tenant scope.
	filter, err := buildFleetFilter(r, tenantID)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_FILTER")
		return
	}

	// Parse optional pagination params. Rejected values are logged sanitized;
	// the error body names the offending param, never the raw client value.
	limit, offset, paginated, err := parseStewardPagination(r.URL.Query())
	if err != nil {
		s.logger.Warn("Rejected steward list pagination params",
			"limit", logging.SanitizeLogValue(r.URL.Query().Get("limit")),
			"offset", logging.SanitizeLogValue(r.URL.Query().Get("offset")),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_PAGINATION")
		return
	}

	// When a filter is specified, use FleetQuery for filtered results (connected stewards only).
	if !isEmptyFilter(filter) {
		results, err := s.fleetQuery.Search(r.Context(), filter)
		if err != nil {
			s.logger.Error("Fleet query failed", "error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to query fleet", "INTERNAL_ERROR")
			return
		}
		stewardList := make([]StewardInfo, 0, len(results))
		for _, res := range results {
			info := StewardInfo{
				ID:       res.ID,
				TenantID: res.TenantID,
				Status:   res.Status,
				LastSeen: res.LastHeartbeat,
				Version:  res.DNAAttributes["steward.version"],
			}
			if len(res.DNAAttributes) > 0 {
				attrs := make(map[string]string, len(res.DNAAttributes)+1)
				for k, v := range res.DNAAttributes {
					attrs[k] = v
				}
				if res.TenantID != "" {
					attrs["tenant"] = res.TenantID
				}
				info.DNA = &DNAInfo{
					Hostname:     res.Hostname,
					OS:           res.OS,
					Architecture: res.Architecture,
					Attributes:   attrs,
				}
			}
			stewardList = append(stewardList, info)
		}
		if paginated {
			page := paginateStewards(stewardList, limit, offset)
			s.logger.Info("Listed stewards (filtered, paginated)", "count", len(page.Stewards), "total", page.Total)
			s.writeSuccessResponse(w, page)
			return
		}
		s.logger.Info("Listed stewards (filtered)", "count", len(stewardList))
		s.writeSuccessResponse(w, stewardList)
		return
	}

	// No filter: return all stewards including registered-but-not-connected.
	// Deregistered stewards are excluded by default; pass ?include_deregistered=true to restore them.
	// Hidden and quarantined stewards are excluded by default (Issue #2918).
	includeDeregistered := r.URL.Query().Get("include_deregistered") == "true"
	includeQuarantined := r.URL.Query().Get("include_quarantined") == "true"
	includeHidden := r.URL.Query().Get("include_hidden") == "true"
	stewards := s.controllerService.GetAllStewards()

	stewardList := make([]StewardInfo, 0, len(stewards))

	for _, steward := range stewards {
		if !includeDeregistered && steward.Status == string(business.StewardStatusDeregistered) {
			continue
		}
		if !includeQuarantined && steward.Status == "quarantined" {
			continue
		}
		if !includeHidden && steward.Hidden {
			continue
		}
		info := StewardInfo{
			ID:          steward.ID,
			TenantID:    steward.TenantID,
			Version:     steward.Version,
			Status:      steward.Status,
			LastSeen:    steward.LastHeartbeat,
			ConnectedAt: steward.LastHeartbeat,
			Metrics:     steward.Metrics,
			Hidden:      steward.Hidden,
		}

		if steward.DNA != nil {
			attrs := make(map[string]string, len(steward.DNA.Attributes)+1)
			for k, v := range steward.DNA.Attributes {
				attrs[k] = v
			}
			if steward.TenantID != "" {
				attrs["tenant"] = steward.TenantID
			}
			info.DNA = &DNAInfo{
				Hostname:     steward.DNA.Attributes["hostname"],
				OS:           steward.DNA.Attributes["os"],
				Architecture: steward.DNA.Attributes["arch"],
				Attributes:   attrs,
			}
		}

		stewardList = append(stewardList, info)
	}

	if paginated {
		page := paginateStewards(stewardList, limit, offset)
		s.logger.Info("Listed stewards (paginated)", "count", len(page.Stewards), "total", page.Total)
		s.writeSuccessResponse(w, page)
		return
	}

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
		TenantSubtree: tenantID, // Issue #2919: subtree-aware scope replaces exact TenantID match
		OS:            os,
		Platform:      platform,
		Architecture:  arch,
		Status:        status,
		Hostname:      hostname,
		Tags:          q["tag"],
	}, nil
}

// isEmptyFilter reports whether a filter has no criteria set.
func isEmptyFilter(f fleet.Filter) bool {
	return f.TenantID == "" &&
		f.TenantSubtree == "" && // Issue #2919: must check subtree too
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

	// Cross-tenant scope check: API-key principals carry a non-empty TenantID; admin mTLS
	// principals have TenantID="" meaning no scope restriction (callerTenant == "" → always allowed).
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if !isWithinTenantScope(callerTenant, stewardInfo.TenantID) {
		// 404 instead of 403 to avoid disclosing steward existence across tenants.
		s.logger.Info("Cross-tenant steward get refused",
			"steward_tenant", logging.SanitizeLogValue(stewardInfo.TenantID),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		return
	}

	activeSessions := 0
	connectionState := "disconnected"
	s.mu.RLock()
	reg := s.registry
	s.mu.RUnlock()
	if reg != nil {
		if _, ok := reg.Get(stewardID); ok {
			activeSessions = 1
			connectionState = "connected"
		}
	}

	apiStewardInfo := StewardInfo{
		ID:              stewardInfo.ID,
		TenantID:        stewardInfo.TenantID,
		Status:          stewardInfo.Status,
		LastSeen:        stewardInfo.LastHeartbeat,
		Version:         stewardInfo.Version,
		Metrics:         stewardInfo.Metrics,
		ActiveSessions:  activeSessions,
		ConnectionState: connectionState,
	}

	// Include DNA information if available
	if stewardInfo.DNA != nil {
		apiStewardInfo.DNA = DNAFromProto(stewardInfo.DNA)
		if apiStewardInfo.DNA != nil && stewardInfo.TenantID != "" {
			attrs := make(map[string]string, len(apiStewardInfo.DNA.Attributes)+1)
			for k, v := range apiStewardInfo.DNA.Attributes {
				attrs[k] = v
			}
			attrs["tenant"] = stewardInfo.TenantID
			apiStewardInfo.DNA.Attributes = attrs
		}
	}

	s.writeSuccessResponse(w, apiStewardInfo)
}

// dnaAttributeDenylist contains glob-style patterns (case-insensitive substring match)
// for attribute keys that must never be returned via ?attribute=<key>. 404 is returned
// rather than 403 to avoid disclosing whether a sensitive attribute exists.
var dnaAttributeDenylist = []string{"token", "secret", "password", "credential", "api_key"}

// dnaAttributeMaxLen is the maximum accepted length for the ?attribute= query parameter.
const dnaAttributeMaxLen = 128

// isDNAAttributeDenylisted reports whether key matches any denylist pattern (case-insensitive).
// Returns the matched pattern for logging, or "" when not matched.
func isDNAAttributeDenylisted(key string) string {
	lower := strings.ToLower(key)
	for _, pattern := range dnaAttributeDenylist {
		if strings.Contains(lower, pattern) {
			return pattern
		}
	}
	return ""
}

// handleGetStewardDNA handles GET /api/v1/stewards/{id}/dna
// Optional query parameter: ?attribute=<key> returns a single attribute value.
func (s *Server) handleGetStewardDNA(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	stewardIDForLog := logging.SanitizeLogValue(stewardID)

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	// Cross-tenant check: API-key principals carry a non-empty TenantID; admin mTLS
	// principals have TenantID="" meaning no scope restriction.
	// Use path-separator-aware prefix matching so "tenant-a" cannot match "tenant-abc".
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenant != "" {
		info, ok := s.controllerService.GetStewardInfo(stewardID)
		stewardTenant := ""
		if ok {
			stewardTenant = info.TenantID
		}
		// Allow access when caller's tenant equals or is a hierarchical ancestor of the
		// steward's tenant (e.g. "root/msp-a" can read "root/msp-a/client-1" stewards).
		// The "/" separator boundary prevents "tenant-a" from matching "tenant-abc".
		sameTenant := stewardTenant == callerTenant
		ancestorTenant := strings.HasPrefix(stewardTenant, callerTenant+"/")
		if !ok || (!sameTenant && !ancestorTenant) {
			// 404 instead of 403 to avoid disclosing steward existence across tenants.
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
			return
		}
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

	// Handle optional ?attribute=<key> filter.
	attrKey := r.URL.Query().Get("attribute")
	if attrKey != "" {
		if len(attrKey) > dnaAttributeMaxLen {
			s.writeErrorResponse(w, http.StatusBadRequest, "attribute key too long", "ATTRIBUTE_KEY_TOO_LONG")
			return
		}
		if matched := isDNAAttributeDenylisted(attrKey); matched != "" {
			s.logger.Info("attribute key matches denylist; returning 404", "matched_pattern", matched)
			s.writeErrorResponse(w, http.StatusNotFound, "attribute not found", "DNA_ATTRIBUTE_REDACTED")
			return
		}
		val, ok := dnaInfo.Attributes[attrKey]
		if !ok {
			s.logger.Info("DNA attribute not found", "steward_id", stewardIDForLog, "attribute", logging.SanitizeLogValue(attrKey))
			s.writeErrorResponse(w, http.StatusNotFound, "attribute not found", "DNA_ATTRIBUTE_NOT_FOUND")
			return
		}
		s.respondJSON(w, http.StatusOK, map[string]string{"value": val})
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
	goConfig, err := stewardtypes.FromProto(protoConfig)
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
		UpdatedAt: time.Now().UTC(),
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
	var config stewardtypes.StewardConfig
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

	// Validate resource names at the handler boundary before any storage-side
	// effect. An invalid name (e.g. containing a dot like "docker.io") is a
	// client input error, not a storage fault: reject it with 400
	// VALIDATION_ERROR here rather than letting it reach SetConfiguration and
	// surface as a generic 500 STORAGE_ERROR. The offending name is
	// config-derived and therefore safe to echo back to the caller so the
	// client can self-diagnose without server logs. (Issue #2482)
	for i, resource := range config.Resources {
		if !identifierRegex.MatchString(resource.Name) {
			s.logger.Warn("Invalid resource name in config upload",
				"steward_id", stewardIDForLog,
				"resource_index", i,
				"resource_name", logging.SanitizeLogValue(resource.Name))
			s.writeErrorResponse(w, http.StatusBadRequest,
				fmt.Sprintf("Invalid resource name %q: must contain only alphanumeric characters, hyphens, and underscores", resource.Name),
				"VALIDATION_ERROR")
			return
		}
	}

	// Resolve the tenant the config is stored under. This endpoint targets a
	// specific steward, so the config must be stored under THAT steward's
	// tenant — not the caller's. An admin in tenant "default" may push config
	// to a steward in any tenant; using the caller's tenant would store the
	// config where neither the save=deploy fanout nor the steward's own sync
	// can find it. Fall back to the caller's tenant (then "default") only when
	// the steward is not yet known. (Issue #1572)
	tenantID := "default"
	if tid, ok := r.Context().Value(ctxkeys.TenantID).(string); ok && tid != "" {
		tenantID = tid
	}
	if info, ok := s.controllerService.GetStewardInfo(stewardID); ok && info.TenantID != "" {
		tenantID = info.TenantID
	}

	tenantIDForLog := logging.SanitizeLogValue(tenantID)

	s.logger.Info("Configuration upload request received",
		"steward_id", stewardIDForLog,
		"tenant_id", tenantIDForLog,
		"resource_count", len(config.Resources))

	// Issue #1884: resolve required_modules: against the controller module cache
	// before storing the configuration. When the module subsystem is wired, any
	// declared module that is not cached + approved must block the deployment.
	// Dependencies are nil-tolerant so deployments without the module subsystem
	// (and tests that exercise unrelated paths) continue to function unchanged.
	s.mu.RLock()
	cacheLister := s.moduleCacheLister
	bundleResolver := s.moduleBundleResolver
	bundleApprover := s.moduleBundleApprover
	trustStore := s.moduleTrustStore
	s.mu.RUnlock()
	if len(config.RequiredModules) > 0 &&
		cacheLister != nil && bundleResolver != nil &&
		bundleApprover != nil && trustStore != nil {
		if err := resolution.ResolveCfgRequiredModules(
			r.Context(),
			config.RequiredModules,
			cacheLister,
			bundleResolver,
			bundleApprover,
			trustStore,
		); err != nil {
			s.logger.Warn("cfg deployment blocked by required_modules resolution",
				"steward_id", stewardIDForLog,
				"tenant_id", tenantIDForLog,
				"error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusUnprocessableEntity, err.Error(), "REQUIRED_MODULE_NOT_APPROVED")
			return
		}
	}

	// Store configuration using V2 durable config service
	if err := s.configService.SetConfiguration(r.Context(), tenantID, stewardID, &config); err != nil {
		var ve *service.ValidationFailedError
		if errors.As(err, &ve) {
			s.logger.Warn("Configuration validation failed",
				"steward_id", stewardIDForLog,
				"tenant_id", tenantIDForLog,
				"error_count", len(ve.Errors))
			s.writeErrorResponse(w, http.StatusBadRequest, ve.Error(), "VALIDATION_ERROR")
			return
		}
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
		s.logger.Error("Failed to validate configuration", "steward_id", stewardIDForLog, "error", logging.SanitizeLogValue(err.Error()))
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

// handleStewardAuthRefresh handles POST /api/v1/stewards/{id}/auth/refresh.
// It is a no-op surface that validates the steward exists and acknowledges the
// refresh request. No token or credential state is modified (mTLS is the sole
// auth mechanism; this endpoint exists for HA test instrumentation only).
func (s *Server) handleStewardAuthRefresh(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	idForLog := logging.SanitizeLogValue(id)

	if id == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	_, exists := s.controllerService.GetStewardInfo(id)
	if !exists {
		s.logger.Info("Auth refresh requested for unknown steward", "steward_id", idForLog)
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		return
	}

	s.logger.Info("Auth refresh requested", "steward_id", idForLog)
	s.respondJSON(w, http.StatusOK, map[string]string{"steward_id": id, "status": "refresh_requested"})
}

// handleDeleteStewardConfig handles DELETE /api/v1/stewards/{id}/config
func (s *Server) handleDeleteStewardConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	stewardIDForLog := logging.SanitizeLogValue(stewardID)

	if !identifierRegex.MatchString(stewardID) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid steward ID format", "INVALID_STEWARD_ID")
		return
	}

	tenantID := "default"
	if tid, ok := r.Context().Value(ctxkeys.TenantID).(string); ok && tid != "" {
		tenantID = tid
	}

	err := s.configService.DeleteConfiguration(r.Context(), tenantID, stewardID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			s.logger.Debug("Configuration not found for deletion", "steward_id", stewardIDForLog)
			s.writeErrorResponse(w, http.StatusNotFound, "Configuration not found", "CONFIG_NOT_FOUND")
		} else {
			s.logger.Error("Failed to delete configuration", "steward_id", stewardIDForLog, "error", err)
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete configuration", "INTERNAL_ERROR")
		}
		return
	}

	s.logger.Info("Configuration deleted", "steward_id", stewardIDForLog)
	w.WriteHeader(http.StatusNoContent)
}

// handleDecommissionSteward handles DELETE /api/v1/stewards/{id}.
// Tombstones the steward's durable record (status: deregistered), updates the in-memory
// registry, and drops any active QUIC/gRPC session. The record is retained for audit.
// Requires an admin mTLS certificate (TierMTLSOnly gate). Issue #2408.
func (s *Server) handleDecommissionSteward(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	if !identifierRegex.MatchString(stewardID) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid steward ID format", "INVALID_STEWARD_ID")
		return
	}

	if s.stewardStore == nil {
		s.logger.Error("decommission failed: steward store not configured",
			"steward_id", logging.SanitizeLogValue(stewardID))
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Fleet store unavailable", "SERVICE_UNAVAILABLE")
		return
	}

	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)

	record, err := s.stewardStore.GetSteward(r.Context(), stewardID)
	if err != nil {
		if !errors.Is(err, business.ErrStewardNotFound) {
			s.logger.Error("decommission failed: store lookup error",
				"steward_id", logging.SanitizeLogValue(stewardID), "error", err)
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up steward", "INTERNAL_ERROR")
			return
		}
		// Fallback: steward registered via gRPC path exists only in the in-memory
		// registry but not in the durable store (Issue #2929 root cause).
		memInfo, memExists := s.controllerService.GetStewardInfo(stewardID)
		if !memExists {
			// Not in either store — genuinely unknown steward.
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
			return
		}
		// Cross-tenant scope check using the in-memory record's TenantID (fallback path).
		// 404 instead of 403 to avoid existence disclosure across tenant boundaries.
		if callerTenant != "" {
			sameTenant := memInfo.TenantID == callerTenant
			ancestorTenant := strings.HasPrefix(memInfo.TenantID, callerTenant+"/")
			if !sameTenant && !ancestorTenant {
				s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
				return
			}
		}
		// Backfill a durable record before tombstoning — must succeed before any in-memory
		// updates (mirrors the "durable write must succeed first" invariant). Populate at
		// minimum ID and TenantID; the store stamps RegisteredAt/LastSeen/Status itself.
		backfill := &business.StewardRecord{
			ID:       stewardID,
			TenantID: memInfo.TenantID,
		}
		if backfillErr := s.stewardStore.RegisterSteward(r.Context(), backfill); backfillErr != nil && !errors.Is(backfillErr, business.ErrStewardAlreadyExists) {
			s.logger.Error("decommission failed: backfill registration error",
				"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(backfillErr.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to decommission steward", "INTERNAL_ERROR")
			return
		}
	} else {
		// Cross-tenant scope check using the durable record's TenantID as the authoritative source.
		// Admin mTLS (empty callerTenant) has global scope; API-key callers are rejected at the
		// TierMTLSOnly gate before reaching here, so callerTenant is always from an mTLS principal.
		if callerTenant != "" {
			sameTenant := record.TenantID == callerTenant
			ancestorTenant := strings.HasPrefix(record.TenantID, callerTenant+"/")
			if !sameTenant && !ancestorTenant {
				// 404 instead of 403 to avoid existence disclosure across tenant boundaries.
				s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
				return
			}
		}
	}

	// Tombstone in durable storage — authoritative; must succeed before in-memory updates.
	if err := s.stewardStore.DeregisterSteward(r.Context(), stewardID); err != nil {
		s.logger.Error("decommission failed: store write error",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to decommission steward", "INTERNAL_ERROR")
		return
	}

	// Update in-memory status — best-effort; durable storage already succeeded.
	if err := s.controllerService.UpdateStewardStatus(stewardID, string(business.StewardStatusDeregistered)); err != nil {
		s.logger.Warn("decommission: in-memory status update failed (non-fatal)",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
	}

	// Drop any active QUIC/gRPC connection.
	s.mu.RLock()
	reg := s.registry
	s.mu.RUnlock()
	if reg != nil {
		reg.Unregister(stewardID)
	}

	// Emit audit event.
	auditTenantID := callerTenant
	if auditTenantID == "" {
		auditTenantID = audit.SystemTenantID
	}
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	principalID := ""
	if principal != nil {
		principalID = principal.ID
	}
	s.emitDecommissionAudit(r.Context(), auditTenantID, principalID, stewardID)

	s.logger.Info("Steward decommissioned",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"principal_id", logging.SanitizeLogValue(principalID))

	s.writeSuccessResponse(w, map[string]interface{}{
		"id":     stewardID,
		"status": string(business.StewardStatusDeregistered),
	})
}

// emitDecommissionAudit records a steward-decommission audit event. No-op when auditManager is nil.
func (s *Server) emitDecommissionAudit(ctx context.Context, tenantID, principalID, stewardID string) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSystemAccess).
		Action("steward.decommissioned").
		User(principalID, business.AuditUserTypeHuman).
		Resource("steward", stewardID, "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh)
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit decommission audit event",
			"error", err, "steward_id", logging.SanitizeLogValue(stewardID))
	}
}

// setVisibilityRequest is the JSON body for PATCH /api/v1/stewards/{id}/visibility.
type setVisibilityRequest struct {
	Hidden bool `json:"hidden"`
}

// handleSetStewardVisibility handles PATCH /api/v1/stewards/{id}/visibility.
// Reversibly hides or unhides a steward from the default fleet view.
// Requires steward:visibility permission at AssuranceBasic (Issue #2918).
func (s *Server) handleSetStewardVisibility(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	if !identifierRegex.MatchString(stewardID) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid steward ID format", "INVALID_STEWARD_ID")
		return
	}

	if s.stewardStore == nil {
		s.logger.Error("visibility update failed: steward store not configured",
			"steward_id", logging.SanitizeLogValue(stewardID))
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Fleet store unavailable", "SERVICE_UNAVAILABLE")
		return
	}

	var req setVisibilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)

	record, err := s.stewardStore.GetSteward(r.Context(), stewardID)
	if err != nil {
		if errors.Is(err, business.ErrStewardNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
			return
		}
		s.logger.Error("visibility update failed: store lookup error",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up steward", "INTERNAL_ERROR")
		return
	}

	// Tenant-scope check: 404 instead of 403 to avoid existence disclosure across tenant boundaries.
	if callerTenant != "" {
		sameTenant := record.TenantID == callerTenant
		ancestorTenant := strings.HasPrefix(record.TenantID, callerTenant+"/")
		if !sameTenant && !ancestorTenant {
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
			return
		}
	}

	// Durable write first — hard-fail the request on error.
	if err := s.stewardStore.SetStewardHidden(r.Context(), stewardID, req.Hidden); err != nil {
		s.logger.Error("visibility update failed: durable write error",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update steward visibility", "INTERNAL_ERROR")
		return
	}

	// Best-effort in-memory update — log-and-continue on error.
	if err := s.controllerService.SetStewardHidden(stewardID, req.Hidden); err != nil {
		s.logger.Warn("visibility update: in-memory update failed (non-fatal)",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
	}

	// Emit audit event at Medium severity: concealment-capable but reversible (Issue #2918 security ruling).
	auditTenantID := callerTenant
	if auditTenantID == "" {
		auditTenantID = audit.SystemTenantID
	}
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	principalID := ""
	if principal != nil {
		principalID = principal.ID
	}
	s.emitVisibilityAudit(r.Context(), auditTenantID, principalID, stewardID, req.Hidden)

	// The logged state is selected through control flow rather than read off the
	// decoded request body: req is populated from the untrusted HTTP body, so any
	// field read of it is a taint source into the log sink. Branching to a literal
	// keeps request-controlled bytes out of the sink entirely.
	visibilityState := "visible"
	if req.Hidden {
		visibilityState = "hidden"
	}

	s.logger.Info("Steward visibility updated",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"visibility", visibilityState,
		"principal_id", logging.SanitizeLogValue(principalID))

	s.writeSuccessResponse(w, map[string]interface{}{
		"id":     stewardID,
		"hidden": req.Hidden,
	})
}

// emitVisibilityAudit records a steward visibility-changed audit event.
// Severity: Medium — concealment-capable (drops device from default view) but reversible.
// No-op when auditManager is nil.
func (s *Server) emitVisibilityAudit(ctx context.Context, tenantID, principalID, stewardID string, hidden bool) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventDataModification).
		Action("steward.visibility_changed").
		User(principalID, business.AuditUserTypeHuman).
		Resource("steward", stewardID, "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityMedium).
		Detail("hidden", hidden)
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit visibility audit event",
			"error", logging.SanitizeLogValue(err.Error()), "steward_id", logging.SanitizeLogValue(stewardID))
	}
}

// handleGetStewardModules handles GET /api/v1/stewards/{id}/modules.
// Returns a 501 placeholder when the steward has no modules.loaded DNA attribute.
func (s *Server) handleGetStewardModules(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	stewardIDForLog := logging.SanitizeLogValue(stewardID)

	if !identifierRegex.MatchString(stewardID) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid steward ID format", "INVALID_STEWARD_ID")
		return
	}

	stewardInfo, exists := s.controllerService.GetStewardInfo(stewardID)
	if !exists {
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		return
	}

	// Cross-tenant check: the caller's tenant must be a prefix of or equal to the
	// steward's tenant. Return 404 (not 403) to avoid existence disclosure.
	// mTLS admin principals have empty TenantID (global access), so check is skipped for them.
	adminPrincipal := s.extractAdminPrincipal(r)
	var callerTenantID string
	if adminPrincipal != nil {
		callerTenantID = adminPrincipal.TenantID
	} else {
		callerTenantID, _ = r.Context().Value(ctxkeys.TenantID).(string)
	}
	if callerTenantID != "" {
		tenantMatch := stewardInfo.TenantID == callerTenantID ||
			strings.HasPrefix(stewardInfo.TenantID, callerTenantID+"/")
		if !tenantMatch {
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
			return
		}
	}

	// Check DNA for modules.loaded attribute.
	if stewardInfo.DNA == nil || stewardInfo.DNA.Attributes == nil {
		s.logger.Info("Modules unavailable: steward DNA has no attributes", "steward_id", stewardIDForLog)
		s.writeErrorResponse(w, http.StatusNotImplemented,
			"steward does not report loaded modules in DNA; ensure steward version supports module DNA attributes",
			"MODULES_UNAVAILABLE")
		return
	}

	modulesRaw, ok := stewardInfo.DNA.Attributes["modules.loaded"]
	if !ok {
		s.logger.Info("Modules unavailable: modules.loaded attribute absent", "steward_id", stewardIDForLog)
		s.writeErrorResponse(w, http.StatusNotImplemented,
			"steward does not report loaded modules in DNA; ensure steward version supports module DNA attributes",
			"MODULES_UNAVAILABLE")
		return
	}

	type moduleEntry struct {
		Name string `json:"name"`
	}
	parts := strings.Split(modulesRaw, ",")
	modules := make([]moduleEntry, 0, len(parts))
	for _, name := range parts {
		name = strings.TrimSpace(name)
		if name != "" {
			modules = append(modules, moduleEntry{Name: name})
		}
	}

	s.logger.Info("Fetched steward loaded modules", "steward_id", stewardIDForLog, "count", len(modules))
	s.writeSuccessResponse(w, map[string]interface{}{"modules": modules})
}

// stewardLogEvent is the per-event shape returned in the logs response.
type stewardLogEvent struct {
	Timestamp     time.Time              `json:"timestamp"`
	Level         string                 `json:"level"`
	Message       string                 `json:"message"`
	Component     string                 `json:"component,omitempty"`
	CorrelationID string                 `json:"correlation_id,omitempty"`
	Fields        map[string]interface{} `json:"fields,omitempty"`
}

// stewardLogRecord is one logical event in the logs response. Correlated
// detection+outcome pairs share a CorrelationID and are rolled into one record.
// A detection with no outcome in the query window carries PendingOutcome=true
// (the "monitor fired, convergence never completed" wedge signal from ADR-012 §2).
type stewardLogRecord struct {
	CorrelationID  string           `json:"correlation_id,omitempty"`
	Detection      *stewardLogEvent `json:"detection"`
	Outcome        *stewardLogEvent `json:"outcome,omitempty"`
	PendingOutcome bool             `json:"pending_outcome,omitempty"`
}

// handleGetStewardLogs handles GET /api/v1/stewards/{id}/logs.
// Reads from the dedicated steward-event LoggingManager via QueryTimeRange,
// scopes to the path steward by post-filtering on steward_id, rolls up
// correlated detection+outcome pairs, and gates on the caller's tenant.
func (s *Server) handleGetStewardLogs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]
	stewardIDForLog := logging.SanitizeLogValue(stewardID)

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	q := r.URL.Query()

	// Parse and validate tail (default 100, max 1000).
	tail := 100
	if tailStr := q.Get("tail"); tailStr != "" {
		v, err := strconv.Atoi(tailStr)
		if err != nil || v < 1 || v > 1000 {
			s.writeErrorResponse(w, http.StatusBadRequest, "tail must be an integer between 1 and 1000", "INVALID_PARAMETER")
			return
		}
		tail = v
	}

	// Validate since is a parseable Go duration.
	since := q.Get("since")
	if since != "" {
		if _, err := time.ParseDuration(since); err != nil {
			s.writeErrorResponse(w, http.StatusBadRequest, "since must be a valid Go duration (e.g. 1h, 30m)", "INVALID_PARAMETER")
			return
		}
	}

	// Validate level is one of the four allowed values.
	level := q.Get("level")
	if level != "" && level != "DEBUG" && level != "INFO" && level != "WARN" && level != "ERROR" {
		s.writeErrorResponse(w, http.StatusBadRequest, "level must be DEBUG, INFO, WARN, or ERROR", "INVALID_PARAMETER")
		return
	}

	// Cap module at 128 characters.
	module := q.Get("module")
	if len(module) > 128 {
		s.writeErrorResponse(w, http.StatusBadRequest, "module parameter exceeds maximum length of 128 characters", "INVALID_PARAMETER")
		return
	}

	s.logger.Debug("Steward log pull request",
		"steward_id", stewardIDForLog,
		"tail", tail,
		"since", logging.SanitizeLogValue(since),
		"level", logging.SanitizeLogValue(level),
		"module", logging.SanitizeLogValue(module),
	)

	// Cross-tenant check: API-key principals carry a non-empty TenantID; admin mTLS
	// principals have TenantID="" meaning no scope restriction.
	// Use path-separator-aware prefix matching so "tenant-a" cannot match "tenant-abc".
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	info, exists := s.controllerService.GetStewardInfo(stewardID)
	if callerTenant != "" {
		stewardTenant := ""
		if exists {
			stewardTenant = info.TenantID
		}
		sameTenant := stewardTenant == callerTenant
		ancestorTenant := strings.HasPrefix(stewardTenant, callerTenant+"/")
		if !exists || (!sameTenant && !ancestorTenant) {
			// 404 instead of 403 to avoid disclosing steward existence across tenants.
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
			return
		}
	} else if !exists {
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		return
	}

	// Return empty events when the manager is not yet wired.
	s.mu.RLock()
	mgr := s.stewardEventLoggingManager
	s.mu.RUnlock()

	emptyEvents := []stewardLogRecord{}
	if mgr == nil {
		s.writeSuccessResponse(w, map[string]interface{}{"events": emptyEvents})
		return
	}

	// Map query params to TimeRangeQuery.
	startTime := time.Now().Add(-24 * time.Hour) // default: last 24 hours
	if since != "" {
		d, _ := time.ParseDuration(since) // already validated above
		startTime = time.Now().Add(-d)
	}

	filters := map[string]interface{}{
		"steward_id": stewardID,
	}
	if level != "" {
		filters["level"] = level
	}
	if module != "" {
		filters["component"] = module
	}

	query := loggingInterfaces.TimeRangeQuery{
		StartTime: startTime,
		EndTime:   time.Now(),
		Filters:   filters,
		Limit:     tail,
	}

	entries, err := mgr.QueryTimeRange(r.Context(), query)
	if err != nil {
		s.logger.Error("Failed to query steward event log",
			"steward_id", stewardIDForLog,
			"error", err,
		)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to query event log", "QUERY_ERROR")
		return
	}

	// Defensive post-filter: the shared steward-event manager co-mingles all stewards;
	// the ACL gates endpoint access but does not scope the result set. Only entries
	// whose steward_id field exactly matches the path parameter are returned.
	filtered := make([]loggingInterfaces.LogEntry, 0, len(entries))
	for _, e := range entries {
		if sid, ok := e.Fields["steward_id"].(string); ok && sid == stewardID {
			filtered = append(filtered, e)
		}
	}

	records := rollupStewardLogsByCorrelationID(filtered)
	s.writeSuccessResponse(w, map[string]interface{}{"events": records})
}

// rollupStewardLogsByCorrelationID groups log entries by correlation_id.
// Entries without a correlation_id are standalone records. Correlated pairs
// are merged into one record (detection = earlier timestamp, outcome = later).
// A detection with no paired outcome is marked PendingOutcome=true.
func rollupStewardLogsByCorrelationID(entries []loggingInterfaces.LogEntry) []stewardLogRecord {
	var records []stewardLogRecord

	// Group entries by correlation_id. Entries with no correlation_id are
	// immediately emitted as standalone records, preserving source order.
	grouped := make(map[string][]loggingInterfaces.LogEntry)
	var corrOrder []string // tracks first-seen order for deterministic output
	seen := make(map[string]bool)

	for _, e := range entries {
		if e.CorrelationID == "" {
			records = append(records, stewardLogRecord{
				Detection: logEntryToStewardEvent(e),
			})
			continue
		}
		if !seen[e.CorrelationID] {
			corrOrder = append(corrOrder, e.CorrelationID)
			seen[e.CorrelationID] = true
		}
		grouped[e.CorrelationID] = append(grouped[e.CorrelationID], e)
	}

	for _, corrID := range corrOrder {
		events := grouped[corrID]
		// Sort by timestamp: earlier = detection, later = outcome.
		sort.Slice(events, func(i, j int) bool {
			return events[i].Timestamp.Before(events[j].Timestamp)
		})
		record := stewardLogRecord{
			CorrelationID: corrID,
			Detection:     logEntryToStewardEvent(events[0]),
		}
		if len(events) >= 2 {
			record.Outcome = logEntryToStewardEvent(events[1])
		} else {
			record.PendingOutcome = true
		}
		records = append(records, record)
	}

	return records
}

// logEntryToStewardEvent converts a LogEntry to the API response event shape.
func logEntryToStewardEvent(e loggingInterfaces.LogEntry) *stewardLogEvent {
	return &stewardLogEvent{
		Timestamp:     e.Timestamp,
		Level:         e.Level,
		Message:       e.Message,
		Component:     e.Component,
		CorrelationID: e.CorrelationID,
		Fields:        e.Fields,
	}
}

// moveStewardRequest is the JSON body for POST /api/v1/stewards/{id}/move.
type moveStewardRequest struct {
	NewTenantID string `json:"new_tenant_id"`
}

// allowedMoveSources is the set of statuses from which a steward may be moved.
// Revoked stewards are excluded: accepting a move would silently back-door re-entry
// into a new tenant without going through the registration-refresh approval flow.
var allowedMoveSources = map[string]bool{
	"registered":   true,
	"active":       true,
	"lost":         true,
	"archived":     true,
	"dormant":      true,
	"deregistered": true,
}

// handleMoveSteward handles POST /api/v1/stewards/{id}/move.
// Moves a steward to a different tenant: updates durable storage AND the live
// in-memory registry, and invalidates the per-tenant config cache for both the
// source and destination tenants. Registered in the Tier-3 (mTLS-only) endpoint
// class (Issue #2341).
func (s *Server) handleMoveSteward(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]
	stewardIDForLog := logging.SanitizeLogValue(stewardID)

	if !identifierRegex.MatchString(stewardID) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid steward ID format", "INVALID_STEWARD_ID")
		return
	}

	var req moveStewardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	newTenantID := req.NewTenantID
	if newTenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "new_tenant_id is required", "MISSING_TENANT_ID")
		return
	}
	if !tenantPathRegex.MatchString(newTenantID) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid tenant ID format", "INVALID_TENANT_ID")
		return
	}
	newTenantIDForLog := logging.SanitizeLogValue(newTenantID)

	// Steward must exist in durable storage.
	if s.stewardStore == nil {
		s.logger.Error("steward move failed: steward store not configured", "steward_id", stewardIDForLog)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Steward store not configured", "INTERNAL_ERROR")
		return
	}

	record, err := s.stewardStore.GetSteward(r.Context(), stewardID)
	if err != nil {
		s.logger.Info("steward not found for move", "steward_id", stewardIDForLog)
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		return
	}

	oldTenantID := record.TenantID
	oldTenantIDForLog := logging.SanitizeLogValue(oldTenantID)

	// Extract the caller's principal and scope from context once so they are available
	// throughout authorization, audit, and the success path.
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	callerTenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)

	// Dual-admin authorization (Issue #2342).
	// An unscoped (root) admin (callerTenantID == "") is always permitted; the move is
	// recorded as a privileged cross-tenant action. A scoped admin must have scope that is
	// an ancestor of (or equal to) BOTH source AND destination via the anchored-prefix form.
	// The "/" separator boundary prevents "tenant-a" from matching "tenant-abc".
	if callerTenantID != "" {
		sourceInScope := oldTenantID == callerTenantID || strings.HasPrefix(oldTenantID, callerTenantID+"/")
		destInScope := newTenantID == callerTenantID || strings.HasPrefix(newTenantID, callerTenantID+"/")
		if !sourceInScope || !destInScope {
			s.logger.Warn("steward move denied: scoped admin has insufficient scope",
				"steward_id", stewardIDForLog,
				"source_tenant", oldTenantIDForLog,
				"dest_tenant", newTenantIDForLog,
				"caller_scope", logging.SanitizeLogValue(callerTenantID),
			)
			s.emitMoveAudit(r, stewardID, oldTenantID, newTenantID, principal,
				business.AuditEventSecurityEvent, "steward_move",
				business.AuditResultDenied, business.AuditSeverityCritical,
				map[string]interface{}{
					"decision":        "denied",
					"reason":          "insufficient_scope",
					"source_in_scope": sourceInScope,
					"dest_in_scope":   destInScope,
				})
			s.writeErrorResponse(w, http.StatusForbidden, "Insufficient scope to move steward between these tenants", "INSUFFICIENT_SCOPE")
			return
		}
	}

	// Self-move: destination equals current tenant — short-circuit with no state change.
	if oldTenantID == newTenantID {
		s.logger.Info("steward move skipped (self-move)",
			"steward_id", stewardIDForLog,
			"tenant_id", newTenantIDForLog,
		)
		s.writeSuccessResponse(w, map[string]any{
			"steward_id":      stewardID,
			"tenant_id":       newTenantID,
			"previous_tenant": oldTenantID,
			"status":          "no_change",
		})
		return
	}

	// Revoked stewards may not be moved (would back-door un-revoke).
	if string(record.Status) == "revoked" {
		s.logger.Warn("steward move rejected: source status is revoked",
			"steward_id", stewardIDForLog,
		)
		s.writeErrorResponse(w, http.StatusBadRequest, "Revoked stewards cannot be moved", "STEWARD_REVOKED")
		return
	}

	// Validate source status against the allowed set.
	if !allowedMoveSources[string(record.Status)] {
		s.logger.Warn("steward move rejected: source status not allowed",
			"steward_id", stewardIDForLog,
			"status", logging.SanitizeLogValue(string(record.Status)),
		)
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Steward status does not permit a move", "STEWARD_STATUS_INVALID")
		return
	}

	// Destination tenant must exist and be active.
	if s.tenantManager == nil {
		s.logger.Error("steward move failed: tenant manager not configured", "steward_id", stewardIDForLog)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Tenant manager not configured", "INTERNAL_ERROR")
		return
	}

	destTenant, err := s.tenantManager.GetTenant(r.Context(), newTenantID)
	if err != nil {
		s.logger.Info("destination tenant not found for steward move",
			"steward_id", stewardIDForLog,
			"new_tenant_id", newTenantIDForLog,
		)
		s.writeErrorResponse(w, http.StatusBadRequest, "Destination tenant not found", "TENANT_NOT_FOUND")
		return
	}
	if destTenant.Status != "active" {
		s.logger.Warn("destination tenant is not active",
			"steward_id", stewardIDForLog,
			"new_tenant_id", newTenantIDForLog,
			"tenant_status", logging.SanitizeLogValue(string(destTenant.Status)),
		)
		s.writeErrorResponse(w, http.StatusBadRequest, "Destination tenant is not active", "TENANT_NOT_ACTIVE")
		return
	}

	// Update durable storage.
	if err := s.stewardStore.UpdateStewardTenant(r.Context(), stewardID, newTenantID); err != nil {
		s.logger.Error("steward move: failed to update durable store",
			"steward_id", stewardIDForLog,
			"new_tenant_id", newTenantIDForLog,
			"error", logging.SanitizeLogValue(err.Error()),
		)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update steward tenant", "INTERNAL_ERROR")
		return
	}

	// Update the live in-memory registry. The steward may not be connected yet
	// (e.g. the controller just restarted); a miss here is not an error — the
	// durable store update is authoritative and the registry will be warm on
	// next reconnect.
	if regErr := s.controllerService.UpdateStewardTenant(stewardID, newTenantID); regErr != nil {
		s.logger.Info("steward move: registry entry not present (steward not yet connected)",
			"steward_id", stewardIDForLog,
		)
	}

	// Invalidate per-tenant config cache for both source and destination so the
	// next config resolution uses the correct tenant path.
	s.tenantManager.InvalidateConfigCache(oldTenantID)
	s.tenantManager.InvalidateConfigCache(newTenantID)

	s.logger.Info("steward moved to new tenant",
		"steward_id", stewardIDForLog,
		"old_tenant_id", oldTenantIDForLog,
		"new_tenant_id", newTenantIDForLog,
	)

	s.emitMoveAudit(r, stewardID, oldTenantID, newTenantID, principal,
		business.AuditEventDataModification, "steward_move",
		business.AuditResultSuccess, business.AuditSeverityHigh,
		map[string]interface{}{
			"decision":                "approved",
			"privileged_cross_tenant": callerTenantID == "",
		})

	s.writeSuccessResponse(w, map[string]any{
		"steward_id":      stewardID,
		"tenant_id":       newTenantID,
		"previous_tenant": oldTenantID,
		"status":          "moved",
	})
}

// emitMoveAudit records a steward-move audit event. It is a no-op when auditManager is nil.
// Must be called before WriteHeader on every code path.
func (s *Server) emitMoveAudit(
	r *http.Request,
	stewardID, sourceTenantID, destTenantID string,
	principal *Principal,
	eventType business.AuditEventType,
	action string,
	result business.AuditResult,
	severity business.AuditSeverity,
	extras map[string]interface{},
) {
	if s.auditManager == nil {
		return
	}
	callerID := ""
	certSerial := ""
	certFingerprint := ""
	if principal != nil {
		callerID = principal.ID
		certSerial = principal.CertSerial
		certFingerprint = principal.CertFingerprint
	}

	b := audit.NewEventBuilder().
		Tenant(sourceTenantID).
		Type(eventType).
		Action(action).
		User(callerID, business.AuditUserTypeHuman).
		Resource("steward", stewardID, "").
		Result(result).
		Severity(severity).
		Request(s.getRequestID(r), r.Method, r.URL.Path, extractSourceIP(r, s.trustedProxies), r.Header.Get("User-Agent")).
		Changes(
			map[string]interface{}{"tenant_id": logging.SanitizeLogValue(sourceTenantID)},
			map[string]interface{}{"tenant_id": logging.SanitizeLogValue(destTenantID)},
			[]string{"tenant_id"},
		).
		Detail("steward_id", logging.SanitizeLogValue(stewardID)).
		Detail("source_tenant", logging.SanitizeLogValue(sourceTenantID)).
		Detail("dest_tenant", logging.SanitizeLogValue(destTenantID)).
		Detail("admin_cn", logging.SanitizeLogValue(callerID)).
		Detail("cert_serial", logging.SanitizeLogValue(certSerial)).
		Detail("cert_fingerprint", logging.SanitizeLogValue(certFingerprint))

	for k, v := range extras {
		b = b.Detail(k, v)
	}

	if err := s.auditManager.RecordEvent(r.Context(), b); err != nil {
		s.logger.Warn("Failed to emit move audit event",
			"error", err,
			"steward_id", logging.SanitizeLogValue(stewardID),
		)
	}
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
