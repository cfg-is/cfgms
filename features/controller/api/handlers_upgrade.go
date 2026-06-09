// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/fleet"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	blob "github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// dispatchUpgradeRequest is the JSON body for POST /api/v1/stewards/upgrade.
type dispatchUpgradeRequest struct {
	Selector string `json:"selector"`
	Version  string `json:"version"`
	Platform string `json:"platform"`
	Arch     string `json:"arch"`
}

// dispatchUpgradeResponse is the JSON body returned on 202 Accepted.
type dispatchUpgradeResponse struct {
	UpgradeID    string `json:"upgrade_id"`
	StewardCount int    `json:"steward_count"`
	Status       string `json:"status"`
}

// rollbackRequest is the JSON body for POST /api/v1/stewards/upgrade/{upgrade_id}/rollback.
type rollbackRequest struct {
	Version string `json:"version"`
}

// isTerminalUpgradeStatus reports whether the given upgrade status is terminal
// (committed, rolled_back, or failed). Non-terminal records block re-dispatch.
func isTerminalUpgradeStatus(s business.UpgradeStatus) bool {
	return s == business.UpgradeStatusCommitted ||
		s == business.UpgradeStatusRolledBack ||
		s == business.UpgradeStatusFailed
}

// handleDispatchUpgrade handles POST /api/v1/stewards/upgrade.
//
// Resolves the selector against the fleet, enforces tenant isolation, verifies the
// binary blob is approved, recomputes SHA-256 at dispatch time, creates UpgradeRecords
// in the durable store, and fans out CommandPushStewardBinary to matching stewards.
// Returns 202 Accepted immediately; fan-out runs in a background goroutine.
func (s *Server) handleDispatchUpgrade(w http.ResponseWriter, r *http.Request) {
	if s.upgradeStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"Upgrade store not configured; durable UpgradeStore is required",
			"UPGRADE_STORE_UNAVAILABLE")
		return
	}
	if s.blobStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"Binary storage not available",
			"BINARY_STORE_UNAVAILABLE")
		return
	}

	callerTenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenantID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}
	callerUserID, _ := r.Context().Value(ctxkeys.UserIDKey).(string)

	var req dispatchUpgradeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Warn("Failed to decode dispatch upgrade body", "error", err)
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_BODY")
		return
	}

	if req.Selector == "" || req.Version == "" || req.Platform == "" || req.Arch == "" {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"selector, version, platform, and arch are required",
			"MISSING_FIELDS")
		return
	}
	if !stewardBinaryVersionRe.MatchString(req.Version) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Invalid version: "+logging.SanitizeLogValue(req.Version)+"; must match ^v\\d+\\.\\d+\\.\\d+(-[a-zA-Z0-9][a-zA-Z0-9.-]*)?",
			"INVALID_VERSION")
		return
	}
	if !validPlatforms[req.Platform] {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Unknown platform: "+logging.SanitizeLogValue(req.Platform)+"; valid values: windows, darwin, linux",
			"INVALID_PLATFORM")
		return
	}
	if !validArchs[req.Arch] {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Unknown arch: "+logging.SanitizeLogValue(req.Arch)+"; valid values: amd64, arm64",
			"INVALID_ARCH")
		return
	}

	// Parse selector and apply tenant scope.
	filter, err := fleet.ParseTargetSelector(req.Selector)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Invalid selector: "+err.Error(),
			"INVALID_SELECTOR")
		return
	}
	filter.TenantID = callerTenantID

	// Resolve matching stewards.
	stewards, err := s.fleetQuery.Search(r.Context(), filter)
	if err != nil {
		s.logger.Error("Fleet query failed during upgrade dispatch", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Fleet query failed", "FLEET_QUERY_ERROR")
		return
	}

	// Enforce tenant isolation: drop stewards from other tenants, return 403 if none remain.
	var tenantStewards []fleet.StewardResult
	for _, st := range stewards {
		if st.TenantID == callerTenantID {
			tenantStewards = append(tenantStewards, st)
		}
	}
	if len(tenantStewards) == 0 {
		s.writeErrorResponse(w, http.StatusForbidden,
			"No stewards in caller tenant match the given selector",
			"CROSS_TENANT")
		return
	}

	// Fetch the approved binary blob.
	blobKey := stewardBinaryBlobKey(callerTenantID, req.Version, req.Platform, req.Arch)
	rc, blobMeta, err := s.blobStore.GetBlob(r.Context(), blobKey)
	if err != nil {
		if errors.Is(err, blob.ErrBlobNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound,
				fmt.Sprintf("Steward binary not found: %s/%s/%s", logging.SanitizeLogValue(req.Version), logging.SanitizeLogValue(req.Platform), logging.SanitizeLogValue(req.Arch)),
				"BINARY_NOT_FOUND")
			return
		}
		s.logger.Error("Failed to retrieve steward binary", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve binary", "GET_BINARY_ERROR")
		return
	}

	// Recompute SHA-256 from stored blob at dispatch time (do not trust BlobMeta.Checksum).
	blobContent, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		s.logger.Error("Failed to read steward binary for SHA-256 recompute", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read binary", "READ_BINARY_ERROR")
		return
	}
	blobSum := sha256.Sum256(blobContent)
	computedSHA256 := hex.EncodeToString(blobSum[:])

	// Approval gate: approved_by label must be present.
	if blobMeta.Labels["approved_by"] == "" {
		s.writeErrorResponse(w, http.StatusForbidden,
			"Binary has not been approved; transition from published to approved state is required before dispatch",
			"NOT_APPROVED")
		return
	}

	// Extract publisher provenance from blob labels.
	publisher := blobMeta.Labels["publisher"]
	sigDigest := blobMeta.Labels["signature_digest"]
	sigBase64 := blobMeta.Labels["signature"]
	var bundleSig []byte
	if sigBase64 != "" {
		bundleSig, err = base64.RawURLEncoding.DecodeString(sigBase64)
		if err != nil {
			s.logger.Error("Failed to decode bundle signature from blob label", "error", err)
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to decode signature", "SIGNATURE_DECODE_ERROR")
			return
		}
	}

	// Reject concurrent upgrades and create UpgradeRecords.
	// For single-steward dispatch (id:) this is one record; upgrade_id = that record's ID.
	type createdRecord struct {
		stewardID string
		upgradeID string
	}
	var created []createdRecord

	for _, st := range tenantStewards {
		// Check for non-terminal upgrade records for this steward.
		existing, listErr := s.upgradeStore.ListUpgradesBySteward(r.Context(), st.ID)
		if listErr != nil {
			s.logger.Error("Failed to list upgrades for steward",
				"error", listErr,
				"steward_id", logging.SanitizeLogValue(st.ID))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to check existing upgrades", "LIST_UPGRADES_ERROR")
			return
		}
		for _, rec := range existing {
			if !isTerminalUpgradeStatus(rec.Status) {
				s.writeErrorResponse(w, http.StatusConflict,
					fmt.Sprintf("Steward %s has a non-terminal upgrade in progress (status: %s)", logging.SanitizeLogValue(st.ID), rec.Status),
					"CONCURRENT_UPGRADE")
				return
			}
		}

		// Generate nonce for replay defense.
		nonce := make([]byte, 32)
		if _, nErr := rand.Read(nonce); nErr != nil {
			s.logger.Error("Failed to generate operation nonce", "error", nErr)
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to generate nonce", "NONCE_ERROR")
			return
		}

		upgradeID := uuid.New().String()
		record := &business.UpgradeRecord{
			ID:        upgradeID,
			StewardID: st.ID,
			TenantID:  callerTenantID,
			Version:   req.Version,
			Platform:  req.Platform,
			Arch:      req.Arch,
			SHA256:    computedSHA256,
			Status:    business.UpgradeStatusDispatched,
			InitiatedBy: business.InitiatedByIdentity{
				Subject:    callerUserID,
				TenantID:   callerTenantID,
				AuthMethod: "api_key",
			},
			Publisher:       publisher,
			SignatureDigest: sigDigest,
			BundleSignature: bundleSig,
			CreatedAt:       time.Now().UTC(),
			OperationNonce:  nonce,
			DispatchedAt:    time.Now().UTC(),
		}
		if createErr := s.upgradeStore.CreateUpgrade(r.Context(), record); createErr != nil {
			s.logger.Error("Failed to create upgrade record",
				"error", createErr,
				"steward_id", logging.SanitizeLogValue(st.ID))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to record upgrade", "CREATE_RECORD_ERROR")
			return
		}
		created = append(created, createdRecord{stewardID: st.ID, upgradeID: upgradeID})
	}

	// Return upgrade_id as the first record's ID (single-steward: maps directly to the record).
	returnUpgradeID := created[0].upgradeID

	// Fan-out CommandPushStewardBinary with completion callbacks so the upgrade
	// record advances from dispatched → committed (success) or failed (error/timeout).
	if s.commandPublisher != nil {
		// Stewards download the binary via the controller's HTTPS API.
		// ExternalURL (set via CFGMS_EXTERNAL_URL env or external_url in config) is the
		// URL the steward uses to reach the controller's HTTP API. The download URL uses
		// the caller's tenant namespace so the blob-store lookup resolves correctly.
		baseURL := ""
		if s.cfg != nil {
			baseURL = strings.TrimRight(s.cfg.ExternalURL, "/")
		}
		if baseURL == "" {
			baseURL = "https://localhost:9080"
		}
		downloadURL := fmt.Sprintf("%s/api/v1/public/steward-binaries/%s/%s/%s?tenant=%s",
			baseURL, req.Version, req.Platform, req.Arch, url.QueryEscape(callerTenantID))
		params := map[string]interface{}{
			"version":          req.Version,
			"download_url":     downloadURL,
			"sha256":           computedSHA256,
			"platform":         req.Platform,
			"arch":             req.Arch,
			"publisher":        publisher,
			"bundle_signature": base64.RawURLEncoding.EncodeToString(bundleSig),
		}
		createdSnapshot := created
		go func() {
			for _, entry := range createdSnapshot {
				upgradeID := entry.upgradeID
				stewardID := entry.stewardID
				onComplete := func(event *cpTypes.Event) {
					switch event.Type {
					case cpTypes.EventCommandCompleted:
						if updErr := s.upgradeStore.UpdateUpgradeStatus(context.Background(), upgradeID,
							business.UpgradeStatusCommitted, ""); updErr != nil {
							s.logger.Warn("Failed to mark upgrade committed",
								"upgrade_id", upgradeID, "error", updErr)
						}
					case cpTypes.EventCommandFailed:
						errMsg := ""
						if event.Details != nil {
							if msg, ok := event.Details["error"].(string); ok {
								errMsg = msg
							}
						}
						if updErr := s.upgradeStore.UpdateUpgradeStatus(context.Background(), upgradeID,
							business.UpgradeStatusFailed, errMsg); updErr != nil {
							s.logger.Warn("Failed to mark upgrade failed",
								"upgrade_id", upgradeID, "error", updErr)
						}
					}
				}
				onTimeout := func() {
					if updErr := s.upgradeStore.UpdateUpgradeStatus(context.Background(), upgradeID,
						business.UpgradeStatusFailed, "command timed out"); updErr != nil {
						s.logger.Warn("Failed to mark upgrade failed on timeout",
							"upgrade_id", upgradeID, "error", updErr)
					}
				}
				if _, pubErr := s.commandPublisher.PublishCommandWithCallback(
					context.Background(),
					stewardID,
					cpTypes.CommandPushStewardBinary,
					params,
					2*time.Minute,
					onComplete,
					onTimeout,
				); pubErr != nil {
					s.logger.Error("Failed to dispatch CommandPushStewardBinary",
						"error", pubErr,
						"steward_id", logging.SanitizeLogValue(stewardID),
						"upgrade_id", upgradeID)
					_ = s.upgradeStore.UpdateUpgradeStatus(context.Background(), upgradeID,
						business.UpgradeStatusFailed, pubErr.Error())
				} else {
					s.logger.Info("CommandPushStewardBinary dispatched",
						"steward_id", logging.SanitizeLogValue(stewardID),
						"upgrade_id", upgradeID,
						"version", logging.SanitizeLogValue(req.Version))
				}
			}
		}()
	}

	s.writeResponse(w, http.StatusAccepted, dispatchUpgradeResponse{
		UpgradeID:    returnUpgradeID,
		StewardCount: len(created),
		Status:       "accepted",
	})
}

// handleUpgradeStatus handles GET /api/v1/stewards/upgrade/{upgrade_id}.
// Returns the upgrade record for the given ID, enforcing tenant isolation.
func (s *Server) handleUpgradeStatus(w http.ResponseWriter, r *http.Request) {
	if s.upgradeStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"Upgrade store not configured",
			"UPGRADE_STORE_UNAVAILABLE")
		return
	}

	callerTenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenantID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	upgradeID := mux.Vars(r)["upgrade_id"]
	if upgradeID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "upgrade_id is required", "MISSING_UPGRADE_ID")
		return
	}

	record, err := s.upgradeStore.GetUpgrade(r.Context(), upgradeID)
	if err != nil {
		if errors.Is(err, business.ErrUpgradeNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "Upgrade record not found", "UPGRADE_NOT_FOUND")
			return
		}
		s.logger.Error("Failed to retrieve upgrade record",
			"error", err,
			"upgrade_id", logging.SanitizeLogValue(upgradeID))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve upgrade record", "GET_RECORD_ERROR")
		return
	}

	// Tenant isolation: caller can only view records in their own tenant.
	if record.TenantID != callerTenantID {
		s.writeErrorResponse(w, http.StatusForbidden, "Access denied", "FORBIDDEN")
		return
	}

	s.writeSuccessResponse(w, record)
}

// handleUpgradeRollback handles POST /api/v1/stewards/upgrade/{upgrade_id}/rollback.
// Dispatches CommandPushStewardBinary for the target version to the steward referenced
// by the original upgrade record. Requires installer:dispatch:steward permission.
func (s *Server) handleUpgradeRollback(w http.ResponseWriter, r *http.Request) {
	if s.upgradeStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"Upgrade store not configured",
			"UPGRADE_STORE_UNAVAILABLE")
		return
	}
	if s.blobStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"Binary storage not available",
			"BINARY_STORE_UNAVAILABLE")
		return
	}

	callerTenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenantID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}
	callerUserID, _ := r.Context().Value(ctxkeys.UserIDKey).(string)

	upgradeID := mux.Vars(r)["upgrade_id"]
	if upgradeID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "upgrade_id is required", "MISSING_UPGRADE_ID")
		return
	}

	// Look up original upgrade record to get steward/tenant/platform/arch.
	original, err := s.upgradeStore.GetUpgrade(r.Context(), upgradeID)
	if err != nil {
		if errors.Is(err, business.ErrUpgradeNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "Upgrade record not found", "UPGRADE_NOT_FOUND")
			return
		}
		s.logger.Error("Failed to retrieve upgrade record for rollback", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve upgrade record", "GET_RECORD_ERROR")
		return
	}
	if original.TenantID != callerTenantID {
		s.writeErrorResponse(w, http.StatusForbidden, "Access denied", "FORBIDDEN")
		return
	}

	var req rollbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_BODY")
		return
	}
	if req.Version == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "version is required for rollback", "MISSING_VERSION")
		return
	}
	if !stewardBinaryVersionRe.MatchString(req.Version) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Invalid version: "+logging.SanitizeLogValue(req.Version)+"; must match ^v\\d+\\.\\d+\\.\\d+(-[a-zA-Z0-9][a-zA-Z0-9.-]*)?",
			"INVALID_VERSION")
		return
	}

	// Fetch the rollback binary blob.
	blobKey := stewardBinaryBlobKey(callerTenantID, req.Version, original.Platform, original.Arch)
	rc, blobMeta, err := s.blobStore.GetBlob(r.Context(), blobKey)
	if err != nil {
		if errors.Is(err, blob.ErrBlobNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound,
				fmt.Sprintf("Rollback binary not found: %s/%s/%s", logging.SanitizeLogValue(req.Version), logging.SanitizeLogValue(original.Platform), logging.SanitizeLogValue(original.Arch)),
				"BINARY_NOT_FOUND")
			return
		}
		s.logger.Error("Failed to retrieve rollback binary", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve binary", "GET_BINARY_ERROR")
		return
	}

	blobContent, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		s.logger.Error("Failed to read rollback binary for SHA-256 recompute", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read binary", "READ_BINARY_ERROR")
		return
	}
	blobSum := sha256.Sum256(blobContent)
	computedSHA256 := hex.EncodeToString(blobSum[:])

	if blobMeta.Labels["approved_by"] == "" {
		s.writeErrorResponse(w, http.StatusForbidden,
			"Rollback binary has not been approved",
			"NOT_APPROVED")
		return
	}

	publisher := blobMeta.Labels["publisher"]
	sigDigest := blobMeta.Labels["signature_digest"]
	sigBase64 := blobMeta.Labels["signature"]
	var bundleSig []byte
	if sigBase64 != "" {
		bundleSig, err = base64.RawURLEncoding.DecodeString(sigBase64)
		if err != nil {
			s.logger.Error("Failed to decode bundle signature for rollback", "error", err)
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to decode signature", "SIGNATURE_DECODE_ERROR")
			return
		}
	}

	nonce := make([]byte, 32)
	if _, nErr := rand.Read(nonce); nErr != nil {
		s.logger.Error("Failed to generate operation nonce for rollback", "error", nErr)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to generate nonce", "NONCE_ERROR")
		return
	}

	rollbackUpgradeID := uuid.New().String()
	record := &business.UpgradeRecord{
		ID:        rollbackUpgradeID,
		StewardID: original.StewardID,
		TenantID:  callerTenantID,
		Version:   req.Version,
		Platform:  original.Platform,
		Arch:      original.Arch,
		SHA256:    computedSHA256,
		Status:    business.UpgradeStatusDispatched,
		InitiatedBy: business.InitiatedByIdentity{
			Subject:    callerUserID,
			TenantID:   callerTenantID,
			AuthMethod: "api_key",
		},
		Publisher:       publisher,
		SignatureDigest: sigDigest,
		BundleSignature: bundleSig,
		CreatedAt:       time.Now().UTC(),
		OperationNonce:  nonce,
		DispatchedAt:    time.Now().UTC(),
	}
	if createErr := s.upgradeStore.CreateUpgrade(r.Context(), record); createErr != nil {
		s.logger.Error("Failed to create rollback upgrade record",
			"error", createErr,
			"steward_id", logging.SanitizeLogValue(original.StewardID))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to record rollback upgrade", "CREATE_RECORD_ERROR")
		return
	}

	if s.commandPublisher != nil {
		baseURL := ""
		if s.cfg != nil {
			baseURL = strings.TrimRight(s.cfg.ExternalURL, "/")
		}
		if baseURL == "" {
			baseURL = "https://localhost:9080"
		}
		downloadURL := fmt.Sprintf("%s/api/v1/public/steward-binaries/%s/%s/%s?tenant=%s",
			baseURL, req.Version, original.Platform, original.Arch, url.QueryEscape(callerTenantID))
		params := map[string]interface{}{
			"version":          req.Version,
			"download_url":     downloadURL,
			"sha256":           computedSHA256,
			"platform":         original.Platform,
			"arch":             original.Arch,
			"publisher":        publisher,
			"bundle_signature": base64.RawURLEncoding.EncodeToString(bundleSig),
		}
		stewardID := original.StewardID
		go func() {
			onComplete := func(event *cpTypes.Event) {
				switch event.Type {
				case cpTypes.EventCommandCompleted:
					if updErr := s.upgradeStore.UpdateUpgradeStatus(context.Background(), rollbackUpgradeID,
						business.UpgradeStatusRolledBack, ""); updErr != nil {
						s.logger.Warn("Failed to mark rollback committed",
							"upgrade_id", rollbackUpgradeID, "error", updErr)
					}
				case cpTypes.EventCommandFailed:
					errMsg := ""
					if event.Details != nil {
						if msg, ok := event.Details["error"].(string); ok {
							errMsg = msg
						}
					}
					if updErr := s.upgradeStore.UpdateUpgradeStatus(context.Background(), rollbackUpgradeID,
						business.UpgradeStatusFailed, errMsg); updErr != nil {
						s.logger.Warn("Failed to mark rollback failed",
							"upgrade_id", rollbackUpgradeID, "error", updErr)
					}
				}
			}
			onTimeout := func() {
				if updErr := s.upgradeStore.UpdateUpgradeStatus(context.Background(), rollbackUpgradeID,
					business.UpgradeStatusFailed, "command timed out"); updErr != nil {
					s.logger.Warn("Failed to mark rollback failed on timeout",
						"upgrade_id", rollbackUpgradeID, "error", updErr)
				}
			}
			if _, pubErr := s.commandPublisher.PublishCommandWithCallback(
				context.Background(),
				stewardID,
				cpTypes.CommandPushStewardBinary,
				params,
				2*time.Minute,
				onComplete,
				onTimeout,
			); pubErr != nil {
				s.logger.Error("Failed to dispatch rollback CommandPushStewardBinary",
					"error", pubErr,
					"steward_id", logging.SanitizeLogValue(stewardID),
					"rollback_upgrade_id", rollbackUpgradeID)
				_ = s.upgradeStore.UpdateUpgradeStatus(context.Background(), rollbackUpgradeID,
					business.UpgradeStatusFailed, pubErr.Error())
			} else {
				s.logger.Info("Rollback CommandPushStewardBinary dispatched",
					"steward_id", logging.SanitizeLogValue(stewardID),
					"rollback_upgrade_id", rollbackUpgradeID,
					"version", logging.SanitizeLogValue(req.Version))
			}
		}()
	}

	s.writeResponse(w, http.StatusAccepted, dispatchUpgradeResponse{
		UpgradeID:    rollbackUpgradeID,
		StewardCount: 1,
		Status:       "accepted",
	})
}
