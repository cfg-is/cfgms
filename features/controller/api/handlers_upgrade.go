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
	"github.com/cfgis/cfgms/features/controller/fleet/selector"
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

// approvedBinary is the verified result of loading an approved steward binary
// blob: the SHA-256 is recomputed from the stored content (never taken from
// BlobMeta) and the publisher provenance comes from the blob labels.
type approvedBinary struct {
	sha256    string
	publisher string
	sigDigest string
	bundleSig []byte
}

// approvedBinaryMessages carries the call-site specific error text and log
// messages so dispatch and rollback keep their distinct wording.
type approvedBinaryMessages struct {
	notFound    string
	getLog      string
	readLog     string
	notApproved string
	sigLog      string
}

// upgradeRecordSpec is the input for newDispatchedUpgradeRecord.
type upgradeRecordSpec struct {
	stewardID  string
	tenantID   string
	version    string
	platform   string
	arch       string
	authMethod string
	userID     string
	bin        approvedBinary
	nonce      []byte
}

// createdUpgrade pairs a dispatched steward with its new upgrade record ID.
type createdUpgrade struct {
	stewardID string
	upgradeID string
}

// loadApprovedBinary fetches the steward binary blob, recomputes its SHA-256 from
// the stored content, enforces the approval label and extracts publisher
// provenance. On failure it writes the error response and returns false.
func (s *Server) loadApprovedBinary(w http.ResponseWriter, r *http.Request, blobTenantID, version, platform, arch string, msgs approvedBinaryMessages) (approvedBinary, bool) {
	var bin approvedBinary
	blobKey := stewardBinaryBlobKey(blobTenantID, version, platform, arch)
	rc, blobMeta, err := s.blobStore.GetBlob(r.Context(), blobKey)
	if err != nil {
		if errors.Is(err, blob.ErrBlobNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound,
				fmt.Sprintf("%s: %s/%s/%s", msgs.notFound, logging.SanitizeLogValue(version), logging.SanitizeLogValue(platform), logging.SanitizeLogValue(arch)),
				"BINARY_NOT_FOUND")
			return bin, false
		}
		s.logger.Error(msgs.getLog, "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve binary", "GET_BINARY_ERROR")
		return bin, false
	}

	// Recompute SHA-256 from stored blob at dispatch time (do not trust BlobMeta.Checksum).
	blobContent, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		s.logger.Error(msgs.readLog, "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read binary", "READ_BINARY_ERROR")
		return bin, false
	}
	blobSum := sha256.Sum256(blobContent)
	bin.sha256 = hex.EncodeToString(blobSum[:])

	// Approval gate: approved_by label must be present.
	if blobMeta.Labels["approved_by"] == "" {
		s.writeErrorResponse(w, http.StatusForbidden, msgs.notApproved, "NOT_APPROVED")
		return bin, false
	}

	// Extract publisher provenance from blob labels.
	bin.publisher = blobMeta.Labels["publisher"]
	bin.sigDigest = blobMeta.Labels["signature_digest"]
	if sigBase64 := blobMeta.Labels["signature"]; sigBase64 != "" {
		bin.bundleSig, err = base64.RawURLEncoding.DecodeString(sigBase64)
		if err != nil {
			s.logger.Error(msgs.sigLog, "error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to decode signature", "SIGNATURE_DECODE_ERROR")
			return bin, false
		}
	}
	return bin, true
}

// newDispatchedUpgradeRecord builds an UpgradeRecord in the dispatched state.
func newDispatchedUpgradeRecord(id string, sp upgradeRecordSpec) *business.UpgradeRecord {
	return &business.UpgradeRecord{
		ID:        id,
		StewardID: sp.stewardID,
		TenantID:  sp.tenantID,
		Version:   sp.version,
		Platform:  sp.platform,
		Arch:      sp.arch,
		SHA256:    sp.bin.sha256,
		Status:    business.UpgradeStatusDispatched,
		InitiatedBy: business.InitiatedByIdentity{
			Subject:    sp.userID,
			TenantID:   sp.tenantID,
			AuthMethod: sp.authMethod,
		},
		Publisher:       sp.bin.publisher,
		SignatureDigest: sp.bin.sigDigest,
		BundleSignature: sp.bin.bundleSig,
		CreatedAt:       time.Now().UTC(),
		OperationNonce:  sp.nonce,
		DispatchedAt:    time.Now().UTC(),
	}
}

// pushStewardBinaryParams builds the CommandPushStewardBinary parameters. Stewards
// download the binary via the controller's HTTPS API: ExternalURL (set via
// CFGMS_EXTERNAL_URL env or external_url in config) is the URL the steward uses to
// reach the controller's HTTP API, and the download URL carries the blob namespace
// so the blob-store lookup resolves correctly.
func (s *Server) pushStewardBinaryParams(version, platform, arch, blobTenantID string, bin approvedBinary) map[string]interface{} {
	baseURL := ""
	if s.cfg != nil {
		baseURL = strings.TrimRight(s.cfg.ExternalURL, "/")
	}
	if baseURL == "" {
		baseURL = "https://localhost:9080"
	}
	downloadURL := fmt.Sprintf("%s/api/v1/public/steward-binaries/%s/%s/%s?tenant=%s",
		baseURL, version, platform, arch, url.QueryEscape(blobTenantID))
	return map[string]interface{}{
		"version":      version,
		"download_url": downloadURL,
		"sha256":       bin.sha256,
		"platform":     platform,
		"arch":         arch,
		"publisher":    bin.publisher,
		// StdEncoding (with padding) so the steward's pushStewardBinaryParams.BundleSignature
		// []byte field decodes it via Go's JSON codec, which uses base64.StdEncoding. (Issue #1948)
		"bundle_signature": base64.StdEncoding.EncodeToString(bin.bundleSig),
	}
}

// upgradeCallbacks returns the completion and timeout callbacks that advance an
// upgrade record from dispatched to okStatus (success) or failed (error/timeout).
// noun ("upgrade" or "rollback") selects the log wording.
func (s *Server) upgradeCallbacks(noun, upgradeID string, okStatus business.UpgradeStatus) (func(*cpTypes.Event), func()) {
	onComplete := func(event *cpTypes.Event) {
		switch event.Type {
		case cpTypes.EventCommandCompleted:
			if updErr := s.upgradeStore.UpdateUpgradeStatus(context.Background(), upgradeID,
				okStatus, ""); updErr != nil {
				s.logger.Warn("Failed to mark "+noun+" committed",
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
				s.logger.Warn("Failed to mark "+noun+" failed",
					"upgrade_id", upgradeID, "error", updErr)
			}
		}
	}
	onTimeout := func() {
		if updErr := s.upgradeStore.UpdateUpgradeStatus(context.Background(), upgradeID,
			business.UpgradeStatusFailed, "command timed out"); updErr != nil {
			s.logger.Warn("Failed to mark "+noun+" failed on timeout",
				"upgrade_id", upgradeID, "error", updErr)
		}
	}
	return onComplete, onTimeout
}

// validateDispatchRequest checks the required fields and their formats, writing a
// 400 response on the first failure.
func (s *Server) validateDispatchRequest(w http.ResponseWriter, req dispatchUpgradeRequest) bool {
	if req.Selector == "" || req.Version == "" || req.Platform == "" || req.Arch == "" {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"selector, version, platform, and arch are required",
			"MISSING_FIELDS")
		return false
	}
	if !stewardBinaryVersionRe.MatchString(req.Version) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Invalid version: "+logging.SanitizeLogValue(req.Version)+"; must match ^v\\d+\\.\\d+\\.\\d+(-[a-zA-Z0-9][a-zA-Z0-9.-]*)?",
			"INVALID_VERSION")
		return false
	}
	if !validPlatforms[req.Platform] {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Unknown platform: "+logging.SanitizeLogValue(req.Platform)+"; valid values: windows, darwin, linux",
			"INVALID_PLATFORM")
		return false
	}
	if !validArchs[req.Arch] {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Unknown arch: "+logging.SanitizeLogValue(req.Arch)+"; valid values: amd64, arm64",
			"INVALID_ARCH")
		return false
	}
	return true
}

// scopeDispatchSelector parses the selector and applies the tenant subtree scope.
// An explicit selector prefix must be within the caller's subtree; absent prefix
// defaults to callerTenantID and all descendants. An empty callerTenantID (mTLS
// admin) is unrestricted.
func (s *Server) scopeDispatchSelector(w http.ResponseWriter, r *http.Request, expr, callerTenantID string) (fleet.Filter, bool) {
	filter, parsedTenantPath, err := selector.Parse(expr)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Invalid selector: "+err.Error(),
			"INVALID_SELECTOR")
		return filter, false
	}
	if parsedTenantPath != "" {
		if access := s.tenantAccessForScope(r.Context(), callerTenantScope(r), parsedTenantPath, "POST /api/v1/stewards/upgrade"); access != tenantAuthAllowed {
			if !s.writeTenantCrossingIfNeeded(w, access, parsedTenantPath) {
				s.writeErrorResponse(w, http.StatusForbidden,
					"Target tenant is outside the caller's authorized subtree", "CROSS_TENANT")
			}
			return filter, false
		}
		filter.TenantSubtree = parsedTenantPath
	} else if callerTenantID != "" { //architecture:allow-root-scope -- selector narrowing for tenant callers; the matched stewards then pass authorizeFleetTargets
		s.scopeFilterToTenantSubtree(r.Context(), &filter, callerTenantID)
	}
	return filter, true
}

// resolveDispatchStewards resolves the filter against the fleet and applies the
// per-steward tenant decision.
func (s *Server) resolveDispatchStewards(w http.ResponseWriter, r *http.Request, filter fleet.Filter) ([]fleet.StewardResult, bool) {
	stewards, err := s.fleetQuery.Search(r.Context(), filter)
	if err != nil {
		s.logger.Error("Fleet query failed during upgrade dispatch", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Fleet query failed", "FLEET_QUERY_ERROR")
		return nil, false
	}

	if len(stewards) == 0 {
		s.writeErrorResponse(w, http.StatusForbidden,
			"No stewards match the given selector within the caller's tenant scope",
			"CROSS_TENANT")
		return nil, false
	}
	// An upgrade replaces every matched steward's binary: each one's tenant must
	// pass the caller's tenant decision, crossing included (Issue #4665).
	if !s.authorizeFleetTargets(w, r, stewards, "POST /api/v1/stewards/upgrade") {
		return nil, false
	}
	return stewards, true
}

// rejectConcurrentUpgrade writes a 409/500 and returns true when the steward has a
// non-terminal upgrade record or the lookup fails.
func (s *Server) rejectConcurrentUpgrade(w http.ResponseWriter, r *http.Request, stewardID string) bool {
	existing, listErr := s.upgradeStore.ListUpgradesBySteward(r.Context(), stewardID)
	if listErr != nil {
		s.logger.Error("Failed to list upgrades for steward",
			"error", listErr,
			"steward_id", logging.SanitizeLogValue(stewardID))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to check existing upgrades", "LIST_UPGRADES_ERROR")
		return true
	}
	for _, rec := range existing {
		if !isTerminalUpgradeStatus(rec.Status) {
			s.writeErrorResponse(w, http.StatusConflict,
				fmt.Sprintf("Steward %s has a non-terminal upgrade in progress (status: %s)", logging.SanitizeLogValue(stewardID), rec.Status),
				"CONCURRENT_UPGRADE")
			return true
		}
	}
	return false
}

// createDispatchRecords rejects concurrent upgrades and creates one UpgradeRecord
// per matched steward. For single-steward dispatch (id:) this is one record.
func (s *Server) createDispatchRecords(w http.ResponseWriter, r *http.Request, stewards []fleet.StewardResult, req dispatchUpgradeRequest, callerTenantID, callerUserID string, bin approvedBinary) ([]createdUpgrade, bool) {
	var created []createdUpgrade
	for _, st := range stewards {
		if s.rejectConcurrentUpgrade(w, r, st.ID) {
			return nil, false
		}

		// Generate nonce for replay defense.
		nonce := make([]byte, 32)
		if _, nErr := rand.Read(nonce); nErr != nil {
			s.logger.Error("Failed to generate operation nonce", "error", nErr)
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to generate nonce", "NONCE_ERROR")
			return nil, false
		}

		// Record tenant: scoped callers are bound to their own tenant (== steward tenant by
		// the isolation filter). Admin callers (empty tenant) attribute each record to
		// the target steward's tenant so per-tenant status/rollback isolation keeps working
		// (Issue #1999).
		recordTenantID := callerTenantID
		authMethod := "api_key"
		if callerTenantID == "" { //architecture:allow-root-scope -- record attribution, not an access decision
			recordTenantID = st.TenantID
			authMethod = "mtls_admin"
		}

		upgradeID := uuid.New().String()
		record := newDispatchedUpgradeRecord(upgradeID, upgradeRecordSpec{
			stewardID:  st.ID,
			tenantID:   recordTenantID,
			version:    req.Version,
			platform:   req.Platform,
			arch:       req.Arch,
			authMethod: authMethod,
			userID:     callerUserID,
			bin:        bin,
			nonce:      nonce,
		})
		if createErr := s.upgradeStore.CreateUpgrade(r.Context(), record); createErr != nil {
			s.logger.Error("Failed to create upgrade record",
				"error", logging.SanitizeLogValue(createErr.Error()),
				"steward_id", logging.SanitizeLogValue(st.ID))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to record upgrade", "CREATE_RECORD_ERROR")
			return nil, false
		}
		created = append(created, createdUpgrade{stewardID: st.ID, upgradeID: upgradeID})
	}
	return created, true
}

// fanOutUpgradeCommands publishes CommandPushStewardBinary to every created
// record's steward in the background, with completion callbacks so the record
// advances from dispatched to committed (success) or failed (error/timeout).
func (s *Server) fanOutUpgradeCommands(created []createdUpgrade, params map[string]interface{}, version string) {
	// #nosec G118 -- persisted upgrade commands intentionally outlive the
	// HTTP request; each publisher call has a fixed two-minute deadline.
	go func() {
		for _, entry := range created {
			upgradeID := entry.upgradeID
			stewardID := entry.stewardID
			onComplete, onTimeout := s.upgradeCallbacks("upgrade", upgradeID, business.UpgradeStatusCommitted)
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
					"error", logging.SanitizeLogValue(pubErr.Error()),
					"steward_id", logging.SanitizeLogValue(stewardID),
					"upgrade_id", upgradeID)
				_ = s.upgradeStore.UpdateUpgradeStatus(context.Background(), upgradeID,
					business.UpgradeStatusFailed, pubErr.Error())
			} else {
				s.logger.Info("CommandPushStewardBinary dispatched",
					"steward_id", logging.SanitizeLogValue(stewardID),
					"upgrade_id", upgradeID,
					"version", logging.SanitizeLogValue(version))
			}
		}
	}()
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

	// An empty callerTenantID (mTLS admin) yields an unscoped fleet search; the
	// per-tenant isolation filter below is skipped for admins. Only a NON-admin caller
	// with no tenant is a genuine auth failure (Issue #1999, same pattern as #1990).
	_, callerTenantID, ok := s.authRunAccess(w, r)
	if !ok {
		return
	}
	callerUserID, _ := r.Context().Value(ctxkeys.UserIDKey).(string)
	// The blob store requires a non-empty tenant; admins (empty tenant) read the binary
	// from and key the upgrade record under the "default" namespace, matching the publish
	// path's installerBlobTenant fallback (Issue #1999).
	blobTenantID := installerBlobTenant(callerTenantID)

	var req dispatchUpgradeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Warn("Failed to decode dispatch upgrade body", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_BODY")
		return
	}
	if !s.validateDispatchRequest(w, req) {
		return
	}

	filter, ok := s.scopeDispatchSelector(w, r, req.Selector, callerTenantID)
	if !ok {
		return
	}
	stewards, ok := s.resolveDispatchStewards(w, r, filter)
	if !ok {
		return
	}

	bin, ok := s.loadApprovedBinary(w, r, blobTenantID, req.Version, req.Platform, req.Arch, approvedBinaryMessages{
		notFound:    "Steward binary not found",
		getLog:      "Failed to retrieve steward binary",
		readLog:     "Failed to read steward binary for SHA-256 recompute",
		notApproved: "Binary has not been approved; transition from published to approved state is required before dispatch",
		sigLog:      "Failed to decode bundle signature from blob label",
	})
	if !ok {
		return
	}

	created, ok := s.createDispatchRecords(w, r, stewards, req, callerTenantID, callerUserID, bin)
	if !ok {
		return
	}

	// Return upgrade_id as the first record's ID (single-steward: maps directly to the record).
	returnUpgradeID := created[0].upgradeID

	if s.commandPublisher != nil {
		params := s.pushStewardBinaryParams(req.Version, req.Platform, req.Arch, blobTenantID, bin)
		s.fanOutUpgradeCommands(created, params, req.Version)
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

	// An empty callerTenantID (mTLS admin) has unrestricted access; only a NON-admin
	// caller with no tenant is a genuine auth failure (Issue #1999, same pattern as #1990).
	_, _, ok := s.authRunAccess(w, r)
	if !ok {
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
			"error", logging.SanitizeLogValue(err.Error()),
			"upgrade_id", logging.SanitizeLogValue(upgradeID))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve upgrade record", "GET_RECORD_ERROR")
		return
	}

	// Tenant isolation: callers scoped to a tenant can only view records within their
	// authorized subtree; a root caller subject to the ADR-025 boundary needs a
	// crossing for a client tenant's record. 404 instead of 403 to avoid disclosing
	// upgrade record existence across tenants (Issue #4091) — mirrors the genuine
	// not-found response above.
	if !s.authorizeRecordRead(w, r, record.TenantID, "GET /api/v1/stewards/upgrade/{upgrade_id}", func() {
		s.writeErrorResponse(w, http.StatusNotFound, "Upgrade record not found", "UPGRADE_NOT_FOUND")
	}) {
		return
	}

	s.writeSuccessResponse(w, record)
}

// loadRollbackOriginal looks up the original upgrade record and enforces tenant
// isolation: callers scoped to a tenant can only roll back records within their
// authorized subtree; an empty callerTenantID (mTLS admin) has unrestricted access.
// 404 instead of 403 to avoid disclosing upgrade record existence across tenants
// (Issue #4091) — mirrors the genuine not-found response.
func (s *Server) loadRollbackOriginal(w http.ResponseWriter, r *http.Request, upgradeID string) (*business.UpgradeRecord, bool) {
	original, err := s.upgradeStore.GetUpgrade(r.Context(), upgradeID)
	if err != nil {
		if errors.Is(err, business.ErrUpgradeNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "Upgrade record not found", "UPGRADE_NOT_FOUND")
			return nil, false
		}
		s.logger.Error("Failed to retrieve upgrade record for rollback", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve upgrade record", "GET_RECORD_ERROR")
		return nil, false
	}
	if access := s.tenantAccessForScope(r.Context(), callerTenantScope(r), original.TenantID, "POST /api/v1/stewards/upgrade/{upgrade_id}/rollback"); access != tenantAuthAllowed {
		if !s.writeTenantCrossingIfNeeded(w, access, original.TenantID) {
			s.writeErrorResponse(w, http.StatusNotFound, "Upgrade record not found", "UPGRADE_NOT_FOUND")
		}
		return nil, false
	}
	return original, true
}

// decodeRollbackRequest decodes and validates the rollback body, writing a 400
// response on failure.
func (s *Server) decodeRollbackRequest(w http.ResponseWriter, r *http.Request) (rollbackRequest, bool) {
	var req rollbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_BODY")
		return req, false
	}
	if req.Version == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "version is required for rollback", "MISSING_VERSION")
		return req, false
	}
	if !stewardBinaryVersionRe.MatchString(req.Version) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Invalid version: "+logging.SanitizeLogValue(req.Version)+"; must match ^v\\d+\\.\\d+\\.\\d+(-[a-zA-Z0-9][a-zA-Z0-9.-]*)?",
			"INVALID_VERSION")
		return req, false
	}
	return req, true
}

// createRollbackRecord creates the dispatched rollback UpgradeRecord for the
// original record's steward and returns its ID.
func (s *Server) createRollbackRecord(w http.ResponseWriter, r *http.Request, original *business.UpgradeRecord, version, callerTenantID, callerUserID string, bin approvedBinary) (string, bool) {
	nonce := make([]byte, 32)
	if _, nErr := rand.Read(nonce); nErr != nil {
		s.logger.Error("Failed to generate operation nonce for rollback", "error", nErr)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to generate nonce", "NONCE_ERROR")
		return "", false
	}

	// Record tenant: the rollback record is attributed to the original record's tenant for
	// admin callers (empty tenant) and to the caller's tenant for tenant-scoped callers
	// (== original tenant by the isolation check), so per-tenant status/listing
	// stays consistent (Issue #1999).
	effectiveTenantID := callerTenantID
	rollbackAuthMethod := "api_key"
	if callerTenantID == "" { //architecture:allow-root-scope -- record attribution, not an access decision
		effectiveTenantID = original.TenantID
		rollbackAuthMethod = "mtls_admin"
	}
	rollbackUpgradeID := uuid.New().String()
	record := newDispatchedUpgradeRecord(rollbackUpgradeID, upgradeRecordSpec{
		stewardID:  original.StewardID,
		tenantID:   effectiveTenantID,
		version:    version,
		platform:   original.Platform,
		arch:       original.Arch,
		authMethod: rollbackAuthMethod,
		userID:     callerUserID,
		bin:        bin,
		nonce:      nonce,
	})
	if createErr := s.upgradeStore.CreateUpgrade(r.Context(), record); createErr != nil {
		s.logger.Error("Failed to create rollback upgrade record",
			"error", logging.SanitizeLogValue(createErr.Error()),
			"steward_id", logging.SanitizeLogValue(original.StewardID))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to record rollback upgrade", "CREATE_RECORD_ERROR")
		return "", false
	}
	return rollbackUpgradeID, true
}

// publishRollbackCommand sends CommandPushStewardBinary for the rollback target in
// the background.
func (s *Server) publishRollbackCommand(stewardID, rollbackUpgradeID, version string, params map[string]interface{}) {
	// #nosec G118 -- persisted rollback dispatch intentionally outlives the
	// HTTP request; the publisher call has a fixed two-minute deadline.
	go func() {
		onComplete, onTimeout := s.upgradeCallbacks("rollback", rollbackUpgradeID, business.UpgradeStatusRolledBack)
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
				"error", logging.SanitizeLogValue(pubErr.Error()),
				"steward_id", logging.SanitizeLogValue(stewardID),
				"rollback_upgrade_id", rollbackUpgradeID)
			_ = s.upgradeStore.UpdateUpgradeStatus(context.Background(), rollbackUpgradeID,
				business.UpgradeStatusFailed, pubErr.Error())
		} else {
			s.logger.Info("Rollback CommandPushStewardBinary dispatched",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"rollback_upgrade_id", rollbackUpgradeID,
				"version", logging.SanitizeLogValue(version))
		}
	}()
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

	// An empty callerTenantID (mTLS admin) has unrestricted rollback access; only a
	// NON-admin caller with no tenant is a genuine auth failure (Issue #1999).
	_, callerTenantID, ok := s.authRunAccess(w, r)
	if !ok {
		return
	}
	callerUserID, _ := r.Context().Value(ctxkeys.UserIDKey).(string)

	upgradeID := mux.Vars(r)["upgrade_id"]
	if upgradeID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "upgrade_id is required", "MISSING_UPGRADE_ID")
		return
	}

	// Look up original upgrade record to get steward/tenant/platform/arch.
	original, ok := s.loadRollbackOriginal(w, r, upgradeID)
	if !ok {
		return
	}
	// Blob namespace: the rollback binary is read from the caller's namespace, the same place
	// the caller publishes to — scoped callers from their own tenant, admins from "default"
	// (the blob store requires a non-empty tenant; matches installerBlobTenant) — Issue #1999.
	rollbackBlobTenant := installerBlobTenant(callerTenantID)

	req, ok := s.decodeRollbackRequest(w, r)
	if !ok {
		return
	}

	bin, ok := s.loadApprovedBinary(w, r, rollbackBlobTenant, req.Version, original.Platform, original.Arch, approvedBinaryMessages{
		notFound:    "Rollback binary not found",
		getLog:      "Failed to retrieve rollback binary",
		readLog:     "Failed to read rollback binary for SHA-256 recompute",
		notApproved: "Rollback binary has not been approved",
		sigLog:      "Failed to decode bundle signature for rollback",
	})
	if !ok {
		return
	}

	rollbackUpgradeID, ok := s.createRollbackRecord(w, r, original, req.Version, callerTenantID, callerUserID, bin)
	if !ok {
		return
	}

	if s.commandPublisher != nil {
		params := s.pushStewardBinaryParams(req.Version, original.Platform, original.Arch, rollbackBlobTenant, bin)
		s.publishRollbackCommand(original.StewardID, rollbackUpgradeID, req.Version, params)
	}

	s.writeResponse(w, http.StatusAccepted, dispatchUpgradeResponse{
		UpgradeID:    rollbackUpgradeID,
		StewardCount: 1,
		Status:       "accepted",
	})
}
