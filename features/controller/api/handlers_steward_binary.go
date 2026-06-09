// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"regexp"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
	blob "github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
)

// stewardBinaryVersionRe validates semantic version strings like v0.5.12.
var stewardBinaryVersionRe = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// stewardBinaryPublishResponse is the JSON body returned by POST /api/v1/installer/steward-binaries/{version}/{platform}/{arch}.
type stewardBinaryPublishResponse struct {
	Version         string `json:"version"`
	Platform        string `json:"platform"`
	Arch            string `json:"arch"`
	Size            int64  `json:"size"`
	SHA256          string `json:"sha256"`
	PublishedBy     string `json:"published_by"`
	Publisher       string `json:"publisher"`
	SignatureDigest string `json:"signature_digest"`
}

// stewardBinaryTrust returns the trust store used for steward binary signature verification.
// Uses the server-level override when set (injected in tests); otherwise constructs a
// fresh store seeded with CFGMSPublisherIdentity.
func (s *Server) stewardBinaryTrust() trust.TrustStore {
	if s.stewardBinaryTrustStore != nil {
		return s.stewardBinaryTrustStore
	}
	store := trust.NewInMemoryTrustStore()
	_ = store.AddPublisher(trust.CFGMSPublisherIdentity())
	return store
}

// stewardBinaryBlobKey builds the BlobKey for a steward binary within the steward-binaries namespace.
// Name format: "{version}-{platform}-{arch}" (e.g. "v0.5.12-linux-amd64").
// The blob key Name must not contain "/" — the filesystem provider rejects path separators.
func stewardBinaryBlobKey(tenantID, version, platform, arch string) blob.BlobKey {
	return blob.BlobKey{
		TenantID:  tenantID,
		Namespace: "steward-binaries",
		Name:      version + "-" + platform + "-" + arch,
	}
}

// handlePublishStewardBinary handles POST /api/v1/installer/steward-binaries/{version}/{platform}/{arch}.
// Verifies the Ed25519 publisher signature against CFGMSPublisherIdentity before storing the blob.
// Returns 400 if signature is absent or invalid, 409 if the binary already exists (use ?force=true to overwrite).
func (s *Server) handlePublishStewardBinary(w http.ResponseWriter, r *http.Request) {
	if s.blobStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Binary storage not available", "SERVICE_UNAVAILABLE")
		return
	}
	tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	vars := mux.Vars(r)
	version := vars["version"]
	platform := vars["platform"]
	arch := vars["arch"]

	if !stewardBinaryVersionRe.MatchString(version) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Invalid version: "+logging.SanitizeLogValue(version)+"; must match ^v\\d+\\.\\d+\\.\\d+",
			"INVALID_VERSION")
		return
	}
	if !validPlatforms[platform] {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Unknown platform: "+logging.SanitizeLogValue(platform)+"; valid values: windows, darwin, linux",
			"INVALID_PLATFORM")
		return
	}
	if !validArchs[arch] {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Unknown arch: "+logging.SanitizeLogValue(arch)+"; valid values: amd64, arm64",
			"INVALID_ARCH")
		return
	}

	// Require a publisher signature — unsigned uploads are rejected.
	sigBase64 := r.URL.Query().Get("signature")
	if sigBase64 == "" {
		// Also check multipart form field (used when binary is uploaded as multipart).
		if parseErr := r.ParseMultipartForm(32 << 20); parseErr == nil {
			sigBase64 = r.FormValue("signature")
		}
	}
	if sigBase64 == "" {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Signature required; provide ?signature=<base64> or a multipart 'signature' field",
			"SIGNATURE_REQUIRED")
		return
	}

	// Signature is URL-safe base64 (no padding) so it survives query-param sanitization.
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigBase64)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Invalid signature encoding; must be URL-safe base64 (no padding)",
			"INVALID_SIGNATURE_ENCODING")
		return
	}

	// Buffer the binary body to compute SHA-256 for signature verification.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Error("Failed to read request body", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read request body", "READ_ERROR")
		return
	}

	sum := sha256.Sum256(body)
	contentHash := hex.EncodeToString(sum[:])

	// Verify the publisher signature. The Ed25519 message is the UTF-8 bytes of contentHash.
	b := bundle.Bundle{ContentHash: contentHash}
	sig := bundle.BundleSignature{
		Publisher: "cfgms",
		Algorithm: "ed25519",
		Signature: sigBytes,
	}
	if verifyErr := trust.VerifyBundleSignature(&b, sig, s.stewardBinaryTrust()); verifyErr != nil {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Signature verification failed: "+verifyErr.Error(),
			"SIGNATURE_VERIFICATION_FAILED")
		return
	}

	key := stewardBinaryBlobKey(tenantID, version, platform, arch)

	// Enforce 409 Conflict on duplicate unless ?force=true.
	if r.URL.Query().Get("force") != "true" {
		existing, _, lookupErr := s.blobStore.GetBlob(r.Context(), key)
		if lookupErr == nil {
			_ = existing.Close()
			s.writeErrorResponse(w, http.StatusConflict,
				"Steward binary already exists for this version/platform/arch; use --force to overwrite",
				"DUPLICATE_BINARY")
			return
		}
		if !errors.Is(lookupErr, blob.ErrBlobNotFound) {
			s.logger.Error("Failed to check for existing steward binary",
				"error", lookupErr,
				"version", logging.SanitizeLogValue(version),
				"platform", logging.SanitizeLogValue(platform),
				"arch", logging.SanitizeLogValue(arch))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to check for existing binary", "CHECK_ERROR")
			return
		}
	}

	// Compute signature digest (SHA-256 of raw signature bytes) for the manifest.
	sigHashBytes := sha256.Sum256(sigBytes)
	sigDigest := hex.EncodeToString(sigHashBytes[:])

	// Operator identity from auth context.
	publishedBy, _ := r.Context().Value(ctxkeys.UserIDKey).(string)

	labels := map[string]string{
		"version":          version,
		"platform":         platform,
		"arch":             arch,
		"published_by":     publishedBy,
		"publisher":        "cfgms",
		"signature_digest": sigDigest,
		"signature":        base64.RawURLEncoding.EncodeToString(sigBytes),
		"publisher_tenant": tenantID,
	}
	// Issue #1948: auto-approve when test mode is active (CFGMS_SEED_TEST_API_KEYS=1 +
	// CFGMS_TEST_STEWARD_PUBLISHER_KEY set). Production binaries require a separate
	// approval step; this path is never reachable in production.
	if s.testAutoApproveStewardBinaries {
		labels["approved_by"] = "auto-approved-test"
	}
	meta := blob.BlobMeta{
		ContentType: "application/octet-stream",
		Labels:      labels,
	}

	if putErr := s.blobStore.PutBlob(r.Context(), key, bytes.NewReader(body), meta); putErr != nil {
		s.logger.Error("Failed to store steward binary",
			"error", putErr,
			"version", logging.SanitizeLogValue(version),
			"platform", logging.SanitizeLogValue(platform),
			"arch", logging.SanitizeLogValue(arch))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to store binary", "STORE_ERROR")
		return
	}

	// Retrieve stored metadata — provider populates Checksum and Size during PutBlob.
	rc, storedMeta, err := s.blobStore.GetBlob(r.Context(), key)
	if err != nil {
		s.logger.Error("Failed to retrieve stored steward binary metadata",
			"error", err,
			"version", logging.SanitizeLogValue(version),
			"platform", logging.SanitizeLogValue(platform),
			"arch", logging.SanitizeLogValue(arch))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve binary metadata", "METADATA_ERROR")
		return
	}
	_ = rc.Close()

	s.writeSuccessResponse(w, stewardBinaryPublishResponse{
		Version:         version,
		Platform:        platform,
		Arch:            arch,
		Size:            storedMeta.Size,
		SHA256:          storedMeta.Checksum,
		PublishedBy:     publishedBy,
		Publisher:       "cfgms",
		SignatureDigest: sigDigest,
	})
}

// handleGetStewardBinary handles GET /api/v1/installer/steward-binaries/{version}/{platform}/{arch}.
// Returns the raw binary stream. Returns 404 when the binary is absent for this tenant.
func (s *Server) handleGetStewardBinary(w http.ResponseWriter, r *http.Request) {
	if s.blobStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Binary storage not available", "SERVICE_UNAVAILABLE")
		return
	}
	tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	vars := mux.Vars(r)
	version := vars["version"]
	platform := vars["platform"]
	arch := vars["arch"]

	if !stewardBinaryVersionRe.MatchString(version) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Invalid version: "+logging.SanitizeLogValue(version)+"; must match ^v\\d+\\.\\d+\\.\\d+",
			"INVALID_VERSION")
		return
	}
	if !validPlatforms[platform] {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Unknown platform: "+logging.SanitizeLogValue(platform)+"; valid values: windows, darwin, linux",
			"INVALID_PLATFORM")
		return
	}
	if !validArchs[arch] {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Unknown arch: "+logging.SanitizeLogValue(arch)+"; valid values: amd64, arm64",
			"INVALID_ARCH")
		return
	}

	key := stewardBinaryBlobKey(tenantID, version, platform, arch)
	rc, meta, err := s.blobStore.GetBlob(r.Context(), key)
	if err != nil {
		if errors.Is(err, blob.ErrBlobNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "Steward binary not found", "BINARY_NOT_FOUND")
			return
		}
		s.logger.Error("Failed to get steward binary",
			"error", err,
			"version", logging.SanitizeLogValue(version),
			"platform", logging.SanitizeLogValue(platform),
			"arch", logging.SanitizeLogValue(arch))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get binary", "GET_ERROR")
		return
	}
	defer func() {
		if cerr := rc.Close(); cerr != nil {
			s.logger.Warn("failed to close steward binary reader", "error", cerr)
		}
	}()

	contentType := meta.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	if meta.Checksum != "" {
		w.Header().Set("X-CFGMS-SHA256", meta.Checksum)
	}
	w.WriteHeader(http.StatusOK)
	if _, copyErr := io.Copy(w, rc); copyErr != nil {
		s.logger.Warn("Failed to stream steward binary to client", "error", copyErr)
	}
}
