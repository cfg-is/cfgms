// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	blob "github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
)

// validPlatforms is the allow-list of supported installer platforms (Issue #1702).
var validPlatforms = map[string]bool{
	"windows": true,
	"darwin":  true,
	"linux":   true,
}

// validArchs is the allow-list of supported installer architectures (Issue #1702).
var validArchs = map[string]bool{
	"amd64": true,
	"arm64": true,
}

// installerUploadResponse is the JSON body returned by PUT /api/v1/installer/artifacts/{platform}/{arch}.
type installerUploadResponse struct {
	Platform string `json:"platform"`
	Arch     string `json:"arch"`
	Size     int64  `json:"size"`
	Checksum string `json:"checksum"`
}

// installerArtifactInfo is one element in the list/get response for installer artifact endpoints.
type installerArtifactInfo struct {
	Platform    string `json:"platform"`
	Arch        string `json:"arch"`
	Size        int64  `json:"size"`
	Checksum    string `json:"checksum"`
	ContentType string `json:"content_type"`
}

// handleUploadInstallerArtifact handles PUT /api/v1/installer/artifacts/{platform}/{arch}.
// Stores the request body as an installer artifact in the BlobStore under
// Namespace "installers", Name "<platform>-<arch>". Returns 200 with the
// computed size and SHA-256 checksum on success.
func (s *Server) handleUploadInstallerArtifact(w http.ResponseWriter, r *http.Request) {
	if s.blobStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Installer storage not available", "SERVICE_UNAVAILABLE")
		return
	}
	tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	vars := mux.Vars(r)
	platform := vars["platform"]
	arch := vars["arch"]

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

	key := blob.BlobKey{
		TenantID:  tenantID,
		Namespace: "installers",
		Name:      platform + "-" + arch,
	}

	if err := s.blobStore.PutBlob(r.Context(), key, r.Body, blob.BlobMeta{ContentType: "application/octet-stream"}); err != nil {
		s.logger.Error("Failed to store installer artifact",
			"error", err,
			"platform", logging.SanitizeLogValue(platform),
			"arch", logging.SanitizeLogValue(arch))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to store artifact", "STORE_ERROR")
		return
	}

	// Retrieve stored metadata (size + checksum computed by provider during PutBlob).
	rc, storedMeta, err := s.blobStore.GetBlob(r.Context(), key)
	if err != nil {
		s.logger.Error("Failed to retrieve stored artifact metadata",
			"error", err,
			"platform", logging.SanitizeLogValue(platform),
			"arch", logging.SanitizeLogValue(arch))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve artifact metadata", "METADATA_ERROR")
		return
	}
	// Close without reading content — the metadata sidecar is populated by PutBlob.
	_ = rc.Close()

	s.writeSuccessResponse(w, installerUploadResponse{
		Platform: platform,
		Arch:     arch,
		Size:     storedMeta.Size,
		Checksum: storedMeta.Checksum,
	})
}

// handleListInstallerArtifacts handles GET /api/v1/installer/artifacts.
// Returns the list of installer artifacts for the authenticated tenant.
func (s *Server) handleListInstallerArtifacts(w http.ResponseWriter, r *http.Request) {
	if s.blobStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Installer storage not available", "SERVICE_UNAVAILABLE")
		return
	}
	tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	blobs, err := s.blobStore.ListBlobs(r.Context(), blob.BlobKey{
		TenantID:  tenantID,
		Namespace: "installers",
	})
	if err != nil {
		s.logger.Error("Failed to list installer artifacts", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list artifacts", "LIST_ERROR")
		return
	}

	artifacts := make([]installerArtifactInfo, 0, len(blobs))
	for _, b := range blobs {
		platform, arch, ok := parseInstallerName(b.Key.Name)
		if !ok {
			continue
		}
		artifacts = append(artifacts, installerArtifactInfo{
			Platform:    platform,
			Arch:        arch,
			Size:        b.Meta.Size,
			Checksum:    b.Meta.Checksum,
			ContentType: b.Meta.ContentType,
		})
	}

	s.writeSuccessResponse(w, artifacts)
}

// handleGetInstallerArtifact handles GET /api/v1/installer/artifacts/{platform}/{arch}.
// Returns the metadata for a single installer artifact. Returns 404 when absent.
func (s *Server) handleGetInstallerArtifact(w http.ResponseWriter, r *http.Request) {
	if s.blobStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Installer storage not available", "SERVICE_UNAVAILABLE")
		return
	}
	tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	vars := mux.Vars(r)
	platform := vars["platform"]
	arch := vars["arch"]

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

	key := blob.BlobKey{
		TenantID:  tenantID,
		Namespace: "installers",
		Name:      platform + "-" + arch,
	}

	rc, meta, err := s.blobStore.GetBlob(r.Context(), key)
	if err != nil {
		if errors.Is(err, blob.ErrBlobNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "Artifact not found", "ARTIFACT_NOT_FOUND")
			return
		}
		s.logger.Error("Failed to get installer artifact",
			"error", err,
			"platform", logging.SanitizeLogValue(platform),
			"arch", logging.SanitizeLogValue(arch))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get artifact", "GET_ERROR")
		return
	}
	// Metadata is read from the sidecar; close the content reader without streaming it.
	_ = rc.Close()

	s.writeSuccessResponse(w, installerArtifactInfo{
		Platform:    platform,
		Arch:        arch,
		Size:        meta.Size,
		Checksum:    meta.Checksum,
		ContentType: meta.ContentType,
	})
}

// handleDeleteInstallerArtifact handles DELETE /api/v1/installer/artifacts/{platform}/{arch}.
// Removes the installer artifact. Returns 204 on success (including when it did not exist).
func (s *Server) handleDeleteInstallerArtifact(w http.ResponseWriter, r *http.Request) {
	if s.blobStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Installer storage not available", "SERVICE_UNAVAILABLE")
		return
	}
	tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	vars := mux.Vars(r)
	platform := vars["platform"]
	arch := vars["arch"]

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

	key := blob.BlobKey{
		TenantID:  tenantID,
		Namespace: "installers",
		Name:      platform + "-" + arch,
	}

	if err := s.blobStore.DeleteBlob(r.Context(), key); err != nil {
		s.logger.Error("Failed to delete installer artifact",
			"error", err,
			"platform", logging.SanitizeLogValue(platform),
			"arch", logging.SanitizeLogValue(arch))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete artifact", "DELETE_ERROR")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// parseInstallerName splits a blob name like "windows-amd64" into ("windows", "amd64", true).
// Returns ("", "", false) for names that do not match a known platform-arch combination.
func parseInstallerName(name string) (platform, arch string, ok bool) {
	for p := range validPlatforms {
		for a := range validArchs {
			if name == p+"-"+a {
				return p, a, true
			}
		}
	}
	return "", "", false
}
