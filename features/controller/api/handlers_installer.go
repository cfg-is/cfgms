// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/initialization"
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
	if tenantID == downloadTenantID {
		s.publicDownloadCache.invalidate(installerDownloadCacheKey(platform, arch))
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
	if tenantID == downloadTenantID {
		s.publicDownloadCache.invalidate(installerDownloadCacheKey(platform, arch))
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

// downloadTenantID is the fixed tenant used to look up installer artifacts for public download.
// Installer artifacts intended for public distribution must be uploaded by the root tenant.
const downloadTenantID = "root"

func installerDownloadCacheKey(platform, arch string) string {
	return "installer/" + platform + "/" + arch
}

// caIsPrivate reports whether the controller is using a private (self-signed) CA.
// When the cert manager is unavailable or the CA cannot be verified, it logs a warning
// and returns false — a controller that cannot determine its CA type must not assert "private."
func (s *Server) caIsPrivate() bool {
	if s.certManager == nil {
		s.logger.Warn("cert manager not available; skipping CA bundle in install package")
		return false
	}
	caCertPEM, err := s.certManager.GetCACertificate()
	if err != nil {
		s.logger.Warn("failed to read CA certificate from cert manager; skipping CA bundle", "error", err)
		return false
	}
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		s.logger.Warn("CA certificate PEM is invalid; skipping CA bundle")
		return false
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		s.logger.Warn("failed to parse CA certificate; skipping CA bundle", "error", err)
		return false
	}
	// A self-signed CA has identical raw issuer and subject bytes, indicating a private
	// CA controlled by this controller. Publicly-trusted CAs are signed by a root authority
	// with different issuer and subject fields.
	return bytes.Equal(caCert.RawIssuer, caCert.RawSubject)
}

// handleDownloadInstallPackage handles GET /api/v1/installer/download/{platform}/{arch}.
// Assembles a tar.gz containing the installer artifact and, when the controller uses a
// private CA, the CA certificate and SHA-256 fingerprint. No authentication required —
// the download URL is the distribution mechanism (Issue #1704).
func (s *Server) handleDownloadInstallPackage(w http.ResponseWriter, r *http.Request) {
	if s.blobStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Installer storage not available", "SERVICE_UNAVAILABLE")
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

	archiveName := fmt.Sprintf("cfgms-steward-%s-%s.tar.gz", platform, arch)
	asset, err := s.publicDownloadCache.getOrBuild(
		r.Context(),
		installerDownloadCacheKey(platform, arch),
		func() (*publicDownloadAsset, error) {
			return s.buildInstallPackage(r, platform, arch, archiveName)
		},
	)
	if err != nil {
		switch {
		case errors.Is(err, blob.ErrBlobNotFound):
			s.writeErrorResponse(w, http.StatusNotFound, "Installer artifact not found", "ARTIFACT_NOT_FOUND")
		case errors.Is(err, errPublicDownloadTooLarge):
			s.writeErrorResponse(w, http.StatusRequestEntityTooLarge, "Installer artifact too large", "ARTIFACT_TOO_LARGE")
		default:
			s.logger.Error("Failed to build installer artifact for public download",
				"error", err,
				"platform", logging.SanitizeLogValue(platform),
				"arch", logging.SanitizeLogValue(arch))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to build install package", "BUILD_ERROR")
		}
		return
	}
	servePublicDownload(w, r, archiveName, asset)
}

func (s *Server) buildInstallPackage(
	r *http.Request,
	platform, arch, archiveName string,
) (*publicDownloadAsset, error) {
	key := blob.BlobKey{
		TenantID:  downloadTenantID,
		Namespace: "installers",
		Name:      platform + "-" + arch,
	}
	rc, meta, err := s.blobStore.GetBlob(r.Context(), key)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := rc.Close(); cerr != nil {
			s.logger.Warn("failed to close installer artifact reader", "error", cerr)
		}
	}()
	if meta.Size > maxBinaryRequestBodyBytes {
		return nil, errPublicDownloadTooLarge
	}
	artifactBytes, err := io.ReadAll(io.LimitReader(rc, maxBinaryRequestBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read installer artifact: %w", err)
	}
	if int64(len(artifactBytes)) > maxBinaryRequestBodyBytes {
		return nil, errPublicDownloadTooLarge
	}

	var caCertPEM []byte
	var caFingerprint string
	if s.caIsPrivate() {
		caCertPEM, err = s.certManager.GetCACertificate()
		if err != nil {
			return nil, fmt.Errorf("read private CA: %w", err)
		}
		if s.cfg.Certificate == nil || s.cfg.Certificate.CAPath == "" {
			return nil, errors.New("private CA path is not configured")
		}
		marker, markerErr := initialization.ReadInitMarker(s.cfg.Certificate.CAPath)
		if markerErr != nil {
			return nil, fmt.Errorf("read CA fingerprint: %w", markerErr)
		}
		caFingerprint = marker.CAFingerprint
	}

	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzWriter)
	artifactPath := "installer/" + platform + "-" + arch + "/" + installerFilename(platform, arch)
	files := []struct {
		path string
		data []byte
	}{{artifactPath, artifactBytes}}
	if caCertPEM != nil {
		files = append(files,
			struct {
				path string
				data []byte
			}{"installer/ca.crt", caCertPEM},
			struct {
				path string
				data []byte
			}{"installer/ca.fingerprint", []byte(caFingerprint)},
		)
	}
	files = append(files, struct {
		path string
		data []byte
	}{"installer/README.txt", []byte(readmeText(platform, arch))})
	for _, file := range files {
		if err := addTarFile(tw, file.path, file.data); err != nil {
			return nil, fmt.Errorf("write %s to installer archive: %w", file.path, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close installer tar: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		return nil, fmt.Errorf("close installer gzip: %w", err)
	}

	return newPublicDownloadAsset(
		buf.Bytes(),
		"application/gzip",
		fmt.Sprintf(`attachment; filename="%s"`, archiveName),
		"public, max-age=300, must-revalidate",
	), nil
}

// installerFilename returns the filename for the installer binary within the package archive.
func installerFilename(platform, arch string) string {
	if platform == "windows" {
		return "cfgms-steward-" + arch + ".exe"
	}
	return "cfgms-steward-" + arch
}

// readmeText returns a one-line platform-specific install instruction.
func readmeText(platform, arch string) string {
	switch platform {
	case "windows":
		return "Run cfgms-steward-" + arch + ".exe as Administrator to install the CFGMS steward agent."
	case "darwin":
		return "Run: sudo ./cfgms-steward-" + arch + " to install the CFGMS steward agent."
	default:
		return "Run: sudo ./cfgms-steward-" + arch + " to install the CFGMS steward agent."
	}
}

// addTarFile writes a single file entry to a tar archive.
func addTarFile(tw *tar.Writer, path string, content []byte) error {
	if err := tw.WriteHeader(&tar.Header{
		Name: path,
		Mode: 0644,
		Size: int64(len(content)),
		// Generated packages must be byte-stable so validators, range retries,
		// and the response cache all refer to one representation.
		ModTime: time.Unix(0, 0).UTC(),
	}); err != nil {
		return err
	}
	_, err := tw.Write(content)
	return err
}
