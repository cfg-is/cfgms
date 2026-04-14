// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces defines global storage contracts used by all CFGMS modules
package interfaces

import (
	"context"
	"io"
	"time"
)

// BlobStore defines the storage interface for large binary objects.
// Large artifacts (installer binaries, report archives, DNA snapshots) are stored
// and retrieved through this interface. Providers should stream large files for GetBlob.
// PutBlob providers may buffer to compute checksums; the filesystem provider streams
// via io.TeeReader while the S3 provider buffers for content-length negotiation.
type BlobStore interface {
	// PutBlob stores a blob from the given reader with the associated metadata.
	// The meta.ContentType defaults to "application/octet-stream" if empty.
	// Returns ErrBlobTenantRequired if key.TenantID is empty.
	PutBlob(ctx context.Context, key BlobKey, r io.Reader, meta BlobMeta) error

	// GetBlob retrieves a blob and its metadata as a streaming reader.
	// The caller must close the returned reader when done.
	// Returns ErrBlobNotFound if the key does not exist.
	// The reader computes SHA-256 during reads and returns ErrBlobChecksumMismatch
	// on the final Read call (at EOF) if the computed checksum does not match.
	GetBlob(ctx context.Context, key BlobKey) (io.ReadCloser, BlobMeta, error)

	// DeleteBlob removes a blob and its associated metadata.
	// Returns nil if the blob does not exist.
	DeleteBlob(ctx context.Context, key BlobKey) error

	// ListBlobs returns all blobs matching the given prefix fields.
	// A zero-value prefix field matches all values in that field:
	//   - setting only TenantID returns all blobs for that tenant
	//   - setting TenantID + Namespace returns all blobs in that namespace
	// TenantID must always be set.
	ListBlobs(ctx context.Context, prefix BlobKey) ([]BlobInfo, error)

	// BlobExists reports whether a blob exists for the given key.
	// Returns (false, nil) for a missing key — not an error.
	// Does not read the blob content.
	BlobExists(ctx context.Context, key BlobKey) (bool, error)

	// HealthCheck verifies the provider is reachable and operational.
	HealthCheck(ctx context.Context) error
}

// BlobKey uniquely identifies a blob within CFGMS.
// TenantID is mandatory. Namespace partitions blobs by category
// (e.g., "installers", "reports", "dna-snapshots").
type BlobKey struct {
	TenantID  string // Mandatory. Multi-tenant isolation.
	Namespace string // Category partition (e.g., "installers", "reports").
	Name      string // Blob name within the namespace.
}

// BlobMeta holds metadata associated with a stored blob.
type BlobMeta struct {
	ContentType string            // MIME type; defaults to "application/octet-stream" if empty.
	Size        int64             // Size in bytes, populated by the provider on write.
	Checksum    string            // SHA-256 hex digest of the blob content.
	CreatedAt   time.Time         // Time the blob was stored (set by provider).
	Labels      map[string]string // Optional key-value labels for organisation.
}

// BlobInfo combines a key and its metadata; returned by ListBlobs.
type BlobInfo struct {
	Key  BlobKey
	Meta BlobMeta
}

// BlobError represents a blob storage error with a machine-readable code.
type BlobError struct {
	Code    string
	Message string
}

func (e *BlobError) Error() string {
	return e.Message
}

// Blob-specific sentinel errors. These are distinct from the ConfigValidationError
// sentinel errors in config_store.go to avoid conflating blob and config error paths.
var (
	ErrBlobNotFound         = &BlobError{Code: "BLOB_NOT_FOUND", Message: "blob not found"}
	ErrBlobTenantRequired   = &BlobError{Code: "BLOB_TENANT_REQUIRED", Message: "tenant ID is required"}
	ErrBlobChecksumMismatch = &BlobError{Code: "BLOB_CHECKSUM_MISMATCH", Message: "checksum verification failed"}
)
