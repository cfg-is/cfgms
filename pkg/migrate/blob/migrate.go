// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package blob implements the "blob" migrator for CFGMS installer artifacts.
//
// The migrator copies all blobs between backends through pkg/storage/interfaces/blob:
//
//	cfg migrate --provider blob --from filesystem --to s3
//
// Supported backend names: "filesystem" (local filesystem), "s3" (S3-compatible).
// Both directions are supported.
//
// Configuration is read from environment variables:
//
//	CFGMS_BLOB_TENANT_IDS         – comma-separated tenant IDs to migrate (required)
//	CFGMS_BLOB_FILESYSTEM_ROOT    – root directory for the filesystem backend
//	CFGMS_BLOB_S3_BUCKET          – S3 bucket name (required for s3)
//	CFGMS_BLOB_S3_REGION          – AWS region (optional; default "us-east-1")
//	CFGMS_BLOB_S3_ENDPOINT_URL    – S3 endpoint URL for MinIO/local dev (optional)
//
// For tests, bypass the factory and use NewBlobMigrator directly with pre-built
// BlobStore instances.
package blob

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cfgis/cfgms/pkg/migrate"
	blobstore "github.com/cfgis/cfgms/pkg/storage/interfaces/blob"

	_ "github.com/cfgis/cfgms/pkg/storage/providers/blobstore/filesystem" // register filesystem provider
	_ "github.com/cfgis/cfgms/pkg/storage/providers/blobstore/s3"         // register s3 provider
)

func init() {
	migrate.Register("blob", func(from, to string) (migrate.Migrator, error) {
		tenants, err := parseTenantIDs()
		if err != nil {
			return nil, fmt.Errorf("blob migrator: %w", err)
		}

		srcStore, err := openBlobBackend(from)
		if err != nil {
			return nil, fmt.Errorf("blob migrator: source backend %q: %w", from, err)
		}
		dstStore, err := openBlobBackend(to)
		if err != nil {
			return nil, fmt.Errorf("blob migrator: target backend %q: %w", to, err)
		}

		return NewBlobMigrator(srcStore, dstStore, tenants), nil
	})
}

// parseTenantIDs reads the comma-separated CFGMS_BLOB_TENANT_IDS env var.
func parseTenantIDs() ([]string, error) {
	raw := os.Getenv("CFGMS_BLOB_TENANT_IDS")
	if raw == "" {
		return nil, fmt.Errorf("CFGMS_BLOB_TENANT_IDS must be set (comma-separated list of tenant IDs to migrate)")
	}
	parts := strings.Split(raw, ",")
	ids := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			ids = append(ids, t)
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("CFGMS_BLOB_TENANT_IDS must contain at least one non-empty tenant ID")
	}
	return ids, nil
}

// openBlobBackend creates a BlobStore for the named backend using environment variables.
// Mirrors the config keys used in features/controller/server/server.go for S3 and filesystem.
func openBlobBackend(name string) (blobstore.BlobStore, error) {
	switch name {
	case "filesystem":
		root := os.Getenv("CFGMS_BLOB_FILESYSTEM_ROOT")
		if root == "" {
			return nil, fmt.Errorf("CFGMS_BLOB_FILESYSTEM_ROOT must be set for filesystem backend")
		}
		return blobstore.CreateBlobStoreFromConfig("filesystem", map[string]interface{}{
			"root": root,
		})
	case "s3":
		bucket := os.Getenv("CFGMS_BLOB_S3_BUCKET")
		if bucket == "" {
			return nil, fmt.Errorf("CFGMS_BLOB_S3_BUCKET must be set for s3 backend")
		}
		cfg := map[string]interface{}{
			"bucket": bucket,
		}
		if region := os.Getenv("CFGMS_BLOB_S3_REGION"); region != "" {
			cfg["region"] = region
		}
		if endpoint := os.Getenv("CFGMS_BLOB_S3_ENDPOINT_URL"); endpoint != "" {
			cfg["endpoint_url"] = endpoint
		}
		return blobstore.CreateBlobStoreFromConfig("s3", cfg)
	default:
		return nil, fmt.Errorf("unknown backend %q; supported: filesystem, s3", name)
	}
}

// BlobMigrator copies blobs from one BlobStore to another for the specified tenants.
// All blobs are enumerated via ListBlobs and copied via GetBlob → PutBlob, preserving
// BlobKey, BlobMeta, and checksums. A checksum mismatch on any source blob is fatal.
type BlobMigrator struct {
	src     blobstore.BlobStore
	dst     blobstore.BlobStore
	tenants []string
}

// NewBlobMigrator returns a BlobMigrator that copies blobs from src to dst
// for the specified tenant IDs. Panics if src, dst, or tenants are nil/empty.
func NewBlobMigrator(src, dst blobstore.BlobStore, tenants []string) *BlobMigrator {
	if src == nil {
		panic("blob.NewBlobMigrator: src must not be nil")
	}
	if dst == nil {
		panic("blob.NewBlobMigrator: dst must not be nil")
	}
	if len(tenants) == 0 {
		panic("blob.NewBlobMigrator: tenants must not be empty")
	}
	return &BlobMigrator{src: src, dst: dst, tenants: tenants}
}

// Plan lists all blobs from the source and returns per-namespace counts.
// No writes to the target are performed.
func (m *BlobMigrator) Plan(ctx context.Context) (migrate.Report, error) {
	infos, err := m.listAll(ctx)
	if err != nil {
		return migrate.Report{}, fmt.Errorf("blob plan: %w", err)
	}
	return migrate.Report{Counts: countByNamespace(infos), Errors: make(map[string]error)}, nil
}

// Run copies all blobs from the source to the target, preserving BlobKey, BlobMeta,
// and checksums. A checksum mismatch on any source blob fails the migration immediately.
// Run is idempotent: re-running with the same source overwrites with identical content.
func (m *BlobMigrator) Run(ctx context.Context) (migrate.Report, error) {
	infos, err := m.listAll(ctx)
	if err != nil {
		return migrate.Report{}, fmt.Errorf("blob run: list failed: %w", err)
	}

	for _, info := range infos {
		if err := m.copyBlob(ctx, info.Key, info.Meta); err != nil {
			return migrate.Report{}, fmt.Errorf("blob run: copy %s/%s/%s: %w",
				info.Key.TenantID, info.Key.Namespace, info.Key.Name, err)
		}
	}

	return migrate.Report{Counts: countByNamespace(infos), Errors: make(map[string]error)}, nil
}

// listAll enumerates all blobs across all configured tenants from the source.
func (m *BlobMigrator) listAll(ctx context.Context) ([]blobstore.BlobInfo, error) {
	var all []blobstore.BlobInfo
	for _, tenantID := range m.tenants {
		infos, err := m.src.ListBlobs(ctx, blobstore.BlobKey{TenantID: tenantID})
		if err != nil {
			return nil, fmt.Errorf("list blobs for tenant %q: %w", tenantID, err)
		}
		all = append(all, infos...)
	}
	return all, nil
}

// copyBlob reads one blob from src and writes it to dst.
// The source GetBlob reader verifies the SHA-256 checksum at EOF; a mismatch
// propagates through PutBlob and is surfaced as a fatal migration error.
func (m *BlobMigrator) copyBlob(ctx context.Context, key blobstore.BlobKey, srcMeta blobstore.BlobMeta) error {
	rc, _, err := m.src.GetBlob(ctx, key)
	if err != nil {
		return fmt.Errorf("get blob: %w", err)
	}
	defer func() { _ = rc.Close() }()

	if err := m.dst.PutBlob(ctx, key, rc, srcMeta); err != nil {
		if errors.Is(err, blobstore.ErrBlobChecksumMismatch) {
			return fmt.Errorf("source blob checksum mismatch: %w", err)
		}
		return fmt.Errorf("put blob: %w", err)
	}
	return nil
}

// countByNamespace returns a map of namespace → blob count.
func countByNamespace(infos []blobstore.BlobInfo) map[string]int {
	counts := make(map[string]int)
	for _, info := range infos {
		counts[info.Key.Namespace]++
	}
	return counts
}
