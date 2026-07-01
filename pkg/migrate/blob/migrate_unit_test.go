// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package blob_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/migrate"
	blobmigrate "github.com/cfgis/cfgms/pkg/migrate/blob"
	blobstore "github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
)

// newFilesystemStore creates a filesystem BlobStore rooted in a per-test temp dir.
func newFilesystemStore(t *testing.T) blobstore.BlobStore {
	t.Helper()
	store, err := blobstore.CreateBlobStoreFromConfig("filesystem", map[string]interface{}{
		"root": t.TempDir(),
	})
	require.NoError(t, err, "create filesystem test store")
	return store
}

// putTestBlob writes a blob to the store and returns the BlobKey and content.
func putTestBlob(t *testing.T, store blobstore.BlobStore, key blobstore.BlobKey, content []byte, labels map[string]string) {
	t.Helper()
	err := store.PutBlob(context.Background(), key, bytes.NewReader(content), blobstore.BlobMeta{
		ContentType: "application/octet-stream",
		Labels:      labels,
	})
	require.NoErrorf(t, err, "put blob %s/%s/%s", key.TenantID, key.Namespace, key.Name)
}

// TestBlobMigratorFactory_Registered verifies that importing pkg/migrate/blob
// registers the "blob" factory in the migrate registry.
func TestBlobMigratorFactory_Registered(t *testing.T) {
	factory, err := migrate.Lookup("blob")
	require.NoError(t, err, "blob factory must be registered via init()")
	assert.NotNil(t, factory)
}

// TestBlobMigratorFactory_UnknownBackend verifies that the factory rejects an
// unknown backend name with a descriptive error.
func TestBlobMigratorFactory_UnknownBackend(t *testing.T) {
	t.Setenv("CFGMS_BLOB_TENANT_IDS", "root")

	factory, err := migrate.Lookup("blob")
	require.NoError(t, err)

	_, err = factory("bogus-backend", "filesystem")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bogus-backend")
}

// TestBlobMigratorFactory_FilesystemMissingEnv verifies that the factory returns an
// error when the filesystem backend is selected but CFGMS_BLOB_FILESYSTEM_ROOT is absent.
func TestBlobMigratorFactory_FilesystemMissingEnv(t *testing.T) {
	t.Setenv("CFGMS_BLOB_TENANT_IDS", "root")
	t.Setenv("CFGMS_BLOB_FILESYSTEM_ROOT", "")

	factory, err := migrate.Lookup("blob")
	require.NoError(t, err)

	_, err = factory("filesystem", "filesystem")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CFGMS_BLOB_FILESYSTEM_ROOT")
}

// TestBlobMigratorFactory_S3MissingEnv verifies that the factory returns an error
// when the s3 backend is selected but CFGMS_BLOB_S3_BUCKET is absent.
func TestBlobMigratorFactory_S3MissingEnv(t *testing.T) {
	t.Setenv("CFGMS_BLOB_TENANT_IDS", "root")
	t.Setenv("CFGMS_BLOB_S3_BUCKET", "")
	t.Setenv("CFGMS_BLOB_FILESYSTEM_ROOT", t.TempDir())

	factory, err := migrate.Lookup("blob")
	require.NoError(t, err)

	_, err = factory("filesystem", "s3")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CFGMS_BLOB_S3_BUCKET")
}

// TestBlobMigratorFactory_MissingTenantIDs verifies that the factory returns an error
// when CFGMS_BLOB_TENANT_IDS is empty.
func TestBlobMigratorFactory_MissingTenantIDs(t *testing.T) {
	t.Setenv("CFGMS_BLOB_TENANT_IDS", "")
	t.Setenv("CFGMS_BLOB_FILESYSTEM_ROOT", t.TempDir())

	factory, err := migrate.Lookup("blob")
	require.NoError(t, err)

	_, err = factory("filesystem", "filesystem")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CFGMS_BLOB_TENANT_IDS")
}

// TestNewBlobMigrator_NilSrcPanics verifies that a nil src panics.
func TestNewBlobMigrator_NilSrcPanics(t *testing.T) {
	dst := newFilesystemStore(t)
	assert.Panics(t, func() {
		blobmigrate.NewBlobMigrator(nil, dst, []string{"root"})
	})
}

// TestNewBlobMigrator_NilDstPanics verifies that a nil dst panics.
func TestNewBlobMigrator_NilDstPanics(t *testing.T) {
	src := newFilesystemStore(t)
	assert.Panics(t, func() {
		blobmigrate.NewBlobMigrator(src, nil, []string{"root"})
	})
}

// TestNewBlobMigrator_EmptyTenantsPanics verifies that empty tenants panics.
func TestNewBlobMigrator_EmptyTenantsPanics(t *testing.T) {
	src := newFilesystemStore(t)
	dst := newFilesystemStore(t)
	assert.Panics(t, func() {
		blobmigrate.NewBlobMigrator(src, dst, nil)
	})
}

// TestBlobMigrator_Plan_Empty verifies that Plan on an empty source returns zero counts.
func TestBlobMigrator_Plan_Empty(t *testing.T) {
	src := newFilesystemStore(t)
	dst := newFilesystemStore(t)

	m := blobmigrate.NewBlobMigrator(src, dst, []string{"root"})
	report, err := m.Plan(context.Background())
	require.NoError(t, err)

	total := 0
	for _, c := range report.Counts {
		total += c
	}
	assert.Equal(t, 0, total, "empty source must produce zero-count plan")
}

// TestBlobMigrator_Plan_WithBlobs verifies per-namespace counts without writing.
func TestBlobMigrator_Plan_WithBlobs(t *testing.T) {
	ctx := context.Background()
	src := newFilesystemStore(t)
	dst := newFilesystemStore(t)

	tenantID := fmt.Sprintf("tenant-%d", time.Now().UnixNano())
	putTestBlob(t, src, blobstore.BlobKey{TenantID: tenantID, Namespace: "installers", Name: "v1.pkg"}, []byte("v1"), nil)
	putTestBlob(t, src, blobstore.BlobKey{TenantID: tenantID, Namespace: "installers", Name: "v2.pkg"}, []byte("v2"), nil)
	putTestBlob(t, src, blobstore.BlobKey{TenantID: tenantID, Namespace: "reports", Name: "rep.pdf"}, []byte("pdf"), nil)

	m := blobmigrate.NewBlobMigrator(src, dst, []string{tenantID})
	report, err := m.Plan(ctx)
	require.NoError(t, err)

	assert.Equal(t, 2, report.Counts["installers"], "plan must count installers namespace")
	assert.Equal(t, 1, report.Counts["reports"], "plan must count reports namespace")

	// Plan must not write to destination.
	dstList, err := dst.ListBlobs(ctx, blobstore.BlobKey{TenantID: tenantID})
	require.NoError(t, err)
	assert.Empty(t, dstList, "plan must not write to destination")
}

// TestBlobMigrator_Run_Empty verifies that migrating an empty source succeeds.
func TestBlobMigrator_Run_Empty(t *testing.T) {
	src := newFilesystemStore(t)
	dst := newFilesystemStore(t)

	m := blobmigrate.NewBlobMigrator(src, dst, []string{"root"})
	report, err := m.Run(context.Background())
	require.NoError(t, err, "empty source migration must succeed")

	total := 0
	for _, c := range report.Counts {
		total += c
	}
	assert.Equal(t, 0, total, "empty source must produce zero-count report")
}

// TestBlobMigrator_Run_FilesystemToFilesystem verifies a basic filesystem→filesystem roundtrip.
func TestBlobMigrator_Run_FilesystemToFilesystem(t *testing.T) {
	ctx := context.Background()
	src := newFilesystemStore(t)
	dst := newFilesystemStore(t)

	tenantID := fmt.Sprintf("tenant-%d", time.Now().UnixNano())
	content := []byte("installer payload amd64")
	key := blobstore.BlobKey{TenantID: tenantID, Namespace: "installers", Name: "agent.pkg"}
	putTestBlob(t, src, key, content, map[string]string{"arch": "amd64"})

	m := blobmigrate.NewBlobMigrator(src, dst, []string{tenantID})
	report, err := m.Run(ctx)
	require.NoError(t, err, "migration must succeed")
	assert.Equal(t, 1, report.Counts["installers"])

	// Verify the blob is readable from the destination.
	rc, meta, err := dst.GetBlob(ctx, key)
	require.NoError(t, err, "migrated blob must be readable from destination")

	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	assert.Equal(t, content, got, "blob content must match")
	assert.Equal(t, "application/octet-stream", meta.ContentType)
	assert.Equal(t, map[string]string{"arch": "amd64"}, meta.Labels, "labels must be preserved")
}

// TestBlobMigrator_Run_PreservesChecksum verifies that the destination checksum matches
// the source after a successful migration.
func TestBlobMigrator_Run_PreservesChecksum(t *testing.T) {
	ctx := context.Background()
	src := newFilesystemStore(t)
	dst := newFilesystemStore(t)

	tenantID := fmt.Sprintf("tenant-%d", time.Now().UnixNano())
	content := []byte("checksum verification payload")
	key := blobstore.BlobKey{TenantID: tenantID, Namespace: "installers", Name: "check.pkg"}
	putTestBlob(t, src, key, content, nil)

	// Record source checksum.
	srcList, err := src.ListBlobs(ctx, blobstore.BlobKey{TenantID: tenantID})
	require.NoError(t, err)
	require.Len(t, srcList, 1)
	srcChecksum := srcList[0].Meta.Checksum
	require.NotEmpty(t, srcChecksum, "source must have a non-empty checksum")

	m := blobmigrate.NewBlobMigrator(src, dst, []string{tenantID})
	_, err = m.Run(ctx)
	require.NoError(t, err)

	// Destination blob must have the same checksum.
	dstList, err := dst.ListBlobs(ctx, blobstore.BlobKey{TenantID: tenantID})
	require.NoError(t, err)
	require.Len(t, dstList, 1)
	assert.Equal(t, srcChecksum, dstList[0].Meta.Checksum, "destination checksum must match source")
}

// TestBlobMigrator_Run_MultipleNamespaces verifies per-namespace counts.
func TestBlobMigrator_Run_MultipleNamespaces(t *testing.T) {
	ctx := context.Background()
	src := newFilesystemStore(t)
	dst := newFilesystemStore(t)

	tenantID := fmt.Sprintf("tenant-%d", time.Now().UnixNano())
	putTestBlob(t, src, blobstore.BlobKey{TenantID: tenantID, Namespace: "installers", Name: "a.pkg"}, []byte("a"), nil)
	putTestBlob(t, src, blobstore.BlobKey{TenantID: tenantID, Namespace: "installers", Name: "b.pkg"}, []byte("b"), nil)
	putTestBlob(t, src, blobstore.BlobKey{TenantID: tenantID, Namespace: "reports", Name: "r.pdf"}, []byte("r"), nil)

	m := blobmigrate.NewBlobMigrator(src, dst, []string{tenantID})
	report, err := m.Run(ctx)
	require.NoError(t, err)

	assert.Equal(t, 2, report.Counts["installers"], "must count installers namespace")
	assert.Equal(t, 1, report.Counts["reports"], "must count reports namespace")

	// All blobs must be in destination.
	dstList, err := dst.ListBlobs(ctx, blobstore.BlobKey{TenantID: tenantID})
	require.NoError(t, err)
	assert.Len(t, dstList, 3)
}

// TestBlobMigrator_Run_MultipleTenants verifies that blobs from multiple tenants
// are migrated and tenant isolation is preserved.
func TestBlobMigrator_Run_MultipleTenants(t *testing.T) {
	ctx := context.Background()
	src := newFilesystemStore(t)
	dst := newFilesystemStore(t)

	ts := time.Now().UnixNano()
	tenantA := fmt.Sprintf("tenant-a-%d", ts)
	tenantB := fmt.Sprintf("tenant-b-%d", ts)

	putTestBlob(t, src, blobstore.BlobKey{TenantID: tenantA, Namespace: "installers", Name: "a.pkg"}, []byte("tenant-a blob"), nil)
	putTestBlob(t, src, blobstore.BlobKey{TenantID: tenantB, Namespace: "installers", Name: "b.pkg"}, []byte("tenant-b blob"), nil)

	m := blobmigrate.NewBlobMigrator(src, dst, []string{tenantA, tenantB})
	report, err := m.Run(ctx)
	require.NoError(t, err)

	assert.Equal(t, 2, report.Counts["installers"], "both tenant blobs must be counted")

	// Each tenant's blob must land in the correct tenant namespace in the destination.
	listA, err := dst.ListBlobs(ctx, blobstore.BlobKey{TenantID: tenantA})
	require.NoError(t, err)
	assert.Len(t, listA, 1, "tenant-a must have exactly one blob")
	assert.Equal(t, tenantA, listA[0].Key.TenantID)

	listB, err := dst.ListBlobs(ctx, blobstore.BlobKey{TenantID: tenantB})
	require.NoError(t, err)
	assert.Len(t, listB, 1, "tenant-b must have exactly one blob")
	assert.Equal(t, tenantB, listB[0].Key.TenantID)
}

// TestBlobMigrator_Run_Idempotent verifies that running the migration twice
// yields identical counts with no duplicates.
func TestBlobMigrator_Run_Idempotent(t *testing.T) {
	ctx := context.Background()
	src := newFilesystemStore(t)
	dst := newFilesystemStore(t)

	tenantID := fmt.Sprintf("tenant-%d", time.Now().UnixNano())
	putTestBlob(t, src, blobstore.BlobKey{TenantID: tenantID, Namespace: "installers", Name: "x.pkg"}, []byte("idempotent"), nil)

	m := blobmigrate.NewBlobMigrator(src, dst, []string{tenantID})

	report1, err := m.Run(ctx)
	require.NoError(t, err, "first run must succeed")

	report2, err := m.Run(ctx)
	require.NoError(t, err, "second run must succeed (idempotent)")

	for ns, c1 := range report1.Counts {
		c2, ok := report2.Counts[ns]
		require.True(t, ok, "second run must include namespace %q", ns)
		assert.Equal(t, c1, c2, "second run count for %q must match first", ns)
	}

	// Destination must have exactly one blob, not two.
	list, err := dst.ListBlobs(ctx, blobstore.BlobKey{TenantID: tenantID})
	require.NoError(t, err)
	assert.Len(t, list, 1, "idempotent re-run must not duplicate blobs")
}

// errBlobStore is a real BlobStore that wraps a filesystem store but overrides
// ListBlobs to return an error, allowing error-path testing without mocks.
type errBlobStore struct {
	blobstore.BlobStore
	listErr error
}

func (e *errBlobStore) ListBlobs(ctx context.Context, prefix blobstore.BlobKey) ([]blobstore.BlobInfo, error) {
	if e.listErr != nil {
		return nil, e.listErr
	}
	return e.BlobStore.ListBlobs(ctx, prefix)
}

// TestBlobMigrator_Plan_ListError verifies that a ListBlobs error from the source
// propagates correctly through Plan.
func TestBlobMigrator_Plan_ListError(t *testing.T) {
	src := &errBlobStore{
		BlobStore: newFilesystemStore(t),
		listErr:   fmt.Errorf("list blobs: simulated storage failure"),
	}
	dst := newFilesystemStore(t)

	m := blobmigrate.NewBlobMigrator(src, dst, []string{"root"})
	_, err := m.Plan(context.Background())
	require.Error(t, err, "Plan must propagate ListBlobs error")
	assert.Contains(t, err.Error(), "simulated storage failure")
}

// TestBlobMigrator_Run_ListError verifies that a ListBlobs error from the source
// propagates correctly through Run.
func TestBlobMigrator_Run_ListError(t *testing.T) {
	src := &errBlobStore{
		BlobStore: newFilesystemStore(t),
		listErr:   fmt.Errorf("list blobs: simulated storage failure"),
	}
	dst := newFilesystemStore(t)

	m := blobmigrate.NewBlobMigrator(src, dst, []string{"root"})
	_, err := m.Run(context.Background())
	require.Error(t, err, "Run must propagate ListBlobs error")
	assert.Contains(t, err.Error(), "simulated storage failure")
}

// TestBlobMigrator_Run_ChecksumMismatch verifies that a corrupted source blob
// causes the migration to fail with an error wrapping ErrBlobChecksumMismatch.
func TestBlobMigrator_Run_ChecksumMismatch(t *testing.T) {
	ctx := context.Background()

	// Use a real filesystem source so we can corrupt the blob file on disk.
	srcRoot := t.TempDir()
	src, err := blobstore.CreateBlobStoreFromConfig("filesystem", map[string]interface{}{"root": srcRoot})
	require.NoError(t, err)
	dst := newFilesystemStore(t)

	tenantID := fmt.Sprintf("tenant-%d", time.Now().UnixNano())
	key := blobstore.BlobKey{TenantID: tenantID, Namespace: "installers", Name: "corrupt.pkg"}
	putTestBlob(t, src, key, []byte("original content"), nil)

	// Corrupt the blob file on disk; the checksum sidecar still references the original.
	blobFilePath := filepath.Join(srcRoot, tenantID, "installers", "corrupt.pkg")
	err = os.WriteFile(blobFilePath, []byte("tampered!!!"), 0o600)
	require.NoError(t, err, "must be able to corrupt the blob file for test")

	m := blobmigrate.NewBlobMigrator(src, dst, []string{tenantID})
	_, err = m.Run(ctx)
	require.Error(t, err, "migration must fail when source blob is corrupted")
	assert.ErrorIs(t, err, blobstore.ErrBlobChecksumMismatch, "error must wrap ErrBlobChecksumMismatch")
}
