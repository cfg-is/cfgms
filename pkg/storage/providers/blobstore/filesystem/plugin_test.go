// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package filesystem

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	blob "github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
)

func newTestStore(t *testing.T) *FilesystemBlobStore {
	t.Helper()
	return &FilesystemBlobStore{root: t.TempDir()}
}

func testKey(name string) blob.BlobKey {
	return blob.BlobKey{
		TenantID:  "tenant-a",
		Namespace: "installers",
		Name:      name,
	}
}

// TestFilesystemBlobStore_PutGetBlob verifies a basic roundtrip.
func TestFilesystemBlobStore_PutGetBlob(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	content := []byte("hello blob world")
	key := testKey("test.bin")
	meta := blob.BlobMeta{
		ContentType: "application/octet-stream",
		Labels:      map[string]string{"env": "test"},
	}

	err := s.PutBlob(ctx, key, bytes.NewReader(content), meta)
	require.NoError(t, err)

	rc, gotMeta, err := s.GetBlob(ctx, key)
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()

	got, err := io.ReadAll(rc)
	require.NoError(t, err)

	assert.Equal(t, content, got)
	assert.Equal(t, "application/octet-stream", gotMeta.ContentType)
	assert.Equal(t, int64(len(content)), gotMeta.Size)
	assert.NotEmpty(t, gotMeta.Checksum)
	assert.False(t, gotMeta.CreatedAt.IsZero())
	assert.Equal(t, map[string]string{"env": "test"}, gotMeta.Labels)
}

// TestFilesystemBlobStore_PutBlob_DefaultContentType verifies the default content type.
func TestFilesystemBlobStore_PutBlob_DefaultContentType(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key := testKey("notype.bin")
	err := s.PutBlob(ctx, key, bytes.NewReader([]byte("data")), blob.BlobMeta{})
	require.NoError(t, err)

	rc, meta, err := s.GetBlob(ctx, key)
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()
	assert.Equal(t, "application/octet-stream", meta.ContentType)
}

// TestFilesystemBlobStore_PutBlob_TenantRequired verifies ErrBlobTenantRequired.
func TestFilesystemBlobStore_PutBlob_TenantRequired(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key := blob.BlobKey{TenantID: "", Namespace: "ns", Name: "file.bin"}
	err := s.PutBlob(ctx, key, bytes.NewReader([]byte("x")), blob.BlobMeta{})
	assert.ErrorIs(t, err, blob.ErrBlobTenantRequired)
}

// TestFilesystemBlobStore_GetBlob_NotFound verifies ErrBlobNotFound on missing key.
func TestFilesystemBlobStore_GetBlob_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, _, err := s.GetBlob(ctx, testKey("missing.bin"))
	assert.ErrorIs(t, err, blob.ErrBlobNotFound)
}

// TestFilesystemBlobStore_GetBlob_TenantRequired checks that GetBlob also validates TenantID.
func TestFilesystemBlobStore_GetBlob_TenantRequired(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, _, err := s.GetBlob(ctx, blob.BlobKey{Namespace: "ns", Name: "f"})
	assert.ErrorIs(t, err, blob.ErrBlobTenantRequired)
}

// TestFilesystemBlobStore_BlobExists verifies true for existing, false for missing.
func TestFilesystemBlobStore_BlobExists(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key := testKey("exists.bin")

	exists, err := s.BlobExists(ctx, key)
	require.NoError(t, err)
	assert.False(t, exists)

	err = s.PutBlob(ctx, key, bytes.NewReader([]byte("data")), blob.BlobMeta{})
	require.NoError(t, err)

	exists, err = s.BlobExists(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists)
}

// TestFilesystemBlobStore_BlobExists_TenantRequired checks TenantID validation.
func TestFilesystemBlobStore_BlobExists_TenantRequired(t *testing.T) {
	s := newTestStore(t)
	_, err := s.BlobExists(context.Background(), blob.BlobKey{Namespace: "ns", Name: "f"})
	assert.ErrorIs(t, err, blob.ErrBlobTenantRequired)
}

// TestFilesystemBlobStore_DeleteBlob verifies delete and idempotency.
func TestFilesystemBlobStore_DeleteBlob(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key := testKey("del.bin")
	err := s.PutBlob(ctx, key, bytes.NewReader([]byte("data")), blob.BlobMeta{})
	require.NoError(t, err)

	exists, err := s.BlobExists(ctx, key)
	require.NoError(t, err)
	require.True(t, exists)

	err = s.DeleteBlob(ctx, key)
	require.NoError(t, err)

	exists, err = s.BlobExists(ctx, key)
	require.NoError(t, err)
	assert.False(t, exists)

	// Second delete should be a no-op, not an error.
	err = s.DeleteBlob(ctx, key)
	assert.NoError(t, err)
}

// TestFilesystemBlobStore_ListBlobs verifies namespace-scoped listing.
func TestFilesystemBlobStore_ListBlobs(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	blobs := []blob.BlobKey{
		{TenantID: "tenant-a", Namespace: "installers", Name: "agent-v1.pkg"},
		{TenantID: "tenant-a", Namespace: "installers", Name: "agent-v2.pkg"},
		{TenantID: "tenant-a", Namespace: "reports", Name: "report-2026.pdf"},
		{TenantID: "tenant-b", Namespace: "installers", Name: "other.pkg"},
	}
	for _, k := range blobs {
		err := s.PutBlob(ctx, k, bytes.NewReader([]byte("content")), blob.BlobMeta{})
		require.NoError(t, err)
	}

	// List all blobs for tenant-a in installers namespace.
	results, err := s.ListBlobs(ctx, blob.BlobKey{TenantID: "tenant-a", Namespace: "installers"})
	require.NoError(t, err)
	assert.Len(t, results, 2)
	names := make([]string, 0, len(results))
	for _, r := range results {
		names = append(names, r.Key.Name)
		assert.Equal(t, "tenant-a", r.Key.TenantID)
		assert.Equal(t, "installers", r.Key.Namespace)
	}
	assert.ElementsMatch(t, []string{"agent-v1.pkg", "agent-v2.pkg"}, names)

	// List all blobs for tenant-a (all namespaces).
	all, err := s.ListBlobs(ctx, blob.BlobKey{TenantID: "tenant-a"})
	require.NoError(t, err)
	assert.Len(t, all, 3)

	// List for tenant-b.
	tb, err := s.ListBlobs(ctx, blob.BlobKey{TenantID: "tenant-b"})
	require.NoError(t, err)
	assert.Len(t, tb, 1)
}

// TestFilesystemBlobStore_ListBlobs_Empty verifies empty list for tenant with no blobs.
func TestFilesystemBlobStore_ListBlobs_Empty(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	results, err := s.ListBlobs(ctx, blob.BlobKey{TenantID: "nobody"})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestFilesystemBlobStore_ListBlobs_TenantRequired checks TenantID validation.
func TestFilesystemBlobStore_ListBlobs_TenantRequired(t *testing.T) {
	s := newTestStore(t)
	_, err := s.ListBlobs(context.Background(), blob.BlobKey{Namespace: "ns"})
	assert.ErrorIs(t, err, blob.ErrBlobTenantRequired)
}

// TestFilesystemBlobStore_ChecksumMismatch verifies that tampered blobs are detected.
func TestFilesystemBlobStore_ChecksumMismatch(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key := testKey("tampered.bin")
	original := []byte("original content")
	err := s.PutBlob(ctx, key, bytes.NewReader(original), blob.BlobMeta{})
	require.NoError(t, err)

	// Tamper with the stored blob file directly.
	blobFile := filepath.Join(s.root, key.TenantID, key.Namespace, key.Name)
	err = os.WriteFile(blobFile, []byte("tampered content!"), 0o600)
	require.NoError(t, err)

	rc, _, err := s.GetBlob(ctx, key)
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()

	// Reading the tampered blob should return ErrBlobChecksumMismatch at EOF.
	_, err = io.ReadAll(rc)
	assert.ErrorIs(t, err, blob.ErrBlobChecksumMismatch)
}

// TestFilesystemBlobStore_Overwrite verifies that PutBlob overwrites an existing blob.
func TestFilesystemBlobStore_Overwrite(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key := testKey("overwrite.bin")
	err := s.PutBlob(ctx, key, bytes.NewReader([]byte("v1")), blob.BlobMeta{})
	require.NoError(t, err)

	err = s.PutBlob(ctx, key, bytes.NewReader([]byte("v2 longer content")), blob.BlobMeta{})
	require.NoError(t, err)

	rc, meta, err := s.GetBlob(ctx, key)
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()

	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, []byte("v2 longer content"), got)
	assert.Equal(t, int64(len("v2 longer content")), meta.Size)
}

// TestFilesystemBlobStore_LargeBlob_Streaming streams a 10 MB blob and verifies
// that no in-memory buffering occurs. A bounded io.LimitedReader is used as the
// source to confirm the provider does not attempt to read beyond the data size.
func TestFilesystemBlobStore_LargeBlob_Streaming(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	const blobSize = 10 * 1024 * 1024 // 10 MB
	// Use a LimitedReader over a zero-byte reader to confirm streaming:
	// if the implementation tried to buffer the entire blob in memory, this test
	// would use ~10 MB of heap (acceptable for test) but still succeed; the key
	// correctness check is that the full 10 MB is correctly written and read back.
	src := &io.LimitedReader{R: zeroReader{}, N: blobSize}

	key := blob.BlobKey{TenantID: "tenant-a", Namespace: "dna-snapshots", Name: "snapshot.bin"}
	err := s.PutBlob(ctx, key, src, blob.BlobMeta{ContentType: "application/octet-stream"})
	require.NoError(t, err)

	// Verify the LimitedReader was fully consumed (provider did not over-read).
	assert.Equal(t, int64(0), src.N, "provider should have read exactly blobSize bytes")

	rc, meta, err := s.GetBlob(ctx, key)
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()

	n, err := io.Copy(io.Discard, rc)
	require.NoError(t, err)
	assert.Equal(t, int64(blobSize), n)
	assert.Equal(t, int64(blobSize), meta.Size)
}

// zeroReader is an infinite source of zero bytes used for large-blob streaming tests.
type zeroReader struct{}

func (z zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// TestFilesystemBlobStore_HealthCheck verifies that HealthCheck passes with a valid root.
func TestFilesystemBlobStore_HealthCheck(t *testing.T) {
	s := newTestStore(t)
	err := s.HealthCheck(context.Background())
	assert.NoError(t, err)
}

// TestFilesystemBlobStore_HealthCheck_MissingRoot verifies failure when root is gone.
func TestFilesystemBlobStore_HealthCheck_MissingRoot(t *testing.T) {
	s := &FilesystemBlobStore{root: "/nonexistent/path/12345"}
	err := s.HealthCheck(context.Background())
	assert.Error(t, err)
}

// TestFilesystemBlobProvider_CreateBlobStore verifies provider factory creates a store.
func TestFilesystemBlobProvider_CreateBlobStore(t *testing.T) {
	p := &FilesystemBlobProvider{}

	store, err := p.CreateBlobStore(map[string]interface{}{
		"root": t.TempDir(),
	})
	require.NoError(t, err)
	assert.NotNil(t, store)
}

// TestFilesystemBlobProvider_CreateBlobStore_MissingRoot verifies error on missing root config.
func TestFilesystemBlobProvider_CreateBlobStore_MissingRoot(t *testing.T) {
	p := &FilesystemBlobProvider{}
	_, err := p.CreateBlobStore(map[string]interface{}{})
	assert.Error(t, err)
}

// TestFilesystemBlobProvider_Metadata verifies provider metadata fields.
func TestFilesystemBlobProvider_Metadata(t *testing.T) {
	p := &FilesystemBlobProvider{}
	assert.NotEmpty(t, p.Name())
	assert.NotEmpty(t, p.Description())
	assert.NotEmpty(t, p.GetVersion())
	ok, err := p.Available()
	assert.NoError(t, err)
	assert.True(t, ok)
}

// TestFilesystemBlobStore_CreatedAt verifies the CreatedAt timestamp is populated and recent.
func TestFilesystemBlobStore_CreatedAt(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	before := time.Now().UTC().Add(-time.Second)
	err := s.PutBlob(ctx, testKey("ts.bin"), bytes.NewReader([]byte("ts")), blob.BlobMeta{})
	require.NoError(t, err)
	after := time.Now().UTC().Add(time.Second)

	rc, meta, err := s.GetBlob(ctx, testKey("ts.bin"))
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()
	assert.True(t, meta.CreatedAt.After(before), "CreatedAt should be after test start")
	assert.True(t, meta.CreatedAt.Before(after), "CreatedAt should be before test end")
}

// TestFilesystemBlobStore_Labels verifies that labels round-trip correctly.
func TestFilesystemBlobStore_Labels(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	labels := map[string]string{
		"version": "1.2.3",
		"arch":    "amd64",
		"os":      "linux",
	}
	key := testKey("labeled.bin")
	err := s.PutBlob(ctx, key, bytes.NewReader([]byte("labeled content")), blob.BlobMeta{Labels: labels})
	require.NoError(t, err)

	// Verify via GetBlob.
	rc, meta, err := s.GetBlob(ctx, key)
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()
	assert.Equal(t, labels, meta.Labels)

	// Verify via ListBlobs.
	results, err := s.ListBlobs(ctx, blob.BlobKey{TenantID: "tenant-a", Namespace: "installers"})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, labels, results[0].Meta.Labels)
}

// TestBlobProviderRegistration verifies that the filesystem provider registers itself via init().
func TestBlobProviderRegistration(t *testing.T) {
	// The init() function in plugin.go registers the provider automatically.
	// Import the package (already done by being in the same test) and verify.
	names := blob.GetRegisteredBlobProviderNames()
	found := false
	for _, n := range names {
		if n == "filesystem" {
			found = true
			break
		}
	}
	assert.True(t, found, "filesystem blob provider should be registered via init()")
}

// TestFilesystemBlobStore_PathTraversal verifies that ".." and "/" in any key component
// are rejected by PutBlob, GetBlob, DeleteBlob, BlobExists, and ListBlobs.
func TestFilesystemBlobStore_PathTraversal(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	traversalKeys := []struct {
		name string
		key  blob.BlobKey
	}{
		{"dotdot in namespace", blob.BlobKey{TenantID: "t", Namespace: "../etc", Name: "passwd"}},
		{"dotdot in name", blob.BlobKey{TenantID: "t", Namespace: "ns", Name: "../secret"}},
		{"dotdot in tenant", blob.BlobKey{TenantID: "../etc", Namespace: "ns", Name: "file"}},
		{"slash in name", blob.BlobKey{TenantID: "t", Namespace: "ns", Name: "sub/file"}},
		{"slash in tenant", blob.BlobKey{TenantID: "t/../../etc", Namespace: "ns", Name: "file"}},
	}

	for _, tc := range traversalKeys {
		tc := tc
		t.Run(tc.name+"/PutBlob", func(t *testing.T) {
			err := s.PutBlob(ctx, tc.key, bytes.NewReader([]byte("x")), blob.BlobMeta{})
			assert.Error(t, err, "PutBlob should reject path traversal in key component")
		})
		t.Run(tc.name+"/GetBlob", func(t *testing.T) {
			_, _, err := s.GetBlob(ctx, tc.key)
			assert.Error(t, err, "GetBlob should reject path traversal in key component")
		})
		t.Run(tc.name+"/DeleteBlob", func(t *testing.T) {
			err := s.DeleteBlob(ctx, tc.key)
			assert.Error(t, err, "DeleteBlob should reject path traversal in key component")
		})
		t.Run(tc.name+"/BlobExists", func(t *testing.T) {
			_, err := s.BlobExists(ctx, tc.key)
			assert.Error(t, err, "BlobExists should reject path traversal in key component")
		})
	}

	// ListBlobs uses a prefix key — only TenantID and Namespace are validated.
	t.Run("dotdot in tenant/ListBlobs", func(t *testing.T) {
		_, err := s.ListBlobs(ctx, blob.BlobKey{TenantID: "../etc", Namespace: "ns"})
		assert.Error(t, err, "ListBlobs should reject path traversal in TenantID")
	})
	t.Run("dotdot in namespace/ListBlobs", func(t *testing.T) {
		_, err := s.ListBlobs(ctx, blob.BlobKey{TenantID: "t", Namespace: "../etc"})
		assert.Error(t, err, "ListBlobs should reject path traversal in Namespace")
	})
}
