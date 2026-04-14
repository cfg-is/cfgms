// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package s3provider

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// inMemoryS3 is a real in-memory implementation of the s3API interface used for tests.
// It stores objects in a map keyed by bucket/objectKey and is safe for concurrent use.
// This is not a mock — it faithfully implements the S3 semantics used by S3BlobStore.
type inMemoryS3 struct {
	mu      sync.RWMutex
	objects map[string]*inMemoryObject
}

type inMemoryObject struct {
	body        []byte
	contentType string
	metadata    map[string]string
}

func newInMemoryS3() *inMemoryS3 {
	return &inMemoryS3{objects: make(map[string]*inMemoryObject)}
}

func (m *inMemoryS3) objectKey(bucket, key string) string {
	return bucket + "/" + key
}

func (m *inMemoryS3) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	body, err := io.ReadAll(params.Body)
	if err != nil {
		return nil, err
	}

	contentType := "application/octet-stream"
	if params.ContentType != nil {
		contentType = *params.ContentType
	}

	meta := make(map[string]string, len(params.Metadata))
	for k, v := range params.Metadata {
		meta[k] = v
	}

	k := m.objectKey(*params.Bucket, *params.Key)
	m.mu.Lock()
	m.objects[k] = &inMemoryObject{body: body, contentType: contentType, metadata: meta}
	m.mu.Unlock()

	return &s3.PutObjectOutput{}, nil
}

func (m *inMemoryS3) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	k := m.objectKey(*params.Bucket, *params.Key)
	m.mu.RLock()
	obj, exists := m.objects[k]
	m.mu.RUnlock()
	if !exists {
		return nil, &s3types.NoSuchKey{Message: aws.String("object not found")}
	}

	ct := obj.contentType
	cl := int64(len(obj.body))
	meta := make(map[string]string, len(obj.metadata))
	for k, v := range obj.metadata {
		meta[k] = v
	}
	return &s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(obj.body)),
		ContentType:   &ct,
		ContentLength: &cl,
		Metadata:      meta,
	}, nil
}

func (m *inMemoryS3) HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	k := m.objectKey(*params.Bucket, *params.Key)
	m.mu.RLock()
	obj, exists := m.objects[k]
	m.mu.RUnlock()
	if !exists {
		return nil, &s3types.NotFound{Message: aws.String("object not found")}
	}

	ct := obj.contentType
	cl := int64(len(obj.body))
	meta := make(map[string]string, len(obj.metadata))
	for k, v := range obj.metadata {
		meta[k] = v
	}
	return &s3.HeadObjectOutput{
		ContentType:   &ct,
		ContentLength: &cl,
		Metadata:      meta,
	}, nil
}

func (m *inMemoryS3) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	prefix := ""
	if params.Prefix != nil {
		prefix = *params.Prefix
	}

	bucketPrefix := *params.Bucket + "/"
	m.mu.RLock()
	defer m.mu.RUnlock()

	var contents []s3types.Object
	for k, obj := range m.objects {
		// Strip bucket prefix from key.
		if len(k) <= len(bucketPrefix) {
			continue
		}
		objKey := k[len(bucketPrefix):]
		if prefix != "" && len(objKey) < len(prefix) {
			continue
		}
		if prefix == "" || objKey[:len(prefix)] == prefix {
			sz := int64(len(obj.body))
			keyPtr := objKey
			contents = append(contents, s3types.Object{
				Key:  &keyPtr,
				Size: &sz,
			})
		}
	}

	return &s3.ListObjectsV2Output{Contents: contents}, nil
}

func (m *inMemoryS3) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	k := m.objectKey(*params.Bucket, *params.Key)
	m.mu.Lock()
	delete(m.objects, k)
	m.mu.Unlock()
	return &s3.DeleteObjectOutput{}, nil
}

// newTestStore creates an S3BlobStore backed by the in-memory S3 client.
func newTestS3Store(t *testing.T) *S3BlobStore {
	t.Helper()
	return &S3BlobStore{
		client: newInMemoryS3(),
		bucket: "test-bucket",
		prefix: "",
	}
}

func testS3Key(name string) interfaces.BlobKey {
	return interfaces.BlobKey{
		TenantID:  "tenant-a",
		Namespace: "installers",
		Name:      name,
	}
}

// TestS3BlobStore_PutGetBlob verifies a basic roundtrip.
func TestS3BlobStore_PutGetBlob(t *testing.T) {
	store := newTestS3Store(t)
	ctx := context.Background()

	content := []byte("s3 blob content")
	key := testS3Key("agent.pkg")
	meta := interfaces.BlobMeta{
		ContentType: "application/octet-stream",
		Labels:      map[string]string{"arch": "amd64"},
	}

	err := store.PutBlob(ctx, key, bytes.NewReader(content), meta)
	require.NoError(t, err)

	rc, gotMeta, err := store.GetBlob(ctx, key)
	require.NoError(t, err)
	defer rc.Close()

	got, err := io.ReadAll(rc)
	require.NoError(t, err)

	assert.Equal(t, content, got)
	assert.Equal(t, "application/octet-stream", gotMeta.ContentType)
	assert.Equal(t, int64(len(content)), gotMeta.Size)
	assert.NotEmpty(t, gotMeta.Checksum)
	assert.False(t, gotMeta.CreatedAt.IsZero())
	assert.Equal(t, map[string]string{"arch": "amd64"}, gotMeta.Labels)
}

// TestS3BlobStore_PutBlob_DefaultContentType verifies default content type.
func TestS3BlobStore_PutBlob_DefaultContentType(t *testing.T) {
	store := newTestS3Store(t)
	ctx := context.Background()

	err := store.PutBlob(ctx, testS3Key("notype.bin"), bytes.NewReader([]byte("data")), interfaces.BlobMeta{})
	require.NoError(t, err)

	_, meta, err := store.GetBlob(ctx, testS3Key("notype.bin"))
	require.NoError(t, err)
	assert.Equal(t, "application/octet-stream", meta.ContentType)
}

// TestS3BlobStore_PutBlob_TenantRequired verifies ErrBlobTenantRequired.
func TestS3BlobStore_PutBlob_TenantRequired(t *testing.T) {
	store := newTestS3Store(t)
	err := store.PutBlob(context.Background(),
		interfaces.BlobKey{Namespace: "ns", Name: "file.bin"},
		bytes.NewReader([]byte("x")),
		interfaces.BlobMeta{})
	assert.ErrorIs(t, err, interfaces.ErrBlobTenantRequired)
}

// TestS3BlobStore_GetBlob_NotFound verifies ErrBlobNotFound for a missing key.
func TestS3BlobStore_GetBlob_NotFound(t *testing.T) {
	store := newTestS3Store(t)
	_, _, err := store.GetBlob(context.Background(), testS3Key("missing.bin"))
	assert.ErrorIs(t, err, interfaces.ErrBlobNotFound)
}

// TestS3BlobStore_GetBlob_TenantRequired verifies TenantID validation in GetBlob.
func TestS3BlobStore_GetBlob_TenantRequired(t *testing.T) {
	store := newTestS3Store(t)
	_, _, err := store.GetBlob(context.Background(),
		interfaces.BlobKey{Namespace: "ns", Name: "f"})
	assert.ErrorIs(t, err, interfaces.ErrBlobTenantRequired)
}

// TestS3BlobStore_BlobExists verifies true for existing, false for missing.
func TestS3BlobStore_BlobExists(t *testing.T) {
	store := newTestS3Store(t)
	ctx := context.Background()

	key := testS3Key("exists.bin")
	exists, err := store.BlobExists(ctx, key)
	require.NoError(t, err)
	assert.False(t, exists)

	err = store.PutBlob(ctx, key, bytes.NewReader([]byte("data")), interfaces.BlobMeta{})
	require.NoError(t, err)

	exists, err = store.BlobExists(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists)
}

// TestS3BlobStore_BlobExists_TenantRequired verifies TenantID validation.
func TestS3BlobStore_BlobExists_TenantRequired(t *testing.T) {
	store := newTestS3Store(t)
	_, err := store.BlobExists(context.Background(), interfaces.BlobKey{Namespace: "ns", Name: "f"})
	assert.ErrorIs(t, err, interfaces.ErrBlobTenantRequired)
}

// TestS3BlobStore_DeleteBlob verifies delete and idempotency.
func TestS3BlobStore_DeleteBlob(t *testing.T) {
	store := newTestS3Store(t)
	ctx := context.Background()

	key := testS3Key("del.bin")
	err := store.PutBlob(ctx, key, bytes.NewReader([]byte("data")), interfaces.BlobMeta{})
	require.NoError(t, err)

	err = store.DeleteBlob(ctx, key)
	require.NoError(t, err)

	exists, err := store.BlobExists(ctx, key)
	require.NoError(t, err)
	assert.False(t, exists)

	// Second delete is a no-op.
	err = store.DeleteBlob(ctx, key)
	assert.NoError(t, err)
}

// TestS3BlobStore_DeleteBlob_TenantRequired verifies TenantID validation in DeleteBlob.
func TestS3BlobStore_DeleteBlob_TenantRequired(t *testing.T) {
	store := newTestS3Store(t)
	err := store.DeleteBlob(context.Background(), interfaces.BlobKey{Namespace: "ns", Name: "f"})
	assert.ErrorIs(t, err, interfaces.ErrBlobTenantRequired)
}

// TestS3BlobStore_ListBlobs verifies namespace-scoped listing.
func TestS3BlobStore_ListBlobs(t *testing.T) {
	store := newTestS3Store(t)
	ctx := context.Background()

	blobs := []interfaces.BlobKey{
		{TenantID: "tenant-a", Namespace: "installers", Name: "v1.pkg"},
		{TenantID: "tenant-a", Namespace: "installers", Name: "v2.pkg"},
		{TenantID: "tenant-a", Namespace: "reports", Name: "report.pdf"},
		{TenantID: "tenant-b", Namespace: "installers", Name: "other.pkg"},
	}
	for _, k := range blobs {
		err := store.PutBlob(ctx, k, bytes.NewReader([]byte("body")), interfaces.BlobMeta{})
		require.NoError(t, err)
	}

	// List tenant-a installers only.
	results, err := store.ListBlobs(ctx, interfaces.BlobKey{TenantID: "tenant-a", Namespace: "installers"})
	require.NoError(t, err)
	assert.Len(t, results, 2)
	for _, r := range results {
		assert.Equal(t, "tenant-a", r.Key.TenantID)
		assert.Equal(t, "installers", r.Key.Namespace)
	}

	// List all tenant-a blobs.
	all, err := store.ListBlobs(ctx, interfaces.BlobKey{TenantID: "tenant-a"})
	require.NoError(t, err)
	assert.Len(t, all, 3)

	// Tenant-b has one.
	tb, err := store.ListBlobs(ctx, interfaces.BlobKey{TenantID: "tenant-b"})
	require.NoError(t, err)
	assert.Len(t, tb, 1)
}

// TestS3BlobStore_ListBlobs_Empty verifies empty list when tenant has no blobs.
func TestS3BlobStore_ListBlobs_Empty(t *testing.T) {
	store := newTestS3Store(t)
	results, err := store.ListBlobs(context.Background(), interfaces.BlobKey{TenantID: "nobody"})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestS3BlobStore_ListBlobs_TenantRequired verifies TenantID validation.
func TestS3BlobStore_ListBlobs_TenantRequired(t *testing.T) {
	store := newTestS3Store(t)
	_, err := store.ListBlobs(context.Background(), interfaces.BlobKey{Namespace: "ns"})
	assert.ErrorIs(t, err, interfaces.ErrBlobTenantRequired)
}

// TestS3BlobStore_Overwrite verifies that PutBlob replaces an existing blob.
func TestS3BlobStore_Overwrite(t *testing.T) {
	store := newTestS3Store(t)
	ctx := context.Background()

	key := testS3Key("overwrite.bin")
	err := store.PutBlob(ctx, key, bytes.NewReader([]byte("v1")), interfaces.BlobMeta{})
	require.NoError(t, err)

	err = store.PutBlob(ctx, key, bytes.NewReader([]byte("v2 longer")), interfaces.BlobMeta{})
	require.NoError(t, err)

	rc, meta, err := store.GetBlob(ctx, key)
	require.NoError(t, err)
	defer rc.Close()

	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, []byte("v2 longer"), got)
	assert.Equal(t, int64(len("v2 longer")), meta.Size)
}

// TestS3BlobStore_WithPrefix verifies that a configured global prefix is applied to keys.
func TestS3BlobStore_WithPrefix(t *testing.T) {
	client := newInMemoryS3()
	store := &S3BlobStore{client: client, bucket: "bkt", prefix: "cfgms"}

	ctx := context.Background()
	key := testS3Key("file.bin")

	err := store.PutBlob(ctx, key, bytes.NewReader([]byte("data")), interfaces.BlobMeta{})
	require.NoError(t, err)

	// Verify the raw S3 object key includes the prefix.
	expectedObjKey := "bkt/cfgms/tenant-a/installers/file.bin"
	client.mu.RLock()
	_, exists := client.objects[expectedObjKey]
	client.mu.RUnlock()
	assert.True(t, exists, "S3 object key should include the configured prefix")

	// GetBlob and ListBlobs should also work transparently with the prefix.
	exists2, err := store.BlobExists(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists2)
}

// TestS3BlobStore_ChecksumMismatch verifies ErrBlobChecksumMismatch when blob data is tampered.
// It directly manipulates the in-memory S3 store to simulate a corrupted object.
func TestS3BlobStore_ChecksumMismatch(t *testing.T) {
	client := newInMemoryS3()
	store := &S3BlobStore{client: client, bucket: "test-bucket"}
	ctx := context.Background()

	key := testS3Key("tampered.bin")
	err := store.PutBlob(ctx, key, bytes.NewReader([]byte("original content")), interfaces.BlobMeta{})
	require.NoError(t, err)

	// Tamper with the stored blob object directly in the in-memory client.
	blobObjKey := "test-bucket/" + store.objectKey(key)
	client.mu.Lock()
	client.objects[blobObjKey].body = []byte("tampered content!!")
	client.mu.Unlock()

	rc, _, err := store.GetBlob(ctx, key)
	require.NoError(t, err)
	defer rc.Close()

	// Reading the tampered blob must return ErrBlobChecksumMismatch at EOF.
	_, err = io.ReadAll(rc)
	assert.ErrorIs(t, err, interfaces.ErrBlobChecksumMismatch)
}

// TestS3BlobStore_HealthCheck_Reachable verifies that HealthCheck returns nil
// when the bucket is reachable (HeadObject returns 404 for the sentinel key).
func TestS3BlobStore_HealthCheck_Reachable(t *testing.T) {
	store := newTestS3Store(t)
	err := store.HealthCheck(context.Background())
	assert.NoError(t, err)
}

// TestS3BlobStore_ChecksumRoundtrip verifies checksum is stored and returned.
func TestS3BlobStore_ChecksumRoundtrip(t *testing.T) {
	store := newTestS3Store(t)
	ctx := context.Background()

	content := []byte("checksum content")
	key := testS3Key("checksum.bin")
	err := store.PutBlob(ctx, key, bytes.NewReader(content), interfaces.BlobMeta{})
	require.NoError(t, err)

	_, meta, err := store.GetBlob(ctx, key)
	require.NoError(t, err)
	// Should be a 64-char lowercase hex SHA-256.
	assert.Len(t, meta.Checksum, 64, "checksum should be a 64-char SHA-256 hex string")
	assert.NotEmpty(t, meta.Checksum)
}

// TestS3BlobProvider_Metadata verifies provider metadata fields.
func TestS3BlobProvider_Metadata(t *testing.T) {
	p := &S3BlobProvider{}
	assert.NotEmpty(t, p.Name())
	assert.NotEmpty(t, p.Description())
	assert.NotEmpty(t, p.GetVersion())
	ok, err := p.Available()
	assert.NoError(t, err)
	assert.True(t, ok)
}

// TestS3BlobProvider_CreateBlobStore_MissingBucket verifies error when bucket is not set.
func TestS3BlobProvider_CreateBlobStore_MissingBucket(t *testing.T) {
	p := &S3BlobProvider{}
	_, err := p.CreateBlobStore(map[string]interface{}{})
	assert.Error(t, err)
}

// TestS3BlobProviderRegistration verifies auto-registration via init().
func TestS3BlobProviderRegistration(t *testing.T) {
	names := interfaces.GetRegisteredBlobProviderNames()
	found := false
	for _, n := range names {
		if n == "s3" {
			found = true
			break
		}
	}
	assert.True(t, found, "s3 blob provider should be registered via init()")
}
