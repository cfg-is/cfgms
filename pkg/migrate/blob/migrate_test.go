//go:build integration

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package blob_test contains integration tests for the blob migrator.
//
// Prerequisites:
//
//	docker compose --profile blob-migrate -f docker-compose.test.yml up -d minio-test
//
// Environment variables (defaults match the docker-compose service):
//
//	CFGMS_S3_TEST_BUCKET       – S3 bucket name (default: "cfgms-test-blobs")
//	CFGMS_S3_TEST_ENDPOINT_URL – MinIO endpoint URL (default: "http://localhost:9002")
package blob_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	blobmigrate "github.com/cfgis/cfgms/pkg/migrate/blob"
	blobstore "github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
)

// testS3Config holds MinIO connection parameters for the integration test.
type testS3Config struct {
	bucket      string
	endpointURL string
	accessKey   string
	secretKey   string
}

// minioConfig reads MinIO connection parameters from environment variables.
// Defaults match the docker-compose.test.yml minio-test service.
// Variables: CFGMS_S3_TEST_BUCKET, CFGMS_S3_TEST_ENDPOINT_URL,
// CFGMS_S3_TEST_ACCESS_KEY, CFGMS_S3_TEST_SECRET_KEY.
func minioConfig() testS3Config {
	bucket := os.Getenv("CFGMS_S3_TEST_BUCKET")
	if bucket == "" {
		bucket = "cfgms-test-blobs"
	}
	endpointURL := os.Getenv("CFGMS_S3_TEST_ENDPOINT_URL")
	if endpointURL == "" {
		endpointURL = "http://localhost:9002"
	}
	accessKey := os.Getenv("CFGMS_S3_TEST_ACCESS_KEY")
	if accessKey == "" {
		accessKey = "minioadmin"
	}
	secretKey := os.Getenv("CFGMS_S3_TEST_SECRET_KEY")
	if secretKey == "" {
		secretKey = "minioadmin"
	}
	return testS3Config{
		bucket:      bucket,
		endpointURL: endpointURL,
		accessKey:   accessKey,
		secretKey:   secretKey,
	}
}

// ensureTestBucket creates the test bucket if it does not already exist.
func ensureTestBucket(t *testing.T, cfg testS3Config) {
	t.Helper()

	ctx := context.Background()
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.accessKey, cfg.secretKey, ""),
		),
	)
	require.NoError(t, err, "failed to load AWS config")

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(cfg.endpointURL)
		o.UsePathStyle = true
	})

	_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(cfg.bucket)})
	if err != nil {
		var owned *s3types.BucketAlreadyOwnedByYou
		var exists *s3types.BucketAlreadyExists
		if !errors.As(err, &owned) && !errors.As(err, &exists) {
			t.Fatalf("failed to create test bucket %q: %v — is minio-test running?", cfg.bucket, err)
		}
	}
}

// newS3Store creates a BlobStore backed by the docker-compose MinIO instance.
func newS3Store(t *testing.T, cfg testS3Config) blobstore.BlobStore {
	t.Helper()

	store, err := blobstore.CreateBlobStoreFromConfig("s3", map[string]interface{}{
		"bucket":            cfg.bucket,
		"endpoint_url":      cfg.endpointURL,
		"access_key_id":     cfg.accessKey,
		"secret_access_key": cfg.secretKey,
	})
	require.NoError(t, err, "failed to create S3 test store")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, store.HealthCheck(ctx),
		"S3 health check failed — is minio-test running? "+
			"Start with: docker compose --profile blob-migrate -f docker-compose.test.yml up -d minio-test")

	return store
}

// TestBlobMigrate_FilesystemToS3RoundTrip verifies a full filesystem → S3 → filesystem
// round-trip using a real filesystem store and a real MinIO-backed S3 store.
// Asserts that installer artifacts are preserved with matching checksums and keys.
func TestBlobMigrate_FilesystemToS3RoundTrip(t *testing.T) {
	cfg := minioConfig()
	ensureTestBucket(t, cfg)

	ctx := context.Background()
	// S3 provider rejects "/" in TenantID (breaks parseObjectKey's SplitN logic);
	// use a flat ID valid for both filesystem and S3 providers.
	tenantID := fmt.Sprintf("integration%d", time.Now().UnixNano())

	// Source: real filesystem store.
	src, err := blobstore.CreateBlobStoreFromConfig("filesystem", map[string]interface{}{
		"root": t.TempDir(),
	})
	require.NoError(t, err)

	// Destination: real S3 store backed by MinIO.
	s3Dst := newS3Store(t, cfg)

	// Populate source with installer artifacts.
	type testBlob struct {
		key     blobstore.BlobKey
		content []byte
		labels  map[string]string
	}
	blobs := []testBlob{
		{
			key:     blobstore.BlobKey{TenantID: tenantID, Namespace: "installers", Name: "agent-amd64.pkg"},
			content: []byte("fake installer payload for amd64 architecture"),
			labels:  map[string]string{"arch": "amd64", "version": "1.0.0"},
		},
		{
			key:     blobstore.BlobKey{TenantID: tenantID, Namespace: "installers", Name: "agent-arm64.pkg"},
			content: []byte("fake installer payload for arm64 architecture"),
			labels:  map[string]string{"arch": "arm64", "version": "1.0.0"},
		},
		{
			key:     blobstore.BlobKey{TenantID: tenantID, Namespace: "reports", Name: "audit.pdf"},
			content: []byte("audit report content"),
			labels:  map[string]string{"type": "audit"},
		},
	}

	for _, b := range blobs {
		err := src.PutBlob(ctx, b.key, bytes.NewReader(b.content), blobstore.BlobMeta{
			ContentType: "application/octet-stream",
			Labels:      b.labels,
		})
		require.NoErrorf(t, err, "put source blob %s", b.key.Name)
	}

	// Record source checksums before migration.
	srcList, err := src.ListBlobs(ctx, blobstore.BlobKey{TenantID: tenantID})
	require.NoError(t, err)
	require.Len(t, srcList, len(blobs))
	srcChecksums := make(map[string]string, len(srcList))
	for _, info := range srcList {
		srcChecksums[info.Key.Name] = info.Meta.Checksum
	}

	// ─── Phase 1: filesystem → S3 ───────────────────────────────────────────

	m := blobmigrate.NewBlobMigrator(src, s3Dst, []string{tenantID})
	report, err := m.Run(ctx)
	require.NoError(t, err, "filesystem→S3 migration must succeed")

	assert.Equal(t, 2, report.Counts["installers"], "installer count must match")
	assert.Equal(t, 1, report.Counts["reports"], "reports count must match")
	assert.Empty(t, report.Errors, "no errors expected")

	// Verify all blobs are readable from S3 with matching content and checksums.
	for _, b := range blobs {
		rc, meta, err := s3Dst.GetBlob(ctx, b.key)
		require.NoErrorf(t, err, "blob %q must be readable from S3", b.key.Name)

		got, err := io.ReadAll(rc)
		require.NoError(t, err)
		require.NoErrorf(t, rc.Close(), "blob %q close must not error", b.key.Name)

		assert.Equalf(t, b.content, got, "blob %q content must match", b.key.Name)
		assert.Equalf(t, b.labels, meta.Labels, "blob %q labels must be preserved", b.key.Name)
		assert.Lenf(t, meta.Checksum, 64, "blob %q checksum must be 64-char SHA-256", b.key.Name)
		assert.Equalf(t, srcChecksums[b.key.Name], meta.Checksum,
			"blob %q checksum must match source after migration", b.key.Name)
	}

	// ─── Phase 2: S3 → filesystem (reverse) ─────────────────────────────────

	dst2, err := blobstore.CreateBlobStoreFromConfig("filesystem", map[string]interface{}{
		"root": t.TempDir(),
	})
	require.NoError(t, err)

	revMig := blobmigrate.NewBlobMigrator(s3Dst, dst2, []string{tenantID})
	revReport, err := revMig.Run(ctx)
	require.NoError(t, err, "S3→filesystem migration must succeed")

	assert.Equal(t, 2, revReport.Counts["installers"], "reverse: installer count must match")
	assert.Equal(t, 1, revReport.Counts["reports"], "reverse: reports count must match")

	// Verify round-trip: filesystem checksums must match original source checksums.
	for _, b := range blobs {
		rc, meta, err := dst2.GetBlob(ctx, b.key)
		require.NoErrorf(t, err, "blob %q must be readable after round-trip", b.key.Name)

		got, err := io.ReadAll(rc)
		require.NoError(t, err)
		require.NoErrorf(t, rc.Close(), "blob %q close must not error on round-trip", b.key.Name)

		assert.Equalf(t, b.content, got, "blob %q content must survive round-trip", b.key.Name)
		assert.Equalf(t, srcChecksums[b.key.Name], meta.Checksum,
			"blob %q checksum must match original after round-trip", b.key.Name)
	}
}
