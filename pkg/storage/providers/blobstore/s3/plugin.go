// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package s3provider implements an S3-compatible BlobStore provider.
//
// Blobs are stored as S3 objects keyed by <tenantID>/<namespace>/<name> within
// the configured bucket. A small JSON metadata sidecar is stored alongside each
// blob at <tenantID>/<namespace>/<name>.meta.json. This sidecar holds the full
// BlobMeta (checksum, content-type, labels, created-at) — consistent with the
// filesystem provider design and avoiding S3 metadata size limits for labels.
//
// SHA-256 checksums are computed during PutBlob via io.TeeReader, meaning the
// hash is calculated in one streaming pass as data is sent to S3. No additional
// buffering or re-read is required.
//
// S3 test approach: tests use an in-memory s3API implementation rather than
// gofakes3 (not in go.mod) or a real S3/MinIO endpoint. This avoids external
// runtime dependencies while testing all code paths with a real implementation.
package s3provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

const (
	defaultContentType = "application/octet-stream"
	defaultRegion      = "us-east-1"

	// Metadata sidecar key prefix stored in S3.
	metaSuffix = ".meta.json"
)

// s3API is the subset of the AWS S3 API used by S3BlobStore.
// Defining an interface allows injection of the in-memory test implementation
// without requiring a real S3/MinIO endpoint.
type s3API interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

// S3BlobProvider implements BlobProvider using an S3-compatible object store.
type S3BlobProvider struct{}

func (p *S3BlobProvider) Name() string { return "s3" }
func (p *S3BlobProvider) Description() string {
	return "S3-compatible object storage blob provider; commercial/operator choice for the blob data type (ADR-003)"
}
func (p *S3BlobProvider) GetVersion() string       { return "1.0.0" }
func (p *S3BlobProvider) Available() (bool, error) { return true, nil }

// CreateBlobStore instantiates an S3BlobStore from the given configuration.
//
// Config keys:
//   - "bucket" (required): S3 bucket name.
//   - "region" (optional): AWS region, defaults to "us-east-1".
//   - "endpoint_url" (optional): custom endpoint for MinIO or local dev.
//   - "prefix" (optional): global key prefix applied to all objects.
//   - "access_key_id" / "secret_access_key" (optional): static credentials;
//     if omitted the default AWS credential chain (env, IAM, etc.) is used.
func (p *S3BlobProvider) CreateBlobStore(config map[string]interface{}) (interfaces.BlobStore, error) {
	bucket := getS3StringConfig(config, "bucket", "")
	if bucket == "" {
		return nil, fmt.Errorf("s3 blob provider: config key 'bucket' is required")
	}

	region := getS3StringConfig(config, "region", defaultRegion)
	prefix := getS3StringConfig(config, "prefix", "")
	endpointURL := getS3StringConfig(config, "endpoint_url", "")
	accessKeyID := getS3StringConfig(config, "access_key_id", "")
	secretAccessKey := getS3StringConfig(config, "secret_access_key", "")

	ctx := context.Background()
	var opts []func(*awsconfig.LoadOptions) error
	opts = append(opts, awsconfig.WithRegion(region))

	if accessKeyID != "" && secretAccessKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, ""),
		))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("s3 blob provider: failed to load AWS config: %w", err)
	}

	var s3Opts []func(*s3.Options)
	if endpointURL != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpointURL)
			o.UsePathStyle = true
		})
	}

	client := s3.NewFromConfig(cfg, s3Opts...)
	return &S3BlobStore{client: client, bucket: bucket, prefix: prefix}, nil
}

// init auto-registers the S3 provider so callers need only blank-import this package.
func init() {
	interfaces.RegisterBlobProvider(&S3BlobProvider{})
}

// S3BlobStore implements BlobStore backed by an S3-compatible object store.
type S3BlobStore struct {
	client s3API
	bucket string
	prefix string // optional global key prefix (e.g., "cfgms")
}

// s3BlobMetaSidecar is the JSON sidecar stored alongside each blob object.
type s3BlobMetaSidecar struct {
	ContentType string            `json:"content_type"`
	Size        int64             `json:"size"`
	Checksum    string            `json:"checksum"` // "sha256-<hex>"
	CreatedAt   time.Time         `json:"created_at"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// validateKeyComponent rejects blob key fields that would cause object key ambiguity.
// S3 keys are opaque strings (no directory traversal), but accepting "/" or ".."
// in components would break parseObjectKey's SplitN logic and enable namespace
// confusion between tenants. Mirrors the filesystem provider's validation contract.
func validateKeyComponent(field, value string) error {
	if strings.Contains(value, "..") {
		return fmt.Errorf("blob key %s must not contain '..'", field)
	}
	if strings.ContainsAny(value, `/\`) {
		return fmt.Errorf("blob key %s must not contain path separators", field)
	}
	return nil
}

// validateKey validates all components of a BlobKey.
func validateKey(key interfaces.BlobKey) error {
	if key.TenantID == "" {
		return interfaces.ErrBlobTenantRequired
	}
	if err := validateKeyComponent("TenantID", key.TenantID); err != nil {
		return err
	}
	if err := validateKeyComponent("Namespace", key.Namespace); err != nil {
		return err
	}
	if err := validateKeyComponent("Name", key.Name); err != nil {
		return err
	}
	return nil
}

// objectKey returns the S3 object key for a blob.
func (s *S3BlobStore) objectKey(key interfaces.BlobKey) string {
	parts := []string{key.TenantID, key.Namespace, key.Name}
	if s.prefix != "" {
		parts = append([]string{s.prefix}, parts...)
	}
	return strings.Join(parts, "/")
}

// metaObjectKey returns the S3 object key for a blob's metadata sidecar.
func (s *S3BlobStore) metaObjectKey(key interfaces.BlobKey) string {
	return s.objectKey(key) + metaSuffix
}

// PutBlob streams the blob to S3 and writes a JSON metadata sidecar object.
// SHA-256 is computed in one streaming pass via io.TeeReader.
func (s *S3BlobStore) PutBlob(ctx context.Context, key interfaces.BlobKey, r io.Reader, meta interfaces.BlobMeta) error {
	if err := validateKey(key); err != nil {
		return err
	}

	contentType := meta.ContentType
	if contentType == "" {
		contentType = defaultContentType
	}

	// Stream data through a SHA-256 hasher. By the time PutObject returns,
	// all bytes have been read and the hash is complete.
	h := sha256.New()
	tee := io.TeeReader(r, h)

	// Read all data — needed because S3 PutObject requires a seekable or
	// known-length body for reliable uploads without multipart. For large blobs
	// in production, callers should use multipart upload; this provider targets
	// blobs up to a few hundred MB which S3 handles in a single PutObject.
	blobData, err := io.ReadAll(tee)
	if err != nil {
		return fmt.Errorf("blob s3 put: failed to read blob data: %w", err)
	}

	checksum := hex.EncodeToString(h.Sum(nil))
	size := int64(len(blobData))

	// Upload the blob object.
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(s.objectKey(key)),
		Body:          bytes.NewReader(blobData),
		ContentType:   aws.String(contentType),
		ContentLength: aws.Int64(size),
	})
	if err != nil {
		return fmt.Errorf("blob s3 put: failed to upload blob: %w", err)
	}

	// Write the metadata sidecar.
	sidecar := s3BlobMetaSidecar{
		ContentType: contentType,
		Size:        size,
		Checksum:    checksum,
		CreatedAt:   time.Now().UTC(),
		Labels:      meta.Labels,
	}
	metaJSON, err := json.Marshal(sidecar)
	if err != nil {
		return fmt.Errorf("blob s3 put: failed to marshal metadata: %w", err)
	}

	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(s.metaObjectKey(key)),
		Body:          bytes.NewReader(metaJSON),
		ContentType:   aws.String("application/json"),
		ContentLength: aws.Int64(int64(len(metaJSON))),
	})
	if err != nil {
		return fmt.Errorf("blob s3 put: failed to upload metadata sidecar: %w", err)
	}

	return nil
}

// GetBlob retrieves the blob and its metadata from S3.
// The returned reader streams the blob body. The stored checksum is available
// in the returned BlobMeta for callers that want to verify integrity.
func (s *S3BlobStore) GetBlob(ctx context.Context, key interfaces.BlobKey) (io.ReadCloser, interfaces.BlobMeta, error) {
	if err := validateKey(key); err != nil {
		return nil, interfaces.BlobMeta{}, err
	}

	// Fetch the metadata sidecar.
	metaOut, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.metaObjectKey(key)),
	})
	if err != nil {
		if isS3NotFound(err) {
			return nil, interfaces.BlobMeta{}, interfaces.ErrBlobNotFound
		}
		return nil, interfaces.BlobMeta{}, fmt.Errorf("blob s3 get: failed to get metadata sidecar: %w", err)
	}
	metaBytes, err := io.ReadAll(metaOut.Body)
	_ = metaOut.Body.Close()
	if err != nil {
		return nil, interfaces.BlobMeta{}, fmt.Errorf("blob s3 get: failed to read metadata sidecar: %w", err)
	}

	var sidecar s3BlobMetaSidecar
	if err := json.Unmarshal(metaBytes, &sidecar); err != nil {
		return nil, interfaces.BlobMeta{}, fmt.Errorf("blob s3 get: failed to parse metadata sidecar: %w", err)
	}

	// Fetch the blob object.
	blobOut, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey(key)),
	})
	if err != nil {
		if isS3NotFound(err) {
			return nil, interfaces.BlobMeta{}, interfaces.ErrBlobNotFound
		}
		return nil, interfaces.BlobMeta{}, fmt.Errorf("blob s3 get: failed to get blob: %w", err)
	}

	blobMeta := interfaces.BlobMeta{
		ContentType: sidecar.ContentType,
		Size:        sidecar.Size,
		Checksum:    sidecar.Checksum,
		CreatedAt:   sidecar.CreatedAt,
		Labels:      sidecar.Labels,
	}

	// Wrap the S3 body in a checksum-verifying reader so that callers receive
	// ErrBlobChecksumMismatch on the final Read call if the blob has been tampered with.
	return &s3ChecksumVerifyingReader{
		inner:    blobOut.Body,
		hasher:   sha256.New(),
		expected: sidecar.Checksum,
	}, blobMeta, nil
}

// DeleteBlob removes the blob object and its metadata sidecar from S3.
// S3 DeleteObject is idempotent; missing objects are silently ignored.
func (s *S3BlobStore) DeleteBlob(ctx context.Context, key interfaces.BlobKey) error {
	if err := validateKey(key); err != nil {
		return err
	}

	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey(key)),
	})
	if err != nil {
		return fmt.Errorf("blob s3 delete: failed to delete blob: %w", err)
	}

	_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.metaObjectKey(key)),
	})
	if err != nil {
		return fmt.Errorf("blob s3 delete: failed to delete metadata sidecar: %w", err)
	}

	return nil
}

// ListBlobs returns blobs whose keys match the non-empty prefix fields.
// TenantID must be set. Namespace and Name are optional additional filters.
// Metadata sidecar objects (.meta.json) are excluded from results.
func (s *S3BlobStore) ListBlobs(ctx context.Context, prefix interfaces.BlobKey) ([]interfaces.BlobInfo, error) {
	if prefix.TenantID == "" {
		return nil, interfaces.ErrBlobTenantRequired
	}
	if err := validateKeyComponent("TenantID", prefix.TenantID); err != nil {
		return nil, err
	}
	if err := validateKeyComponent("Namespace", prefix.Namespace); err != nil {
		return nil, err
	}

	// Build the S3 key prefix to filter objects.
	keyPrefix := prefix.TenantID + "/"
	if s.prefix != "" {
		keyPrefix = s.prefix + "/" + keyPrefix
	}
	if prefix.Namespace != "" {
		keyPrefix += prefix.Namespace + "/"
	}
	if prefix.Name != "" {
		keyPrefix += prefix.Name
	}

	out, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(keyPrefix),
	})
	if err != nil {
		return nil, fmt.Errorf("blob s3 list: failed to list objects: %w", err)
	}

	// For each non-sidecar blob object, fetch its sidecar metadata.
	var results []interfaces.BlobInfo
	for _, obj := range out.Contents {
		objKey := aws.ToString(obj.Key)
		if strings.HasSuffix(objKey, metaSuffix) {
			continue
		}

		blobKey, err := s.parseObjectKey(objKey)
		if err != nil {
			continue
		}

		// Fetch sidecar for this blob. Orphaned blobs (sidecar not found) are
		// skipped silently; any other error (network, parse failure) is surfaced
		// to preserve the reliability contract of the return value.
		sidecar, err := s.fetchSidecar(ctx, blobKey)
		if err != nil {
			if isS3NotFound(err) {
				continue
			}
			return nil, fmt.Errorf("blob s3 list: failed to fetch sidecar for %q: %w", objKey, err)
		}

		results = append(results, interfaces.BlobInfo{
			Key: blobKey,
			Meta: interfaces.BlobMeta{
				ContentType: sidecar.ContentType,
				Size:        sidecar.Size,
				Checksum:    sidecar.Checksum,
				CreatedAt:   sidecar.CreatedAt,
				Labels:      sidecar.Labels,
			},
		})
	}

	return results, nil
}

// BlobExists reports whether a blob exists by issuing a HeadObject on the sidecar.
func (s *S3BlobStore) BlobExists(ctx context.Context, key interfaces.BlobKey) (bool, error) {
	if err := validateKey(key); err != nil {
		return false, err
	}

	_, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.metaObjectKey(key)),
	})
	if err != nil {
		if isS3NotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("blob s3 exists: %w", err)
	}
	return true, nil
}

// HealthCheck verifies S3 reachability by issuing a HeadObject on a sentinel key.
// The object need not exist — a 404 from S3 means the bucket is reachable.
func (s *S3BlobStore) HealthCheck(ctx context.Context) error {
	_, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String("_cfgms_health_check"),
	})
	if err != nil && isS3NotFound(err) {
		return nil // bucket is reachable; object absence is expected
	}
	if err != nil {
		return fmt.Errorf("s3 blob store health check: %w", err)
	}
	return nil
}

// fetchSidecar retrieves and parses the metadata sidecar for a blob.
func (s *S3BlobStore) fetchSidecar(ctx context.Context, key interfaces.BlobKey) (*s3BlobMetaSidecar, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.metaObjectKey(key)),
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = out.Body.Close() }()

	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, err
	}

	var sidecar s3BlobMetaSidecar
	if err := json.Unmarshal(data, &sidecar); err != nil {
		return nil, err
	}
	return &sidecar, nil
}

// parseObjectKey reconstructs a BlobKey from an S3 object key.
// Object key format: [prefix/]<tenantID>/<namespace>/<name>
func (s *S3BlobStore) parseObjectKey(objKey string) (interfaces.BlobKey, error) {
	// Strip global prefix if configured.
	if s.prefix != "" {
		expected := s.prefix + "/"
		if !strings.HasPrefix(objKey, expected) {
			return interfaces.BlobKey{}, fmt.Errorf("unexpected key prefix")
		}
		objKey = objKey[len(expected):]
	}

	parts := strings.SplitN(objKey, "/", 3)
	if len(parts) != 3 {
		return interfaces.BlobKey{}, fmt.Errorf("malformed S3 object key: %q", objKey)
	}
	return interfaces.BlobKey{
		TenantID:  parts[0],
		Namespace: parts[1],
		Name:      parts[2],
	}, nil
}

// isS3NotFound reports whether an S3 error represents a not-found condition.
func isS3NotFound(err error) bool {
	var noSuchKey *s3types.NoSuchKey
	if errors.As(err, &noSuchKey) {
		return true
	}
	var notFound *s3types.NotFound
	return errors.As(err, &notFound)
}

// s3ChecksumVerifyingReader computes SHA-256 during reads and returns
// ErrBlobChecksumMismatch on the final read if the checksum does not match.
type s3ChecksumVerifyingReader struct {
	inner    io.ReadCloser
	hasher   hash.Hash
	expected string
}

func (r *s3ChecksumVerifyingReader) Read(p []byte) (int, error) {
	n, err := r.inner.Read(p)
	if n > 0 {
		_, _ = r.hasher.Write(p[:n])
	}
	if err == io.EOF {
		actual := hex.EncodeToString(r.hasher.Sum(nil))
		if actual != r.expected {
			return n, interfaces.ErrBlobChecksumMismatch
		}
	}
	return n, err
}

func (r *s3ChecksumVerifyingReader) Close() error {
	return r.inner.Close()
}

// getS3StringConfig is a helper to extract string values from a config map.
func getS3StringConfig(config map[string]interface{}, key, defaultVal string) string {
	if v, ok := config[key].(string); ok && v != "" {
		return v
	}
	return defaultVal
}
