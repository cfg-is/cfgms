// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package filesystem implements a local-filesystem BlobStore provider.
// Blobs are stored at <root>/<tenantID>/<namespace>/<name>.
// A JSON sidecar at <root>/<tenantID>/<namespace>/<name>.meta.json holds the metadata.
// SHA-256 checksums are computed during PutBlob and verified during GetBlob reads.
package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

const defaultContentType = "application/octet-stream"

// FilesystemBlobProvider implements BlobProvider using the local filesystem.
type FilesystemBlobProvider struct{}

func (p *FilesystemBlobProvider) Name() string { return "filesystem" }
func (p *FilesystemBlobProvider) Description() string {
	return "Local filesystem blob storage; OSS default for the blob data type (ADR-003)"
}
func (p *FilesystemBlobProvider) GetVersion() string       { return "1.0.0" }
func (p *FilesystemBlobProvider) Available() (bool, error) { return true, nil }

// CreateBlobStore instantiates a FilesystemBlobStore rooted at the configured directory.
// Config key: "root" (required) — absolute path to the storage root directory.
func (p *FilesystemBlobProvider) CreateBlobStore(config map[string]interface{}) (interfaces.BlobStore, error) {
	root, ok := config["root"].(string)
	if !ok || root == "" {
		return nil, fmt.Errorf("filesystem blob provider: config key 'root' is required and must be a non-empty string")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("filesystem blob provider: failed to create root directory %q: %w", root, err)
	}
	return &FilesystemBlobStore{root: root}, nil
}

// init auto-registers the filesystem provider so callers need only blank-import this package.
func init() {
	interfaces.RegisterBlobProvider(&FilesystemBlobProvider{})
}

// FilesystemBlobStore implements BlobStore backed by the local filesystem.
type FilesystemBlobStore struct {
	root string
}

// blobMetaSidecar is the on-disk format of the JSON metadata sidecar.
type blobMetaSidecar struct {
	ContentType string            `json:"content_type"`
	Size        int64             `json:"size"`
	Checksum    string            `json:"checksum"` // SHA-256 hex
	CreatedAt   time.Time         `json:"created_at"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// validateKeyComponent rejects blob key fields that would enable path traversal.
// Returns an error if the component contains "..", "/", or "\" characters.
func validateKeyComponent(field, value string) error {
	if strings.Contains(value, "..") {
		return fmt.Errorf("blob key %s must not contain '..'", field)
	}
	if strings.ContainsAny(value, `/\`) {
		return fmt.Errorf("blob key %s must not contain path separators", field)
	}
	return nil
}

// validateKey validates all components of a BlobKey for path safety.
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

func (s *FilesystemBlobStore) blobPath(key interfaces.BlobKey) string {
	return filepath.Join(s.root, key.TenantID, key.Namespace, key.Name)
}

func (s *FilesystemBlobStore) metaPath(key interfaces.BlobKey) string {
	return s.blobPath(key) + ".meta.json"
}

// PutBlob writes a blob and its sidecar metadata file atomically.
// Data is streamed via io.TeeReader; SHA-256 is computed during the write.
// The blob file is written to a temp file and then renamed to prevent partial writes.
func (s *FilesystemBlobStore) PutBlob(ctx context.Context, key interfaces.BlobKey, r io.Reader, meta interfaces.BlobMeta) error {
	if err := validateKey(key); err != nil {
		return err
	}

	dir := filepath.Join(s.root, key.TenantID, key.Namespace)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("blob put: failed to create directory: %w", err)
	}

	// Write to a temp file in the same directory so os.Rename is atomic.
	tmpFile, err := os.CreateTemp(dir, ".blob-tmp-*")
	if err != nil {
		return fmt.Errorf("blob put: failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()

	// Stream data through SHA-256 hash into the temp file.
	h := sha256.New()
	tee := io.TeeReader(r, h)
	written, err := io.Copy(tmpFile, tee)
	if err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("blob put: failed to write blob data: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("blob put: failed to close temp file: %w", err)
	}

	checksum := hex.EncodeToString(h.Sum(nil))
	contentType := meta.ContentType
	if contentType == "" {
		contentType = defaultContentType
	}

	// Atomic rename to the final path.
	if err := os.Rename(tmpPath, s.blobPath(key)); err != nil {
		return fmt.Errorf("blob put: failed to rename to final path: %w", err)
	}
	success = true

	// Write sidecar metadata after blob is safely in place.
	sidecar := blobMetaSidecar{
		ContentType: contentType,
		Size:        written,
		Checksum:    checksum,
		CreatedAt:   time.Now().UTC(),
		Labels:      meta.Labels,
	}
	metaJSON, err := json.Marshal(sidecar)
	if err != nil {
		return fmt.Errorf("blob put: failed to marshal metadata: %w", err)
	}
	if err := os.WriteFile(s.metaPath(key), metaJSON, 0o600); err != nil {
		return fmt.Errorf("blob put: failed to write metadata sidecar: %w", err)
	}

	return nil
}

// GetBlob returns a streaming reader for the blob.
// The reader wraps the file in a checksumVerifyingReader that computes SHA-256
// during reads and returns ErrBlobChecksumMismatch on the final read if the
// computed digest does not match the stored checksum.
func (s *FilesystemBlobStore) GetBlob(ctx context.Context, key interfaces.BlobKey) (io.ReadCloser, interfaces.BlobMeta, error) {
	if err := validateKey(key); err != nil {
		return nil, interfaces.BlobMeta{}, err
	}

	metaBytes, err := os.ReadFile(s.metaPath(key))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, interfaces.BlobMeta{}, interfaces.ErrBlobNotFound
		}
		return nil, interfaces.BlobMeta{}, fmt.Errorf("blob get: failed to read metadata sidecar: %w", err)
	}

	var sidecar blobMetaSidecar
	if err := json.Unmarshal(metaBytes, &sidecar); err != nil {
		return nil, interfaces.BlobMeta{}, fmt.Errorf("blob get: failed to parse metadata sidecar: %w", err)
	}

	f, err := os.Open(s.blobPath(key))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, interfaces.BlobMeta{}, interfaces.ErrBlobNotFound
		}
		return nil, interfaces.BlobMeta{}, fmt.Errorf("blob get: failed to open blob file: %w", err)
	}

	blobMeta := interfaces.BlobMeta{
		ContentType: sidecar.ContentType,
		Size:        sidecar.Size,
		Checksum:    sidecar.Checksum,
		CreatedAt:   sidecar.CreatedAt,
		Labels:      sidecar.Labels,
	}

	return &checksumVerifyingReader{
		inner:    f,
		hasher:   sha256.New(),
		expected: sidecar.Checksum,
	}, blobMeta, nil
}

// DeleteBlob removes both the blob file and its sidecar metadata.
// Returns nil if neither file exists.
func (s *FilesystemBlobStore) DeleteBlob(ctx context.Context, key interfaces.BlobKey) error {
	if err := validateKey(key); err != nil {
		return err
	}

	if err := os.Remove(s.blobPath(key)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("blob delete: failed to remove blob file: %w", err)
	}
	if err := os.Remove(s.metaPath(key)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("blob delete: failed to remove metadata sidecar: %w", err)
	}
	return nil
}

// ListBlobs returns all blobs whose key matches the non-empty prefix fields.
// TenantID must be set. If Namespace is set, only blobs in that namespace are returned.
// If Name is set, only blobs whose Name has that prefix are returned.
func (s *FilesystemBlobStore) ListBlobs(ctx context.Context, prefix interfaces.BlobKey) ([]interfaces.BlobInfo, error) {
	if prefix.TenantID == "" {
		return nil, interfaces.ErrBlobTenantRequired
	}
	if err := validateKeyComponent("TenantID", prefix.TenantID); err != nil {
		return nil, err
	}
	if err := validateKeyComponent("Namespace", prefix.Namespace); err != nil {
		return nil, err
	}

	searchDir := filepath.Join(s.root, prefix.TenantID)
	if prefix.Namespace != "" {
		searchDir = filepath.Join(searchDir, prefix.Namespace)
	}

	var results []interfaces.BlobInfo

	err := filepath.WalkDir(searchDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".meta.json") {
			return nil
		}

		metaBytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("list blobs: failed to read metadata: %w", err)
		}

		var sidecar blobMetaSidecar
		if err := json.Unmarshal(metaBytes, &sidecar); err != nil {
			return fmt.Errorf("list blobs: failed to parse metadata: %w", err)
		}

		// Reconstruct the key from the relative path: <tenantID>/<namespace>/<name>.meta.json
		rel, err := filepath.Rel(s.root, path)
		if err != nil {
			return err
		}
		rel = strings.TrimSuffix(rel, ".meta.json")
		parts := strings.SplitN(filepath.ToSlash(rel), "/", 3)
		if len(parts) != 3 {
			return nil
		}

		key := interfaces.BlobKey{
			TenantID:  parts[0],
			Namespace: parts[1],
			Name:      parts[2],
		}

		if prefix.Name != "" && !strings.HasPrefix(key.Name, prefix.Name) {
			return nil
		}

		results = append(results, interfaces.BlobInfo{
			Key: key,
			Meta: interfaces.BlobMeta{
				ContentType: sidecar.ContentType,
				Size:        sidecar.Size,
				Checksum:    sidecar.Checksum,
				CreatedAt:   sidecar.CreatedAt,
				Labels:      sidecar.Labels,
			},
		})
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("list blobs: %w", err)
	}
	return results, nil
}

// BlobExists reports whether a blob exists by checking for its sidecar metadata file.
// Does not read the blob content.
func (s *FilesystemBlobStore) BlobExists(ctx context.Context, key interfaces.BlobKey) (bool, error) {
	if key.TenantID == "" {
		return false, interfaces.ErrBlobTenantRequired
	}
	if err := validateKeyComponent("TenantID", key.TenantID); err != nil {
		return false, err
	}
	if err := validateKeyComponent("Namespace", key.Namespace); err != nil {
		return false, err
	}
	if err := validateKeyComponent("Name", key.Name); err != nil {
		return false, err
	}
	_, err := os.Stat(s.metaPath(key))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("blob exists: %w", err)
	}
	return true, nil
}

// HealthCheck verifies that the root directory is accessible.
func (s *FilesystemBlobStore) HealthCheck(ctx context.Context) error {
	if _, err := os.Stat(s.root); err != nil {
		return fmt.Errorf("filesystem blob store: root directory not accessible: %w", err)
	}
	return nil
}

// checksumVerifyingReader wraps an io.ReadCloser and computes SHA-256 during reads.
// On the final Read that returns io.EOF, it compares the computed digest against
// the expected checksum and returns ErrBlobChecksumMismatch if they differ.
type checksumVerifyingReader struct {
	inner    io.ReadCloser
	hasher   hash.Hash
	expected string
}

func (r *checksumVerifyingReader) Read(p []byte) (int, error) {
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

func (r *checksumVerifyingReader) Close() error {
	return r.inner.Close()
}
