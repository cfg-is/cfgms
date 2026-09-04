// SPDX-License-Identifier: AGPL-3.0-only
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

	blob "github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
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
func (p *FilesystemBlobProvider) CreateBlobStore(config map[string]interface{}) (blob.BlobStore, error) {
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
	blob.RegisterBlobProvider(&FilesystemBlobProvider{})
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
// TenantID may contain "/" to express hierarchical tenants (e.g. "root/child-a");
// all other fields (Namespace, Name) must not contain path separators.
// All fields reject ".." and leading "/" to prevent directory traversal.
func validateKeyComponent(field, value string) error {
	if strings.Contains(value, "..") {
		return fmt.Errorf("blob key %s must not contain '..'", field)
	}
	if strings.Contains(value, `\`) {
		return fmt.Errorf("blob key %s must not contain '\\'", field)
	}
	if field == "TenantID" {
		// Hierarchical tenants use "/" as a path separator; reject only a leading
		// slash (which would make filepath.Join treat it as an absolute path).
		if strings.HasPrefix(value, "/") {
			return fmt.Errorf("blob key TenantID must not start with '/'")
		}
		return nil
	}
	if strings.Contains(value, "/") {
		return fmt.Errorf("blob key %s must not contain '/'", field)
	}
	return nil
}

// validateKey validates all components of a BlobKey for path safety.
func validateKey(key blob.BlobKey) error {
	if key.TenantID == "" {
		return blob.ErrBlobTenantRequired
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

func (s *FilesystemBlobStore) blobPath(key blob.BlobKey) string {
	return filepath.Join(s.root, key.TenantID, key.Namespace, key.Name)
}

func (s *FilesystemBlobStore) metaPath(key blob.BlobKey) string {
	return s.blobPath(key) + ".meta.json"
}

// PutBlob writes a blob and its sidecar metadata file atomically.
// Data is streamed via io.TeeReader; SHA-256 is computed during the write.
// The blob file is written to a temp file and then renamed to prevent partial writes.
func (s *FilesystemBlobStore) PutBlob(ctx context.Context, key blob.BlobKey, r io.Reader, meta blob.BlobMeta) error {
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

// PutBlobIfAbsent stores a blob only if no blob currently exists for key,
// atomic with respect to concurrent PutBlob/PutBlobIfAbsent calls for the same
// key (Issue #3895). The metadata sidecar file's O_CREATE|O_EXCL create is the
// atomicity point: exactly one concurrent caller can create it for a given
// key, so blob data is written to the temp file first (harmless if this
// caller loses) and only renamed into the final blob path after this caller
// wins the sidecar create — the loser's temp file is discarded without ever
// touching the final blob path.
//
// A process crash between winning the sidecar create and completing the
// rename leaves a metadata sidecar with no corresponding blob file, which
// would make every future PutBlobIfAbsent for this key report
// ErrBlobAlreadyExists while GetBlob 404s on the missing blob file. Recoverable
// via PutBlob (the handler's force=true path), which overwrites both files
// unconditionally.
func (s *FilesystemBlobStore) PutBlobIfAbsent(ctx context.Context, key blob.BlobKey, r io.Reader, meta blob.BlobMeta) error {
	if err := validateKey(key); err != nil {
		return err
	}

	dir := filepath.Join(s.root, key.TenantID, key.Namespace)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("blob put-if-absent: failed to create directory: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, ".blob-tmp-*")
	if err != nil {
		return fmt.Errorf("blob put-if-absent: failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	tmpConsumed := false
	defer func() {
		if !tmpConsumed {
			_ = os.Remove(tmpPath)
		}
	}()

	h := sha256.New()
	tee := io.TeeReader(r, h)
	written, err := io.Copy(tmpFile, tee)
	if err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("blob put-if-absent: failed to write blob data: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("blob put-if-absent: failed to close temp file: %w", err)
	}

	checksum := hex.EncodeToString(h.Sum(nil))
	contentType := meta.ContentType
	if contentType == "" {
		contentType = defaultContentType
	}
	sidecar := blobMetaSidecar{
		ContentType: contentType,
		Size:        written,
		Checksum:    checksum,
		CreatedAt:   time.Now().UTC(),
		Labels:      meta.Labels,
	}
	metaJSON, err := json.Marshal(sidecar)
	if err != nil {
		return fmt.Errorf("blob put-if-absent: failed to marshal metadata: %w", err)
	}

	// Atomicity point: exactly one concurrent caller wins this O_EXCL create
	// for a given key.
	metaFile, err := os.OpenFile(s.metaPath(key), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return blob.ErrBlobAlreadyExists
		}
		return fmt.Errorf("blob put-if-absent: failed to create metadata sidecar: %w", err)
	}
	if _, err := metaFile.Write(metaJSON); err != nil {
		_ = metaFile.Close()
		_ = os.Remove(s.metaPath(key))
		return fmt.Errorf("blob put-if-absent: failed to write metadata sidecar: %w", err)
	}
	if err := metaFile.Close(); err != nil {
		_ = os.Remove(s.metaPath(key))
		return fmt.Errorf("blob put-if-absent: failed to close metadata sidecar: %w", err)
	}

	// Won the race: move the blob data into place.
	if err := os.Rename(tmpPath, s.blobPath(key)); err != nil {
		_ = os.Remove(s.metaPath(key))
		return fmt.Errorf("blob put-if-absent: failed to rename to final path: %w", err)
	}
	tmpConsumed = true

	return nil
}

// GetBlob returns a streaming reader for the blob.
// The reader wraps the file in a checksumVerifyingReader that computes SHA-256
// during reads and returns ErrBlobChecksumMismatch on the final read if the
// computed digest does not match the stored checksum.
func (s *FilesystemBlobStore) GetBlob(ctx context.Context, key blob.BlobKey) (io.ReadCloser, blob.BlobMeta, error) {
	if err := validateKey(key); err != nil {
		return nil, blob.BlobMeta{}, err
	}

	metaBytes, err := os.ReadFile(s.metaPath(key))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, blob.BlobMeta{}, blob.ErrBlobNotFound
		}
		return nil, blob.BlobMeta{}, fmt.Errorf("blob get: failed to read metadata sidecar: %w", err)
	}

	var sidecar blobMetaSidecar
	if err := json.Unmarshal(metaBytes, &sidecar); err != nil {
		return nil, blob.BlobMeta{}, fmt.Errorf("blob get: failed to parse metadata sidecar: %w", err)
	}

	f, err := os.Open(s.blobPath(key))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, blob.BlobMeta{}, blob.ErrBlobNotFound
		}
		return nil, blob.BlobMeta{}, fmt.Errorf("blob get: failed to open blob file: %w", err)
	}

	blobMeta := blob.BlobMeta{
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
func (s *FilesystemBlobStore) DeleteBlob(ctx context.Context, key blob.BlobKey) error {
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
func (s *FilesystemBlobStore) ListBlobs(ctx context.Context, prefix blob.BlobKey) ([]blob.BlobInfo, error) {
	if prefix.TenantID == "" {
		return nil, blob.ErrBlobTenantRequired
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

	var results []blob.BlobInfo
	metadataRoot, err := os.OpenRoot(searchDir)
	if err != nil {
		if os.IsNotExist(err) {
			return results, nil
		}
		return nil, fmt.Errorf("list blobs: open metadata root: %w", err)
	}
	defer func() { _ = metadataRoot.Close() }()

	err = filepath.WalkDir(searchDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".meta.json") {
			return nil
		}

		relativePath, err := filepath.Rel(searchDir, path)
		if err != nil {
			return fmt.Errorf("list blobs: resolve metadata path: %w", err)
		}
		metaBytes, err := metadataRoot.ReadFile(relativePath)
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

		key := blob.BlobKey{
			TenantID:  parts[0],
			Namespace: parts[1],
			Name:      parts[2],
		}

		if prefix.Name != "" && !strings.HasPrefix(key.Name, prefix.Name) {
			return nil
		}

		results = append(results, blob.BlobInfo{
			Key: key,
			Meta: blob.BlobMeta{
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
func (s *FilesystemBlobStore) BlobExists(ctx context.Context, key blob.BlobKey) (bool, error) {
	if key.TenantID == "" {
		return false, blob.ErrBlobTenantRequired
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
			return n, blob.ErrBlobChecksumMismatch
		}
	}
	return n, err
}

func (r *checksumVerifyingReader) Close() error {
	return r.inner.Close()
}
