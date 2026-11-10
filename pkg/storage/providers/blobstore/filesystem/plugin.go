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

	"github.com/cfgis/cfgms/pkg/atomicfile"
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

// resolveKeyPaths builds the directory, blob and sidecar paths for key and
// verifies each stays strictly inside the store root. It is the path guard at
// the point of construction: callers must use the returned paths and must not
// touch the filesystem when it returns an error.
func (s *FilesystemBlobStore) resolveKeyPaths(key blob.BlobKey) (dir, blobFile, metaFile string, err error) {
	root := filepath.Clean(s.root)
	rootPrefix := root + string(os.PathSeparator)
	dir = filepath.Clean(filepath.Join(root, key.TenantID, key.Namespace))
	blobFile = filepath.Clean(filepath.Join(dir, key.Name))
	metaFile = filepath.Clean(blobFile + ".meta.json")
	// Each path is checked by its own HasPrefix guard on the Clean result so
	// static path-injection analysis can see the guard dominate every use.
	errOutside := fmt.Errorf("blob key resolves outside the store root")
	if !strings.HasPrefix(dir, rootPrefix) {
		return "", "", "", errOutside
	}
	if !strings.HasPrefix(blobFile, rootPrefix) {
		return "", "", "", errOutside
	}
	if !strings.HasPrefix(metaFile, rootPrefix) {
		return "", "", "", errOutside
	}
	// The blob must also sit inside its own namespace directory.
	if !strings.HasPrefix(blobFile, dir+string(os.PathSeparator)) {
		return "", "", "", fmt.Errorf("blob key resolves outside its namespace directory")
	}
	return dir, blobFile, metaFile, nil
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

	// Atomic rename to the final path.
	if err := os.Rename(tmpPath, s.blobPath(key)); err != nil {
		return fmt.Errorf("blob put: failed to rename to final path: %w", err)
	}
	success = true

	// Write sidecar metadata after blob is safely in place.
	metaJSON, err := marshalSidecar(meta, written, checksum)
	if err != nil {
		return fmt.Errorf("blob put: failed to marshal metadata: %w", err)
	}
	if err := replaceSidecar(dir, s.metaPath(key), metaJSON); err != nil {
		return fmt.Errorf("blob put: failed to publish metadata sidecar: %w", err)
	}

	return nil
}

// marshalSidecar builds the metadata sidecar JSON for a blob of the given size
// and checksum, applying the default content type when meta names none.
func marshalSidecar(meta blob.BlobMeta, size int64, checksum string) ([]byte, error) {
	contentType := meta.ContentType
	if contentType == "" {
		contentType = defaultContentType
	}
	return json.Marshal(blobMetaSidecar{
		ContentType: contentType,
		Size:        size,
		Checksum:    checksum,
		CreatedAt:   time.Now().UTC(),
		Labels:      meta.Labels,
	})
}

// replaceSidecar publishes metaJSON at metaFilePath with one rename, so a
// concurrent reader sees either the previous complete sidecar or the new
// complete one, never a truncated or partly written file. The temp file is
// removed if it cannot be published.
func replaceSidecar(dir, metaFilePath string, metaJSON []byte) error {
	tmpSidecar, err := writeSidecarTemp(dir, metaJSON)
	if err != nil {
		return err
	}
	if err := atomicfile.AtomicReplace(tmpSidecar, metaFilePath); err != nil {
		_ = os.Remove(tmpSidecar)
		return err
	}
	return nil
}

// sidecarTempPattern names temporary sidecar files. It must not end in
// ".meta.json": ListBlobs treats every file with that suffix as a published
// sidecar, so a temp file with that suffix would be listed while incomplete.
const sidecarTempPattern = ".meta-tmp-*"

// writeSidecarTemp writes metaJSON in full to a new temp file in dir and returns
// its path. The file is closed and complete on success; on failure it is removed.
// The caller owns the returned path and must publish or remove it. Because it
// lives in the same directory as the final sidecar, a rename or hard link from
// it to the final path stays on one filesystem.
func writeSidecarTemp(dir string, metaJSON []byte) (string, error) {
	f, err := os.CreateTemp(dir, sidecarTempPattern)
	if err != nil {
		return "", fmt.Errorf("failed to create temp sidecar: %w", err)
	}
	path := f.Name()
	if _, err := f.Write(metaJSON); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("failed to write temp sidecar: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("failed to close temp sidecar: %w", err)
	}
	return path, nil
}

// PutBlobIfAbsent stores a blob only if no blob currently exists for key,
// atomic with respect to concurrent PutBlob/PutBlobIfAbsent calls for the same
// key (Issue #3895). The hard link that publishes the metadata sidecar is the
// atomicity point: the complete sidecar JSON is first written to a temp file in
// the same directory, then link(2) makes it visible at <name>.meta.json in one
// operation. link fails with EEXIST when the target exists, so exactly one
// concurrent caller can publish the sidecar for a given key, and a concurrent
// reader sees either no sidecar or the complete one, never a partial file. Blob
// data is written to the temp file first (harmless if this caller loses) and
// only renamed into the final blob path after this caller wins the link — the
// loser's temp files are discarded without ever touching the final blob path.
//
// The sidecar publication needs a filesystem with hard-link support (on Windows
// NTFS or ReFS). Any link failure other than "already exists" is returned as an
// error; there is no fallback that opens the final sidecar path for writing.
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

	dir, blobFilePath, metaFilePath, err := s.resolveKeyPaths(key)
	if err != nil {
		return err
	}
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
	metaJSON, err := marshalSidecar(meta, written, checksum)
	if err != nil {
		return fmt.Errorf("blob put-if-absent: failed to marshal metadata: %w", err)
	}

	if err := createSidecarExclusive(dir, metaFilePath, metaJSON); err != nil {
		return err
	}

	// Won the race: move the blob data into place.
	if err := os.Rename(tmpPath, blobFilePath); err != nil {
		_ = os.Remove(metaFilePath)
		return fmt.Errorf("blob put-if-absent: failed to rename to final path: %w", err)
	}
	tmpConsumed = true

	return nil
}

// createSidecarExclusive is the PutBlobIfAbsent atomicity point: exactly one
// concurrent caller wins the hard-link publication of the metadata sidecar for
// a given key. The sidecar JSON is written completely to a temp file in dir
// first and then linked to metaFilePath, so the final path never exists with
// partial content. It returns blob.ErrBlobAlreadyExists when the sidecar already
// exists (os.Link reports EEXIST, or ERROR_ALREADY_EXISTS on Windows, both of
// which satisfy os.IsExist) and always removes the temp file. dir and
// metaFilePath must come from resolveKeyPaths.
func createSidecarExclusive(dir, metaFilePath string, metaJSON []byte) error {
	tmpSidecar, err := writeSidecarTemp(dir, metaJSON)
	if err != nil {
		return fmt.Errorf("blob put-if-absent: failed to write metadata sidecar: %w", err)
	}
	defer func() { _ = os.Remove(tmpSidecar) }()

	if err := os.Link(tmpSidecar, metaFilePath); err != nil {
		if os.IsExist(err) {
			return blob.ErrBlobAlreadyExists
		}
		return fmt.Errorf("blob put-if-absent: failed to publish metadata sidecar: %w", err)
	}
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

	metaBytes, err := atomicfile.ReadFile(s.metaPath(key))
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

// readContainedSidecar reads one sidecar found while walking a ListBlobs search
// directory. Containment: the entry is resolved through os.Root and must be a
// regular file, so a symlinked sidecar cannot redirect the read out of the
// search directory. The read itself goes through atomicfile.ReadFile, which
// retries Windows sharing violations raised while a concurrent writer swaps the
// sidecar in. Genuine read errors are returned; they are never skipped.
func readContainedSidecar(metadataRoot *os.Root, relativePath, fullPath string) ([]byte, error) {
	info, err := metadataRoot.Lstat(relativePath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.ToSlash(relativePath))
	}
	return atomicfile.ReadFile(fullPath)
}

// keyFromSidecarPath reconstructs the blob key for a sidecar found at
// relativePath under the ListBlobs search directory. It reports false when the
// path has no namespace segment to split off.
//
// The key is rebuilt from relativePath (relative to searchDir, which
// is already rooted at <root>/<TenantID>[/<Namespace>]). This must not
// re-derive TenantID by splitting the full path on "/": TenantID
// itself legitimately contains "/" for a hierarchical tenant (e.g.
// "root/msp-a/client-1" — CLAUDE.md's recursive parent-child tenant
// model), and a fixed SplitN(rel, "/", 3) silently misassigns segments
// of the tenant path into Namespace/Name for any TenantID with more
// than one segment. Using searchDir — which was built from the
// already-known prefix.TenantID — as the split point sidesteps that
// entirely, since nothing downstream needs to reparse TenantID out of
// the full path.
func keyFromSidecarPath(prefix blob.BlobKey, relativePath string) (blob.BlobKey, bool) {
	name := strings.TrimSuffix(filepath.ToSlash(relativePath), ".meta.json")
	namespace := prefix.Namespace
	if namespace == "" {
		// searchDir omitted Namespace, so relativePath is
		// "<namespace>/<name>" — split off exactly the first segment.
		idx := strings.Index(name, "/")
		if idx < 0 {
			return blob.BlobKey{}, false
		}
		namespace = name[:idx]
		name = name[idx+1:]
	}
	return blob.BlobKey{TenantID: prefix.TenantID, Namespace: namespace, Name: name}, true
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
		metaBytes, err := readContainedSidecar(metadataRoot, relativePath, path)
		if err != nil {
			return fmt.Errorf("list blobs: failed to read metadata: %w", err)
		}

		var sidecar blobMetaSidecar
		if err := json.Unmarshal(metaBytes, &sidecar); err != nil {
			return fmt.Errorf("list blobs: failed to parse metadata: %w", err)
		}

		key, ok := keyFromSidecarPath(prefix, relativePath)
		if !ok {
			return nil
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
