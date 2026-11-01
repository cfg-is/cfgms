// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package activedirectory

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/cfgis/cfgms/pkg/security"
)

// BindingStore records which directory object (objectGUID) each declared
// resource is bound to. It is steward-side module state: it never goes into a
// configuration and holds no secret.
type BindingStore interface {
	// get returns the objectGUID bound to resourceID, if any.
	get(resourceID string) (guid string, ok bool, err error)
	// put binds resourceID to guid durably.
	put(resourceID, guid string) error
	// all returns every binding, keyed by resourceID.
	all() (map[string]string, error)
}

const (
	bindingFileName    = "bindings.json"
	bindingFileVersion = 1
	maxBindingFileSize = 8 << 20
)

// bindingFile is the on-disk form of the bindings.
type bindingFile struct {
	Version  int               `json:"version"`
	Bindings map[string]string `json:"bindings"`
}

// bindingFileLocks serializes access to each binding file within the process.
// The executor's module instance and the observe sweep's instance have their
// own store objects for the same file.
var (
	bindingFileLocksMu sync.Mutex
	bindingFileLocks   = map[string]*sync.Mutex{}
)

func bindingFileLock(path string) *sync.Mutex {
	bindingFileLocksMu.Lock()
	defer bindingFileLocksMu.Unlock()
	mu, ok := bindingFileLocks[path]
	if !ok {
		mu = &sync.Mutex{}
		bindingFileLocks[path] = mu
	}
	return mu
}

// fileBindingStore keeps the bindings in one JSON file, re-read on every
// access so every store object for the same directory sees every write. Writes
// replace the file atomically.
type fileBindingStore struct {
	dir string
	// secure applies security.EnsureAdminOnlyDir to dir before every write.
	secure bool
}

// NewFileBindingStore returns the binding store kept in dir. dir is secured
// with security.EnsureAdminOnlyDir before every write.
func NewFileBindingStore(dir string) BindingStore {
	return &fileBindingStore{dir: dir, secure: true}
}

func (s *fileBindingStore) path() string { return filepath.Join(s.dir, bindingFileName) }

func (s *fileBindingStore) get(resourceID string) (string, bool, error) {
	all, err := s.all()
	if err != nil {
		return "", false, err
	}
	guid, ok := all[resourceID]
	return guid, ok, nil
}

func (s *fileBindingStore) all() (map[string]string, error) {
	mu := bindingFileLock(s.path())
	mu.Lock()
	defer mu.Unlock()
	return s.readLocked()
}

func (s *fileBindingStore) readLocked() (map[string]string, error) {
	f, err := os.Open(s.path()) // #nosec G304 -- module-built path inside the module's state directory
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("activedirectory: open bindings: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxBindingFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("activedirectory: read bindings: %w", err)
	}
	if len(data) > maxBindingFileSize {
		return nil, fmt.Errorf("activedirectory: bindings file exceeds %d bytes", maxBindingFileSize)
	}
	var file bindingFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("activedirectory: decode bindings: %w", err)
	}
	if file.Version != bindingFileVersion {
		return nil, fmt.Errorf("activedirectory: unsupported bindings version %d", file.Version)
	}
	out := make(map[string]string, len(file.Bindings))
	for id, guid := range file.Bindings {
		if !objectGUIDPattern.MatchString(guid) {
			return nil, fmt.Errorf("activedirectory: bindings file holds a malformed objectGUID")
		}
		out[id] = guid
	}
	return out, nil
}

func (s *fileBindingStore) put(resourceID, guid string) error {
	if !objectGUIDPattern.MatchString(guid) {
		return fmt.Errorf("activedirectory: refusing to bind a malformed objectGUID")
	}
	mu := bindingFileLock(s.path())
	mu.Lock()
	defer mu.Unlock()

	if s.secure {
		if err := security.EnsureAdminOnlyDir(s.dir); err != nil {
			return fmt.Errorf("activedirectory: secure bindings directory: %w", err)
		}
	} else if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("activedirectory: create bindings directory: %w", err)
	}

	current, err := s.readLocked()
	if err != nil {
		return err
	}
	current[resourceID] = guid
	data, err := json.MarshalIndent(bindingFile{Version: bindingFileVersion, Bindings: current}, "", "  ")
	if err != nil {
		return fmt.Errorf("activedirectory: encode bindings: %w", err)
	}

	tmp, err := os.CreateTemp(s.dir, "bindings-*.tmp")
	if err != nil {
		return fmt.Errorf("activedirectory: create bindings file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("activedirectory: write bindings: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("activedirectory: sync bindings: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("activedirectory: close bindings: %w", err)
	}
	if err := os.Rename(tmpPath, s.path()); err != nil {
		return fmt.Errorf("activedirectory: replace bindings: %w", err)
	}
	return nil
}
