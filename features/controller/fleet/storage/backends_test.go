// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package storage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newTestFileBackend builds a FileBackend rooted at t.TempDir() rather than
// NewFileBackend's fixed /tmp path, so a traversal attempt in these tests is
// contained and observable: anything written outside base is a real escape.
func newTestFileBackend(t *testing.T) (*FileBackend, string) {
	t.Helper()

	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "default"), 0o750); err != nil {
		t.Fatalf("failed to create default shard directory: %v", err)
	}

	config := DefaultConfig()
	config.EnableSharding = false

	return &FileBackend{
		logger:   logging.NewLogger("error"),
		config:   config,
		basePath: base,
		stats: &StorageStats{
			ShardSizes:  make(map[string]int64),
			CollectedAt: time.Now(),
		},
	}, base
}

// countFilesOutside reports paths created anywhere under the parent of base that
// are not inside base itself — the observable signature of a path escape.
func countFilesOutside(t *testing.T, base string) []string {
	t.Helper()

	parent := filepath.Dir(base)
	var escaped []string
	if err := filepath.Walk(parent, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasPrefix(path, base+string(os.PathSeparator)) {
			escaped = append(escaped, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("failed to walk %s: %v", parent, err)
	}
	return escaped
}

// TestFileBackend_RejectsTraversalContentHash covers the path-traversal finding:
// the content hash is interpolated into a filesystem path, and filepath.Join
// cleans "../" segments instead of rejecting them, so an unvalidated
// steward-supplied DNA.aggregate_root escapes basePath and turns StoreRecord
// into an arbitrary file write.
func TestFileBackend_RejectsTraversalContentHash(t *testing.T) {
	backend, base := newTestFileBackend(t)
	ctx := context.Background()

	hostile := []string{
		"../../../../etc/cron.d/x",
		"..",
		"../escape",
		"sub/dir",
		"abc",
		"",
		strings.Repeat("A", 64), // uppercase is not an encoding AggregateRoot emits
	}

	for _, contentHash := range hostile {
		t.Run("StoreRecord/"+contentHash, func(t *testing.T) {
			record := &DNARecord{
				DeviceID:    "steward-1",
				DNA:         &commonpb.DNA{Id: "steward-1"},
				ContentHash: contentHash,
				ShardID:     "default",
				StoredAt:    time.Now(),
			}
			if err := backend.StoreRecord(ctx, record, []byte("payload")); err == nil {
				t.Errorf("StoreRecord accepted hostile content hash %q", contentHash)
			}
		})

		t.Run("StoreReference/"+contentHash, func(t *testing.T) {
			record := &DNARecord{
				DeviceID:    "steward-1",
				ContentHash: contentHash,
				ShardID:     "default",
				StoredAt:    time.Now(),
			}
			if err := backend.StoreReference(ctx, record); err == nil {
				t.Errorf("StoreReference accepted hostile content hash %q", contentHash)
			}
		})

		t.Run("GetRecord/"+contentHash, func(t *testing.T) {
			if _, err := backend.GetRecord(ctx, contentHash, "default"); err == nil {
				t.Errorf("GetRecord accepted hostile content hash %q", contentHash)
			}
		})

		t.Run("HasContent/"+contentHash, func(t *testing.T) {
			exists, err := backend.HasContent(ctx, contentHash)
			if err == nil {
				t.Errorf("HasContent accepted hostile content hash %q", contentHash)
			}
			if exists {
				t.Errorf("HasContent reported existence for hostile content hash %q", contentHash)
			}
		})
	}

	if escaped := countFilesOutside(t, base); len(escaped) > 0 {
		t.Errorf("files written outside the backend base path: %v", escaped)
	}
}

// TestFileBackend_ContainsHostileDeviceID pins the second interpolated component
// of the reference filename. The device ID is steward-influenced, so it must not
// be able to redirect the write either.
func TestFileBackend_ContainsHostileDeviceID(t *testing.T) {
	backend, base := newTestFileBackend(t)
	ctx := context.Background()

	contentHash := validAggregateRoot("device-id-containment")
	record := &DNARecord{
		DeviceID:    "../../../../tmp/escaped",
		ContentHash: contentHash,
		ShardID:     "default",
		StoredAt:    time.Now(),
	}

	if err := backend.StoreReference(ctx, record); err != nil {
		t.Fatalf("StoreReference failed for a well-formed content hash: %v", err)
	}

	if escaped := countFilesOutside(t, base); len(escaped) > 0 {
		t.Errorf("reference file written outside the backend base path: %v", escaped)
	}

	refDir := filepath.Join(base, "default", "refs")
	entries, err := os.ReadDir(refDir)
	if err != nil {
		t.Fatalf("failed to read refs directory: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one reference file in %s, got %d", refDir, len(entries))
	}
	if strings.Contains(entries[0].Name(), "..") {
		t.Errorf("reference filename retained traversal segments: %q", entries[0].Name())
	}
}

// TestFileBackend_StoresAndReadsWellFormedHash proves the validation does not
// break the legitimate path: a real 64-hex content address still round-trips.
func TestFileBackend_StoresAndReadsWellFormedHash(t *testing.T) {
	backend, _ := newTestFileBackend(t)
	ctx := context.Background()

	contentHash := validAggregateRoot("round-trip")
	record := &DNARecord{
		DeviceID:    "steward-1",
		DNA:         &commonpb.DNA{Id: "steward-1", AggregateRoot: contentHash},
		ContentHash: contentHash,
		ShardID:     "default",
		Version:     1,
		StoredAt:    time.Now(),
	}

	if err := backend.StoreRecord(ctx, record, []byte("payload")); err != nil {
		t.Fatalf("StoreRecord failed for a well-formed content hash: %v", err)
	}

	exists, err := backend.HasContent(ctx, contentHash)
	if err != nil {
		t.Fatalf("HasContent failed for a well-formed content hash: %v", err)
	}
	if !exists {
		t.Error("HasContent did not find the record just written")
	}

	got, err := backend.GetRecord(ctx, contentHash, "default")
	if err != nil {
		t.Fatalf("GetRecord failed for a well-formed content hash: %v", err)
	}
	if got.ContentHash != contentHash {
		t.Errorf("GetRecord returned content hash %q, want %q", got.ContentHash, contentHash)
	}
	if got.DeviceID != "steward-1" {
		t.Errorf("GetRecord returned device ID %q, want %q", got.DeviceID, "steward-1")
	}
}

// TestShortHash_NeverPanics covers the log-argument helper directly: the eager
// contentHash[:16] it replaces panicked on any hash shorter than 16 characters.
func TestShortHash_NeverPanics(t *testing.T) {
	cases := map[string]string{
		"":                      "",
		"abc":                   "abc",
		strings.Repeat("a", 16): strings.Repeat("a", 16),
		strings.Repeat("a", 64): strings.Repeat("a", 16),
	}
	for in, want := range cases {
		if got := shortHash(in); got != want {
			t.Errorf("shortHash(%q) = %q, want %q", in, got, want)
		}
	}
}
