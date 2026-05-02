// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package siem

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestFileWatcherHasChangesConcurrent verifies HasChanges is race-free under
// concurrent callers (mirrors the autoReloadLoop tick pattern).
func TestFileWatcherHasChangesConcurrent(t *testing.T) {
	dir := t.TempDir()
	watchedFile := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(watchedFile, []byte("rule: 1"), 0600); err != nil {
		t.Fatal(err)
	}

	fw := NewFileWatcher()
	fw.AddPath(watchedFile)

	const goroutines = 5
	const duration = 100 * time.Millisecond

	var wg sync.WaitGroup
	deadline := time.Now().Add(duration)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				fw.HasChanges()
			}
		}()
	}

	// Modify the file mid-run so HasChanges actually writes watchedPaths.
	time.Sleep(duration / 2)
	if err := os.WriteFile(watchedFile, []byte("rule: 2"), 0600); err != nil {
		t.Fatal(err)
	}

	wg.Wait()
}

// TestFileWatcherHasChangesDetectsModification verifies HasChanges returns
// true after a file is modified and false before any modification.
func TestFileWatcherHasChangesDetectsModification(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(f, []byte("v1"), 0600); err != nil {
		t.Fatal(err)
	}

	fw := NewFileWatcher()
	fw.AddPath(f)

	assert.False(t, fw.HasChanges(), "no change expected immediately after AddPath")

	// Ensure mtime advances past what the OS may round to.
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(f, []byte("v2"), 0600); err != nil {
		t.Fatal(err)
	}
	// Touch the mtime explicitly so the test is not flaky on fast filesystems.
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(f, future, future); err != nil {
		t.Fatal(err)
	}

	assert.True(t, fw.HasChanges(), "change expected after file modification")
	assert.False(t, fw.HasChanges(), "no change expected after HasChanges resets the timestamp")
}

// TestFileWatcherHasChangesNoWatchedPaths verifies HasChanges returns false
// when no paths have been registered.
func TestFileWatcherHasChangesNoWatchedPaths(t *testing.T) {
	fw := NewFileWatcher()
	assert.False(t, fw.HasChanges())
}

// TestFileWatcherAddPathMissingFile verifies AddPath handles a non-existent
// path without panicking and HasChanges still returns false.
func TestFileWatcherAddPathMissingFile(t *testing.T) {
	fw := NewFileWatcher()
	fw.AddPath("/nonexistent/path/rules.yaml")
	assert.False(t, fw.HasChanges())
}
