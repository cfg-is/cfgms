// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package main

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSaveIdentity_ReplacesWhileFileOpenWithShareDelete holds the identity
// file open with every share flag and proves saveIdentity still replaces it.
func TestSaveIdentity_ReplacesWhileFileOpenWithShareDelete(t *testing.T) {
	dir := t.TempDir()
	oldID := StewardIdentity{StewardID: "old", TransportAddress: "ctrl:4433"}
	newID := StewardIdentity{StewardID: "new", TransportAddress: "ctrl:4433"}
	require.NoError(t, saveIdentity(dir, oldID))

	path := filepath.Join(dir, "steward-identity.json")
	pathW, err := syscall.UTF16PtrFromString(path)
	require.NoError(t, err)
	h, err := syscall.CreateFile(pathW, syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	require.NoError(t, err)
	held := os.NewFile(uintptr(h), path)
	defer func() { _ = held.Close() }()

	require.NoError(t, saveIdentity(dir, newID))

	oldBytes, err := io.ReadAll(held)
	require.NoError(t, err)
	assert.Contains(t, string(oldBytes), `"old"`)

	got, err := loadIdentity(dir)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "new", got.StewardID)
}
