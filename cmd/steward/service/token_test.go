// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateToken(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid token",
			token:   "tok_abc123XYZ_valid",
			wantErr: false,
		},
		{
			name:    "empty token",
			token:   "",
			wantErr: true,
			errMsg:  "empty",
		},
		{
			name:    "token with space",
			token:   "tok_abc 123",
			wantErr: true,
			errMsg:  "whitespace",
		},
		{
			name:    "token with newline injection",
			token:   "tok_abc\nExecStart=/bin/evil",
			wantErr: true,
			errMsg:  "whitespace",
		},
		{
			name:    "token with tab",
			token:   "tok_abc\t123",
			wantErr: true,
			errMsg:  "whitespace",
		},
		{
			name:    "token with carriage return",
			token:   "tok_abc\r123",
			wantErr: true,
			errMsg:  "whitespace",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateToken(tc.token)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestPurgeRegistrationToken(t *testing.T) {
	t.Setenv("CFGMS_INSTALL_PREFIX", t.TempDir())
	path := platformTokenFilePath()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
	require.NoError(t, os.WriteFile(path, []byte("tok_purge_test"), 0600))

	require.NoError(t, purgeRegistrationToken(false))
	_, err := os.Stat(path)
	require.NoError(t, err, "non-purge must keep the token file")

	require.NoError(t, purgeRegistrationToken(true))
	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err), "purge must delete the token file")

	assert.NoError(t, purgeRegistrationToken(true), "missing file is not an error")
}

func TestPurgeRegistrationTokenRemovalError(t *testing.T) {
	t.Setenv("CFGMS_INSTALL_PREFIX", t.TempDir())
	path := platformTokenFilePath()
	require.NoError(t, os.MkdirAll(filepath.Join(path, "child"), 0700))

	err := purgeRegistrationToken(true)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "tok_")
}
