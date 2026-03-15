// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package service

import (
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
