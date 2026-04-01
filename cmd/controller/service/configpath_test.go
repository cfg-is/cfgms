// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateConfigPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid path",
			path:    "/etc/cfgms/controller.cfg",
			wantErr: false,
		},
		{
			name:    "valid windows path",
			path:    `C:\cfgms\controller.cfg`,
			wantErr: false,
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
			errMsg:  "empty",
		},
		{
			name:    "path with double quote injection",
			path:    `/etc/cfgms/controller.cfg" --injected-arg`,
			wantErr: true,
			errMsg:  "double-quote",
		},
		{
			name:    "path with XML tag injection",
			path:    `/etc/cfgms</string><key>RunAtLoad</key>.cfg`,
			wantErr: true,
			errMsg:  "XML-special",
		},
		{
			name:    "path with ampersand injection",
			path:    `/etc/cfgms/controller.cfg&injected`,
			wantErr: true,
			errMsg:  "XML-special",
		},
		{
			name:    "path with null byte",
			path:    "/etc/cfgms/controller\x00.cfg",
			wantErr: true,
			errMsg:  "XML-special",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateConfigPath(tc.path)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
