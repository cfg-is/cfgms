// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package script

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParameterInjection(t *testing.T) {
	dnaProvider := NewSimpleDNAProvider(map[string]interface{}{
		"OS": map[string]interface{}{
			"Version": "Ubuntu 22.04",
			"Arch":    "amd64",
		},
		"Hardware": map[string]interface{}{
			"CPUCores": 8,
			"Memory":   "16GB",
		},
	})

	configProvider := NewSimpleConfigProvider(map[string]interface{}{
		"CompanySettings": map[string]interface{}{
			"BackupPath":    "/backup/data",
			"RetentionDays": 30,
		},
		"TenantPolicy": map[string]interface{}{
			"MaxUsers": 100,
		},
	})

	injector := NewParameterInjector(dnaProvider, configProvider)

	tests := []struct {
		name       string
		content    string
		parameters map[string]string
		want       string
		wantErr    bool
	}{
		{
			name:       "inject DNA property",
			content:    "OS Version: $DNA.OS.Version",
			parameters: nil,
			want:       "OS Version: Ubuntu 22.04",
			wantErr:    false,
		},
		{
			name:       "inject multiple DNA properties",
			content:    "CPU: $DNA.Hardware.CPUCores cores, Mem: $DNA.Hardware.Memory",
			parameters: nil,
			want:       "CPU: 8 cores, Mem: 16GB",
			wantErr:    false,
		},
		{
			name:       "inject config setting",
			content:    "Backup to: $CompanySettings.BackupPath",
			parameters: nil,
			want:       "Backup to: /backup/data",
			wantErr:    false,
		},
		{
			name:       "inject tenant policy",
			content:    "Max users: $TenantPolicy.MaxUsers",
			parameters: nil,
			want:       "Max users: 100",
			wantErr:    false,
		},
		{
			name:       "inject custom parameter",
			content:    "Hello $Name!",
			parameters: map[string]string{"Name": "World"},
			want:       "Hello World!",
			wantErr:    false,
		},
		{
			name:       "mixed injection",
			content:    "OS: $DNA.OS.Version, Backup: $CompanySettings.BackupPath, Name: $Name",
			parameters: map[string]string{"Name": "Test"},
			want:       "OS: Ubuntu 22.04, Backup: /backup/data, Name: Test",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := injector.InjectParameters(tt.content, tt.parameters)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractRequiredParameters(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name:    "DNA parameters",
			content: "OS: $DNA.OS.Version, Arch: $DNA.OS.Arch",
			want:    []string{"DNA.OS.Version", "DNA.OS.Arch"},
		},
		{
			name:    "config parameters",
			content: "Path: $CompanySettings.BackupPath, Days: $TenantPolicy.RetentionDays",
			want:    []string{"CompanySettings.BackupPath", "TenantPolicy.RetentionDays"},
		},
		{
			name:    "custom parameters",
			content: "Hello $Name, your ID is $UserID",
			want:    []string{"Name", "UserID"},
		},
		{
			name:    "mixed parameters",
			content: "$DNA.OS.Version $CompanySettings.BackupPath $CustomVar",
			want:    []string{"DNA.OS.Version", "CompanySettings.BackupPath", "CustomVar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractRequiredParameters(tt.content)
			// Sort both slices for comparison
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestValidateParameters(t *testing.T) {
	dnaProvider := NewSimpleDNAProvider(map[string]interface{}{
		"OS": map[string]interface{}{
			"Version": "Ubuntu 22.04",
		},
	})

	configProvider := NewSimpleConfigProvider(map[string]interface{}{
		"CompanySettings": map[string]interface{}{
			"BackupPath": "/backup",
		},
	})

	injector := NewParameterInjector(dnaProvider, configProvider)

	tests := []struct {
		name       string
		content    string
		parameters map[string]string
		wantErr    bool
	}{
		{
			name:       "all parameters provided",
			content:    "OS: $DNA.OS.Version, Path: $CompanySettings.BackupPath, Name: $Name",
			parameters: map[string]string{"Name": "Test"},
			wantErr:    false,
		},
		{
			name:       "missing custom parameter",
			content:    "Name: $Name, ID: $UserID",
			parameters: map[string]string{"Name": "Test"},
			wantErr:    true,
		},
		{
			name:       "no parameters needed",
			content:    "Hello World",
			parameters: nil,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := injector.ValidateParameters(tt.content, tt.parameters)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSimpleDNAProvider(t *testing.T) {
	provider := NewSimpleDNAProvider(map[string]interface{}{
		"OS": map[string]interface{}{
			"Version": "Ubuntu 22.04",
			"Details": map[string]interface{}{
				"Codename": "Jammy",
			},
		},
	})

	tests := []struct {
		name    string
		path    string
		want    interface{}
		wantErr bool
	}{
		{
			name:    "simple property",
			path:    "OS.Version",
			want:    "Ubuntu 22.04",
			wantErr: false,
		},
		{
			name:    "nested property",
			path:    "OS.Details.Codename",
			want:    "Jammy",
			wantErr: false,
		},
		{
			name:    "non-existent property",
			path:    "OS.NonExistent",
			wantErr: true,
		},
		{
			name:    "invalid path",
			path:    "OS.Version.Invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := provider.GetProperty(tt.path)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
