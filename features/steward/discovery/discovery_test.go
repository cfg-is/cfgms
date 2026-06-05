// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package discovery

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createBundleLayout creates a valid bundle directory layout under modulePath:
// module.yaml + a linux-amd64/ subdirectory with a placeholder binary.
func createBundleLayout(t *testing.T, modulePath string, moduleYAML string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(modulePath, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(modulePath, "module.yaml"), []byte(moduleYAML), 0644))
	archDir := filepath.Join(modulePath, "linux-amd64")
	require.NoError(t, os.MkdirAll(archDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(archDir, "module"), []byte("ELF"), 0755))
}

func TestDiscoverModules(t *testing.T) {
	tests := []struct {
		name        string
		setupFunc   func(t *testing.T) ([]string, func())
		wantModules []string
		wantErr     bool
	}{
		{
			name: "discovers modules from custom path",
			setupFunc: func(t *testing.T) ([]string, func()) {
				tempDir := t.TempDir()
				modulePath := filepath.Join(tempDir, "test-module")
				moduleYAML := `name: test-module
version: 1.0.0
description: Test module
capabilities:
  - file-management
`
				createBundleLayout(t, modulePath, moduleYAML)
				return []string{tempDir}, func() {}
			},
			wantModules: []string{"test-module"},
			wantErr:     false,
		},
		{
			name: "handles non-existent paths gracefully",
			setupFunc: func(t *testing.T) ([]string, func()) {
				return []string{"/non/existent/path"}, func() {}
			},
			wantModules: []string{},
			wantErr:     false,
		},
		{
			name: "discovers multiple modules",
			setupFunc: func(t *testing.T) ([]string, func()) {
				tempDir := t.TempDir()

				createBundleLayout(t, filepath.Join(tempDir, "module1"), `name: module1
version: 1.0.0
description: First module
`)
				createBundleLayout(t, filepath.Join(tempDir, "module2"), `name: module2
version: 2.0.0
description: Second module
`)
				return []string{tempDir}, func() {}
			},
			wantModules: []string{"module1", "module2"},
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			customPaths, cleanup := tt.setupFunc(t)
			defer cleanup()

			registry, err := DiscoverModules(customPaths)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Len(t, registry, len(tt.wantModules))

			for _, moduleName := range tt.wantModules {
				assert.Contains(t, registry, moduleName)
				assert.NotEmpty(t, registry[moduleName].Path)
				assert.NotEmpty(t, registry[moduleName].Version)
			}
		})
	}
}

func TestParseModuleMetadata(t *testing.T) {
	tests := []struct {
		name     string
		yamlData string
		want     ModuleInfo
		wantErr  bool
	}{
		{
			name: "valid module metadata",
			yamlData: `name: test-module
version: 1.0.0
description: Test module
capabilities:
  - file-management
  - directory-management
`,
			want: ModuleInfo{
				Name:         "test-module",
				Version:      "1.0.0",
				Description:  "Test module",
				Capabilities: []string{"file-management", "directory-management"},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			yamlData: `version: 1.0.0
description: Test module
`,
			wantErr: true,
		},
		{
			name: "missing version",
			yamlData: `name: test-module
description: Test module
`,
			wantErr: true,
		},
		{
			name:     "invalid YAML",
			yamlData: `invalid: yaml: content:`,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempFile := filepath.Join(t.TempDir(), "module.yaml")
			require.NoError(t, os.WriteFile(tempFile, []byte(tt.yamlData), 0644))

			got, err := ParseModuleMetadata(tempFile)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, tt.want.Version, got.Version)
			assert.Equal(t, tt.want.Description, got.Description)
			assert.Equal(t, tt.want.Capabilities, got.Capabilities)
		})
	}
}

func TestValidateModuleStructure(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(t *testing.T) string
		wantErr   bool
	}{
		{
			name: "valid bundle structure with os-arch subdir",
			setupFunc: func(t *testing.T) string {
				tempDir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(tempDir, "module.yaml"), []byte("name: test"), 0644))
				archDir := filepath.Join(tempDir, "linux-amd64")
				require.NoError(t, os.MkdirAll(archDir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(archDir, "module"), []byte("ELF"), 0755))
				return tempDir
			},
			wantErr: false,
		},
		{
			name: "valid bundle structure with windows binary",
			setupFunc: func(t *testing.T) string {
				tempDir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(tempDir, "module.yaml"), []byte("name: test"), 0644))
				archDir := filepath.Join(tempDir, "windows-amd64")
				require.NoError(t, os.MkdirAll(archDir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(archDir, "module.exe"), []byte("MZ"), 0755))
				return tempDir
			},
			wantErr: false,
		},
		{
			name: "missing module.yaml",
			setupFunc: func(t *testing.T) string {
				tempDir := t.TempDir()
				archDir := filepath.Join(tempDir, "linux-amd64")
				require.NoError(t, os.MkdirAll(archDir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(archDir, "module"), []byte("ELF"), 0755))
				return tempDir
			},
			wantErr: true,
		},
		{
			name: "module.yaml present but no os-arch subdir",
			setupFunc: func(t *testing.T) string {
				tempDir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(tempDir, "module.yaml"), []byte("name: test"), 0644))
				return tempDir
			},
			wantErr: true,
		},
		{
			name: "os-arch subdir exists but is empty",
			setupFunc: func(t *testing.T) string {
				tempDir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(tempDir, "module.yaml"), []byte("name: test"), 0644))
				require.NoError(t, os.MkdirAll(filepath.Join(tempDir, "linux-amd64"), 0755))
				return tempDir
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modulePath := tt.setupFunc(t)

			err := ValidateModuleStructure(modulePath)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBuildSearchPaths(t *testing.T) {
	tests := []struct {
		name        string
		customPaths []string
		wantLength  int
	}{
		{
			name:        "with custom paths",
			customPaths: []string{"/custom/path1", "/custom/path2"},
			wantLength:  4, // 2 custom + 1 relative + 1 system
		},
		{
			name:        "without custom paths",
			customPaths: []string{},
			wantLength:  2, // 1 relative + 1 system
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := buildSearchPaths(tt.customPaths)

			assert.Len(t, paths, tt.wantLength)

			// Custom paths should come first
			for i, customPath := range tt.customPaths {
				assert.Equal(t, customPath, paths[i])
			}
		})
	}
}
