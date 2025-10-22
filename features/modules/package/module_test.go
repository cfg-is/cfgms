package package_module

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

// Helper function to create Config from YAML string
func createConfigFromYAML(yamlStr string) *Config {
	var cfg Config
	if err := yaml.Unmarshal([]byte(yamlStr), &cfg); err != nil {
		panic(err) // Test helper, panic on unexpected errors
	}
	return &cfg
}

func TestPackageModule(t *testing.T) {
	tests := []struct {
		name         string
		resourceID   string
		config       *Config
		setupFunc    func(*testing.T, modules.Module)
		validateFunc func(*testing.T, modules.Module)
		wantErr      bool
		errType      error
	}{
		{
			name:       "Install single package",
			resourceID: "nginx",
			config: createConfigFromYAML(`
name: nginx
state: present
version: latest
`),
			validateFunc: func(t *testing.T, m modules.Module) {
				state, err := m.Get(context.Background(), "nginx")
				assert.NoError(t, err)
				stateMap := state.AsMap()
				assert.Equal(t, "present", stateMap["state"])
			},
		},
		{
			name:       "Remove package",
			resourceID: "htop",
			config: createConfigFromYAML(`
name: htop
state: absent
`),
			setupFunc: func(t *testing.T, m modules.Module) {
				// First install the package
				err := m.Set(context.Background(), "htop", createConfigFromYAML(`
name: htop
state: present
version: latest
`))
				assert.NoError(t, err)
			},
			validateFunc: func(t *testing.T, m modules.Module) {
				state, err := m.Get(context.Background(), "htop")
				assert.NoError(t, err)
				stateMap := state.AsMap()
				assert.Equal(t, "absent", stateMap["state"])
			},
		},
		{
			name:       "Invalid package name",
			resourceID: "invalid/package",
			config: createConfigFromYAML(`
name: invalid/package
state: present
`),
			wantErr: true,
			errType: ErrInvalidPackageName,
		},
		{
			name:       "Invalid state",
			resourceID: "nginx",
			config: createConfigFromYAML(`
name: nginx
state: maybe
`),
			wantErr: true,
			errType: ErrInvalidState,
		},
		{
			name:       "Test idempotency",
			resourceID: "apache2",
			config: createConfigFromYAML(`
name: apache2
state: present
version: latest
`),
			setupFunc: func(t *testing.T, m modules.Module) {
				// Install package first
				err := m.Set(context.Background(), "apache2", createConfigFromYAML(`
name: apache2
state: present
version: latest
`))
				assert.NoError(t, err)
			},
			validateFunc: func(t *testing.T, m modules.Module) {
				// Verify it's installed
				state1, err := m.Get(context.Background(), "apache2")
				assert.NoError(t, err)
				stateMap1 := state1.AsMap()
				assert.Equal(t, "present", stateMap1["state"])

				// Try to install again
				err = m.Set(context.Background(), "apache2", createConfigFromYAML(`
name: apache2
state: present
version: latest
`))
				assert.NoError(t, err)

				// Should still be in the same state
				state2, err := m.Get(context.Background(), "apache2")
				assert.NoError(t, err)
				assert.Equal(t, state1.AsMap(), state2.AsMap())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewPackageModule()
			require.NoError(t, err)

			if tt.setupFunc != nil {
				tt.setupFunc(t, m)
			}

			err = m.Set(context.Background(), tt.resourceID, tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errType != nil {
					assert.Equal(t, tt.errType, err)
				}
				return
			}

			assert.NoError(t, err)

			if tt.validateFunc != nil {
				tt.validateFunc(t, m)
			}
		})
	}
}

// TestPackageModule_BasicDependencies tests basic dependency handling
func TestPackageModule_BasicDependencies(t *testing.T) {
	tests := []struct {
		name         string
		resourceID   string
		config       *Config
		validateFunc func(*testing.T, modules.Module)
	}{
		{
			name:       "Install with single dependency",
			resourceID: "nodejs",
			config: createConfigFromYAML(`
name: nodejs
state: present
version: latest
dependencies:
  - npm
`),
			validateFunc: func(t *testing.T, m modules.Module) {
				// Check main package
				state, err := m.Get(context.Background(), "nodejs")
				assert.NoError(t, err)
				stateMap := state.AsMap()
				assert.Equal(t, "present", stateMap["state"])

				// Check dependency
				state, err = m.Get(context.Background(), "npm")
				assert.NoError(t, err)
				stateMap = state.AsMap()
				assert.Equal(t, "present", stateMap["state"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewPackageModule()
			require.NoError(t, err)

			err = m.Set(context.Background(), tt.resourceID, tt.config)
			assert.NoError(t, err)

			if tt.validateFunc != nil {
				tt.validateFunc(t, m)
			}
		})
	}
}

// TestPackageModule_VersionValidation tests version number validation
func TestPackageModule_VersionValidation(t *testing.T) {
	tests := []struct {
		name       string
		resourceID string
		config     *Config
		wantErr    bool
		errType    error
	}{
		{
			name:       "Valid semantic version",
			resourceID: "redis",
			config: createConfigFromYAML(`
name: redis
state: present
version: "1.2.3"
`),
			wantErr: false,
		},
		{
			name:       "Valid semantic version with prerelease",
			resourceID: "redis",
			config: createConfigFromYAML(`
name: redis
state: present
version: "1.2.3-beta.1"
`),
			wantErr: false,
		},
		{
			name:       "Valid semantic version with build metadata",
			resourceID: "redis",
			config: createConfigFromYAML(`
name: redis
state: present
version: "1.2.3+20130313144700"
`),
			wantErr: false,
		},
		{
			name:       "Valid simple version",
			resourceID: "nginx",
			config: createConfigFromYAML(`
name: nginx
state: present
version: "1.18"
`),
			wantErr: false,
		},
		{
			name:       "Valid latest version",
			resourceID: "nginx",
			config: createConfigFromYAML(`
name: nginx
state: present
version: "latest"
`),
			wantErr: false,
		},
		{
			name:       "Valid apt version format",
			resourceID: "apache2",
			config: createConfigFromYAML(`
name: apache2
state: present
version: "2.4.54-1ubuntu1.1"
`),
			wantErr: false,
		},
		{
			name:       "Valid apt version with epoch",
			resourceID: "apache2",
			config: createConfigFromYAML(`
name: apache2
state: present
version: "1:2.4.54-1ubuntu1.1"
`),
			wantErr: false,
		},
		{
			name:       "Valid yum version format",
			resourceID: "httpd",
			config: createConfigFromYAML(`
name: httpd
state: present
version: "2.4.37-43.module+el8.5.0+1022+b3f0b710"
`),
			wantErr: false,
		},
		{
			name:       "Valid homebrew version format",
			resourceID: "node",
			config: createConfigFromYAML(`
name: node
state: present
version: "18.12.1_1"
`),
			wantErr: false,
		},
		{
			name:       "Valid macports version format",
			resourceID: "python",
			config: createConfigFromYAML(`
name: python
state: present
version: "3.9.12_0"
`),
			wantErr: false,
		},
		{
			name:       "Valid chocolatey version format",
			resourceID: "git",
			config: createConfigFromYAML(`
name: git
state: present
version: "2.38.1.2"
`),
			wantErr: false,
		},
		{
			name:       "Valid version with leading zeros",
			resourceID: "openssl",
			config: createConfigFromYAML(`
name: openssl
state: present
version: "01.02.03"
`),
			wantErr: false,
		},
		{
			name:       "Valid version with many segments",
			resourceID: "kernel",
			config: createConfigFromYAML(`
name: kernel
state: present
version: "5.15.0-56.62-generic"
`),
			wantErr: false,
		},
		{
			name:       "Valid version with special characters",
			resourceID: "php",
			config: createConfigFromYAML(`
name: php
state: present
version: "8.1.2+0ubuntu0.20.04.1+deb.sury.org+1"
`),
			wantErr: false,
		},
		{
			name:       "Valid version with underscores",
			resourceID: "ruby",
			config: createConfigFromYAML(`
name: ruby
state: present
version: "3.0.2_1"
`),
			wantErr: false,
		},
		{
			name:       "Invalid version format - non-numeric start",
			resourceID: "redis",
			config: createConfigFromYAML(`
name: redis
state: present
version: "not.a.version"
`),
			wantErr: true,
			errType: ErrInvalidVersion,
		},
		{
			name:       "Invalid version format - empty",
			resourceID: "redis",
			config: createConfigFromYAML(`
name: redis
state: present
version: ""
`),
			wantErr: true,
			errType: ErrInvalidVersion,
		},
		{
			name:       "Invalid version format - special characters only",
			resourceID: "redis",
			config: createConfigFromYAML(`
name: redis
state: present
version: "@#$%^&*"
`),
			wantErr: true,
			errType: ErrInvalidVersion,
		},
		{
			name:       "Invalid version format - spaces",
			resourceID: "redis",
			config: createConfigFromYAML(`
name: redis
state: present
version: "1 2 3"
`),
			wantErr: true,
			errType: ErrInvalidVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewPackageModule()
			require.NoError(t, err)

			err = m.Set(context.Background(), tt.resourceID, tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errType != nil {
					assert.Equal(t, tt.errType, err)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
