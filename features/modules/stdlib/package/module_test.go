// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package package_module

import (
	"context"
	"errors"
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
			m, err := NewPackageModule(newTestPackageManager())
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
			m, err := NewPackageModule(newTestPackageManager())
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
			m, err := NewPackageModule(newTestPackageManager())
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

// TestPackageModule_ConfigNameDiffersFromResourceID is the acceptance-criterion test
// for Issue #2478: resource named docker-engine, config.name docker.io, fake apt
// executor reporting not-installed → Set installs docker.io; second converge with
// installed state reports compliant (no reinstall).
func TestPackageModule_ConfigNameDiffersFromResourceID(t *testing.T) {
	t.Run("apt not-installed then install uses config.name", func(t *testing.T) {
		mgr := newTestPackageManager()
		m, err := NewPackageModule(mgr)
		require.NoError(t, err)

		ctx := context.Background()
		resourceID := "docker-engine"
		cfg := createConfigFromYAML(`
name: docker.io
state: present
version: latest
`)

		// Executor calls Configure before Get so the module knows the package name.
		configurable, ok := modules.Module(m).(modules.Configurable)
		require.True(t, ok, "PackageModule must implement modules.Configurable")
		require.NoError(t, configurable.Configure(cfg))

		// First converge: docker.io not installed → Get returns absent.
		state, err := m.Get(ctx, resourceID)
		require.NoError(t, err, "Get on not-installed package must return absent, not an error")
		assert.Equal(t, "absent", state.AsMap()["state"])

		// Set must install docker.io, not docker-engine.
		require.NoError(t, m.Set(ctx, resourceID, cfg))
		_, dockerIOInstalled := mgr.installed["docker.io"]
		assert.True(t, dockerIOInstalled, "docker.io must be installed")
		_, dockerEngineInstalled := mgr.installed["docker-engine"]
		assert.False(t, dockerEngineInstalled, "docker-engine must NOT be installed")

		// Second converge: Configure again, then Get → present (compliant, no reinstall).
		require.NoError(t, configurable.Configure(cfg))
		state, err = m.Get(ctx, resourceID)
		require.NoError(t, err)
		assert.Equal(t, "present", state.AsMap()["state"])
		assert.Equal(t, 1, len(mgr.installed), "only docker.io should be installed; no duplicate")
	})

	t.Run("not-installed is absent state not error", func(t *testing.T) {
		mgr := newTestPackageManager()
		m, err := NewPackageModule(mgr)
		require.NoError(t, err)

		state, err := m.Get(context.Background(), "git")
		require.NoError(t, err, "Get on uninstalled package must not return an error")
		assert.Equal(t, "absent", state.AsMap()["state"])
	})

	t.Run("config.name same as resourceID still works", func(t *testing.T) {
		mgr := newTestPackageManager()
		m, err := NewPackageModule(mgr)
		require.NoError(t, err)

		ctx := context.Background()
		cfg := createConfigFromYAML(`
name: nginx
state: present
version: latest
`)
		configurable := modules.Module(m).(modules.Configurable)
		require.NoError(t, configurable.Configure(cfg))

		require.NoError(t, m.Set(ctx, "nginx", cfg))

		state, err := m.Get(ctx, "nginx")
		require.NoError(t, err)
		assert.Equal(t, "present", state.AsMap()["state"])
	})

	t.Run("remove uses config.name not resourceID", func(t *testing.T) {
		mgr := newTestPackageManager()
		mgr.installed["docker.io"] = "latest"
		m, err := NewPackageModule(mgr)
		require.NoError(t, err)

		ctx := context.Background()
		cfg := createConfigFromYAML(`
name: docker.io
state: absent
`)
		require.NoError(t, m.Set(ctx, "docker-engine", cfg))
		_, stillInstalled := mgr.installed["docker.io"]
		assert.False(t, stillInstalled, "docker.io must be removed")
	})
}

// TestErrPackageModule verifies that a module constructed from a failed init
// returns the init error from both Get and Set rather than fake data.
func TestErrPackageModule(t *testing.T) {
	initErr := errors.New("no supported package manager found on Linux")
	m := &errPackageModule{err: initErr}

	ctx := context.Background()

	// Get must return the init error
	state, err := m.Get(ctx, "nginx")
	assert.Nil(t, state)
	assert.ErrorIs(t, err, initErr)

	// Set must return the init error
	cfg := &Config{Name: "nginx", State: "present", Version: "latest"}
	err = m.Set(ctx, "nginx", cfg)
	assert.ErrorIs(t, err, initErr)

	// errPackageModule must implement LoggingInjectable so the factory can
	// inject loggers even when no package manager is available (e.g. Windows
	// CI runners without winget/choco).
	_, ok := modules.Module(m).(modules.LoggingInjectable)
	require.True(t, ok, "errPackageModule must implement modules.LoggingInjectable")
}

// TestNewPackageModule_NilManager verifies that passing nil returns an error.
func TestNewPackageModule_NilManager(t *testing.T) {
	_, err := NewPackageModule(nil)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidConfig, err)
}

// TestPackageModule_ErrorPaths tests sentinel error paths in Set().
func TestPackageModule_ErrorPaths(t *testing.T) {
	t.Run("NilConfig", func(t *testing.T) {
		m, err := NewPackageModule(newTestPackageManager())
		require.NoError(t, err)
		// Pass nil modules.ConfigState (not a typed nil *Config) to trigger the
		// config == nil guard at module.go:94.
		err = m.Set(context.Background(), "nginx", nil)
		assert.ErrorIs(t, err, ErrInvalidConfig)
	})

	t.Run("ConfigNameDiffersFromResourceID", func(t *testing.T) {
		// config.name different from resourceID is now valid: Set installs config.name
		m, err := NewPackageModule(newTestPackageManager())
		require.NoError(t, err)
		cfg := createConfigFromYAML(`
name: other-package
state: present
version: latest
`)
		err = m.Set(context.Background(), "nginx", cfg)
		assert.NoError(t, err)
	})

	t.Run("InvalidPackageManager", func(t *testing.T) {
		m, err := NewPackageModule(newTestPackageManager())
		require.NoError(t, err)
		cfg := createConfigFromYAML(`
name: nginx
state: present
version: latest
package_manager: unknown-manager
`)
		err = m.Set(context.Background(), "nginx", cfg)
		assert.ErrorIs(t, err, ErrInvalidPackageManager)
	})

	t.Run("CircularDependency", func(t *testing.T) {
		m, err := NewPackageModule(newTestPackageManager())
		require.NoError(t, err)
		cfg := createConfigFromYAML(`
name: nginx
state: present
version: latest
dependencies:
  - nginx
`)
		err = m.Set(context.Background(), "nginx", cfg)
		assert.ErrorIs(t, err, ErrCircularDependency)
	})

	t.Run("DependencyInstallFailure", func(t *testing.T) {
		mgr := newTestPackageManager()
		mgr.setFailingPackage("npm", true)
		m, err := NewPackageModule(mgr)
		require.NoError(t, err)
		cfg := createConfigFromYAML(`
name: nodejs
state: present
version: latest
dependencies:
  - npm
`)
		err = m.Set(context.Background(), "nodejs", cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "npm")
	})
}

// TestLinux_NotFoundDetectionHelpers verifies the output-parsing helpers that
// map OS package manager exit output to ErrPackageNotFound. These functions are
// unit-testable without calling the real binaries.
func TestLinux_NotFoundDetectionHelpers(t *testing.T) {
	t.Run("aptOutputIsNotFound", func(t *testing.T) {
		cases := []struct {
			output string
			want   bool
		}{
			{"dpkg-query: no packages found matching git\n", true},
			{"dpkg-query: no packages found matching docker.io\n", true},
			{"2.39.2\n", false},
			{"", false},
			{"error: something else\n", false},
		}
		for _, tc := range cases {
			got := aptOutputIsNotFound([]byte(tc.output))
			assert.Equal(t, tc.want, got, "aptOutputIsNotFound(%q)", tc.output)
		}
	})

	t.Run("rpmOutputIsNotFound", func(t *testing.T) {
		cases := []struct {
			output string
			want   bool
		}{
			{"package git is not installed\n", true},
			{"package docker-ce is not installed\n", true},
			{"2.39.2\n", false},
			{"", false},
			{"rpmdb: cannot open Packages\n", false},
		}
		for _, tc := range cases {
			got := rpmOutputIsNotFound([]byte(tc.output))
			assert.Equal(t, tc.want, got, "rpmOutputIsNotFound(%q)", tc.output)
		}
	})

	t.Run("pacmanOutputIsNotFound", func(t *testing.T) {
		cases := []struct {
			output string
			want   bool
		}{
			{"error: package 'git' was not found\n", true},
			{"error: target not found: docker\n", true},
			{"git 2.39.2-1\n", false},
			{"", false},
			{"error: failed to init transaction\n", false},
		}
		for _, tc := range cases {
			got := pacmanOutputIsNotFound([]byte(tc.output))
			assert.Equal(t, tc.want, got, "pacmanOutputIsNotFound(%q)", tc.output)
		}
	})
}

// TestValidatePackageName_RejectsLeadingDash verifies that names starting with
// '-' are rejected to prevent argument injection into root-run package managers.
func TestValidatePackageName_RejectsLeadingDash(t *testing.T) {
	dangerous := []string{
		"--allow-unauthenticated",
		"-oAPT::Get::AllowUnauthenticated=true",
		"--setopt=gpgcheck=0",
		"-y",
	}
	for _, name := range dangerous {
		err := validatePackageName(name)
		assert.ErrorIs(t, err, ErrInvalidPackageName, "validatePackageName(%q) should reject leading dash", name)
	}

	// Valid package names with dots (e.g. docker.io) must still pass.
	assert.NoError(t, validatePackageName("docker.io"))
	assert.NoError(t, validatePackageName("python3-pip"))
}
