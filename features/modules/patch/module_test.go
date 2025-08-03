package patch

import (
	"context"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Helper function to create Config from YAML string
func createConfigFromYAML(yamlStr string) *Config {
	var cfg Config
	if err := yaml.Unmarshal([]byte(yamlStr), &cfg); err != nil {
		// Test helper - should not fail in practice
		panic(err)
	}
	return &cfg
}

func TestPatchModule(t *testing.T) {
	tests := []struct {
		name         string
		resourceID   string
		config       *Config
		setupFunc    func(*testing.T, modules.Module, *MockPatchManager)
		validateFunc func(*testing.T, modules.Module, *MockPatchManager)
		wantErr      bool
		errType      error
	}{
		{
			name:       "Install security patches (test mode)",
			resourceID: "system",
			config: createConfigFromYAML(`
patch_type: security
auto_reboot: false
test_mode: true
`),
			validateFunc: func(t *testing.T, m modules.Module, mock *MockPatchManager) {
				// Check that security patches were processed in test mode
				state, err := m.Get(context.Background(), "system")
				assert.NoError(t, err)
				stateMap := state.AsMap()
				assert.Equal(t, "security", stateMap["patch_type"])
			},
		},
		{
			name:       "Install all patches with auto-reboot",
			resourceID: "system",
			config: createConfigFromYAML(`
patch_type: all
auto_reboot: true
test_mode: false
`),
			validateFunc: func(t *testing.T, m modules.Module, mock *MockPatchManager) {
				state, err := m.Get(context.Background(), "system")
				assert.NoError(t, err)
				stateMap := state.AsMap()
				assert.Equal(t, "security", stateMap["patch_type"]) // Get returns current state, not desired
			},
		},
		{
			name:       "Test mode - dry run",
			resourceID: "system",
			config: createConfigFromYAML(`
patch_type: security
auto_reboot: false
test_mode: true
`),
			validateFunc: func(t *testing.T, m modules.Module, mock *MockPatchManager) {
				// In test mode, no actual changes should be made
				state, err := m.Get(context.Background(), "system")
				assert.NoError(t, err)
				assert.NotNil(t, state)
			},
		},
		{
			name:       "Include specific patches",
			resourceID: "system",
			config: createConfigFromYAML(`
patch_type: security
include_patches:
  - SEC-2024-001
auto_reboot: false
test_mode: false
`),
			validateFunc: func(t *testing.T, m modules.Module, mock *MockPatchManager) {
				state, err := m.Get(context.Background(), "system")
				assert.NoError(t, err)
				assert.NotNil(t, state)
			},
		},
		{
			name:       "Exclude specific patches",
			resourceID: "system",
			config: createConfigFromYAML(`
patch_type: all
exclude_patches:
  - KER-2024-001
auto_reboot: false
test_mode: false
`),
			validateFunc: func(t *testing.T, m modules.Module, mock *MockPatchManager) {
				state, err := m.Get(context.Background(), "system")
				assert.NoError(t, err)
				assert.NotNil(t, state)
			},
		},
		{
			name:       "Invalid patch type",
			resourceID: "system",
			config: createConfigFromYAML(`
patch_type: invalid
auto_reboot: false
test_mode: false
`),
			wantErr: true,
			errType: ErrInvalidPatchType,
		},
		{
			name:       "Invalid max downtime",
			resourceID: "system",
			config: createConfigFromYAML(`
patch_type: security
max_downtime: invalid_duration
auto_reboot: false
test_mode: false
`),
			wantErr: true,
			errType: ErrInvalidMaxDowntime,
		},
		{
			name:       "Conflicting patch lists",
			resourceID: "system",
			config: createConfigFromYAML(`
patch_type: security
include_patches:
  - SEC-2024-001
exclude_patches:
  - SEC-2024-001
auto_reboot: false
test_mode: false
`),
			wantErr: true,
			errType: ErrConflictingPatchLists,
		},
		{
			name:       "Reboot required error",
			resourceID: "system",
			config: createConfigFromYAML(`
patch_type: security
auto_reboot: false
test_mode: false
`),
			wantErr: true,
			errType: ErrRebootRequired,
		},
		{
			name:       "Valid maintenance window",
			resourceID: "system",
			config: createConfigFromYAML(`
patch_type: security
auto_reboot: false
test_mode: true
maintenance:
  window: sunday_3am
`),
			validateFunc: func(t *testing.T, m modules.Module, mock *MockPatchManager) {
				state, err := m.Get(context.Background(), "system")
				assert.NoError(t, err)
				assert.NotNil(t, state)
			},
		},
		{
			name:       "Platform-specific options",
			resourceID: "system",
			config: createConfigFromYAML(`
patch_type: security
auto_reboot: false
test_mode: true
platform:
  use_apt: true
  update_kernel: false
`),
			validateFunc: func(t *testing.T, m modules.Module, mock *MockPatchManager) {
				state, err := m.Get(context.Background(), "system")
				assert.NoError(t, err)
				assert.NotNil(t, state)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock patch manager
			mockPatchManager := NewMockPatchManager()
			
			// Create patch module with mock
			m, err := NewPatchModule(mockPatchManager)
			require.NoError(t, err)

			if tt.setupFunc != nil {
				tt.setupFunc(t, m, mockPatchManager)
			}

			err = m.Set(context.Background(), tt.resourceID, tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
				return
			}

			assert.NoError(t, err)

			if tt.validateFunc != nil {
				tt.validateFunc(t, m, mockPatchManager)
			}
		})
	}
}

func TestPatchModule_PatchTypes(t *testing.T) {
	tests := []struct {
		name       string
		patchType  string
		wantErr    bool
	}{
		{"Valid security", "security", false},
		{"Valid all", "all", false},
		{"Valid kernel", "kernel", false},
		{"Valid critical", "critical", false},
		{"Invalid empty", "", true},
		{"Invalid unknown", "unknown", true},
		{"Invalid spaces", "security patches", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockPatchManager := NewMockPatchManager()
			m, err := NewPatchModule(mockPatchManager)
			require.NoError(t, err)

			config := &Config{
				PatchType:  tt.patchType,
				AutoReboot: false,
				TestMode:   true, // Use test mode to avoid actual patching
			}

			err = m.Set(context.Background(), "system", config)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPatchModule_ErrorHandling(t *testing.T) {
	tests := []struct {
		name         string
		resourceID   string
		config       *Config
		setupFunc    func(*MockPatchManager)
		expectedErr  error
	}{
		{
			name:       "Network error",
			resourceID: "system",
			config: &Config{
				PatchType:  "security",
				AutoReboot: false,
				TestMode:   false,
			},
			setupFunc: func(mock *MockPatchManager) {
				mock.SetSimulateNetworkError(true)
			},
			expectedErr: ErrNetworkError,
		},
		{
			name:       "Permission error",
			resourceID: "system",
			config: &Config{
				PatchType:  "security",
				AutoReboot: false,
				TestMode:   false,
			},
			setupFunc: func(mock *MockPatchManager) {
				mock.SetSimulatePermissionError(true)
			},
			expectedErr: ErrPermissionDenied,
		},
		{
			name:        "Invalid resource ID",
			resourceID:  "",
			config:      &Config{PatchType: "security"},
			expectedErr: ErrInvalidResourceID,
		},
		{
			name:        "Nil config",
			resourceID:  "system",
			config:      nil,
			expectedErr: ErrInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockPatchManager := NewMockPatchManager()
			
			if tt.setupFunc != nil {
				tt.setupFunc(mockPatchManager)
			}

			m, err := NewPatchModule(mockPatchManager)
			require.NoError(t, err)

			err = m.Set(context.Background(), tt.resourceID, tt.config)
			assert.Error(t, err)
			assert.ErrorIs(t, err, tt.expectedErr)
		})
	}
}

func TestPatchModule_Get(t *testing.T) {
	mockPatchManager := NewMockPatchManager()
	m, err := NewPatchModule(mockPatchManager)
	require.NoError(t, err)

	// Test getting current patch status
	state, err := m.Get(context.Background(), "system")
	assert.NoError(t, err)
	assert.NotNil(t, state)

	stateMap := state.AsMap()
	assert.Equal(t, "security", stateMap["patch_type"])
	assert.Equal(t, false, stateMap["auto_reboot"])
	assert.Equal(t, false, stateMap["test_mode"])
}

func TestPatchModule_GetPatchStatus(t *testing.T) {
	mockPatchManager := NewMockPatchManager()
	m, err := NewPatchModule(mockPatchManager)
	require.NoError(t, err)

	status, err := m.GetPatchStatus(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, status)

	// Check that status contains expected fields
	assert.NotZero(t, status.LastPatchDate)
	assert.NotNil(t, status.AvailablePatches)
	assert.NotNil(t, status.InstalledPatches)
	assert.GreaterOrEqual(t, len(status.AvailablePatches), 0)
	assert.GreaterOrEqual(t, len(status.InstalledPatches), 0)
}

func TestConfig_ConfigStateInterface(t *testing.T) {
	config := &Config{
		PatchType:  "security",
		AutoReboot: true,
		TestMode:   false,
		IncludePatches: []string{"SEC-2024-001"},
		ExcludePatches: []string{"KER-2024-001"},
		MaxDowntime: "1h",
		PrePatchScript: "echo 'starting patch'",
		PostPatchScript: "echo 'patch complete'",
	}

	// Test AsMap
	configMap := config.AsMap()
	assert.Equal(t, "security", configMap["patch_type"])
	assert.Equal(t, true, configMap["auto_reboot"])
	assert.Equal(t, false, configMap["test_mode"])
	assert.Equal(t, []string{"SEC-2024-001"}, configMap["include_patches"])
	assert.Equal(t, []string{"KER-2024-001"}, configMap["exclude_patches"])
	assert.Equal(t, "1h", configMap["max_downtime"])

	// Test ToYAML
	yamlData, err := config.ToYAML()
	assert.NoError(t, err)
	assert.Contains(t, string(yamlData), "patch_type: security")
	assert.Contains(t, string(yamlData), "auto_reboot: true")

	// Test FromYAML
	newConfig := &Config{}
	err = newConfig.FromYAML(yamlData)
	assert.NoError(t, err)
	assert.Equal(t, config.PatchType, newConfig.PatchType)
	assert.Equal(t, config.AutoReboot, newConfig.AutoReboot)
	assert.Equal(t, config.TestMode, newConfig.TestMode)

	// Test Validate
	err = config.Validate()
	assert.NoError(t, err)

	// Test GetManagedFields
	fields := config.GetManagedFields()
	assert.Contains(t, fields, "patch_type")
	assert.Contains(t, fields, "auto_reboot")
	assert.Contains(t, fields, "test_mode")
	assert.Contains(t, fields, "include_patches")
	assert.Contains(t, fields, "exclude_patches")
	assert.Contains(t, fields, "max_downtime")
}

func TestConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errType error
	}{
		{
			name: "Valid security config",
			config: &Config{
				PatchType:  "security",
				AutoReboot: false,
				TestMode:   false,
			},
			wantErr: false,
		},
		{
			name: "Valid config with maintenance window",
			config: &Config{
				PatchType:  "all",
				AutoReboot: true,
				TestMode:   false,
				Maintenance: struct {
					Window   string        `yaml:"window"`
					Schedule string        `yaml:"schedule"`
					Duration time.Duration `yaml:"duration"`
					Timezone string        `yaml:"timezone"`
				}{
					Window: "sunday_3am",
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid patch type",
			config: &Config{
				PatchType: "invalid",
			},
			wantErr: true,
			errType: ErrInvalidPatchType,
		},
		{
			name: "Invalid max downtime",
			config: &Config{
				PatchType:   "security",
				MaxDowntime: "invalid",
			},
			wantErr: true,
			errType: ErrInvalidMaxDowntime,
		},
		{
			name: "Conflicting patch lists",
			config: &Config{
				PatchType:      "security",
				IncludePatches: []string{"PATCH-001"},
				ExcludePatches: []string{"PATCH-001"},
			},
			wantErr: true,
			errType: ErrConflictingPatchLists,
		},
		{
			name: "Conflicting platform options",
			config: &Config{
				PatchType: "security",
				Platform: struct {
					UseYum        bool   `yaml:"use_yum"`
					UseApt        bool   `yaml:"use_apt"`
					UpdateKernel  bool   `yaml:"update_kernel"`
					UseWSUS       bool   `yaml:"use_wsus"`
					WSUSServer    string `yaml:"wsus_server"`
					IncludeAppStore bool `yaml:"include_app_store"`
				}{
					UseYum: true,
					UseApt: true,
				},
			},
			wantErr: true,
			errType: ErrConflictingPlatformOptions,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMockPatchManager(t *testing.T) {
	mock := NewMockPatchManager()

	// Test ListAvailablePatches
	patches, err := mock.ListAvailablePatches(context.Background(), "security")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(patches), 1)

	// Test ListInstalledPatches
	installed, err := mock.ListInstalledPatches(context.Background())
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(installed), 1)

	// Test InstallPatches
	config := &Config{
		PatchType:  "security",
		AutoReboot: false,
		TestMode:   false,
	}
	err = mock.InstallPatches(context.Background(), config)
	assert.NoError(t, err)

	// Test CheckRebootRequired (should be true after installing kernel patches)
	rebootRequired, err := mock.CheckRebootRequired(context.Background())
	assert.NoError(t, err)
	assert.True(t, rebootRequired) // Should be true after kernel patch installation

	// Test GetLastPatchDate
	lastPatch, err := mock.GetLastPatchDate(context.Background())
	assert.NoError(t, err)
	assert.True(t, lastPatch.Before(time.Now()))

	// Test Name
	name := mock.Name()
	assert.NotEmpty(t, name)

	// Test IsValidPatchType
	assert.True(t, mock.IsValidPatchType("security"))
	assert.False(t, mock.IsValidPatchType("invalid"))
}