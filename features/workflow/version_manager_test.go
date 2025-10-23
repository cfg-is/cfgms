// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// MockConfigStore implements interfaces.ConfigStore for testing
type MockConfigStore struct {
	mock.Mock
}

func (m *MockConfigStore) StoreConfig(ctx context.Context, config *interfaces.ConfigEntry) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *MockConfigStore) GetConfig(ctx context.Context, key *interfaces.ConfigKey) (*interfaces.ConfigEntry, error) {
	args := m.Called(ctx, key)
	return args.Get(0).(*interfaces.ConfigEntry), args.Error(1)
}

func (m *MockConfigStore) DeleteConfig(ctx context.Context, key *interfaces.ConfigKey) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockConfigStore) ListConfigs(ctx context.Context, filter *interfaces.ConfigFilter) ([]*interfaces.ConfigEntry, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).([]*interfaces.ConfigEntry), args.Error(1)
}

func (m *MockConfigStore) GetConfigHistory(ctx context.Context, key *interfaces.ConfigKey, limit int) ([]*interfaces.ConfigEntry, error) {
	args := m.Called(ctx, key, limit)
	return args.Get(0).([]*interfaces.ConfigEntry), args.Error(1)
}

func (m *MockConfigStore) GetConfigVersion(ctx context.Context, key *interfaces.ConfigKey, version int64) (*interfaces.ConfigEntry, error) {
	args := m.Called(ctx, key, version)
	return args.Get(0).(*interfaces.ConfigEntry), args.Error(1)
}

func (m *MockConfigStore) StoreConfigBatch(ctx context.Context, configs []*interfaces.ConfigEntry) error {
	args := m.Called(ctx, configs)
	return args.Error(0)
}

func (m *MockConfigStore) DeleteConfigBatch(ctx context.Context, keys []*interfaces.ConfigKey) error {
	args := m.Called(ctx, keys)
	return args.Error(0)
}

func (m *MockConfigStore) ResolveConfigWithInheritance(ctx context.Context, key *interfaces.ConfigKey) (*interfaces.ConfigEntry, error) {
	args := m.Called(ctx, key)
	return args.Get(0).(*interfaces.ConfigEntry), args.Error(1)
}

func (m *MockConfigStore) ValidateConfig(ctx context.Context, config *interfaces.ConfigEntry) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *MockConfigStore) GetConfigStats(ctx context.Context) (*interfaces.ConfigStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(*interfaces.ConfigStats), args.Error(1)
}

func TestVersionManager_CreateWorkflow(t *testing.T) {
	mockStore := new(MockConfigStore)
	vm := NewVersionManager(mockStore, "tenant1")

	workflow := Workflow{
		Name:        "test-workflow",
		Description: "A test workflow",
		Steps:       []Step{},
	}

	ctx := context.Background()

	t.Run("successful creation", func(t *testing.T) {
		// Mock that workflow doesn't exist yet
		mockStore.On("ListConfigs", ctx, mock.MatchedBy(func(filter *interfaces.ConfigFilter) bool {
			return filter.Namespace == WorkflowNamespace &&
				len(filter.Names) == 1 &&
				filter.Names[0] == "test-workflow"
		})).Return([]*interfaces.ConfigEntry{}, nil)

		// Mock successful storage
		mockStore.On("StoreConfig", ctx, mock.AnythingOfType("*interfaces.ConfigEntry")).Return(nil)

		versionedWorkflow, err := vm.CreateWorkflow(ctx, workflow, "1.0.0")
		require.NoError(t, err)

		assert.Equal(t, "test-workflow", versionedWorkflow.Name)
		assert.Equal(t, SemanticVersion{1, 0, 0, "", ""}, versionedWorkflow.SemanticVersion)
		assert.Equal(t, "1.0.0", versionedWorkflow.Version)
		assert.Len(t, versionedWorkflow.Changelog, 1)
		assert.Equal(t, "Initial version", versionedWorkflow.Changelog[0].Description)

		mockStore.AssertExpectations(t)
	})

	t.Run("invalid version", func(t *testing.T) {
		_, err := vm.CreateWorkflow(ctx, workflow, "invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid initial version")
	})

	t.Run("workflow already exists", func(t *testing.T) {
		// Reset mock
		mockStore.ExpectedCalls = nil

		// Mock existing workflow
		existingWorkflow := &VersionedWorkflow{
			Workflow:        workflow,
			SemanticVersion: SemanticVersion{1, 0, 0, "", ""},
		}

		existingEntry := createMockWorkflowEntry(existingWorkflow)

		// Mock the ListWorkflowVersions call (used by GetLatestWorkflow)
		mockStore.On("ListConfigs", ctx, mock.MatchedBy(func(filter *interfaces.ConfigFilter) bool {
			return filter.Namespace == WorkflowNamespace &&
				len(filter.Names) == 1 &&
				filter.Names[0] == "test-workflow"
		})).Return([]*interfaces.ConfigEntry{existingEntry}, nil)

		// Mock the GetWorkflow call (used by GetLatestWorkflow after ListWorkflowVersions)
		mockStore.On("GetConfig", ctx, mock.MatchedBy(func(key *interfaces.ConfigKey) bool {
			return key.Namespace == WorkflowNamespace &&
				key.Name == "test-workflow" &&
				key.Scope == "1.0.0"
		})).Return(existingEntry, nil)

		_, err := vm.CreateWorkflow(ctx, workflow, "1.0.0")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "workflow already exists")

		mockStore.AssertExpectations(t)
	})
}

func TestVersionManager_UpdateWorkflow(t *testing.T) {
	mockStore := new(MockConfigStore)
	vm := NewVersionManager(mockStore, "tenant1")

	ctx := context.Background()

	existingWorkflow := &VersionedWorkflow{
		Workflow: Workflow{
			Name:        "test-workflow",
			Description: "Original description",
			Steps:       []Step{},
		},
		SemanticVersion: SemanticVersion{1, 0, 0, "", ""},
		Changelog: []ChangelogEntry{
			{
				Version:     SemanticVersion{1, 0, 0, "", ""},
				Description: "Initial version",
			},
		},
	}

	updatedWorkflow := Workflow{
		Name:        "test-workflow",
		Description: "Updated description",
		Steps:       []Step{},
	}

	changes := []Change{
		{
			Type:        ChangeTypeChanged,
			Description: "Updated workflow description",
		},
	}

	t.Run("successful update", func(t *testing.T) {
		// Mock getting latest workflow
		existingEntry := createMockWorkflowEntry(existingWorkflow)
		mockStore.On("ListConfigs", ctx, mock.AnythingOfType("*interfaces.ConfigFilter")).Return([]*interfaces.ConfigEntry{existingEntry}, nil)
		mockStore.On("GetConfig", ctx, mock.AnythingOfType("*interfaces.ConfigKey")).Return(existingEntry, nil)

		// Mock successful storage
		mockStore.On("StoreConfig", ctx, mock.AnythingOfType("*interfaces.ConfigEntry")).Return(nil)

		versionedWorkflow, err := vm.UpdateWorkflow(ctx, "test-workflow", updatedWorkflow, "1.1.0", changes)
		require.NoError(t, err)

		assert.Equal(t, "test-workflow", versionedWorkflow.Name)
		assert.Equal(t, SemanticVersion{1, 1, 0, "", ""}, versionedWorkflow.SemanticVersion)
		assert.Equal(t, "Updated description", versionedWorkflow.Description)
		assert.Len(t, versionedWorkflow.Changelog, 2) // Original + new entry
		assert.Equal(t, "Updated to version 1.1.0", versionedWorkflow.Changelog[0].Description)

		mockStore.AssertExpectations(t)
	})

	t.Run("invalid version upgrade", func(t *testing.T) {
		// Reset mock
		mockStore.ExpectedCalls = nil

		existingEntry := createMockWorkflowEntry(existingWorkflow)
		mockStore.On("ListConfigs", ctx, mock.AnythingOfType("*interfaces.ConfigFilter")).Return([]*interfaces.ConfigEntry{existingEntry}, nil)
		mockStore.On("GetConfig", ctx, mock.AnythingOfType("*interfaces.ConfigKey")).Return(existingEntry, nil)

		_, err := vm.UpdateWorkflow(ctx, "test-workflow", updatedWorkflow, "0.9.0", changes)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid version upgrade")

		mockStore.AssertExpectations(t)
	})
}

func TestVersionManager_GetWorkflow(t *testing.T) {
	mockStore := new(MockConfigStore)
	vm := NewVersionManager(mockStore, "tenant1")

	ctx := context.Background()

	workflow := &VersionedWorkflow{
		Workflow: Workflow{
			Name: "test-workflow",
		},
		SemanticVersion: SemanticVersion{1, 2, 3, "", ""},
	}

	t.Run("get specific version", func(t *testing.T) {
		entry := createMockWorkflowEntry(workflow)
		mockStore.On("GetConfig", ctx, mock.MatchedBy(func(key *interfaces.ConfigKey) bool {
			return key.Name == "test-workflow" && key.Scope == "1.2.3"
		})).Return(entry, nil)

		result, err := vm.GetWorkflow(ctx, "test-workflow", "1.2.3")
		require.NoError(t, err)
		assert.Equal(t, workflow.Name, result.Name)
		assert.Equal(t, workflow.SemanticVersion, result.SemanticVersion)

		mockStore.AssertExpectations(t)
	})

	t.Run("get latest version", func(t *testing.T) {
		// Reset mock
		mockStore.ExpectedCalls = nil

		entry := createMockWorkflowEntry(workflow)
		mockStore.On("ListConfigs", ctx, mock.AnythingOfType("*interfaces.ConfigFilter")).Return([]*interfaces.ConfigEntry{entry}, nil)
		mockStore.On("GetConfig", ctx, mock.AnythingOfType("*interfaces.ConfigKey")).Return(entry, nil)

		result, err := vm.GetWorkflow(ctx, "test-workflow", "latest")
		require.NoError(t, err)
		assert.Equal(t, workflow.Name, result.Name)

		mockStore.AssertExpectations(t)
	})

	t.Run("invalid version format", func(t *testing.T) {
		_, err := vm.GetWorkflow(ctx, "test-workflow", "invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid version")
	})
}

func TestVersionManager_ForkWorkflow(t *testing.T) {
	mockStore := new(MockConfigStore)
	vm := NewVersionManager(mockStore, "tenant1")

	ctx := context.Background()

	originalWorkflow := &VersionedWorkflow{
		Workflow: Workflow{
			Name: "test-workflow",
		},
		SemanticVersion: SemanticVersion{1, 0, 0, "", ""},
		VersionTags:     []string{"stable"},
		Changelog: []ChangelogEntry{
			{Version: SemanticVersion{1, 0, 0, "", ""}, Description: "Initial"},
		},
	}

	t.Run("successful fork", func(t *testing.T) {
		// Mock getting source workflow
		sourceEntry := createMockWorkflowEntry(originalWorkflow)
		mockStore.On("GetConfig", ctx, mock.MatchedBy(func(key *interfaces.ConfigKey) bool {
			return key.Scope == "1.0.0"
		})).Return(sourceEntry, nil)

		// Mock storing forked workflow
		mockStore.On("StoreConfig", ctx, mock.AnythingOfType("*interfaces.ConfigEntry")).Return(nil)

		forked, err := vm.ForkWorkflow(ctx, "test-workflow", "1.0.0", "1.1.0")
		require.NoError(t, err)

		assert.Equal(t, SemanticVersion{1, 1, 0, "", ""}, forked.SemanticVersion)
		assert.Contains(t, forked.VersionTags, "stable") // Tags copied
		assert.Len(t, forked.Changelog, 2)               // Original + fork entry
		assert.Contains(t, forked.Changelog[0].Description, "Forked from version 1.0.0")

		mockStore.AssertExpectations(t)
	})

	t.Run("invalid version upgrade", func(t *testing.T) {
		_, err := vm.ForkWorkflow(ctx, "test-workflow", "1.0.0", "0.9.0")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid version upgrade")
	})
}

func TestVersionManager_Templates(t *testing.T) {
	mockStore := new(MockConfigStore)
	vm := NewVersionManager(mockStore, "tenant1")

	ctx := context.Background()

	template := &WorkflowTemplate{
		ID:      "test-template",
		Name:    "Test Template",
		Version: SemanticVersion{1, 0, 0, "", ""},
		Parameters: []TemplateParameter{
			{
				Name:     "name",
				Type:     ParameterTypeString,
				Required: true,
			},
		},
		Workflow: Workflow{
			Name: "${name}",
		},
	}

	t.Run("create template", func(t *testing.T) {
		mockStore.On("StoreConfig", ctx, mock.AnythingOfType("*interfaces.ConfigEntry")).Return(nil)

		err := vm.CreateTemplate(ctx, template)
		require.NoError(t, err)

		mockStore.AssertExpectations(t)
	})

	t.Run("get template", func(t *testing.T) {
		// Reset mock
		mockStore.ExpectedCalls = nil

		templateEntry := createMockTemplateEntry(template)
		mockStore.On("GetConfig", ctx, mock.MatchedBy(func(key *interfaces.ConfigKey) bool {
			return key.Namespace == WorkflowTemplateNamespace && key.Name == "test-template"
		})).Return(templateEntry, nil)

		result, err := vm.GetTemplate(ctx, "test-template", "1.0.0")
		require.NoError(t, err)
		assert.Equal(t, template.ID, result.ID)
		assert.Equal(t, template.Name, result.Name)

		mockStore.AssertExpectations(t)
	})

	t.Run("instantiate template", func(t *testing.T) {
		// Reset mock
		mockStore.ExpectedCalls = nil

		templateEntry := createMockTemplateEntry(template)
		mockStore.On("ListConfigs", ctx, mock.AnythingOfType("*interfaces.ConfigFilter")).Return([]*interfaces.ConfigEntry{templateEntry}, nil)
		mockStore.On("StoreConfig", ctx, mock.AnythingOfType("*interfaces.ConfigEntry")).Return(nil)

		parameters := map[string]interface{}{
			"name": "my-workflow",
		}

		instance, err := vm.InstantiateTemplate(ctx, "test-template", "latest", parameters)
		require.NoError(t, err)

		assert.Equal(t, "test-template", instance.TemplateID)
		assert.Equal(t, "Test Template", instance.TemplateName)
		assert.Equal(t, "my-workflow", instance.Parameters["name"])
		assert.NotEmpty(t, instance.ID)

		mockStore.AssertExpectations(t)
	})
}

func TestVersionManager_FindCompatibleWorkflows(t *testing.T) {
	mockStore := new(MockConfigStore)
	vm := NewVersionManager(mockStore, "tenant1")

	ctx := context.Background()

	workflows := []*VersionedWorkflow{
		{
			Workflow:        Workflow{Name: "test-workflow"},
			SemanticVersion: SemanticVersion{1, 0, 0, "", ""},
		},
		{
			Workflow:        Workflow{Name: "test-workflow"},
			SemanticVersion: SemanticVersion{1, 1, 0, "", ""},
		},
		{
			Workflow:        Workflow{Name: "test-workflow"},
			SemanticVersion: SemanticVersion{2, 0, 0, "", ""},
		},
		{
			Workflow:        Workflow{Name: "test-workflow"},
			SemanticVersion: SemanticVersion{1, 2, 0, "", ""},
			Deprecated:      true, // Should be excluded
		},
	}

	entries := make([]*interfaces.ConfigEntry, len(workflows))
	for i, wf := range workflows {
		entries[i] = createMockWorkflowEntry(wf)
	}

	mockStore.On("ListConfigs", ctx, mock.AnythingOfType("*interfaces.ConfigFilter")).Return(entries, nil)

	t.Run("find compatible versions", func(t *testing.T) {
		compatible, err := vm.FindCompatibleWorkflows(ctx, "test-workflow", ">=1.0.0,<2.0.0")
		require.NoError(t, err)

		// Should find versions 1.0.0 and 1.1.0 (not 1.2.0 because it's deprecated, not 2.0.0 because it's outside range)
		assert.Len(t, compatible, 2)

		versions := make([]string, len(compatible))
		for i, wf := range compatible {
			versions[i] = wf.SemanticVersion.String()
		}
		assert.Contains(t, versions, "1.0.0")
		assert.Contains(t, versions, "1.1.0")
		assert.NotContains(t, versions, "2.0.0")
		assert.NotContains(t, versions, "1.2.0") // Deprecated
	})

	mockStore.AssertExpectations(t)
}

// Helper functions for creating mock entries

func createMockWorkflowEntry(workflow *VersionedWorkflow) *interfaces.ConfigEntry {
	data, _ := yaml.Marshal(workflow)

	return &interfaces.ConfigEntry{
		Key: &interfaces.ConfigKey{
			TenantID:  "tenant1",
			Namespace: WorkflowNamespace,
			Name:      workflow.Name,
			Scope:     workflow.SemanticVersion.String(),
		},
		Data:      data,
		Format:    interfaces.ConfigFormatYAML,
		Version:   1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func createMockTemplateEntry(template *WorkflowTemplate) *interfaces.ConfigEntry {
	data, _ := yaml.Marshal(template)

	return &interfaces.ConfigEntry{
		Key: &interfaces.ConfigKey{
			TenantID:  "tenant1",
			Namespace: WorkflowTemplateNamespace,
			Name:      template.ID,
			Scope:     template.Version.String(),
		},
		Data:      data,
		Format:    interfaces.ConfigFormatYAML,
		Version:   1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}
