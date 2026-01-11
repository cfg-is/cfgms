// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Manager handles workflow integration with the steward system
type Manager struct {
	engine        *Engine
	parser        *Parser
	logger        logging.Logger
	workflowPaths []string
}

// NewManager creates a new workflow manager
func NewManager(moduleFactory *factory.ModuleFactory, logger logging.Logger) *Manager {
	return &Manager{
		engine: NewEngine(moduleFactory, logger),
		parser: NewParser(),
		logger: logger,
		workflowPaths: []string{
			"./workflows",
			"/etc/cfgms/workflows",
			"/usr/local/etc/cfgms/workflows",
		},
	}
}

// WorkflowConfig extends steward configuration to support workflows
type WorkflowConfig struct {
	// Workflows defines workflow execution configurations
	Workflows []WorkflowExecution `yaml:"workflows,omitempty"`

	// WorkflowPaths defines additional directories to search for workflow files
	WorkflowPaths []string `yaml:"workflow_paths,omitempty"`
}

// WorkflowExecution defines a workflow to be executed by the steward
type WorkflowExecutionConfig struct {
	// Name is the identifier for this workflow execution
	Name string `yaml:"name"`

	// WorkflowFile is the path to the workflow definition file
	WorkflowFile string `yaml:"workflow_file,omitempty"`

	// WorkflowName is the name of the workflow (if using embedded definition)
	WorkflowName string `yaml:"workflow_name,omitempty"`

	// Variables are the input variables for the workflow
	Variables map[string]interface{} `yaml:"variables,omitempty"`

	// Schedule defines when the workflow should run (future enhancement)
	Schedule string `yaml:"schedule,omitempty"`

	// Enabled controls whether this workflow execution is active
	Enabled bool `yaml:"enabled"`
}

// ExtendedStewardConfig adds workflow support to the standard steward config
type ExtendedStewardConfig struct {
	config.StewardConfig `yaml:",inline"`
	WorkflowConfig       `yaml:",inline"`
}

// LoadWorkflow loads a workflow from a file
func (m *Manager) LoadWorkflow(workflowFile string) (Workflow, error) {
	// Try to find the workflow file in search paths
	var fullPath string
	var found bool

	if filepath.IsAbs(workflowFile) {
		fullPath = workflowFile
		found = true
	} else {
		// Search in workflow paths
		for _, searchPath := range m.workflowPaths {
			candidate := filepath.Join(searchPath, workflowFile)
			if fileExists(candidate) {
				fullPath = candidate
				found = true
				break
			}
		}
	}

	if !found {
		return Workflow{}, fmt.Errorf("workflow file not found: %s", workflowFile)
	}

	m.logger.Info("Loading workflow from file",
		"file", fullPath)

	return m.parser.ParseFile(fullPath)
}

// ExecuteWorkflow executes a workflow with given variables
func (m *Manager) ExecuteWorkflow(ctx context.Context, workflowName string, variables map[string]interface{}) (*WorkflowExecution, error) {
	// Load the workflow
	workflow, err := m.LoadWorkflow(workflowName)
	if err != nil {
		return nil, fmt.Errorf("failed to load workflow: %w", err)
	}

	// Execute the workflow
	return m.engine.ExecuteWorkflow(ctx, workflow, variables)
}

// ExecuteWorkflowConfigs executes workflows defined in steward configuration
func (m *Manager) ExecuteWorkflowConfigs(ctx context.Context, workflowConfigs []WorkflowExecutionConfig) error {
	for _, workflowConfig := range workflowConfigs {
		if !workflowConfig.Enabled {
			m.logger.Info("Skipping disabled workflow",
				"workflow", workflowConfig.Name)
			continue
		}

		m.logger.Info("Executing configured workflow",
			"workflow", workflowConfig.Name)

		var execution *WorkflowExecution
		var err error

		if workflowConfig.WorkflowFile != "" {
			// Load from file
			workflow, loadErr := m.LoadWorkflow(workflowConfig.WorkflowFile)
			if loadErr != nil {
				m.logger.Error("Failed to load workflow from file",
					"workflow", workflowConfig.Name,
					"file", workflowConfig.WorkflowFile,
					"error", loadErr)
				continue
			}

			execution, err = m.engine.ExecuteWorkflow(ctx, workflow, workflowConfig.Variables)
		} else {
			return fmt.Errorf("workflow execution %s: either workflow_file must be specified", workflowConfig.Name)
		}

		if err != nil {
			m.logger.Error("Failed to start workflow execution",
				"workflow", workflowConfig.Name,
				"error", err)
			continue
		}

		m.logger.Info("Started workflow execution",
			"workflow", workflowConfig.Name,
			"execution_id", execution.ID)
	}

	return nil
}

// GetEngine returns the workflow engine for direct access
func (m *Manager) GetEngine() *Engine {
	return m.engine
}

// AddWorkflowPath adds a directory to the workflow search paths
func (m *Manager) AddWorkflowPath(path string) {
	m.workflowPaths = append(m.workflowPaths, path)
}

// ConvertResourcesToWorkflow converts traditional resource configurations to a workflow
func (m *Manager) ConvertResourcesToWorkflow(resources []config.ResourceConfig) Workflow {
	workflow := Workflow{
		Name:        "steward-resources",
		Description: "Auto-generated workflow from steward resource configuration",
		Version:     "1.0.0",
		Steps:       make([]Step, len(resources)),
	}

	// Convert each resource to a task step
	for i, resource := range resources {
		step := Step{
			Name:   resource.Name,
			Type:   StepTypeTask,
			Module: resource.Module,
			Config: resource.Config,
		}
		workflow.Steps[i] = step
	}

	return workflow
}

// ExecuteResourcesAsWorkflow executes traditional resources as a workflow
func (m *Manager) ExecuteResourcesAsWorkflow(ctx context.Context, resources []config.ResourceConfig) (*WorkflowExecution, error) {
	workflow := m.ConvertResourcesToWorkflow(resources)
	return m.engine.ExecuteWorkflow(ctx, workflow, nil)
}

// fileExists checks if a file exists
func fileExists(filename string) bool {
	info, err := filepath.Abs(filename)
	if err != nil {
		return false
	}
	_, err = filepath.Abs(info)
	return err == nil
}
