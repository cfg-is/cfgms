// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package nodes

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/modules/script"
	"github.com/cfgis/cfgms/features/workflow"
)

// ScriptStepConfig defines configuration for script execution workflow steps
type ScriptStepConfig struct {
	// ScriptID is the ID of the script to execute (from repository)
	ScriptID string `yaml:"script_id,omitempty" json:"script_id,omitempty"`

	// ScriptVersion is the specific version to execute (empty = latest)
	ScriptVersion string `yaml:"script_version,omitempty" json:"script_version,omitempty"`

	// InlineScript allows specifying script content directly
	InlineScript string `yaml:"inline_script,omitempty" json:"inline_script,omitempty"`

	// Shell is the shell type to use
	Shell script.ShellType `yaml:"shell" json:"shell"`

	// Parameters are custom parameters to pass to the script
	Parameters map[string]string `yaml:"parameters,omitempty" json:"parameters,omitempty"`

	// Devices specifies an explicit list of device IDs to target.
	// When set, DeviceFilter and the FleetQuery are bypassed entirely.
	Devices []string `yaml:"devices,omitempty" json:"devices,omitempty"`

	// DeviceFilter selects target devices via fleet-wide search.
	// Uses the same fleet.Filter that GET /api/v1/stewards?os=...&tag=... uses,
	// ensuring one filter definition and one query path across the system.
	// Ignored when Devices is non-empty.
	// For recurring workflows the filter is re-evaluated on each run.
	DeviceFilter *fleet.Filter `yaml:"device_filter,omitempty" json:"device_filter,omitempty"`

	// Timeout for script execution
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// CaptureOutput determines if stdout/stderr should be captured
	CaptureOutput bool `yaml:"capture_output,omitempty" json:"capture_output,omitempty"`

	// GenerateAPIKey determines if an ephemeral API key should be generated
	GenerateAPIKey bool `yaml:"generate_api_key,omitempty" json:"generate_api_key,omitempty"`

	// APIKeyTTL is the time-to-live for the ephemeral API key
	APIKeyTTL time.Duration `yaml:"api_key_ttl,omitempty" json:"api_key_ttl,omitempty"`

	// WaitForCompletion determines if workflow should wait for script to complete
	WaitForCompletion bool `yaml:"wait_for_completion,omitempty" json:"wait_for_completion,omitempty"`

	// OnSuccess defines actions to take on successful execution
	OnSuccess *ScriptActionConfig `yaml:"on_success,omitempty" json:"on_success,omitempty"`

	// OnFailure defines actions to take on failed execution
	OnFailure *ScriptActionConfig `yaml:"on_failure,omitempty" json:"on_failure,omitempty"`
}

// ScriptActionConfig defines actions to take based on script results
type ScriptActionConfig struct {
	// SetVariable sets workflow variables based on script output
	SetVariable map[string]string `yaml:"set_variable,omitempty" json:"set_variable,omitempty"`

	// TriggerWorkflow triggers another workflow
	TriggerWorkflow string `yaml:"trigger_workflow,omitempty" json:"trigger_workflow,omitempty"`

	// SendNotification sends a notification
	SendNotification *NotificationConfig `yaml:"send_notification,omitempty" json:"send_notification,omitempty"`
}

// NotificationConfig defines notification configuration
type NotificationConfig struct {
	// Type is the notification type (email, webhook, slack, etc.)
	Type string `yaml:"type" json:"type"`

	// Recipients are the notification recipients
	Recipients []string `yaml:"recipients" json:"recipients"`

	// Message is the notification message
	Message string `yaml:"message" json:"message"`
}

// ScriptNode implements the workflow.Node interface for script execution
type ScriptNode struct {
	workflow.BaseNode
	config         *ScriptStepConfig
	repository     script.ScriptRepository
	monitor        *script.ExecutionMonitor
	keyManager     *script.EphemeralKeyManager
	dnaProvider    script.DNAProvider
	configProvider script.ConfigProvider
	fleetQuery     fleet.FleetQuery
}

// NewScriptNode creates a new script execution node
func NewScriptNode(id, name string, config *ScriptStepConfig, repository script.ScriptRepository, monitor *script.ExecutionMonitor, keyManager *script.EphemeralKeyManager) *ScriptNode {
	return &ScriptNode{
		BaseNode: workflow.BaseNode{
			ID:   id,
			Type: "script",
			Name: name,
		},
		config:     config,
		repository: repository,
		monitor:    monitor,
		keyManager: keyManager,
	}
}

// SetFleetQuery sets the fleet query used to resolve device IDs from filters.
func (n *ScriptNode) SetFleetQuery(fq fleet.FleetQuery) {
	n.fleetQuery = fq
}

// resolveDeviceIDs determines the set of device IDs to target.
//
// Priority:
//  1. Explicit Devices list — bypasses fleet query entirely.
//  2. DeviceFilter via fleetQuery.Search — evaluated fresh on every call.
//  3. Default to localhost when neither is configured.
//
// Returns (deviceIDs, zeroMatch, error).
// zeroMatch is true when the filter resolved successfully but matched no devices.
func (n *ScriptNode) resolveDeviceIDs() ([]string, bool, error) {
	// Explicit device list overrides fleet query
	if len(n.config.Devices) > 0 {
		return n.config.Devices, false, nil
	}

	// Fleet filter path
	if n.config.DeviceFilter != nil {
		if n.fleetQuery == nil {
			// DeviceFilter configured but no FleetQuery wired — misconfiguration.
			// Return an error so callers know the filter was ignored, rather than
			// silently targeting localhost when fleet-wide targeting was intended.
			return nil, false, fmt.Errorf("device_filter is configured but no FleetQuery is wired; call SetFleetQuery before Execute")
		}
		ids, err := n.fleetQuery.Search(*n.config.DeviceFilter)
		if err != nil {
			return nil, false, fmt.Errorf("fleet query failed: %w", err)
		}
		if len(ids) == 0 {
			return nil, true, nil
		}
		return ids, false, nil
	}

	// Default fallback
	return []string{"localhost"}, false, nil
}

// Execute implements workflow.Node interface
func (n *ScriptNode) Execute(ctx context.Context, input workflow.NodeInput) (workflow.NodeOutput, error) {
	// Get script content
	var scriptContent string
	var metadata *script.ScriptMetadata

	if n.config.InlineScript != "" {
		// Use inline script
		scriptContent = n.config.InlineScript
	} else if n.config.ScriptID != "" {
		// Get script from repository
		versioned, err := n.repository.Get(n.config.ScriptID, n.config.ScriptVersion)
		if err != nil {
			return workflow.NodeOutput{
				Success: false,
				Error:   fmt.Sprintf("failed to get script: %v", err),
			}, err
		}
		scriptContent = versioned.Content
		metadata = versioned.Metadata
	} else {
		return workflow.NodeOutput{
			Success: false,
			Error:   "either script_id or inline_script must be specified",
		}, fmt.Errorf("no script specified")
	}

	// Inject parameters
	if n.dnaProvider != nil || n.configProvider != nil {
		injector := script.NewParameterInjector(n.dnaProvider, n.configProvider)
		injectedContent, err := injector.InjectParameters(scriptContent, n.config.Parameters)
		if err != nil {
			return workflow.NodeOutput{
				Success: false,
				Error:   fmt.Sprintf("failed to inject parameters: %v", err),
			}, err
		}
		scriptContent = injectedContent
	}

	// Resolve target device IDs — re-evaluated on each Execute call so that
	// recurring scheduled workflows always reflect current fleet state.
	deviceIDs, zeroMatch, err := n.resolveDeviceIDs()
	if err != nil {
		return workflow.NodeOutput{
			Success: false,
			Error:   fmt.Sprintf("failed to resolve target devices: %v", err),
		}, err
	}

	// Zero-match: filter resolved but no devices matched.
	// Log a warning and complete successfully — this is not an error condition.
	if zeroMatch {
		return workflow.NodeOutput{
			Success: true,
			Data: map[string]interface{}{
				"warning": "no matching devices found for the configured filter; no executions queued",
			},
		}, nil
	}

	scriptName := n.Name
	if metadata != nil {
		scriptName = metadata.Name
	}

	execution, err := n.monitor.StartExecution(ctx, n.config.ScriptID, scriptName, "", deviceIDs)
	if err != nil {
		return workflow.NodeOutput{
			Success: false,
			Error:   fmt.Sprintf("failed to start execution monitoring: %v", err),
		}, err
	}

	// Generate ephemeral API key if requested
	var apiKey *script.EphemeralAPIKey
	if n.config.GenerateAPIKey && n.keyManager != nil {
		ttl := n.config.APIKeyTTL
		if ttl == 0 {
			ttl = 1 * time.Hour // Default TTL
		}
		apiKey, err = n.keyManager.GenerateKey(
			n.config.ScriptID,
			execution.ID,
			"", // tenantID
			deviceIDs[0],
			ttl,
			script.ScriptCallbackPermissions(),
			0, // unlimited usage
		)
		if err != nil {
			return workflow.NodeOutput{
				Success: false,
				Error:   fmt.Sprintf("failed to generate API key: %v", err),
			}, err
		}
	}

	// Execute script on each device
	results := make(map[string]*script.ExecutionResult)
	for _, deviceID := range deviceIDs {
		// Create script config
		scriptConfig := &script.ScriptConfig{
			Content:     scriptContent,
			Shell:       n.config.Shell,
			Timeout:     n.config.Timeout,
			Environment: make(map[string]string),
		}

		// Add API key to environment if generated
		if apiKey != nil {
			scriptConfig.Environment["CFGMS_API_KEY"] = apiKey.Key
			scriptConfig.Environment["CFGMS_EXECUTION_ID"] = execution.ID
			scriptConfig.Environment["CFGMS_DEVICE_ID"] = deviceID
		}

		// Execute script
		executor := script.NewExecutor(scriptConfig)
		result, execErr := executor.Execute(ctx)

		// Update execution monitor.
		// Best-effort telemetry: a status-update failure must not mask the actual
		// script execution result, so the error is intentionally ignored here.
		status := script.StatusCompleted
		if execErr != nil {
			status = script.StatusFailed
		}
		_ = n.monitor.UpdateDeviceStatus(execution.ID, deviceID, status, result, execErr) //nolint:errcheck // best-effort telemetry

		results[deviceID] = result
	}

	// Wait for completion if requested
	if n.config.WaitForCompletion {
		// Poll execution status until complete
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		timeout := time.After(n.config.Timeout)
		for {
			select {
			case <-ctx.Done():
				return workflow.NodeOutput{
					Success: false,
					Error:   "execution cancelled",
				}, ctx.Err()
			case <-timeout:
				return workflow.NodeOutput{
					Success: false,
					Error:   "execution timeout",
				}, fmt.Errorf("timeout waiting for script completion")
			case <-ticker.C:
				exec, err := n.monitor.GetExecution(execution.ID)
				if err != nil {
					continue
				}
				if exec.Status == script.StatusCompleted || exec.Status == script.StatusFailed {
					goto ExecutionComplete
				}
			}
		}
	}

ExecutionComplete:
	// Get final execution status
	finalExecution, err := n.monitor.GetExecution(execution.ID)
	if err != nil {
		return workflow.NodeOutput{
			Success: false,
			Error:   fmt.Sprintf("failed to get execution status: %v", err),
		}, err
	}

	// Build output
	outputData := map[string]interface{}{
		"execution_id": execution.ID,
		"summary":      finalExecution.Summary,
		"results":      results,
	}

	if apiKey != nil {
		outputData["api_key"] = apiKey.Key
	}

	success := finalExecution.Status == script.StatusCompleted
	errorMsg := ""
	if !success {
		errorMsg = fmt.Sprintf("script execution failed: %d devices failed", finalExecution.Summary.Failed)
	}

	return workflow.NodeOutput{
		Data:    outputData,
		Success: success,
		Error:   errorMsg,
	}, nil
}

// SetDNAProvider sets the DNA provider for parameter injection
func (n *ScriptNode) SetDNAProvider(provider script.DNAProvider) {
	n.dnaProvider = provider
}

// SetConfigProvider sets the config provider for parameter injection
func (n *ScriptNode) SetConfigProvider(provider script.ConfigProvider) {
	n.configProvider = provider
}

// ScriptStepExecutor executes script workflow steps
type ScriptStepExecutor struct {
	repository     script.ScriptRepository
	monitor        *script.ExecutionMonitor
	keyManager     *script.EphemeralKeyManager
	dnaProvider    script.DNAProvider
	configProvider script.ConfigProvider
	fleetQuery     fleet.FleetQuery
}

// NewScriptStepExecutor creates a new script step executor
func NewScriptStepExecutor(repository script.ScriptRepository, monitor *script.ExecutionMonitor, keyManager *script.EphemeralKeyManager) *ScriptStepExecutor {
	return &ScriptStepExecutor{
		repository: repository,
		monitor:    monitor,
		keyManager: keyManager,
	}
}

// SetFleetQuery sets the fleet query used to resolve device IDs from filters.
func (e *ScriptStepExecutor) SetFleetQuery(fq fleet.FleetQuery) {
	e.fleetQuery = fq
}

// ExecuteStep implements workflow.StepExecutor interface
func (e *ScriptStepExecutor) ExecuteStep(ctx context.Context, step workflow.Step, variables map[string]interface{}) (workflow.StepResult, error) {
	// Parse script config from step config
	config, err := parseScriptStepConfig(step.Config)
	if err != nil {
		return workflow.StepResult{
			Status:    workflow.StatusFailed,
			StartTime: time.Now(),
			Error:     fmt.Sprintf("failed to parse script step config: %v", err),
		}, err
	}

	// Create script node
	node := NewScriptNode(step.Name, step.Name, config, e.repository, e.monitor, e.keyManager)
	node.SetDNAProvider(e.dnaProvider)
	node.SetConfigProvider(e.configProvider)
	if e.fleetQuery != nil {
		node.SetFleetQuery(e.fleetQuery)
	}

	// Execute node
	startTime := time.Now()
	output, err := node.Execute(ctx, workflow.NodeInput{
		Data:    variables,
		Context: make(map[string]interface{}),
	})
	endTime := time.Now()

	// Build step result
	status := workflow.StatusCompleted
	if !output.Success {
		status = workflow.StatusFailed
	}

	return workflow.StepResult{
		Status:    status,
		StartTime: startTime,
		EndTime:   &endTime,
		Duration:  endTime.Sub(startTime),
		Output:    output.Data,
		Error:     output.Error,
	}, err
}

// SetDNAProvider sets the DNA provider
func (e *ScriptStepExecutor) SetDNAProvider(provider script.DNAProvider) {
	e.dnaProvider = provider
}

// SetConfigProvider sets the config provider
func (e *ScriptStepExecutor) SetConfigProvider(provider script.ConfigProvider) {
	e.configProvider = provider
}

// parseScriptStepConfig converts a map[string]interface{} to ScriptStepConfig
func parseScriptStepConfig(configMap map[string]interface{}) (*ScriptStepConfig, error) {
	if configMap == nil {
		return &ScriptStepConfig{}, nil
	}

	config := &ScriptStepConfig{}

	// Parse string fields
	if scriptID, ok := configMap["script_id"].(string); ok {
		config.ScriptID = scriptID
	}
	if scriptVersion, ok := configMap["script_version"].(string); ok {
		config.ScriptVersion = scriptVersion
	}
	if inlineScript, ok := configMap["inline_script"].(string); ok {
		config.InlineScript = inlineScript
	}
	if shell, ok := configMap["shell"].(string); ok {
		config.Shell = script.ShellType(shell)
	}

	// Parse parameters map
	if params, ok := configMap["parameters"].(map[string]interface{}); ok {
		config.Parameters = make(map[string]string)
		for k, v := range params {
			if strVal, ok := v.(string); ok {
				config.Parameters[k] = strVal
			} else {
				config.Parameters[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	// Parse devices slice
	if devices, ok := configMap["devices"].([]interface{}); ok {
		config.Devices = make([]string, 0, len(devices))
		for _, d := range devices {
			if devStr, ok := d.(string); ok {
				config.Devices = append(config.Devices, devStr)
			}
		}
	}

	// Parse device_filter — shares field names with fleet.Filter / REST API query params
	if filterMap, ok := configMap["device_filter"].(map[string]interface{}); ok {
		f := &fleet.Filter{}
		if os, ok := filterMap["os"].(string); ok {
			f.OS = os
		}
		if tags, ok := filterMap["tags"].([]interface{}); ok {
			f.Tags = make([]string, 0, len(tags))
			for _, t := range tags {
				if s, ok := t.(string); ok {
					f.Tags = append(f.Tags, s)
				}
			}
		}
		if groups, ok := filterMap["groups"].([]interface{}); ok {
			f.Groups = make([]string, 0, len(groups))
			for _, g := range groups {
				if s, ok := g.(string); ok {
					f.Groups = append(f.Groups, s)
				}
			}
		}
		if dnaQuery, ok := filterMap["dna_query"].(map[string]interface{}); ok {
			f.DNAQuery = make(map[string]string, len(dnaQuery))
			for k, v := range dnaQuery {
				if s, ok := v.(string); ok {
					f.DNAQuery[k] = s
				}
			}
		}
		config.DeviceFilter = f
	}

	// Parse timeout duration
	if timeout, ok := configMap["timeout"].(string); ok {
		if duration, err := time.ParseDuration(timeout); err == nil {
			config.Timeout = duration
		}
	} else if timeoutInt, ok := configMap["timeout"].(int64); ok {
		config.Timeout = time.Duration(timeoutInt)
	} else if timeoutInt, ok := configMap["timeout"].(int); ok {
		config.Timeout = time.Duration(timeoutInt)
	}

	// Parse boolean fields
	if captureOutput, ok := configMap["capture_output"].(bool); ok {
		config.CaptureOutput = captureOutput
	}
	if generateAPIKey, ok := configMap["generate_api_key"].(bool); ok {
		config.GenerateAPIKey = generateAPIKey
	}
	if waitForCompletion, ok := configMap["wait_for_completion"].(bool); ok {
		config.WaitForCompletion = waitForCompletion
	}

	// Parse API key TTL
	if apiKeyTTL, ok := configMap["api_key_ttl"].(string); ok {
		if duration, err := time.ParseDuration(apiKeyTTL); err == nil {
			config.APIKeyTTL = duration
		}
	} else if apiKeyTTLInt, ok := configMap["api_key_ttl"].(int64); ok {
		config.APIKeyTTL = time.Duration(apiKeyTTLInt)
	} else if apiKeyTTLInt, ok := configMap["api_key_ttl"].(int); ok {
		config.APIKeyTTL = time.Duration(apiKeyTTLInt)
	}

	return config, nil
}
