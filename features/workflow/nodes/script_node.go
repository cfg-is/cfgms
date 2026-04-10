// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package nodes

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/modules/script"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
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

	// Devices specifies explicit device IDs to run the script on.
	// Takes priority over DeviceFilter when non-empty.
	Devices []string `yaml:"devices,omitempty" json:"devices,omitempty"`

	// DeviceFilter resolves target devices via the fleet package at execution
	// time. Re-evaluated on every Execute call (recurring workflow support).
	// Ignored when Devices is non-empty.
	DeviceFilter *fleet.Filter `yaml:"device_filter,omitempty" json:"device_filter,omitempty"`

	// Timeout for script execution
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// CaptureOutput determines if stdout/stderr should be captured
	CaptureOutput bool `yaml:"capture_output,omitempty" json:"capture_output,omitempty"`

	// GenerateAPIKey determines if an ephemeral API key should be generated
	GenerateAPIKey bool `yaml:"generate_api_key,omitempty" json:"generate_api_key,omitempty"`

	// APIKeyTTL is the time-to-live for the ephemeral API key
	APIKeyTTL time.Duration `yaml:"api_key_ttl,omitempty" json:"api_key_ttl,omitempty"`

	// ExecutionContext controls which OS user runs the script (system or logged_in_user)
	ExecutionContext script.ExecutionContext `yaml:"execution_context,omitempty" json:"execution_context,omitempty"`

	// WaitForCompletion determines if workflow should wait for script to complete
	WaitForCompletion bool `yaml:"wait_for_completion,omitempty" json:"wait_for_completion,omitempty"`

	// SecretBindings declares parameters that are resolved from the steward
	// secret store at execution time. Secrets are delivered via env vars and
	// never appear in command-line arguments or script block content.
	SecretBindings []script.ParamBinding `yaml:"secret_bindings,omitempty" json:"secret_bindings,omitempty"`

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
	secretStore    interfaces.SecretStore
	fleetQuery     fleet.FleetQuery
	executionQueue *script.ExecutionQueue
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

// resolveDeviceIDs returns the device IDs to target for this execution.
// Priority: explicit Devices > fleet filter > localhost fallback.
// A fleet filter matching zero devices returns (nil, nil) — the caller logs a
// warning and returns success rather than treating this as an error.
// The filter is re-evaluated on every call to support recurring workflows.
func (n *ScriptNode) resolveDeviceIDs(ctx context.Context) ([]string, error) {
	// Priority 1: explicit device list wins
	if len(n.config.Devices) > 0 {
		return n.config.Devices, nil
	}

	// Priority 2: fleet filter (re-evaluated each call for recurring workflows)
	if n.config.DeviceFilter != nil && n.fleetQuery != nil {
		results, err := n.fleetQuery.Search(ctx, *n.config.DeviceFilter)
		if err != nil {
			return nil, fmt.Errorf("fleet query failed: %w", err)
		}
		if len(results) == 0 {
			// Zero-match: not an error — caller logs warning and returns success.
			return nil, nil
		}
		ids := make([]string, len(results))
		for i, r := range results {
			ids[i] = r.ID
		}
		return ids, nil
	}

	// Priority 3: localhost fallback
	return []string{"localhost"}, nil
}

// Execute implements workflow.Node interface
func (n *ScriptNode) Execute(ctx context.Context, input workflow.NodeInput) (workflow.NodeOutput, error) {
	// Resolve device IDs — re-evaluated on each Execute for recurring workflows.
	deviceIDs, err := n.resolveDeviceIDs(ctx)
	if err != nil {
		return workflow.NodeOutput{
			Success: false,
			Error:   fmt.Sprintf("failed to resolve device IDs: %v", err),
		}, err
	}
	if len(deviceIDs) == 0 {
		// Zero-match from fleet filter: success with warning, no dispatch.
		logging.NewLogger("warn").Warn("fleet filter matched no devices; skipping script dispatch",
			"node", n.Name)
		return workflow.NodeOutput{
			Success: true,
			Data: map[string]interface{}{
				"warning": "fleet filter matched no devices",
			},
		}, nil
	}

	// Queue path: enqueue each device; content resolution deferred to dispatch time.
	// StartExecution is called per device so each queue entry has a unique ExecutionID
	// (the queue store uses ExecutionID as the map key).
	if n.executionQueue != nil {
		// Build shared metadata once — the store deep-copies it on enqueue.
		queueMeta := make(map[string]interface{})
		if runID, ok := input.Context["workflow_run_id"]; ok {
			queueMeta["workflow_run_id"] = runID
		}
		if wfName, ok := input.Context["workflow_name"]; ok {
			queueMeta["workflow_name"] = wfName
		}
		if len(n.config.SecretBindings) > 0 {
			bindingsJSON, err := json.Marshal(n.config.SecretBindings)
			if err != nil {
				return workflow.NodeOutput{
					Success: false,
					Error:   fmt.Sprintf("failed to encode secret bindings: %v", err),
				}, err
			}
			queueMeta["secret_bindings"] = string(bindingsJSON)
		}

		var firstExecutionID string
		for _, deviceID := range deviceIDs {
			// Per-device execution so each queue entry gets a unique ExecutionID.
			execution, err := n.monitor.StartExecution(ctx, n.config.ScriptID, n.Name, "", []string{deviceID})
			if err != nil {
				return workflow.NodeOutput{
					Success: false,
					Error:   fmt.Sprintf("failed to start execution monitoring: %v", err),
				}, err
			}
			if firstExecutionID == "" {
				firstExecutionID = execution.ID
			}

			qe := &script.QueuedExecution{
				ExecutionID:      execution.ID,
				ScriptRef:        n.config.ScriptID,
				ScriptVersion:    n.config.ScriptVersion,
				Shell:            n.config.Shell,
				Parameters:       n.config.Parameters,
				Timeout:          n.config.Timeout,
				GenerateAPIKey:   n.config.GenerateAPIKey,
				APIKeyTTL:        n.config.APIKeyTTL,
				ExecutionContext: n.config.ExecutionContext,
				Metadata:         queueMeta,
			}
			if err := n.executionQueue.QueueExecution(deviceID, qe); err != nil {
				return workflow.NodeOutput{
					Success: false,
					Error:   fmt.Sprintf("failed to queue execution for device %s: %v", deviceID, err),
				}, err
			}
		}

		return workflow.NodeOutput{
			Success: true,
			Data: map[string]interface{}{
				"execution_id": firstExecutionID,
				"queued":       len(deviceIDs),
			},
		}, nil
	}

	// Inline execution path (no queue configured): resolve content and execute immediately.
	var scriptContent string
	var scriptMeta *script.ScriptMetadata

	if n.config.InlineScript != "" {
		scriptContent = n.config.InlineScript
	} else if n.config.ScriptID != "" {
		s, err := n.repository.Get(n.config.ScriptID, n.config.ScriptVersion)
		if err != nil {
			return workflow.NodeOutput{
				Success: false,
				Error:   fmt.Sprintf("failed to get script: %v", err),
			}, err
		}
		scriptContent = s.Content
		scriptMeta = s.Metadata
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

	scriptName := n.Name
	if scriptMeta != nil {
		scriptName = scriptMeta.Name
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
			Content:          scriptContent,
			Shell:            n.config.Shell,
			Timeout:          n.config.Timeout,
			ExecutionContext: n.config.ExecutionContext,
			Environment:      make(map[string]string),
		}

		// Add API key to environment if generated
		if apiKey != nil {
			scriptConfig.Environment["CFGMS_API_KEY"] = apiKey.Key
			scriptConfig.Environment["CFGMS_EXECUTION_ID"] = execution.ID
			scriptConfig.Environment["CFGMS_DEVICE_ID"] = deviceID
		}

		// Execute script — use secret-aware executor when bindings are configured.
		var executor *script.Executor
		if n.secretStore != nil && len(n.config.SecretBindings) > 0 {
			executor = script.NewExecutorWithSecrets(scriptConfig, n.secretStore, n.config.SecretBindings)
		} else {
			executor = script.NewExecutor(scriptConfig)
		}
		result, execErr := executor.Execute(ctx)

		// Update execution monitor. The error is intentionally ignored: a monitor
		// tracking failure must not prevent the script result from being recorded
		// in the results map or returned to the caller.
		status := script.StatusCompleted
		if execErr != nil {
			status = script.StatusFailed
		}
		if monErr := n.monitor.UpdateDeviceStatus(execution.ID, deviceID, status, result, execErr); monErr != nil {
			logging.NewLogger("warn").Warn("failed to update device execution status", "device_id", deviceID, "error", monErr)
		}

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

// SetSecretStore sets the secret store used to resolve secret bindings at
// execution time. Required when ScriptStepConfig.SecretBindings is non-empty.
func (n *ScriptNode) SetSecretStore(store interfaces.SecretStore) {
	n.secretStore = store
}

// SetFleetQuery sets the fleet query implementation used to resolve device IDs
// from DeviceFilter at execution time.
func (n *ScriptNode) SetFleetQuery(q fleet.FleetQuery) {
	n.fleetQuery = q
}

// SetExecutionQueue sets the durable execution queue. When set, Execute routes
// each per-device dispatch through the queue instead of executing inline.
func (n *ScriptNode) SetExecutionQueue(q *script.ExecutionQueue) {
	n.executionQueue = q
}

// ScriptStepExecutor executes script workflow steps
type ScriptStepExecutor struct {
	repository     script.ScriptRepository
	monitor        *script.ExecutionMonitor
	keyManager     *script.EphemeralKeyManager
	dnaProvider    script.DNAProvider
	configProvider script.ConfigProvider
	secretStore    interfaces.SecretStore
	fleetQuery     fleet.FleetQuery
	executionQueue *script.ExecutionQueue
}

// NewScriptStepExecutor creates a new script step executor
func NewScriptStepExecutor(repository script.ScriptRepository, monitor *script.ExecutionMonitor, keyManager *script.EphemeralKeyManager) *ScriptStepExecutor {
	return &ScriptStepExecutor{
		repository: repository,
		monitor:    monitor,
		keyManager: keyManager,
	}
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
	node.SetSecretStore(e.secretStore)
	node.SetFleetQuery(e.fleetQuery)
	node.SetExecutionQueue(e.executionQueue)

	// Propagate workflow context so queue metadata includes workflow_run_id/workflow_name.
	inputCtx := make(map[string]interface{})
	if runID, ok := variables["workflow_run_id"]; ok {
		inputCtx["workflow_run_id"] = runID
	}
	if wfName, ok := variables["workflow_name"]; ok {
		inputCtx["workflow_name"] = wfName
	}

	// Execute node
	startTime := time.Now()
	output, err := node.Execute(ctx, workflow.NodeInput{
		Data:    variables,
		Context: inputCtx,
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

// SetSecretStore sets the secret store for resolving secret bindings in steps.
func (e *ScriptStepExecutor) SetSecretStore(store interfaces.SecretStore) {
	e.secretStore = store
}

// SetFleetQuery sets the fleet query implementation propagated to created script nodes.
func (e *ScriptStepExecutor) SetFleetQuery(q fleet.FleetQuery) {
	e.fleetQuery = q
}

// SetExecutionQueue sets the durable execution queue propagated to created script nodes.
func (e *ScriptStepExecutor) SetExecutionQueue(q *script.ExecutionQueue) {
	e.executionQueue = q
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
	if ec, ok := configMap["execution_context"].(string); ok {
		config.ExecutionContext = script.ExecutionContext(ec)
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

	// Parse device_filter into fleet.Filter
	if df, ok := configMap["device_filter"].(map[string]interface{}); ok {
		filter := &fleet.Filter{}
		if v, ok := df["tenant_id"].(string); ok {
			filter.TenantID = v
		}
		if v, ok := df["os"].(string); ok {
			filter.OS = v
		}
		if v, ok := df["platform"].(string); ok {
			filter.Platform = v
		}
		if v, ok := df["architecture"].(string); ok {
			filter.Architecture = v
		}
		if v, ok := df["status"].(string); ok {
			filter.Status = v
		}
		if v, ok := df["hostname"].(string); ok {
			filter.Hostname = v
		}
		if rawTags, ok := df["tags"].([]interface{}); ok {
			filter.Tags = make([]string, 0, len(rawTags))
			for _, t := range rawTags {
				if s, ok := t.(string); ok {
					filter.Tags = append(filter.Tags, s)
				}
			}
		}
		if rawAttrs, ok := df["dna_attributes"].(map[string]interface{}); ok {
			filter.DNAAttributes = make(map[string]string, len(rawAttrs))
			for k, v := range rawAttrs {
				if s, ok := v.(string); ok {
					filter.DNAAttributes[k] = s
				}
			}
		}
		config.DeviceFilter = filter
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

	// Parse secret_bindings slice
	if rawBindings, ok := configMap["secret_bindings"].([]interface{}); ok {
		config.SecretBindings = make([]script.ParamBinding, 0, len(rawBindings))
		for i, rb := range rawBindings {
			bm, ok := rb.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("secret_bindings[%d]: expected a mapping, got %T", i, rb)
			}
			var binding script.ParamBinding
			if name, ok := bm["name"].(string); ok {
				binding.Name = name
			}
			if from, ok := bm["from"].(string); ok {
				binding.From = script.ParamSource(from)
			}
			if key, ok := bm["key"].(string); ok {
				binding.Key = key
			}
			if value, ok := bm["value"].(string); ok {
				binding.Value = value
			}
			config.SecretBindings = append(config.SecretBindings, binding)
		}
	}

	return config, nil
}
