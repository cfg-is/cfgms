// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package nodes

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

var scriptNodeLogger = logging.NewLogger("warn")

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
	config           *ScriptStepConfig
	repository       script.ScriptRepository
	monitor          *script.ExecutionMonitor
	keyManager       *script.EphemeralKeyManager
	dnaProvider      script.DNAProvider
	configProvider   script.ConfigProvider
	secretStore      interfaces.SecretStore
	fleetQuery       fleet.FleetQuery
	tenantID         string
	executionQueue   *script.ExecutionQueue
	executionTracker script.ExecutionTracker

	// restricted is non-nil for a script step of a restricted automation
	// execution, set by the engine through the step executor. A restricted node
	// takes only the queue path, runs only a script its approver approved, and
	// refuses every form of script a grant must not reach (see executeRestricted).
	restricted *workflow.RestrictedRun
	approver   workflow.ScriptApprover
	// resultWait bounds how long a restricted step waits for the queued results.
	resultWait time.Duration
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

// resolveDeviceIDs returns the device IDs to target for this execution, scoped to
// n.tenantID — the execution's authenticated tenant, injected via SetTenantID and
// never sourced from execution.Variables or step.Config (Issue #4338).
//
// Priority: explicit Devices > fleet filter. Both paths are verified against the
// fleet, scoped to n.tenantID: a device outside the authenticated tenant is
// dropped from the result, not dispatched to. Both paths share the same
// preconditions (requireTenantAndFleet) — a missing tenant or a missing fleet
// query is an error on either path, never an unverified passthrough of the
// workflow author's device list. A fleet query matching zero devices returns
// (nil, nil) — the caller logs a warning and returns success rather than
// treating this as an error. The filter is re-evaluated on every call to support
// recurring workflows.
//
// There is no localhost fallback. A step whose Devices/DeviceFilter cannot be
// resolved to a target is a configuration error, not an implicit grant of
// in-process execution on the controller host (Issue #4338).
func (n *ScriptNode) resolveDeviceIDs(ctx context.Context) ([]string, error) {
	results, err := n.searchDevices(ctx)
	if err != nil || len(results) == 0 {
		// Zero-match from a filter: not an error — the caller logs a warning and
		// returns success.
		return nil, err
	}
	ids := make([]string, len(results))
	for i, r := range results {
		ids[i] = r.ID
	}
	return ids, nil
}

// searchDevices runs the fleet query for the configured targets, scoped to
// n.tenantID, and returns the matching devices.
func (n *ScriptNode) searchDevices(ctx context.Context) ([]fleet.StewardResult, error) {
	switch {
	case len(n.config.Devices) > 0:
		if err := n.requireTenantAndFleet(); err != nil {
			return nil, err
		}
		results, err := n.fleetQuery.Search(ctx, fleet.Filter{TenantID: n.tenantID, IDs: n.config.Devices})
		if err != nil {
			return nil, fmt.Errorf("fleet query failed: %w", err)
		}
		return results, nil

	case n.config.DeviceFilter != nil:
		if err := n.requireTenantAndFleet(); err != nil {
			return nil, err
		}
		// An author-supplied filter.TenantID (step.Config is workflow-author-
		// writable) must name the authenticated tenant exactly. A mismatch is
		// refused; it is never rewritten to n.tenantID, because rewriting would
		// widen a deliberately narrow author scope into the whole tenant.
		filter := *n.config.DeviceFilter
		if filter.TenantID != "" && filter.TenantID != n.tenantID {
			return nil, fmt.Errorf("device_filter tenant_id %q does not match the execution's authenticated tenant", filter.TenantID)
		}
		filter.TenantID = n.tenantID
		results, err := n.fleetQuery.Search(ctx, filter)
		if err != nil {
			return nil, fmt.Errorf("fleet query failed: %w", err)
		}
		return results, nil

	default:
		return nil, fmt.Errorf("no devices or device_filter configured; refusing to execute with no resolvable target")
	}
}

// requireTenantAndFleet enforces the two preconditions every device-resolution
// path depends on for tenant scoping to mean anything (Issue #4338).
//
// An empty tenant is not "no scoping applied", it is scoping REMOVED: an empty
// fleet.Filter.TenantID matches every tenant in the fleet, so resolving devices
// without an authenticated tenant would silently widen the query fleet-wide.
// A nil fleet query is the same failure by a different route — without it there
// is no way to check which tenant a named device belongs to. Both fail closed.
func (n *ScriptNode) requireTenantAndFleet() error {
	if n.tenantID == "" {
		return fmt.Errorf("execution has no authenticated tenant_id; refusing to resolve devices against an unscoped fleet query")
	}
	if n.fleetQuery == nil {
		return fmt.Errorf("no fleet query is available to verify device tenant membership")
	}
	return nil
}

// SetTenantID sets the execution's authenticated tenant (Issue #4338), injected by
// the engine — never sourced from execution.Variables or step.Config.
// resolveDeviceIDs uses it to scope both explicit device lists and DeviceFilter
// queries so a step cannot target another tenant's devices.
func (n *ScriptNode) SetTenantID(tenantID string) {
	n.tenantID = tenantID
}

// Execute implements workflow.Node interface
func (n *ScriptNode) Execute(ctx context.Context, input workflow.NodeInput) (workflow.NodeOutput, error) {
	if n.restricted != nil {
		return n.executeRestricted(ctx, input)
	}

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
		scriptNodeLogger.Warn("fleet filter matched no devices; skipping script dispatch",
			"node", n.Name)
		return workflow.NodeOutput{
			Success: true,
			Data: map[string]interface{}{
				"warning": "fleet filter matched no devices",
			},
		}, nil
	}

	// Queue path: enqueue each device; content resolution deferred to dispatch time.
	if n.executionQueue != nil {
		return n.executeQueued(ctx, input, deviceIDs)
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
			n.tenantID,
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
			scriptNodeLogger.Warn("failed to update device execution status", "device_id", deviceID, "error", monErr)
		}

		// Write durable tracking record on terminal state — best-effort.
		if n.executionTracker != nil {
			rec := buildInlineTrackingRecord(execution.ID, deviceID, n.config.ScriptID, n.config.Shell, status, result, input)
			if trackErr := n.executionTracker.Record(ctx, rec); trackErr != nil {
				scriptNodeLogger.Warn("failed to write execution tracking record", "device_id", deviceID, "error", trackErr)
			}
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

// executeQueued enqueues each device. StartExecution is called per device so
// each queue entry has a unique ExecutionID (the queue store uses ExecutionID as
// the map key).
func (n *ScriptNode) executeQueued(ctx context.Context, input workflow.NodeInput, deviceIDs []string) (workflow.NodeOutput, error) {
	queueMeta, err := n.queueMetadata(input)
	if err != nil {
		return workflow.NodeOutput{Success: false, Error: err.Error()}, err
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
			if err == script.ErrDuplicateExecution {
				// Dedup: identical script+device+params already queued.
				// Cancel the orphaned monitor entry to prevent leaks.
				_ = n.monitor.CancelExecution(execution.ID)
				continue
			}
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

// queueMetadata builds the metadata shared by every queue entry of the step; the
// store deep-copies it on enqueue.
func (n *ScriptNode) queueMetadata(input workflow.NodeInput) (map[string]interface{}, error) {
	queueMeta := make(map[string]interface{})
	// The library is stored per tenant: the dispatcher resolves the run's script
	// from the node's authenticated tenant, never from workflow input.
	queueMeta["tenant_id"] = n.tenantID
	if runID, ok := input.Context["workflow_run_id"]; ok {
		queueMeta["workflow_run_id"] = runID
	}
	if wfName, ok := input.Context["workflow_name"]; ok {
		queueMeta["workflow_name"] = wfName
	}
	if len(n.config.SecretBindings) > 0 {
		bindingsJSON, err := json.Marshal(n.config.SecretBindings)
		if err != nil {
			return nil, fmt.Errorf("failed to encode secret bindings: %w", err)
		}
		queueMeta["secret_bindings"] = string(bindingsJSON)
	}
	return queueMeta, nil
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

// SetFleetQuery sets the fleet query implementation used to resolve and
// tenant-verify device IDs at execution time. Required for both the explicit
// Devices list and DeviceFilter — resolution fails closed without it.
func (n *ScriptNode) SetFleetQuery(q fleet.FleetQuery) {
	n.fleetQuery = q
}

// SetExecutionQueue sets the durable execution queue. When set, Execute routes
// each per-device dispatch through the queue instead of executing inline.
func (n *ScriptNode) SetExecutionQueue(q *script.ExecutionQueue) {
	n.executionQueue = q
	// Wire tracker into queue if already set so queue-path completions are tracked.
	if n.executionTracker != nil && q != nil {
		q.SetExecutionTracker(n.executionTracker)
	}
}

// SetExecutionTracker sets the durable execution tracker. When set, Execute
// writes one ExecutionRecord per device when it reaches a terminal state.
// For the queue path, the tracker is also threaded into the ExecutionQueue so
// that AcknowledgeCompletion writes the record on steward callback.
func (n *ScriptNode) SetExecutionTracker(t script.ExecutionTracker) {
	n.executionTracker = t
	if n.executionQueue != nil {
		n.executionQueue.SetExecutionTracker(t)
	}
}

// defaultRestrictedResultWait is how long a restricted script step waits for its
// queued results, on top of the script's own timeout, before it fails. Entries
// still queued then are cancelled, so nothing runs after the step has failed.
const defaultRestrictedResultWait = 15 * time.Minute

// restrictedResultPoll is how often a restricted step reads the execution monitor.
const restrictedResultPoll = 100 * time.Millisecond

// restrictedStepKeys are the only step.Config keys a restricted script step
// accepts. Everything else is refused, so a key that selects an inline, path or
// command form (or one added later) never reaches the queue by being ignored.
var restrictedStepKeys = map[string]bool{
	"script_id": true, "script_version": true, "parameters": true,
	"devices": true, "device_filter": true, "timeout": true,
	"shell": true, "execution_context": true, "capture_output": true,
}

// restrictedRefusedKeys name the forms a restricted step refuses, for a precise
// error. A key in neither map is refused as unsupported.
var restrictedRefusedKeys = map[string]string{
	"inline_script": "an inline script", "secret_bindings": "secret bindings",
	"generate_api_key": "an ephemeral API key", "api_key_ttl": "an ephemeral API key",
	"script": "an inline script", "content": "an inline script",
	"script_path": "a script path", "path": "a script path", "file": "a script path",
	"script_file": "a script path", "command": "a command", "cmd": "a command",
	"args": "a command", "argument_list": "a command",
}

// validateRestrictedStepConfig refuses a raw step.Config a restricted script step
// must not run: any key outside restrictedStepKeys, and any parameter value that
// is not a scalar. It runs on the raw map, before parseScriptStepConfig drops
// keys it does not know.
func validateRestrictedStepConfig(raw map[string]interface{}) error {
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if restrictedStepKeys[k] {
			continue
		}
		if what, ok := restrictedRefusedKeys[k]; ok {
			return fmt.Errorf("a restricted script step does not allow %s (%q)", what, k)
		}
		return fmt.Errorf("a restricted script step does not allow the key %q", k)
	}
	params, present := raw["parameters"]
	if !present || params == nil {
		return nil
	}
	m, ok := params.(map[string]interface{})
	if !ok {
		return fmt.Errorf("a restricted script step needs parameters as a mapping of names to literal values")
	}
	for name, v := range m {
		switch v.(type) {
		case string, bool, int, int32, int64, uint, uint32, uint64, float32, float64:
		default:
			return fmt.Errorf("parameter %q must be a literal value", name)
		}
	}
	return nil
}

// isLiteralParamValue reports whether v carries no template or variable-reference
// marker. A restricted step passes only literal values: an expression would be
// evaluated by something other than the approved script's declared schema.
func isLiteralParamValue(v string) bool {
	return !strings.Contains(v, "{{") && !strings.Contains(v, "${")
}

// restrictedRun is one queued command of a restricted step.
type restrictedRun struct{ deviceID, executionID string }

func refuseStep(err error) (workflow.NodeOutput, error) {
	return workflow.NodeOutput{Success: false, Error: err.Error()}, err
}

// executeRestricted runs the script step of a restricted automation execution.
// Order matters: the cheap structural refusals first, then the approver, then the
// parameters against the approved version's schema, then the devices, and only
// then the queue. Every refusal happens with nothing queued.
func (n *ScriptNode) executeRestricted(ctx context.Context, input workflow.NodeInput) (workflow.NodeOutput, error) {
	vs, decision, err := n.authorizeRestricted(ctx)
	if err != nil {
		return refuseStep(err)
	}
	if err := n.checkRestrictedScript(vs); err != nil {
		return refuseStep(err)
	}
	deviceIDs, err := n.resolveRestrictedDevices(ctx)
	if err != nil {
		return refuseStep(fmt.Errorf("failed to resolve device IDs: %w", err))
	}
	if len(deviceIDs) == 0 {
		scriptNodeLogger.Warn("fleet filter matched no devices; skipping script dispatch", "node", n.Name)
		return workflow.NodeOutput{
			Success: true,
			Data:    map[string]interface{}{"warning": "fleet filter matched no devices"},
		}, nil
	}
	runs, deduped, err := n.queueRestricted(ctx, input, vs, decision, deviceIDs)
	if err != nil {
		return refuseStep(err)
	}
	return n.awaitRestricted(ctx, runs, deduped)
}

// checkRestrictedConfig refuses what a restricted step may not carry and what it
// cannot run without. Each refusal fails closed.
func (n *ScriptNode) checkRestrictedConfig() error {
	if err := n.checkRestrictedForms(); err != nil {
		return err
	}
	return n.checkRestrictedWiring()
}

// checkRestrictedForms refuses the forms a grant must not reach: no script id, no
// pinned version, an inline script, secret bindings, an ephemeral API key.
func (n *ScriptNode) checkRestrictedForms() error {
	c := n.config
	switch {
	case c.ScriptID == "":
		return fmt.Errorf("a restricted script step needs a script_id")
	case c.ScriptVersion == "":
		return fmt.Errorf("a restricted script step needs an explicit script_version; it never runs the latest")
	case c.InlineScript != "":
		return fmt.Errorf("a restricted script step does not allow an inline script")
	case len(c.SecretBindings) > 0:
		return fmt.Errorf("a restricted script step does not allow secret bindings")
	case c.GenerateAPIKey || c.APIKeyTTL != 0:
		return fmt.Errorf("a restricted script step does not allow an ephemeral API key")
	}
	return nil
}

// checkRestrictedWiring refuses a restricted step that lacks what it cannot run
// without: the run's ids, an approver, the queue and a tenant-resolved library.
func (n *ScriptNode) checkRestrictedWiring() error {
	switch {
	case n.restricted.RunID == "" || n.restricted.GrantID == "":
		return fmt.Errorf("a restricted script step needs the run id and grant id of its run")
	case n.approver == nil:
		return fmt.Errorf("no script approver is configured; a restricted script step cannot run")
	case n.executionQueue == nil || n.monitor == nil:
		return fmt.Errorf("no execution queue is configured; a restricted script step runs only through the queue")
	}
	if _, ok := n.repository.(script.TenantScriptResolver); !ok {
		return fmt.Errorf("no tenant-resolved script library is configured; a restricted script step cannot run")
	}
	return nil
}

// authorizeRestricted asks the approver about the pinned script and returns the
// approved version with the decision whose pin the queue binds the command to.
// Pending and denied decisions, an approver error and an incomplete decision all
// fail the step; a pending decision is first handed to the pending recorder.
func (n *ScriptNode) authorizeRestricted(ctx context.Context) (*script.VersionedScript, workflow.ScriptApprovalDecision, error) {
	var d workflow.ScriptApprovalDecision
	if err := n.checkRestrictedConfig(); err != nil {
		return nil, d, err
	}
	id, version := n.config.ScriptID, n.config.ScriptVersion
	d, err := n.approver.Approve(ctx, n.tenantID, n.restricted.Ceiling, id, version)
	if err != nil {
		scriptNodeLogger.Warn("script approval could not be decided",
			"script_id", logging.SanitizeLogValue(id), "error", logging.SanitizeLogValue(err.Error()))
		return nil, d, fmt.Errorf("script %q version %q could not be approved; nothing was queued", id, version)
	}
	if err := n.checkDecision(ctx, d); err != nil {
		return nil, d, err
	}
	vs, err := n.readApproved(d)
	return vs, d, err
}

// checkDecision accepts only an approved, complete decision. A pending one is
// handed to the pending recorder first.
func (n *ScriptNode) checkDecision(ctx context.Context, d workflow.ScriptApprovalDecision) error {
	id, version := n.config.ScriptID, n.config.ScriptVersion
	switch d.State {
	case workflow.ScriptApprovalApproved:
	case workflow.ScriptApprovalPending:
		n.recordPending(ctx, d)
		return fmt.Errorf("script %q version %q is pending approval; nothing was queued", id, version)
	default:
		return fmt.Errorf("script %q version %q is not approved; nothing was queued", id, version)
	}
	if d.OwnerTenant == "" || d.Version == "" || d.ApprovalHash == "" {
		return fmt.Errorf("the script approver returned an incomplete decision for %q; nothing was queued", id)
	}
	return nil
}

// readApproved reads the approved version from the decision's owner tenant, to
// check the step's parameters against its declared schema.
func (n *ScriptNode) readApproved(d workflow.ScriptApprovalDecision) (*script.VersionedScript, error) {
	vs, err := n.repository.(script.TenantScriptResolver).GetForTenant(d.OwnerTenant, n.config.ScriptID, d.Version)
	if err != nil || vs == nil || vs.Metadata == nil {
		return nil, fmt.Errorf("approved script %q version %q could not be read; nothing was queued", n.config.ScriptID, d.Version)
	}
	return vs, nil
}

// recordPending hands a pending decision to the approver's recorder, if it has
// one. A failure is logged only: the step has already failed either way.
func (n *ScriptNode) recordPending(ctx context.Context, d workflow.ScriptApprovalDecision) {
	rec, ok := n.approver.(workflow.ScriptPendingRecorder)
	if !ok {
		return
	}
	if err := rec.RecordPending(ctx, n.tenantID, d); err != nil {
		scriptNodeLogger.Warn("pending script approval could not be recorded",
			"script_id", logging.SanitizeLogValue(n.config.ScriptID), "error", logging.SanitizeLogValue(err.Error()))
	}
}

// checkRestrictedScript checks the step's shell and parameters against the
// approved version's declared schema: every parameter name must be declared, a
// value must be a literal, and a value must be one of the declared AllowedValues.
func (n *ScriptNode) checkRestrictedScript(vs *script.VersionedScript) error {
	if sh := n.config.Shell; sh != "" && sh != vs.Metadata.Shell {
		return fmt.Errorf("shell %q does not match the approved script's shell", sh)
	}
	declared := make(map[string]script.ScriptParameter, len(vs.Metadata.Parameters))
	for _, p := range vs.Metadata.Parameters {
		declared[p.Name] = p
	}
	names := make([]string, 0, len(n.config.Parameters))
	for name := range n.config.Parameters {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p, ok := declared[name]
		if !ok {
			return fmt.Errorf("parameter %q is not declared by the approved script", name)
		}
		value := n.config.Parameters[name]
		if !isLiteralParamValue(value) {
			return fmt.Errorf("parameter %q must be a literal value", name)
		}
		if len(p.AllowedValues) > 0 && !containsString(p.AllowedValues, value) {
			return fmt.Errorf("the value of parameter %q is not one of its allowed values", name)
		}
	}
	return nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// deviceInRunTenant reports whether a device's own tenant is exactly the run
// tenant: a descendant, ancestor or sibling tenant does not pass. It is the same
// rule as runTenantOnly in features/controller/api, which that package does not
// export.
func deviceInRunTenant(runTenant, deviceTenantID string) bool {
	return runTenant != "" && deviceTenantID == runTenant
}

// resolveRestrictedDevices resolves the step's targets through the fleet query
// and verifies every returned device against the run tenant. A device outside it,
// a filter that names a tenant subtree, or an explicit device the fleet does not
// return for the run tenant refuses the whole step; nothing is silently dropped.
func (n *ScriptNode) resolveRestrictedDevices(ctx context.Context) ([]string, error) {
	if f := n.config.DeviceFilter; f != nil && (f.TenantSubtree != "" || len(f.TenantSubtreeIDs) > 0) {
		return nil, fmt.Errorf("device_filter selects a tenant subtree; a restricted script step runs only in the run tenant")
	}
	results, err := n.searchDevices(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(results))
	found := make(map[string]bool, len(results))
	for _, r := range results {
		if !deviceInRunTenant(n.tenantID, r.TenantID) {
			return nil, fmt.Errorf("device %q is not in the run tenant; refusing the whole step", r.ID)
		}
		if !found[r.ID] {
			found[r.ID] = true
			ids = append(ids, r.ID)
		}
	}
	for _, requested := range n.config.Devices {
		if !found[requested] {
			return nil, fmt.Errorf("device %q is not in the run tenant; refusing the whole step", requested)
		}
	}
	return ids, nil
}

// restrictedTimeout is the step's timeout, never above the approved script's own.
func (n *ScriptNode) restrictedTimeout(vs *script.VersionedScript) time.Duration {
	t := n.config.Timeout
	if limit := vs.Metadata.Timeout; limit > 0 && (t == 0 || t > limit) {
		return limit
	}
	return t
}

// restrictedQueuedExecution builds the queue entry for one device from the
// approver's decision: the pin is the decision's owner tenant, resolved version
// and approval hash, and the guard is the run's id and grant id. The shell comes
// from the approved script, never from the step.
func (n *ScriptNode) restrictedQueuedExecution(executionID string, vs *script.VersionedScript, d workflow.ScriptApprovalDecision, meta map[string]interface{}) *script.QueuedExecution {
	qe := &script.QueuedExecution{
		ExecutionID:      executionID,
		ScriptRef:        n.config.ScriptID,
		ScriptVersion:    d.Version,
		Shell:            vs.Metadata.Shell,
		Parameters:       n.config.Parameters,
		Timeout:          n.restrictedTimeout(vs),
		ExecutionContext: n.config.ExecutionContext,
		Metadata:         meta,
	}
	return qe.WithPin(d.OwnerTenant, d.Version, d.ApprovalHash).WithGuard(n.restricted.RunID, n.restricted.GrantID)
}

// queueRestricted queues one pinned, guarded command per device. A failure
// cancels what this step already queued, so a refused step leaves nothing behind.
// A device whose identical command is already queued is returned in deduped.
func (n *ScriptNode) queueRestricted(ctx context.Context, input workflow.NodeInput, vs *script.VersionedScript, d workflow.ScriptApprovalDecision, deviceIDs []string) (runs []restrictedRun, deduped []string, err error) {
	// The library is resolved from the run's tenant, never from workflow input.
	meta := map[string]interface{}{"tenant_id": n.tenantID}
	if runID, ok := input.Context["workflow_run_id"]; ok {
		meta["workflow_run_id"] = runID
	}
	if wfName, ok := input.Context["workflow_name"]; ok {
		meta["workflow_name"] = wfName
	}
	for _, deviceID := range deviceIDs {
		execution, startErr := n.monitor.StartExecution(ctx, n.config.ScriptID, n.Name, n.tenantID, []string{deviceID})
		if startErr != nil {
			n.cancelRestricted(runs)
			return nil, nil, fmt.Errorf("failed to start execution monitoring: %w", startErr)
		}
		queueErr := n.executionQueue.QueueExecution(deviceID, n.restrictedQueuedExecution(execution.ID, vs, d, meta))
		if queueErr == script.ErrDuplicateExecution {
			// Identical script+device+params already queued: drop the orphaned
			// monitor entry and do not wait on a run this step does not own.
			_ = n.monitor.CancelExecution(execution.ID) //nolint:errcheck // the entry was just created
			deduped = append(deduped, deviceID)
			continue
		}
		if queueErr != nil {
			_ = n.monitor.CancelExecution(execution.ID) //nolint:errcheck // the entry was just created
			n.cancelRestricted(runs)
			return nil, nil, fmt.Errorf("failed to queue execution for device %s: %w", deviceID, queueErr)
		}
		runs = append(runs, restrictedRun{deviceID: deviceID, executionID: execution.ID})
	}
	return runs, deduped, nil
}

// cancelRestricted cancels the step's commands that have not finished. A command
// the steward already holds cannot be recalled; it stays guarded by the run.
func (n *ScriptNode) cancelRestricted(runs []restrictedRun) {
	for _, r := range runs {
		_ = n.executionQueue.CancelExecution(r.deviceID, r.executionID) //nolint:errcheck // the entry may already be terminal
	}
}

func terminalStatus(s script.ExecutionStatus) bool {
	switch s {
	case script.StatusCompleted, script.StatusFailed, script.StatusTimeout, script.StatusCancelled:
		return true
	}
	return false
}

// collectRestricted reads each queued command's state from the execution monitor.
// done is true when every command is terminal; failed counts those not completed.
func (n *ScriptNode) collectRestricted(runs []restrictedRun) (results map[string]interface{}, done bool, failed int) {
	results = make(map[string]interface{}, len(runs))
	done = true
	for _, r := range runs {
		dev, err := n.monitor.GetDeviceExecution(r.executionID, r.deviceID)
		if err != nil {
			done = false
			continue
		}
		if !terminalStatus(dev.Status) {
			done = false
			continue
		}
		entry := map[string]interface{}{"status": string(dev.Status), "stdout": dev.Stdout, "stderr": dev.Stderr, "execution_id": r.executionID}
		if dev.Result != nil {
			entry["exit_code"] = dev.Result.ExitCode
		}
		if dev.Error != "" {
			entry["error"] = dev.Error
		}
		if dev.Status != script.StatusCompleted {
			failed++
		}
		results[r.deviceID] = entry
	}
	return results, done, failed
}

// awaitRestricted waits for every queued command to reach a terminal state, so
// the step's output carries each device's result for the steps after it. On a
// cancelled context or a timeout it cancels what is still queued and fails.
func (n *ScriptNode) awaitRestricted(ctx context.Context, runs []restrictedRun, deduped []string) (workflow.NodeOutput, error) {
	wait := n.resultWait
	if wait <= 0 {
		wait = defaultRestrictedResultWait + n.config.Timeout
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	ticker := time.NewTicker(restrictedResultPoll)
	defer ticker.Stop()

	for {
		results, done, failed := n.collectRestricted(runs)
		if done {
			return n.restrictedOutput(runs, deduped, results, failed)
		}
		select {
		case <-ctx.Done():
			n.cancelRestricted(runs)
			return refuseStep(fmt.Errorf("script step cancelled while waiting for results: %w", ctx.Err()))
		case <-timer.C:
			n.cancelRestricted(runs)
			return refuseStep(fmt.Errorf("timed out waiting for script results from %d device(s)", len(runs)))
		case <-ticker.C:
		}
	}
}

// restrictedOutput builds the step output. A command that did not complete fails
// the step with an error (the engine records a step as failed only on an error),
// while the per-device results stay in the output.
func (n *ScriptNode) restrictedOutput(runs []restrictedRun, deduped []string, results map[string]interface{}, failed int) (workflow.NodeOutput, error) {
	data := map[string]interface{}{
		"queued":  len(runs),
		"results": results,
	}
	if len(runs) > 0 {
		data["execution_id"] = runs[0].executionID
	}
	if len(deduped) > 0 {
		data["deduplicated"] = deduped
	}
	if failed > 0 {
		err := fmt.Errorf("script execution failed on %d of %d device(s)", failed, len(runs))
		return workflow.NodeOutput{Success: false, Data: data, Error: err.Error()}, err
	}
	return workflow.NodeOutput{Success: true, Data: data}, nil
}

// SetRestricted marks the node as the script step of a restricted automation
// execution bound to run. The engine sets it through the step executor, from the
// execution and never from step.Config.
func (n *ScriptNode) SetRestricted(run workflow.RestrictedRun) {
	n.restricted = &run
}

// SetApprover sets the approver a restricted node asks before queueing. A
// restricted node without one refuses to run.
func (n *ScriptNode) SetApprover(a workflow.ScriptApprover) {
	n.approver = a
}

// SetResultWaitTimeout overrides how long a restricted node waits for the queued
// results; zero keeps defaultRestrictedResultWait plus the script's own timeout.
func (n *ScriptNode) SetResultWaitTimeout(d time.Duration) {
	n.resultWait = d
}

// ScriptStepExecutor executes script workflow steps
type ScriptStepExecutor struct {
	repository       script.ScriptRepository
	monitor          *script.ExecutionMonitor
	keyManager       *script.EphemeralKeyManager
	dnaProvider      script.DNAProvider
	configProvider   script.ConfigProvider
	secretStore      interfaces.SecretStore
	fleetQuery       fleet.FleetQuery
	executionQueue   *script.ExecutionQueue
	executionTracker script.ExecutionTracker
	approver         workflow.ScriptApprover
	resultWait       time.Duration
}

// NewScriptStepExecutor creates a new script step executor
func NewScriptStepExecutor(repository script.ScriptRepository, monitor *script.ExecutionMonitor, keyManager *script.EphemeralKeyManager) *ScriptStepExecutor {
	return &ScriptStepExecutor{
		repository: repository,
		monitor:    monitor,
		keyManager: keyManager,
	}
}

// ExecuteStep implements workflow.StepExecutor interface. execution.TenantID —
// the engine-injected authenticated tenant, never execution.Variables or
// step.Config — is the only source of tenant scoping passed to the node
// (Issue #4338). It is routed through requireAuthorizedTenant, so an execution
// with no authenticated tenant fails the step closed here rather than reaching
// the fleet with an unscoped (all-tenant) query — the same guard the
// set_ha_role, config_scope_move and ring_health executors use.
func (e *ScriptStepExecutor) ExecuteStep(ctx context.Context, step workflow.Step, execution *workflow.WorkflowExecution) (workflow.StepResult, error) {
	// A restricted execution accepts only the literal library form; refuse the
	// raw config before parseScriptStepConfig drops the keys it does not know.
	if err := checkRestrictedStep(step, execution); err != nil {
		return workflow.StepResult{
			Status:    workflow.StatusFailed,
			StartTime: time.Now(),
			Error:     err.Error(),
		}, err
	}

	// Parse script config from step config
	config, err := parseScriptStepConfig(step.Config)
	if err != nil {
		return workflow.StepResult{
			Status:    workflow.StatusFailed,
			StartTime: time.Now(),
			Error:     fmt.Sprintf("failed to parse script step config: %v", err),
		}, err
	}

	// A device_filter may name a tenant; it must be the authenticated one.
	var configuredTenantID string
	if config.DeviceFilter != nil {
		configuredTenantID = config.DeviceFilter.TenantID
	}
	tenantID, err := requireAuthorizedTenant(execution, configuredTenantID)
	if err != nil {
		err = fmt.Errorf("script step %q: %w", step.Name, err)
		return workflow.StepResult{
			Status:    workflow.StatusFailed,
			StartTime: time.Now(),
			Error:     err.Error(),
		}, err
	}

	// Create script node
	node := NewScriptNode(step.Name, step.Name, config, e.repository, e.monitor, e.keyManager)
	node.SetDNAProvider(e.dnaProvider)
	node.SetConfigProvider(e.configProvider)
	node.SetSecretStore(e.secretStore)
	node.SetFleetQuery(e.fleetQuery)
	node.SetTenantID(tenantID)
	node.SetExecutionQueue(e.executionQueue)
	node.SetExecutionTracker(e.executionTracker)
	e.configureRestricted(node, execution)

	variables := execution.GetVariables()

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

	publishRestrictedResult(step, execution, output)

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

// checkRestrictedStep validates the raw step config of a restricted execution; it
// accepts any step of an unrestricted one.
func checkRestrictedStep(step workflow.Step, execution *workflow.WorkflowExecution) error {
	if execution.Restricted == nil {
		return nil
	}
	if err := validateRestrictedStepConfig(step.Config); err != nil {
		return fmt.Errorf("script step %q: %w", step.Name, err)
	}
	return nil
}

// configureRestricted marks the node of a restricted execution and gives it the
// approver. The restriction comes from the execution, never from step.Config.
func (e *ScriptStepExecutor) configureRestricted(node *ScriptNode, execution *workflow.WorkflowExecution) {
	if execution.Restricted == nil {
		return
	}
	node.SetRestricted(*execution.Restricted)
	node.SetApprover(e.approver)
	node.SetResultWaitTimeout(e.resultWait)
}

// publishRestrictedResult makes a restricted step's output a variable of the run,
// <step>_result, which the steps after it read.
func publishRestrictedResult(step workflow.Step, execution *workflow.WorkflowExecution, output workflow.NodeOutput) {
	if execution.Restricted != nil && output.Data != nil {
		execution.SetVariable(step.Name+"_result", output.Data)
	}
}

// SetApprover sets the approver propagated to the nodes of restricted
// executions. Without one a restricted script step fails closed.
func (e *ScriptStepExecutor) SetApprover(a workflow.ScriptApprover) {
	e.approver = a
}

// SetResultWaitTimeout overrides how long a restricted step waits for queued results.
func (e *ScriptStepExecutor) SetResultWaitTimeout(d time.Duration) {
	e.resultWait = d
}

// SetExecutionTracker sets the durable execution tracker propagated to created
// script nodes so inline and queue-path completions are both recorded.
func (e *ScriptStepExecutor) SetExecutionTracker(t script.ExecutionTracker) {
	e.executionTracker = t
}

// buildInlineTrackingRecord constructs an ExecutionRecord for the inline
// (non-queue) execution path. WorkflowRunID and WorkflowName are extracted
// from input.Context if present.
func buildInlineTrackingRecord(
	executionID, deviceID, scriptRef string,
	shell script.ShellType,
	status script.ExecutionStatus,
	result *script.ExecutionResult,
	input workflow.NodeInput,
) *script.ExecutionRecord {
	rec := &script.ExecutionRecord{
		ExecutionID: executionID,
		DeviceID:    deviceID,
		ScriptRef:   scriptRef,
		Shell:       string(shell),
		State:       string(status),
		CompletedAt: time.Now(),
	}

	if v, ok := input.Context["workflow_run_id"]; ok {
		rec.WorkflowRunID, _ = v.(string)
	}
	if v, ok := input.Context["workflow_name"]; ok {
		rec.WorkflowName, _ = v.(string)
	}

	if result != nil {
		rec.ExitCode = result.ExitCode
		rec.Stdout = result.Stdout
		rec.Stderr = result.Stderr
		rec.DurationMs = result.Duration.Milliseconds()
	}

	return rec
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
