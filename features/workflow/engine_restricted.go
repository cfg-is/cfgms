// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

// Restricted automation validation (ADR-036 section 3).
//
// A grant's actions are reads and pre-approved scripts only, and approving a
// workflow hash must not widen what automation can do. A restricted execution
// (Engine.ExecuteRestrictedWorkflow) therefore checks the whole workflow against a
// positive step-type allowlist before the first step starts, and checks every
// step again as it is dispatched. A step type that is not classified here is
// denied.

// maxRestrictedDepth bounds the step-tree walk so a cyclic step graph built in
// memory cannot loop it.
const maxRestrictedDepth = 64

// restrictedStepPolicy classifies one step type for restricted automation.
type restrictedStepPolicy struct {
	allowed bool
	// reason is why a denied type is refused.
	reason string
}

func allowedInRestricted() restrictedStepPolicy { return restrictedStepPolicy{allowed: true} }

func deniedInRestricted(reason string) restrictedStepPolicy {
	return restrictedStepPolicy{reason: reason}
}

// restrictedStepPolicies classifies every step type the engine defines. The test
// enumerates the StepType constants and fails when one is missing here. A type
// absent from the map is denied (see classifyRestrictedStep).
var restrictedStepPolicies = map[StepType]restrictedStepPolicy{
	// Control flow only decides which nested steps run; the nested steps are
	// validated in turn.
	StepTypeSequential:  allowedInRestricted(),
	StepTypeParallel:    allowedInRestricted(),
	StepTypeConditional: allowedInRestricted(),
	StepTypeFor:         allowedInRestricted(),
	StepTypeWhile:       allowedInRestricted(),
	StepTypeForeach:     allowedInRestricted(),
	StepTypeSwitch:      allowedInRestricted(),
	StepTypeTry:         allowedInRestricted(),
	StepTypeBreak:       allowedInRestricted(),
	StepTypeContinue:    allowedInRestricted(),
	StepTypeDelay:       allowedInRestricted(),

	// notify is allowed only to a tenant-configured channel; see
	// checkRestrictedNotify.
	StepTypeNotify: allowedInRestricted(),

	// The library-script step runs a pre-approved, pinned script version under the
	// run's grant (story #5851).
	StepTypeScript: allowedInRestricted(),

	StepTypeTask:                  deniedInRestricted("a task step always calls a module write"),
	StepTypeHTTP:                  deniedInRestricted("an http step reaches an arbitrary endpoint"),
	StepTypeAPI:                   deniedInRestricted("an api step performs an arbitrary SaaS operation"),
	StepTypeWebhook:               deniedInRestricted("a webhook step reaches an arbitrary endpoint"),
	StepTypeApproval:              deniedInRestricted("an approval gate suspends the run for a human decision"),
	StepTypeWorkflow:              deniedInRestricted("a sub-workflow is not pinned by the approved workflow hash"),
	StepTypeComposite:             deniedInRestricted("a composite step runs composed sub-workflows"),
	StepTypeErrorWorkflow:         deniedInRestricted("an error_workflow step runs another workflow"),
	StepTypeQueryRingHealth:       deniedInRestricted("not on the restricted allowlist"),
	StepTypeSetHARole:             deniedInRestricted("set_ha_role writes device configuration"),
	StepTypeMoveResourceToCluster: deniedInRestricted("move_resource_to_cluster writes device configuration"),
	// transform runs through an injected executor the engine cannot inspect, so it
	// cannot be shown to be expression-only with no I/O or code execution.
	StepTypeTransform: deniedInRestricted("the transform executor is not shown to be free of I/O and code execution"),
	StepTypeBarrier:   deniedInRestricted("not on the restricted allowlist"),
	StepTypeSemaphore: deniedInRestricted("not on the restricted allowlist"),
	StepTypeLock:      deniedInRestricted("not on the restricted allowlist"),
	StepTypeWaitGroup: deniedInRestricted("not on the restricted allowlist"),
	StepTypeFanOut:    deniedInRestricted("a fan-out step runs a worker template outside the validated step tree"),
	StepTypeFanIn:     deniedInRestricted("not on the restricted allowlist"),
}

// classifyRestrictedStep returns the policy for a step type. An unclassified type
// is denied, so a step type added later is refused until it is classified.
func classifyRestrictedStep(t StepType) restrictedStepPolicy {
	if p, ok := restrictedStepPolicies[t]; ok {
		return p
	}
	return deniedInRestricted("step type is not classified for restricted automation")
}

// NotifyChannelResolver reports whether a notify destination is a channel the
// tenant has configured.
type NotifyChannelResolver interface {
	IsTenantChannel(ctx context.Context, tenantID, url string) (bool, error)
}

// WithNotifyChannels gives the engine the resolver a restricted execution uses to
// decide whether a notify step's destination is a tenant-configured channel.
// Without one a restricted execution refuses every notify step.
func WithNotifyChannels(resolver NotifyChannelResolver) EngineOption {
	return func(e *Engine) { e.notifyChannels = resolver }
}

// RestrictedViolation is one step a restricted execution refuses.
type RestrictedViolation struct {
	// Path is the step's position, as step names joined by "/".
	Path   string
	Type   StepType
	Reason string
}

// RestrictedWorkflowError is returned when a workflow fails restricted-automation
// validation. Nothing ran: validation completes before the first step starts.
type RestrictedWorkflowError struct {
	Violations []RestrictedViolation
}

func (e *RestrictedWorkflowError) Error() string {
	parts := make([]string, 0, len(e.Violations))
	for _, v := range e.Violations {
		parts = append(parts, fmt.Sprintf("step %q (type %q): %s", v.Path, v.Type, v.Reason))
	}
	return "workflow refused for restricted automation: " + strings.Join(parts, "; ")
}

// ErrRestrictedStepRefused is returned when a step is refused as it is dispatched
// in a restricted execution.
var ErrRestrictedStepRefused = errors.New("step refused for restricted automation")

// validateRestrictedWorkflow walks every step of workflow, including every nested
// body, and returns a *RestrictedWorkflowError naming each refused step.
func (e *Engine) validateRestrictedWorkflow(ctx context.Context, workflow Workflow) error {
	tenantID, _ := ctx.Value(ctxkeys.TenantID).(string)
	var violations []RestrictedViolation
	if len(workflow.ErrorWorkflows) > 0 {
		violations = append(violations, RestrictedViolation{
			Path:   workflow.Name,
			Reason: "workflow-level error_workflows run other workflows",
		})
	}
	e.walkRestrictedSteps(ctx, tenantID, workflow.Steps, "", 0, &violations)
	if len(violations) > 0 {
		return &RestrictedWorkflowError{Violations: violations}
	}
	return nil
}

func (e *Engine) walkRestrictedSteps(ctx context.Context, tenantID string, steps []Step, parent string, depth int, out *[]RestrictedViolation) {
	for _, step := range steps {
		path := step.Name
		if parent != "" {
			path = parent + "/" + step.Name
		}
		if depth >= maxRestrictedDepth {
			*out = append(*out, RestrictedViolation{Path: path, Type: step.Type, Reason: "steps are nested too deeply"})
			return
		}
		if err := e.checkRestrictedStep(ctx, step, tenantID); err != nil {
			*out = append(*out, RestrictedViolation{Path: path, Type: step.Type, Reason: restrictedReason(err)})
			continue
		}
		e.walkRestrictedSteps(ctx, tenantID, nestedSteps(step), path, depth+1, out)
	}
}

// checkRestrictedStep checks one step (not its nested steps) against the policy.
// It is the single decision the start-time walk and the per-step dispatch share.
func (e *Engine) checkRestrictedStep(ctx context.Context, step Step, tenantID string) error {
	policy := classifyRestrictedStep(step.Type)
	if !policy.allowed {
		return fmt.Errorf("%w: %s", ErrRestrictedStepRefused, policy.reason)
	}
	if step.Type == StepTypeNotify {
		return e.checkRestrictedNotify(ctx, step, tenantID)
	}
	return nil
}

// checkRestrictedNotify allows a notify step only when its destination is a
// literal URL that is a channel configured for the tenant. A destination built
// from inputs or variables (a template) is free-form and refused, as is any
// destination when no resolver is configured or the resolver fails.
func (e *Engine) checkRestrictedNotify(ctx context.Context, step Step, tenantID string) error {
	refuse := func(reason string) error {
		return fmt.Errorf("%w: %s", ErrRestrictedStepRefused, reason)
	}
	switch {
	case step.Notify == nil:
		return refuse("notify configuration is required")
	case strings.Contains(step.Notify.URL, "{{"):
		return refuse("notify destination must not be built from inputs or variables")
	case e.notifyChannels == nil:
		return refuse("no tenant notify channels are configured")
	case tenantID == "":
		return refuse("notify needs an authenticated tenant")
	}
	ok, err := e.notifyChannels.IsTenantChannel(ctx, tenantID, step.Notify.URL)
	if err != nil || !ok {
		return refuse("notify destination is not a tenant-configured channel")
	}
	return nil
}

// restrictedReason returns the reason text of a refusal from checkRestrictedStep.
func restrictedReason(err error) string {
	return strings.TrimPrefix(err.Error(), ErrRestrictedStepRefused.Error()+": ")
}
