// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// ApprovalDecision represents the outcome of a registration approval evaluation.
type ApprovalDecision string

const (
	// DecisionApprove grants full registration: certificates issued, fleet membership active.
	DecisionApprove ApprovalDecision = "approve"

	// DecisionReject denies the registration request.
	DecisionReject ApprovalDecision = "reject"

	// DecisionQuarantine grants certificates but restricts the steward to baseline
	// configuration only (no secrets, no scripts) until an administrator promotes it.
	DecisionQuarantine ApprovalDecision = "quarantine"

	// registrationWorkflowName is the well-known name for the registration approval workflow.
	// Operators replace this workflow to customise approval logic.
	registrationWorkflowName = "steward-registration-approval"

	// registrationDecisionVar is the workflow output variable that holds the approval decision.
	// Valid values: "approve", "reject", "quarantine". Absent or unrecognised → approve.
	registrationDecisionVar = "registration_decision"

	// registrationRejectionReasonVar is an optional workflow output variable for a human-readable
	// rejection reason. Only meaningful when the decision is "reject".
	registrationRejectionReasonVar = "registration_rejection_reason"
)

// RegistrationInput contains the data available to a registration approval hook.
type RegistrationInput struct {
	// Token is the validated registration token for the incoming steward.
	Token *registration.Token

	// SourceIP is the remote address of the registering steward.
	SourceIP string
}

// RegistrationApprovalHook evaluates whether a registration request should be approved.
//
// The hook is called after token validation and before certificate issuance.
// Returning an error is non-fatal: the registration handler logs the error and
// falls back to approve so that transient hook failures do not block registrations.
type RegistrationApprovalHook interface {
	Evaluate(ctx context.Context, input RegistrationInput) (decision ApprovalDecision, reason string, err error)
}

// DefaultApprovalHook approves every valid registration unconditionally.
// It is the out-of-box hook used when no workflow engine is available.
type DefaultApprovalHook struct{}

// Evaluate always returns DecisionApprove.
func (*DefaultApprovalHook) Evaluate(_ context.Context, _ RegistrationInput) (ApprovalDecision, string, error) {
	return DecisionApprove, "", nil
}

// WorkflowApprovalHook delegates registration approval to the workflow engine.
//
// On each call it looks up the workflow named "steward-registration-approval" in the
// configured store, scoped to the token's tenant.  If the workflow is not found it
// falls back to approve so that the absence of a workflow is equivalent to the
// default accept-all policy.
//
// Short-circuit: if the workflow's Variables map contains {"policy": "accept"} the
// engine is not invoked and the decision is approve immediately.  This matches the
// built-in default workflow shipped with CFGMS.
//
// For workflows that run steps, the decision is read from the "registration_decision"
// output variable after execution completes.  An optional "registration_rejection_reason"
// variable provides a human-readable reason for audit logging.
type WorkflowApprovalHook struct {
	engine      *workflow.Engine
	configStore cfgconfig.ConfigStore
	logger      logging.Logger
}

// NewWorkflowApprovalHook creates a WorkflowApprovalHook.
func NewWorkflowApprovalHook(
	engine *workflow.Engine,
	configStore cfgconfig.ConfigStore,
	logger logging.Logger,
) *WorkflowApprovalHook {
	return &WorkflowApprovalHook{
		engine:      engine,
		configStore: configStore,
		logger:      logger,
	}
}

// Evaluate runs the registration approval workflow and returns the decision.
// The workflow is looked up using the token's TenantID so that different tenants
// can configure different approval policies.
func (h *WorkflowApprovalHook) Evaluate(ctx context.Context, input RegistrationInput) (ApprovalDecision, string, error) {
	// Fail open on cancelled context to avoid blocking legitimate registrations.
	if err := ctx.Err(); err != nil {
		return DecisionApprove, "", ctx.Err()
	}

	store := workflow.NewWorkflowStore(h.configStore, input.Token.TenantID)
	vw, err := store.GetLatestWorkflow(ctx, registrationWorkflowName)
	if err != nil {
		// No workflow configured: accept-all default behaviour.
		h.logger.Info("No registration approval workflow configured, approving by default")
		return DecisionApprove, "", nil
	}

	// Short-circuit: built-in accept-all policy via Variables["policy"] = "accept".
	if policy, ok := vw.Variables["policy"].(string); ok && policy == "accept" {
		return DecisionApprove, "", nil
	}

	// Build input variables passed to the workflow execution.
	vars := map[string]interface{}{
		"tenant_id": input.Token.TenantID,
		"group":     input.Token.Group,
		"source_ip": input.SourceIP,
	}
	if input.Token.ExpiresAt != nil {
		vars["token_expiry"] = input.Token.ExpiresAt.UTC().Format(time.RFC3339)
	}

	exec, err := h.engine.ExecuteWorkflow(ctx, vw.Workflow, vars)
	if err != nil {
		return DecisionApprove, "", fmt.Errorf("registration approval workflow failed to start: %w", err)
	}

	// Wait for the workflow to complete or the request context to be cancelled.
	select {
	case <-exec.Done:
	case <-ctx.Done():
		exec.Cancel()
		return DecisionApprove, "", ctx.Err()
	}

	// Read the decision variable written by the workflow steps.
	decisionVal, ok := exec.GetVariable(registrationDecisionVar)
	if !ok {
		// Workflow completed without setting a decision: approve.
		return DecisionApprove, "", nil
	}

	decisionStr, ok := decisionVal.(string)
	if !ok {
		return DecisionApprove, "", nil
	}

	var reason string
	if reasonVal, ok := exec.GetVariable(registrationRejectionReasonVar); ok {
		if r, ok := reasonVal.(string); ok {
			reason = r
		}
	}

	switch ApprovalDecision(decisionStr) {
	case DecisionReject, DecisionQuarantine:
		return ApprovalDecision(decisionStr), reason, nil
	default:
		// "approve" and any unrecognised value → approve.
		return DecisionApprove, "", nil
	}
}

// defaultManualReviewTimeout is the default period after which a pending registration
// is automatically rejected if no operator action is taken.
const defaultManualReviewTimeout = 24 * time.Hour

// ManualReviewApprovalHook stores incoming registration requests in the durable
// PendingRegistrationStore and returns DecisionQuarantine so the steward is held
// in a restricted state until an operator approves or denies via the CLI (#1522-B).
//
// A background goroutine sweeps for expired records every minute and marks them
// as timed-out so operators can distinguish expired requests from active ones.
type ManualReviewApprovalHook struct {
	store   business.PendingRegistrationStore
	timeout time.Duration
	logger  logging.Logger
	cancel  context.CancelFunc
	done    chan struct{}
}

// NewManualReviewApprovalHook creates a ManualReviewApprovalHook and starts
// the background expiry goroutine. Call Stop() when the server shuts down.
func NewManualReviewApprovalHook(
	store business.PendingRegistrationStore,
	timeout time.Duration,
	logger logging.Logger,
) *ManualReviewApprovalHook {
	if timeout <= 0 {
		timeout = defaultManualReviewTimeout
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &ManualReviewApprovalHook{
		store:   store,
		timeout: timeout,
		logger:  logger,
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	go h.runExpiry(ctx)
	return h
}

// Stop shuts down the background expiry goroutine and waits for it to exit.
func (h *ManualReviewApprovalHook) Stop() {
	h.cancel()
	<-h.done
}

// Evaluate stores the registration request in the pending queue and returns
// DecisionQuarantine so the steward receives certificates but is restricted to
// baseline configuration until an operator acts.
//
// Manual-review mode fails closed: when the hook cannot record the request
// (cancelled context or store error) it still returns DecisionQuarantine with a
// nil error, so the steward is held in a restricted state rather than admitted.
// Returning a non-nil error here would cause the registration handler to default
// to approve, which would silently bypass the operator review this mode exists to
// enforce.
func (h *ManualReviewApprovalHook) Evaluate(ctx context.Context, input RegistrationInput) (ApprovalDecision, string, error) {
	if err := ctx.Err(); err != nil {
		// Fail closed: quarantine rather than admit when the context is cancelled.
		h.logger.Warn("ManualReviewApprovalHook: context cancelled before queueing, quarantining",
			"error", err,
			"tenant_id", input.Token.TenantID)
		return DecisionQuarantine, "", nil
	}

	now := time.Now().UTC()
	id := fmt.Sprintf("pr-%s", uuid.New().String())

	record := &business.PendingRegistrationData{
		ID:          id,
		StewardID:   "", // assigned after approval; left empty until operator acts (#1522-B)
		TenantID:    input.Token.TenantID,
		SourceIP:    input.SourceIP,
		TokenPrefix: logging.RedactedID(input.Token.Token),
		Status:      business.PendingRegistrationStatusPending,
		CreatedAt:   now,
		ExpiresAt:   now.Add(h.timeout),
	}

	if err := h.store.CreatePending(ctx, record); err != nil {
		// Fail closed: quarantine rather than admit when the request cannot be
		// recorded. A nil error is returned so the handler honours the quarantine
		// decision instead of defaulting to approve.
		h.logger.Warn("ManualReviewApprovalHook: failed to store pending registration, quarantining",
			"error", err,
			"tenant_id", input.Token.TenantID)
		return DecisionQuarantine, "", nil
	}

	h.logger.Info("Registration queued for manual review",
		"pending_id", id,
		"tenant_id", input.Token.TenantID,
		"source_ip", logging.SanitizeLogValue(input.SourceIP),
		"expires_at", record.ExpiresAt.Format(time.RFC3339))

	return DecisionQuarantine, "", nil
}

// runExpiry periodically marks pending registrations that have passed their
// expiry deadline as timed-out. This prevents the pending queue from growing
// indefinitely when operators do not act on incoming requests.
func (h *ManualReviewApprovalHook) runExpiry(ctx context.Context) {
	defer close(h.done)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.expireTimedOut(ctx)
		}
	}
}

// expireTimedOut finds all pending records whose expires_at has passed and
// transitions them to the timed-out status.
func (h *ManualReviewApprovalHook) expireTimedOut(ctx context.Context) {
	now := time.Now().UTC()
	pending := business.PendingRegistrationStatusPending
	records, err := h.store.ListPending(ctx, &business.PendingRegistrationFilter{
		Status:            &pending,
		ExpiresBeforeOrAt: &now,
	})
	if err != nil {
		if ctx.Err() == nil {
			h.logger.Warn("ManualReviewApprovalHook: failed to list expired pending registrations", "error", err)
		}
		return
	}
	for _, r := range records {
		if err := h.store.UpdatePendingStatus(ctx, r.ID, business.PendingRegistrationStatusTimedOut, "auto-rejected: review timeout exceeded"); err != nil {
			if ctx.Err() == nil {
				h.logger.Warn("ManualReviewApprovalHook: failed to expire pending registration",
					"pending_id", r.ID, "error", err)
			}
		}
	}
}
