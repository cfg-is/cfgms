// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bucketedReason pairs a classification bucket with a one-line rationale for why a
// mutating handler in features/controller/api lacks a HasLeadership() gate.
type bucketedReason struct {
	Bucket string
	Reason string
}

// The three valid bucket values for ungatedHandlerBaseline entries.
const (
	// bucketExcludedByEpicNonGoals covers handlers the epic's own Non-Goals explicitly exclude
	// from authority gating: RBAC, tenant management, web accounts, API keys, session lifecycle,
	// and presentation-state endpoints. These are ordinary admin CRUD or auth mechanics.
	bucketExcludedByEpicNonGoals = "excluded-by-epic-non-goals"

	// bucketGatedViaDeprecatedPrimitive covers handlers that ARE gated, but against the
	// deprecated raw Raft flag (IsLeader()) rather than the lease-backed HasLeadership().
	// Entries in this bucket are NOT ungated — they are gated on the wrong primitive and
	// must migrate to HasLeadership(). Each entry must name the tracking issue.
	bucketGatedViaDeprecatedPrimitive = "gated-via-deprecated-primitive"

	// bucketUnclassifiedPendingRiskReview covers handlers this decomposition did not
	// individually risk-review. Naming and bucketing them is in scope; deciding whether
	// each should be gated is a follow-up story's job. This bucket is an honest record
	// that the work is outstanding, not a judgment that these handlers are safe ungated.
	bucketUnclassifiedPendingRiskReview = "unclassified-pending-risk-review"
)

// ungatedHandlerBaseline is the ratchet that prevents new ungated mutating handlers from
// silently accumulating. Every entry is technical debt to retire, not a blessed exemption.
// Removing an entry (because that handler now calls HasLeadership()) needs no special approval.
//
// A handler that is NOT gated, NOT in this map, and NOT annotated with
// //architecture:allow-nogate on its declaration causes TestNoUngatedMutatingHandler to fail.
//
// Stories A/B/C/D/E/F/I of epic #3411 gated their handlers — those handler names must NOT
// appear here (AC5 of story #3547 verifies this). Entries here are the remainder that this
// decomposition did not address; see the epic for the prioritized follow-up plan.
var ungatedHandlerBaseline = map[string]bucketedReason{

	// ── gated-via-deprecated-primitive ──────────────────────────────────────────────────────
	// These handlers ARE gated, but on the deprecated raw Raft flag (IsLeader()), not on the
	// lease-backed HasLeadership(). Migration is tracked under #3389.

	"handleConfigPush": {
		Bucket: bucketGatedViaDeprecatedPrimitive,
		Reason: "checks s.pushLeaderStatus.IsLeader() not HasLeadership(); migration tracked under #3389",
	},

	// ── excluded-by-epic-non-goals: RBAC / subject-role CRUD ────────────────────────────────
	// Epic #3411 Non-Goals explicitly exclude RBAC management from authority gating.

	"handleCreateRole": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "RBAC role CRUD — excluded by epic Non-Goals",
	},
	"handleUpdateRole": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "RBAC role CRUD — excluded by epic Non-Goals",
	},
	"handleDeleteRole": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "RBAC role CRUD — excluded by epic Non-Goals",
	},
	"handleAssignSubjectRole": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "RBAC subject-role CRUD — excluded by epic Non-Goals",
	},
	"handleRevokeSubjectRole": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "RBAC subject-role CRUD — excluded by epic Non-Goals",
	},

	// ── excluded-by-epic-non-goals: tenant management CRUD ──────────────────────────────────
	// Epic #3411 Non-Goals explicitly exclude tenant management from authority gating.

	"handleCreateTenant": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "tenant management CRUD — excluded by epic Non-Goals",
	},
	"handleUpdateTenant": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "tenant management CRUD — excluded by epic Non-Goals",
	},
	"handleSuspendTenant": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "tenant lifecycle management — excluded by epic Non-Goals",
	},
	"handleRestoreTenant": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "tenant lifecycle management — excluded by epic Non-Goals",
	},
	"handleConfigSourceTest": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "tenant config-source test operation — excluded by epic Non-Goals",
	},
	"handleRequestTenantDeletion": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "tenant deletion workflow — excluded by epic Non-Goals",
	},
	"handleCancelTenantDeletion": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "tenant deletion workflow — excluded by epic Non-Goals",
	},
	"handleApproveTenantDeletion": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "tenant deletion workflow — excluded by epic Non-Goals",
	},
	"handleCreateTenantCrossingGrant": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "tenant crossing grant CRUD — excluded by epic Non-Goals",
	},
	"handleTenantBreakGlass": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "tenant break-glass crossing — excluded by epic Non-Goals",
	},
	"handleSetRefreshPolicy": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "tenant refresh-policy management — excluded by epic Non-Goals",
	},
	"handleSetAssurancePolicy": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "tenant assurance-policy management — excluded by epic Non-Goals",
	},
	"handlePutTenantRebootWindow": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "tenant-level reboot-window override — excluded by epic Non-Goals",
	},

	// ── excluded-by-epic-non-goals: web account CRUD ────────────────────────────────────────
	// Epic #3411 Non-Goals explicitly exclude web account management from authority gating.

	"handleCreateWebAccount": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "web account CRUD — excluded by epic Non-Goals",
	},
	"handleUpdateWebAccount": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "web account CRUD — excluded by epic Non-Goals",
	},
	"handleDeleteWebAccount": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "web account CRUD — excluded by epic Non-Goals",
	},
	"handleRevokeEnrollmentLink": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "web account enrollment management — excluded by epic Non-Goals",
	},

	// ── excluded-by-epic-non-goals: API key CRUD ────────────────────────────────────────────
	// Epic #3411 Non-Goals explicitly exclude API key management from authority gating.

	"handleCreateAPIKey": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "API key CRUD — excluded by epic Non-Goals",
	},
	"handleDeleteAPIKey": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "API key CRUD — excluded by epic Non-Goals",
	},

	// ── excluded-by-epic-non-goals: session credential lifecycle ────────────────────────────
	// Short-lived bearer credential lifecycle, analogous to API key CRUD (excluded by Non-Goals).

	"handleSessionCreate": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "session bearer-credential lifecycle, analogous to API key CRUD — excluded by epic Non-Goals",
	},
	"handleSessionRevoke": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "session bearer-credential lifecycle, analogous to API key CRUD — excluded by epic Non-Goals",
	},

	// ── excluded-by-epic-non-goals: presentation state ──────────────────────────────────────
	// Epic Non-Goals name presentation-state endpoints as explicitly excluded.

	"handleSetStewardVisibility": {
		Bucket: bucketExcludedByEpicNonGoals,
		Reason: "presentation-state flag (PATCH) — excluded by epic Non-Goals (Implementation Notes name this explicitly)",
	},

	// ── unclassified-pending-risk-review: passkey / web-session auth mechanics ───────────────
	// Authentication flow handlers; structurally different from fleet-mutating admin actions.
	// Risk-review of whether these need HasLeadership() is a follow-up story.

	"handleWebLogout": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "web session logout — passkey/session auth mechanic, not reviewed for fleet risk",
	},
	"handlePasskeyLoginBegin": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "passkey authentication flow — auth mechanic, not reviewed for fleet risk",
	},
	"handlePasskeyLoginFinish": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "passkey authentication flow — auth mechanic, not reviewed for fleet risk",
	},
	"handlePasskeyEnrollBegin": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "first-passkey enrollment flow — auth mechanic, not reviewed for fleet risk",
	},
	"handlePasskeyEnrollFinish": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "first-passkey enrollment flow — auth mechanic, not reviewed for fleet risk",
	},

	// ── unclassified-pending-risk-review: webauthn mechanics ────────────────────────────────
	// WebAuthn credential registration, presence assertion, and step-up elevation.
	// Risk-review of whether these need HasLeadership() is a follow-up story.

	"handleWebAuthnRegisterBegin": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "webauthn credential registration — auth mechanic, not reviewed for fleet risk",
	},
	"handleWebAuthnRegisterFinish": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "webauthn credential registration — auth mechanic, not reviewed for fleet risk",
	},
	"handleWebAuthnRevokeCredential": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "webauthn credential revocation — auth mechanic, not reviewed for fleet risk",
	},
	"handlePresenceBegin": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "webauthn user-presence assertion — auth mechanic, not reviewed for fleet risk",
	},
	"handlePresenceFinish": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "webauthn user-presence assertion — auth mechanic, not reviewed for fleet risk",
	},
	"handleStepUpBegin": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "webauthn step-up elevation — auth mechanic, not reviewed for fleet risk",
	},
	"handleStepUpFinish": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "webauthn step-up elevation — auth mechanic, not reviewed for fleet risk",
	},

	// ── unclassified-pending-risk-review: registration / refresh management ──────────────────
	// Registration and refresh lifecycle management. The approve variants (handleApproveRegistration
	// etc.) are HasLeadership-gated; these denial and device-side variants are not — the gap
	// should be reviewed in a follow-up story.

	"handleDenyRegistration": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "deny pending registration; approve variants are HasLeadership-gated but deny is not — gap needs review",
	},
	"handleApproveRefresh": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "approve pending steward refresh; paired reject is also ungated — gap needs review",
	},
	"handleRejectRefresh": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "reject pending steward refresh — gap needs review alongside handleApproveRefresh",
	},
	"handleRefreshChallenge": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "steward device-key proof-of-possession challenge (device-facing, not admin API) — not reviewed for fleet risk",
	},
	"handleRefreshComplete": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "steward device-key proof-of-possession completion (device-facing, not admin API) — not reviewed for fleet risk",
	},

	// ── unclassified-pending-risk-review: IP trust management ───────────────────────────────

	"handleAddIPTrust": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "IP trust auto-approval management — not reviewed for fleet risk",
	},
	"handleRevokeIPTrust": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "IP trust auto-approval management — not reviewed for fleet risk",
	},

	// ── unclassified-pending-risk-review: steward auth refresh ──────────────────────────────

	"handleStewardAuthRefresh": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "steward registration/auth state refresh — not reviewed for fleet risk",
	},

	// ── unclassified-pending-risk-review: alerts ────────────────────────────────────────────

	"handleAcknowledgeAlert": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "alert state management — not reviewed for fleet risk",
	},
	"handleSilenceAlert": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "alert state management — not reviewed for fleet risk",
	},

	// ── unclassified-pending-risk-review: entity graph ──────────────────────────────────────

	"handleAssertEdge": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "operator edge assertion in entity graph — not reviewed for fleet risk",
	},

	// ── unclassified-pending-risk-review: fleet selector ────────────────────────────────────

	"handleResolveSelector": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "fleet selector resolution (POST for query-body semantics, effectively read-only) — not reviewed for fleet risk",
	},

	// ── unclassified-pending-risk-review: role config ────────────────────────────────────────
	// Distinct from RBAC roles (handleCreateRole etc. excluded by Non-Goals); role config is
	// the cfg-driven role definition, not the RBAC assignment layer.

	"handleCreateRoleConfig": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "role config CRUD (cfg-driven role definition, distinct from RBAC assignment) — not reviewed for fleet risk",
	},
	"handleDeleteRoleConfig": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "role config CRUD (cfg-driven role definition, distinct from RBAC assignment) — not reviewed for fleet risk",
	},

	// ── unclassified-pending-risk-review: steward tag / reboot-window / script-retry ─────────

	"handleAddStewardTags": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "steward tag management — not reviewed for fleet risk",
	},
	"handleDeleteStewardTags": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "steward tag management — not reviewed for fleet risk",
	},
	"handlePutStewardRebootWindow": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "device-level reboot-window override — not reviewed for fleet risk",
	},
	"handlePostScriptRetry": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "script execution retry — not reviewed for fleet risk",
	},
	"handleValidateConfig": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "config validation (POST for request-body; non-mutating by intent, but registered as POST) — not reviewed for fleet risk",
	},

	// ── unclassified-pending-risk-review: script privilege escalation ───────────────────────

	"handlePutScriptPrivilege": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "script privilege level management — not reviewed for fleet risk",
	},

	// ── unclassified-pending-risk-review: batch-job / run-script / command dispatch ──────────

	"handleCreateJob": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "batch job dispatch — Story H found batch/run-script path lacks term-stamping; tracked under #3436 for steward-side rejection",
	},
	"handlePostRunScript": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "run-script dispatch — Story H found batch/run-script path lacks term-stamping; tracked under #3436 for steward-side rejection",
	},
	"handlePostRunCommand": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "run-command dispatch — Story H found batch/run-script path lacks term-stamping; tracked under #3436 for steward-side rejection",
	},
	"handleDeleteRun": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "run cancellation/deletion — not reviewed for fleet risk",
	},

	// ── unclassified-pending-risk-review: steward upgrade dispatch / rollback ───────────────

	"handleDispatchUpgrade": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "steward upgrade dispatch — not reviewed for fleet risk",
	},
	"handleUpgradeRollback": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "steward upgrade rollback — not reviewed for fleet risk",
	},

	// ── unclassified-pending-risk-review: WorkflowHandler (receiver: *WorkflowHandler) ──────
	// These handlers are methods on WorkflowHandler, not Server. The detection walk is
	// receiver-agnostic; they appear here because they are not HasLeadership-gated.

	"handleCreateWorkflow": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "workflow CRUD (receiver: *WorkflowHandler) — not reviewed for fleet risk",
	},
	"handleUpdateWorkflow": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "workflow CRUD (receiver: *WorkflowHandler) — not reviewed for fleet risk",
	},
	"handleDeleteWorkflow": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "workflow CRUD (receiver: *WorkflowHandler) — not reviewed for fleet risk",
	},
	"handleExecuteWorkflow": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "workflow execution dispatch (receiver: *WorkflowHandler) — not reviewed for fleet risk",
	},
	"handleCancelExecution": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "workflow execution cancellation (receiver: *WorkflowHandler) — not reviewed for fleet risk",
	},

	// ── unclassified-pending-risk-review: RollbackHandler (receiver: *RollbackHandler) ──────
	// These are exported methods on RollbackHandler with no "handle" prefix — the detection
	// walk is receiver-agnostic and name-prefix-agnostic, so they are visible here.

	"PreviewRollback": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "config rollback preview (receiver: *RollbackHandler, exported method) — not reviewed for fleet risk",
	},
	"ExecuteRollback": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "config rollback execution (receiver: *RollbackHandler, exported method) — not reviewed for fleet risk",
	},
	"CancelRollback": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "config rollback cancellation (receiver: *RollbackHandler, exported method) — not reviewed for fleet risk",
	},

	// ── unclassified-pending-risk-review: internal Raft message handler ──────────────────────
	// handleRaftMessage is registered on the mTLS-only internalRouter (private Raft transport
	// listener), not the admin API router. It is structurally different from admin API actions:
	// it is the consensus wire protocol itself, protected by mutual TLS peer-cert verification
	// at the transport layer, not by HasLeadership(). Bucketed here to make it visible rather
	// than silently absent from the ratchet.

	"handleRaftMessage": {
		Bucket: bucketUnclassifiedPendingRiskReview,
		Reason: "internal Raft consensus wire-protocol handler on the mTLS-only internalRouter — not an admin API action; transport-layer mTLS provides its security boundary",
	},
}

// mutatingHTTPVerbs is the set of HTTP methods that indicate a state-mutating route.
var mutatingHTTPVerbs = map[string]bool{
	"POST": true, "PUT": true, "DELETE": true, "PATCH": true,
}

// apiHandlerScanResult holds the results of scanning features/controller/api for
// mutating route registrations and handler gate/annotation status.
type apiHandlerScanResult struct {
	// mutatingHandlers is the sorted list of handler method names found in route
	// registrations with a mutating HTTP verb (POST/PUT/DELETE/PATCH).
	mutatingHandlers []string

	// gatedHandlers maps handler method names to true when the method's own body
	// contains a HasLeadership() selector call on any receiver.
	gatedHandlers map[string]bool

	// annotatedHandlers maps handler method names to true when the method's
	// declaration carries an //architecture:allow-nogate comment.
	annotatedHandlers map[string]bool
}

// TestNoUngatedMutatingHandler is the regression guard for authority gating in
// features/controller/api (Story #3547, epic #3411). Every mutating handler
// (POST/PUT/DELETE/PATCH) registered in this package must be either:
//
//  1. Gated — its own body contains a call to .HasLeadership() on any receiver.
//  2. Baselined — its name appears in ungatedHandlerBaseline with a bucket and reason.
//  3. Annotated — its function declaration carries //architecture:allow-nogate.
//
// A handler in none of the three states causes this test to fail, preventing the
// authority-gate gap this epic closed from silently reopening.
//
// Coverage limit: the gate check is shallow — it looks for HasLeadership() in the
// handler's own function body only, not in helpers called from there. A handler
// that delegates to a gated helper without a direct call should carry an
// //architecture:allow-nogate annotation explaining the delegation chain.
//
// Detection limit: anonymous handler functions (e.g. the git-sync webhook
// registered as an inline func literal in server.go) are not detected by this
// walk, which requires a <receiver>.<Method> reference. Files compiled only
// under the cfgms_test_endpoints build tag are also excluded from the scan.
func TestNoUngatedMutatingHandler(t *testing.T) {
	repoRoot := findControllerRepoRoot(t)
	apiDir := filepath.Join(repoRoot, "features", "controller", "api")

	result := scanAPIPackage(t, apiDir)

	// AC5: handlers gated by stories A/B/C/D/E/F/I must NOT appear in the baseline.
	// If they do, the ratchet has been gamed — the gating landed but the baseline
	// entry was not removed, making the epic's work invisible to future auditors.
	gatedByEpicStories := []string{
		"handleClusterNodeDrain",        // Story A
		"handleClusterNodeDecommission", // Story A
		"handleApproveModuleBundle",     // Story B
		"handleRejectModuleBundle",      // Story B
		"handleStartRollout",            // Story C
		"handleHaltRollout",             // Story C
		"handleProvisionCertificate",    // Story D
		"handleRotateSigningCert",       // Story D
		"handleRevokeCertificate",       // Story D
		"handleUploadInstallerArtifact", // Story E
		"handleDeleteInstallerArtifact", // Story E
		"handlePublishStewardBinary",    // Story F
		"handleDecommissionSteward",     // Story I
		"handleMoveSteward",             // Story I
		"handleUpdateStewardConfig",     // Story I
		"handleDeleteStewardConfig",     // Story I
	}
	for _, name := range gatedByEpicStories {
		_, inBaseline := ungatedHandlerBaseline[name]
		assert.False(t, inBaseline,
			"handler gated by stories A/B/C/D/E/F/I of epic #3411 must not appear in the baseline (AC5): %s", name)
	}

	// AC6: every baseline entry carries a valid bucket and a non-empty reason.
	// handleConfigPush must name #3389 in its reason.
	validBuckets := map[string]bool{
		bucketExcludedByEpicNonGoals:        true,
		bucketGatedViaDeprecatedPrimitive:   true,
		bucketUnclassifiedPendingRiskReview: true,
	}
	for name, entry := range ungatedHandlerBaseline {
		assert.True(t, validBuckets[entry.Bucket],
			"baseline entry %q has invalid bucket %q", name, entry.Bucket)
		assert.NotEmpty(t, entry.Reason,
			"baseline entry %q must have a non-empty reason", name)
	}
	if entry, ok := ungatedHandlerBaseline["handleConfigPush"]; ok {
		assert.Contains(t, entry.Reason, "#3389",
			"handleConfigPush baseline entry must name issue #3389 (the migration tracking issue)")
	}

	// Main check: detect violations.
	var violations []string
	for _, name := range result.mutatingHandlers {
		if result.gatedHandlers[name] {
			continue // gated by HasLeadership()
		}
		if _, inBaseline := ungatedHandlerBaseline[name]; inBaseline {
			continue // covered by the ratchet baseline
		}
		if result.annotatedHandlers[name] {
			continue // carries //architecture:allow-nogate
		}
		violations = append(violations, name)
	}
	sort.Strings(violations)

	assert.Empty(t, violations,
		"new mutating handler(s) with no HasLeadership() gate, no baseline entry, and no "+
			"//architecture:allow-nogate annotation — add a HasLeadership() gate, or add an "+
			"entry to ungatedHandlerBaseline with a bucket and one-line reason: %v", violations)
}

// TestDetectionFiresOnViolation (AC2) proves the rule fires on a handler that lacks
// HasLeadership() and is not annotated. It also verifies that gated handlers are
// correctly recognised as gated, and that the baseline is what prevents handleConfigPush
// from being flagged as a violation.
func TestDetectionFiresOnViolation(t *testing.T) {
	repoRoot := findControllerRepoRoot(t)
	apiDir := filepath.Join(repoRoot, "features", "controller", "api")
	result := scanAPIPackage(t, apiDir)

	// handleConfigPush must be detected as a mutating handler.
	assert.Contains(t, result.mutatingHandlers, "handleConfigPush",
		"rule must detect handleConfigPush as a mutating handler (it is registered with POST)")

	// handleConfigPush must NOT be detected as HasLeadership-gated.
	// It uses the deprecated IsLeader() primitive — the rule correctly distinguishes these.
	assert.False(t, result.gatedHandlers["handleConfigPush"],
		"handleConfigPush must not be detected as HasLeadership-gated (it uses the deprecated IsLeader() primitive)")

	// Without the baseline, handleConfigPush would be a violation.
	// The baseline entry is the only thing preventing the rule from firing here.
	_, inBaseline := ungatedHandlerBaseline["handleConfigPush"]
	require.True(t, inBaseline,
		"handleConfigPush must be in the baseline; without it the rule would fire on this handler, proving the rule works")

	// Gated handlers must be detected as gated — the rule correctly passes them.
	assert.True(t, result.gatedHandlers["handleClusterNodeDrain"],
		"handleClusterNodeDrain must be detected as HasLeadership-gated (Story A)")
	assert.True(t, result.gatedHandlers["handleProvisionCertificate"],
		"handleProvisionCertificate must be detected as HasLeadership-gated (Story D)")
	assert.True(t, result.gatedHandlers["handlePublishStewardBinary"],
		"handlePublishStewardBinary must be detected as HasLeadership-gated (Story F)")
}

// TestDetectsInlineServerGoHandler (AC3) proves the walk covers the whole package,
// not only routes_*.go files. Handlers registered inline in server.go (around its
// setupRouter function) must be detected.
func TestDetectsInlineServerGoHandler(t *testing.T) {
	repoRoot := findControllerRepoRoot(t)
	apiDir := filepath.Join(repoRoot, "features", "controller", "api")
	result := scanAPIPackage(t, apiDir)

	// handleAddIPTrust and handleRevokeIPTrust are registered directly in server.go
	// (not in any routes_*.go file). If the walk were scoped to routes_*.go only,
	// these would be silently invisible and could be mutated without a gate check.
	assert.Contains(t, result.mutatingHandlers, "handleAddIPTrust",
		"detection must find handleAddIPTrust: registered inline in server.go, not in any routes_*.go")
	assert.Contains(t, result.mutatingHandlers, "handleRevokeIPTrust",
		"detection must find handleRevokeIPTrust: registered inline in server.go, not in any routes_*.go")

	// These are in the baseline (not gated by HasLeadership) — the baseline is what
	// prevents the rule from flagging them, proving they are correctly detected.
	_, addIPInBaseline := ungatedHandlerBaseline["handleAddIPTrust"]
	_, revokeIPInBaseline := ungatedHandlerBaseline["handleRevokeIPTrust"]
	assert.True(t, addIPInBaseline,
		"handleAddIPTrust must be in the baseline (detected as ungated, baseline prevents violation)")
	assert.True(t, revokeIPInBaseline,
		"handleRevokeIPTrust must be in the baseline (detected as ungated, baseline prevents violation)")
}

// TestDetectsNonServerReceiverHandler (AC4) proves the walk is receiver-agnostic
// and not name-pattern-scoped. Handlers on *WorkflowHandler and *RollbackHandler
// — receivers other than *Server — and exported method names with no "handle" prefix
// (PreviewRollback, ExecuteRollback, CancelRollback) must be detected.
func TestDetectsNonServerReceiverHandler(t *testing.T) {
	repoRoot := findControllerRepoRoot(t)
	apiDir := filepath.Join(repoRoot, "features", "controller", "api")
	result := scanAPIPackage(t, apiDir)

	// RollbackHandler: exported method names, no "handle" prefix, receiver *RollbackHandler.
	// A walk scoped to (s *Server) or names matching "handle*" would silently miss these.
	assert.Contains(t, result.mutatingHandlers, "PreviewRollback",
		"detection must find PreviewRollback: exported method on *RollbackHandler, no 'handle' prefix")
	assert.Contains(t, result.mutatingHandlers, "ExecuteRollback",
		"detection must find ExecuteRollback: exported method on *RollbackHandler, no 'handle' prefix")
	assert.Contains(t, result.mutatingHandlers, "CancelRollback",
		"detection must find CancelRollback: exported method on *RollbackHandler, no 'handle' prefix")

	// WorkflowHandler: methods on *WorkflowHandler, not *Server.
	assert.Contains(t, result.mutatingHandlers, "handleCreateWorkflow",
		"detection must find handleCreateWorkflow: method on *WorkflowHandler, not *Server")
	assert.Contains(t, result.mutatingHandlers, "handleDeleteWorkflow",
		"detection must find handleDeleteWorkflow: method on *WorkflowHandler, not *Server")
	assert.Contains(t, result.mutatingHandlers, "handleExecuteWorkflow",
		"detection must find handleExecuteWorkflow: method on *WorkflowHandler, not *Server")

	// These are in the baseline (not HasLeadership-gated) — the baseline prevents a
	// violation, proving the detection found them and they were checked against it.
	for _, name := range []string{"PreviewRollback", "ExecuteRollback", "CancelRollback",
		"handleCreateWorkflow", "handleDeleteWorkflow", "handleExecuteWorkflow"} {
		_, inBaseline := ungatedHandlerBaseline[name]
		assert.True(t, inBaseline,
			"handler on non-Server receiver must be in baseline (detected as ungated, baseline prevents violation): %s", name)
	}
}

// scanAPIPackage walks all non-test, non-test-build-tagged .go files in apiDir
// and returns the detection results needed by the architecture rule.
func scanAPIPackage(t *testing.T, apiDir string) apiHandlerScanResult {
	t.Helper()

	gated := make(map[string]bool)
	annotated := make(map[string]bool)
	mutatingSet := make(map[string]bool)

	err := filepath.WalkDir(apiDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Stay in the top-level api/ directory; do not descend into subdirectories.
			if path != apiDir {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Exclude test files.
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		content, readErr := os.ReadFile(path) // #nosec G304 -- repo scan reads controlled source files
		if readErr != nil {
			return nil
		}

		// Exclude files compiled only with the cfgms_test_endpoints build tag.
		// These are test scaffolding (test_endpoints_enabled.go, handlers_test_admin.go),
		// not production API surface.
		checkLen := min(len(content), 300)
		if strings.Contains(string(content[:checkLen]), "cfgms_test_endpoints") {
			return nil
		}

		fset := token.NewFileSet()
		f, parseErr := parser.ParseFile(fset, path, content, parser.ParseComments)
		if parseErr != nil {
			return nil
		}

		collectHandlerMethodInfo(f, gated, annotated)
		collectMutatingRouteHandlers(f, mutatingSet)
		return nil
	})
	require.NoError(t, err, "walking api directory")

	handlers := make([]string, 0, len(mutatingSet))
	for name := range mutatingSet {
		handlers = append(handlers, name)
	}
	sort.Strings(handlers)

	return apiHandlerScanResult{
		mutatingHandlers:  handlers,
		gatedHandlers:     gated,
		annotatedHandlers: annotated,
	}
}

// collectHandlerMethodInfo walks the file AST and records, for each function declaration:
//   - whether the function body contains a .HasLeadership() selector call (gated)
//   - whether the function declaration carries an //architecture:allow-nogate comment (annotated)
func collectHandlerMethodInfo(f *ast.File, gated, annotated map[string]bool) {
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}
		if fn.Body == nil {
			return true
		}
		name := fn.Name.Name

		// Check for a HasLeadership() selector call anywhere in the function body.
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			sel, isSel := inner.(*ast.SelectorExpr)
			if isSel && sel.Sel.Name == "HasLeadership" {
				gated[name] = true
			}
			return true
		})

		// Check for //architecture:allow-nogate in the function's doc comment block.
		if fn.Doc != nil {
			for _, c := range fn.Doc.List {
				if strings.Contains(c.Text, "//architecture:allow-nogate") {
					annotated[name] = true
				}
			}
		}

		return true
	})
}

// collectMutatingRouteHandlers walks the file AST and, for each route registration
// with a mutating HTTP verb (POST/PUT/DELETE/PATCH), extracts the handler method name
// and adds it to the handlers set.
//
// Detected patterns:
//
//	router.Handle(path, handler).Methods("POST")
//	router.HandleFunc(path, handler).Methods("POST")
//
// where handler may be wrapped in zero or more layers of:
//
//	http.HandlerFunc(s.method)
//	requirePermission(...)(http.HandlerFunc(s.method))
//	wrap("action", h.method)
//	authDefense.Middleware(http.HandlerFunc(s.method))
//
// Anonymous handler functions (func literals) are not detected — this is an explicit
// coverage limit documented in TestNoUngatedMutatingHandler's doc comment.
func collectMutatingRouteHandlers(f *ast.File, handlers map[string]bool) {
	ast.Inspect(f, func(n ast.Node) bool {
		outer, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Check for a .Methods(...) call with at least one mutating verb.
		methodsSel, isSel := outer.Fun.(*ast.SelectorExpr)
		if !isSel || methodsSel.Sel.Name != "Methods" {
			return true
		}

		hasMutating := false
		for _, arg := range outer.Args {
			lit, isLit := arg.(*ast.BasicLit)
			if !isLit {
				continue
			}
			verb := strings.Trim(lit.Value, `"`)
			if mutatingHTTPVerbs[verb] {
				hasMutating = true
				break
			}
		}
		if !hasMutating {
			return true
		}

		// The X of the Methods selector is the Handle or HandleFunc call.
		inner, isCall := methodsSel.X.(*ast.CallExpr)
		if !isCall {
			return true
		}
		innerSel, isInnerSel := inner.Fun.(*ast.SelectorExpr)
		if !isInnerSel {
			return true
		}
		if innerSel.Sel.Name != "Handle" && innerSel.Sel.Name != "HandleFunc" {
			return true
		}

		// The handler is the second argument (index 1).
		if len(inner.Args) < 2 {
			return true
		}
		handlerArg := inner.Args[1]

		if name, found := extractHandlerMethodName(handlerArg); found {
			handlers[name] = true
		}
		return true
	})
}

// extractHandlerMethodName recursively unwraps an expression to find the innermost
// <receiver>.<Method> reference where receiver is a simple identifier. It handles:
//
//   - SelectorExpr{Ident, Method} — direct: s.handler or h.PreviewRollback
//   - CallExpr with args — wrapped: http.HandlerFunc(s.h), wrap("action", h.h),
//     requirePermission(...)(http.HandlerFunc(s.h)), authMiddleware(http.HandlerFunc(s.h))
//
// Anonymous handler functions (FuncLit) and any other expression type return ("", false).
func extractHandlerMethodName(arg ast.Expr) (string, bool) {
	switch v := arg.(type) {
	case *ast.SelectorExpr:
		// Direct method reference: s.handler or h.PreviewRollback.
		if _, isIdent := v.X.(*ast.Ident); isIdent {
			return v.Sel.Name, true
		}
	case *ast.CallExpr:
		// Try each argument recursively; return the first handler-like match found.
		// This handles all wrapping layers without knowing their names or shapes.
		for _, a := range v.Args {
			if name, ok := extractHandlerMethodName(a); ok {
				return name, ok
			}
		}
	}
	return "", false
}

// findControllerRepoRoot walks up from the working directory to find the repository
// root (presence of go.mod). Named to avoid conflicting with findRepoRoot in pkg/cert.
func findControllerRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod not found)")
		}
		dir = parent
	}
}
