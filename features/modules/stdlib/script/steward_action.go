// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script

import "time"

// Queue entry kinds. An empty Kind is a script execution.
const (
	QueueKindScript        = "script"
	QueueKindStewardAction = "steward_action"

	// StewardActionTTL bounds how long a steward action may wait for delivery.
	// It is a safety property, not a tuning value: a stale "stop service" must
	// not fire when a steward reconnects later (Issue #4625).
	StewardActionTTL = 2 * time.Minute
	// StewardActionTimeout bounds how long a dispatched steward action may go
	// unreported. It is also the per-device slot's lifetime, so a steward that
	// never reports does not block the device's other runs.
	StewardActionTimeout = 60 * time.Second
)

// StewardActionSpec is the structured action a steward_action entry carries:
// one verb from the steward's closed allowlist against a typed target.
type StewardActionSpec struct {
	Verb       string            `json:"verb"`
	TargetKind string            `json:"target_kind"`
	TargetName string            `json:"target_name"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

// IsStewardAction reports whether kind selects the steward-action path.
func IsStewardAction(kind string) bool { return kind == QueueKindStewardAction }

// ExpiredActionJob describes a steward-action job the controller closed without
// a steward result: ResultCode is "expired" (never delivered before its TTL;
// "expired, not run") or "no_result" (delivered but never reported; "sent, no
// result reported" — the action may have run). It is what the run store hands
// the dispatcher for audit when its sweep wins the compare-and-set.
type ExpiredActionJob struct {
	RunID       string
	JobID       string
	DeviceID    string
	ExecutionID string
	TenantID    string
	CreatedBy   string
	Action      StewardActionSpec
	ResultCode  string
	Detail      string
	At          time.Time
}

// NormalizeActionResultCode maps a steward-reported result code to the recorded
// set: the codes a steward reports are kept; anything else (including empty) is
// "failed", so a steward cannot write arbitrary text into the run record or the
// audit log.
func NormalizeActionResultCode(code string) string {
	switch code {
	case "ok", "self_protect", "process_changed", "unsupported", "failed", "not_found", "permission_denied":
		return code
	}
	return "failed"
}
