// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package jit

import "context"

// EscalationTypeDefault is the key used by SendEscalationNotification when querying the registry.
// Operators configure recipients for this key to control who receives escalation alerts.
const EscalationTypeDefault = "escalation"

// ApproverRegistry resolves the set of recipients for a given escalation type.
// Implementations can be backed by controller config, a database, or any other
// operator-controlled source so that escalation targets are configurable without
// code modification.
type ApproverRegistry interface {
	GetApprovers(ctx context.Context, escalationType string) ([]string, error)
}

// StaticApproverRegistry is an ApproverRegistry backed by a static map of
// escalation type → recipient slice. It is the default implementation for
// controller-config-driven deployments.
//
// The empty-string key "" acts as a fallback for escalation types not
// explicitly mapped.
type StaticApproverRegistry struct {
	approvers map[string][]string
}

// NewStaticApproverRegistry creates a StaticApproverRegistry from the provided map.
// Use an empty-string key "" as a catch-all for types not explicitly listed.
func NewStaticApproverRegistry(approvers map[string][]string) *StaticApproverRegistry {
	return &StaticApproverRegistry{approvers: approvers}
}

// GetApprovers returns the recipient list for escalationType, falling back to
// the "" key if the type is not explicitly mapped. Returns nil (no error) when
// neither the type nor the fallback is present.
func (r *StaticApproverRegistry) GetApprovers(_ context.Context, escalationType string) ([]string, error) {
	if recipients, ok := r.approvers[escalationType]; ok {
		return recipients, nil
	}
	if fallback, ok := r.approvers[""]; ok {
		return fallback, nil
	}
	return nil, nil
}
