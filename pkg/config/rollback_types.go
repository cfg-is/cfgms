// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package config defines shared rollback request/response types used by the
// ConfigurationServiceV2 public API. The rollback implementation lives in
// features/config/rollback; these types are a translation boundary.
package config

import "time"

// RollbackRequest represents a configuration rollback request from the gRPC API.
type RollbackRequest struct {
	TenantID       string    `json:"tenant_id"`
	StewardID      string    `json:"steward_id"`
	TargetVersion  int64     `json:"target_version"`
	Reason         string    `json:"reason"`
	RequestedBy    string    `json:"requested_by"`
	RequestedAt    time.Time `json:"requested_at"`
	ValidateOnly   bool      `json:"validate_only"`
	SkipValidation bool      `json:"skip_validation"`
}

// RollbackResponse represents the result of a rollback operation.
type RollbackResponse struct {
	Success          bool                            `json:"success"`
	RollbackID       string                          `json:"rollback_id"`
	PreviousVersion  int64                           `json:"previous_version"`
	NewVersion       int64                           `json:"new_version"`
	RiskLevel        RollbackRiskLevel               `json:"risk_level"`
	Warnings         []string                        `json:"warnings"`
	Errors           []string                        `json:"errors"`
	ExecutedAt       time.Time                       `json:"executed_at"`
	ValidationIssues []*ConfigurationValidationError `json:"validation_issues,omitempty"`
}

// RollbackRiskLevel indicates the risk level of a rollback operation.
type RollbackRiskLevel string

const (
	RollbackRiskLow      RollbackRiskLevel = "low"
	RollbackRiskMedium   RollbackRiskLevel = "medium"
	RollbackRiskHigh     RollbackRiskLevel = "high"
	RollbackRiskCritical RollbackRiskLevel = "critical"
)

// ConfigurationValidationError represents a validation error associated with a rollback.
type ConfigurationValidationError struct {
	Field      string `json:"field"`
	Message    string `json:"message"`
	Code       string `json:"code"`
	Severity   string `json:"severity"`
	Suggestion string `json:"suggestion,omitempty"`
}
