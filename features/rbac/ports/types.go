// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package ports

// ConditionOperator defines the comparison operator for a policy condition.
type ConditionOperator string

const (
	ConditionOperatorEquals      ConditionOperator = "equals"
	ConditionOperatorNotEquals   ConditionOperator = "not_equals"
	ConditionOperatorContains    ConditionOperator = "contains"
	ConditionOperatorRegex       ConditionOperator = "regex"
	ConditionOperatorGreaterThan ConditionOperator = "greater_than"
	ConditionOperatorLessThan    ConditionOperator = "less_than"
	ConditionOperatorIn          ConditionOperator = "in"
	ConditionOperatorNotIn       ConditionOperator = "not_in"
)

// PolicyCondition is the canonical condition type used across RBAC sub-packages.
type PolicyCondition struct {
	Field     string            `json:"field"`
	Operator  ConditionOperator `json:"operator"`
	Value     interface{}       `json:"value"`
	ValueType string            `json:"value_type"`
}
