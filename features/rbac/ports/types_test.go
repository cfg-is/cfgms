// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package ports_test

import "github.com/cfgis/cfgms/features/rbac/ports"

// compile-time assertion: PolicyCondition has all 4 fields with correct types
var _ = ports.PolicyCondition{Field: "x", Operator: ports.ConditionOperatorEquals, Value: nil, ValueType: "string"}

// compile-time assertions: all 8 ConditionOperator constants exist and are exported
var _ ports.ConditionOperator = ports.ConditionOperatorEquals
var _ ports.ConditionOperator = ports.ConditionOperatorNotEquals
var _ ports.ConditionOperator = ports.ConditionOperatorContains
var _ ports.ConditionOperator = ports.ConditionOperatorRegex
var _ ports.ConditionOperator = ports.ConditionOperatorGreaterThan
var _ ports.ConditionOperator = ports.ConditionOperatorLessThan
var _ ports.ConditionOperator = ports.ConditionOperatorIn
var _ ports.ConditionOperator = ports.ConditionOperatorNotIn
