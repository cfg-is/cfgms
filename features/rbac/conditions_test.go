package rbac

import (
	"context"
	"testing"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/stretchr/testify/assert"
)

func TestConditionEngine(t *testing.T) {
	ctx := context.Background()
	engine := NewConditionEngine()

	t.Run("TimeConditions", func(t *testing.T) {
		now := time.Now()
		
		// Test TIME_WITHIN condition
		condition := &common.Condition{
			Type:     "time",
			Operator: common.ConditionOperator_CONDITION_OPERATOR_TIME_WITHIN,
			Values:   []string{now.Add(-1 * time.Hour).Format(time.RFC3339), now.Add(1 * time.Hour).Format(time.RFC3339)},
		}

		evaluationContext := map[string]string{
			"time": now.Format(time.RFC3339),
		}

		result, reason := engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.True(t, result, "Should allow access within time range")
		assert.Contains(t, reason, "within range")

		// Test outside time range
		condition.Values = []string{now.Add(-2 * time.Hour).Format(time.RFC3339), now.Add(-1 * time.Hour).Format(time.RFC3339)}
		result, reason = engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.False(t, result, "Should deny access outside time range")
		assert.Contains(t, reason, "outside range")

		// Test GREATER_THAN condition
		condition.Operator = common.ConditionOperator_CONDITION_OPERATOR_GREATER_THAN
		condition.Values = []string{now.Add(-1 * time.Hour).Format(time.RFC3339)}
		result, reason = engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.True(t, result, "Should allow access when time is after threshold")
		assert.Contains(t, reason, "after")

		// Test LESS_THAN condition
		condition.Operator = common.ConditionOperator_CONDITION_OPERATOR_LESS_THAN
		condition.Values = []string{now.Add(1 * time.Hour).Format(time.RFC3339)}
		result, reason = engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.True(t, result, "Should allow access when time is before threshold")
		assert.Contains(t, reason, "before")
	})

	t.Run("IPConditions", func(t *testing.T) {
		// Test IP_IN_RANGE condition
		condition := &common.Condition{
			Type:     "ip",
			Operator: common.ConditionOperator_CONDITION_OPERATOR_IP_IN_RANGE,
			Values:   []string{"192.168.1.0/24", "10.0.0.0/8"},
		}

		evaluationContext := map[string]string{
			"ip": "192.168.1.100",
		}

		result, reason := engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.True(t, result, "Should allow access from allowed IP range")
		assert.Contains(t, reason, "in allowed range")

		// Test IP outside range
		evaluationContext["ip"] = "172.16.1.1"
		result, reason = engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.False(t, result, "Should deny access from disallowed IP")
		assert.Contains(t, reason, "not in any allowed range")

		// Test IP EQUALS condition
		condition.Operator = common.ConditionOperator_CONDITION_OPERATOR_EQUALS
		condition.Values = []string{"192.168.1.100", "10.0.0.1"}
		evaluationContext["ip"] = "192.168.1.100"

		result, reason = engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.True(t, result, "Should allow access from exact IP match")
		assert.Contains(t, reason, "matches")

		evaluationContext["ip"] = "192.168.1.101"
		result, reason = engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.False(t, result, "Should deny access from non-matching IP")
		assert.Contains(t, reason, "does not match")
	})

	t.Run("StringConditions", func(t *testing.T) {
		// Test EQUALS condition
		condition := &common.Condition{
			Type:     "device_id",
			Operator: common.ConditionOperator_CONDITION_OPERATOR_EQUALS,
			Values:   []string{"device1", "device2"},
		}

		evaluationContext := map[string]string{
			"device_id": "device1",
		}

		result, reason := engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.True(t, result, "Should allow access for matching device")
		assert.Contains(t, reason, "equals")

		evaluationContext["device_id"] = "device3"
		result, reason = engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.False(t, result, "Should deny access for non-matching device")
		assert.Contains(t, reason, "does not equal")

		// Test CONTAINS condition
		condition.Operator = common.ConditionOperator_CONDITION_OPERATOR_CONTAINS
		condition.Values = []string{"admin", "manager"}
		evaluationContext["device_id"] = "admin-device"

		result, reason = engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.True(t, result, "Should allow access when value contains substring")
		assert.Contains(t, reason, "contains")

		// Test REGEX condition
		condition.Operator = common.ConditionOperator_CONDITION_OPERATOR_REGEX
		condition.Values = []string{"^admin-.*", "^manager-.*"}
		evaluationContext["device_id"] = "admin-device-001"

		result, reason = engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.True(t, result, "Should allow access when value matches regex")
		assert.Contains(t, reason, "matches")

		evaluationContext["device_id"] = "user-device-001"
		result, reason = engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.False(t, result, "Should deny access when value doesn't match regex")
		assert.Contains(t, reason, "does not match")
	})

	t.Run("NumericConditions", func(t *testing.T) {
		// Test EQUALS condition
		condition := &common.Condition{
			Type:     "security_level",
			Operator: common.ConditionOperator_CONDITION_OPERATOR_EQUALS,
			Values:   []string{"5"},
		}

		evaluationContext := map[string]string{
			"security_level": "5",
		}

		result, _ := engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.True(t, result, "Should allow access when numeric values match")

		// Test GREATER_THAN condition
		condition.Operator = common.ConditionOperator_CONDITION_OPERATOR_GREATER_THAN
		condition.Values = []string{"3"}
		evaluationContext["security_level"] = "5"

		result, _ = engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.True(t, result, "Should allow access when value is greater than threshold")

		evaluationContext["security_level"] = "2"
		result, _ = engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.False(t, result, "Should deny access when value is not greater than threshold")

		// Test LESS_THAN condition
		condition.Operator = common.ConditionOperator_CONDITION_OPERATOR_LESS_THAN
		condition.Values = []string{"10"}
		evaluationContext["security_level"] = "5"

		result, reason := engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.True(t, result, "Should allow access when value is less than threshold")
		assert.Contains(t, reason, "less than")
	})

	t.Run("BooleanConditions", func(t *testing.T) {
		condition := &common.Condition{
			Type:     "mfa_verified",
			Operator: common.ConditionOperator_CONDITION_OPERATOR_EQUALS,
			Values:   []string{"true"},
		}

		evaluationContext := map[string]string{
			"mfa_verified": "true",
		}

		result, reason := engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.True(t, result, "Should allow access when boolean condition is met")
		assert.Contains(t, reason, "equals")

		evaluationContext["mfa_verified"] = "false"
		result, _ = engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.False(t, result, "Should deny access when boolean condition is not met")
	})

	t.Run("MultipleConditions", func(t *testing.T) {
		conditions := []*common.Condition{
			{
				Type:     "ip",
				Operator: common.ConditionOperator_CONDITION_OPERATOR_IP_IN_RANGE,
				Values:   []string{"192.168.1.0/24"},
			},
			{
				Type:     "mfa_verified",
				Operator: common.ConditionOperator_CONDITION_OPERATOR_EQUALS,
				Values:   []string{"true"},
			},
		}

		evaluationContext := map[string]string{
			"ip":           "192.168.1.100",
			"mfa_verified": "true",
		}

		result, reason := engine.EvaluateConditions(ctx, conditions, evaluationContext)
		assert.True(t, result, "Should allow access when all conditions are met")
		assert.Contains(t, reason, "all conditions passed")

		// Fail one condition
		evaluationContext["mfa_verified"] = "false"
		result, reason = engine.EvaluateConditions(ctx, conditions, evaluationContext)
		assert.False(t, result, "Should deny access when any condition fails")
		assert.Contains(t, reason, "condition failed")
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		// Test unsupported condition type
		condition := &common.Condition{
			Type:     "unsupported_type",
			Operator: common.ConditionOperator_CONDITION_OPERATOR_EQUALS,
			Values:   []string{"test"},
		}

		evaluationContext := map[string]string{
			"unsupported_type": "test",
		}

		result, reason := engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.False(t, result, "Should deny access for unsupported condition type")
		assert.Contains(t, reason, "unsupported condition type")

		// Test missing context value
		condition.Type = "device_id"
		evaluationContext = map[string]string{
			"other_key": "value",
		}

		result, reason = engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.False(t, result, "Should deny access when context value is missing")
		assert.Contains(t, reason, "missing context value")

		// Test invalid IP format
		condition = &common.Condition{
			Type:     "ip",
			Operator: common.ConditionOperator_CONDITION_OPERATOR_IP_IN_RANGE,
			Values:   []string{"192.168.1.0/24"},
		}

		evaluationContext = map[string]string{
			"ip": "invalid-ip",
		}

		result, reason = engine.EvaluateCondition(ctx, condition, evaluationContext)
		assert.False(t, result, "Should deny access for invalid IP format")
		assert.Contains(t, reason, "invalid IP address")
	})

	t.Run("BuildEvaluationContext", func(t *testing.T) {
		authContext := &common.AuthorizationContext{
			TenantId:  "tenant1",
			SubjectId: "user1",
			Environment: map[string]string{
				"ip":         "192.168.1.100",
				"user_agent": "TestAgent/1.0",
			},
			ResourceAttributes: map[string]string{
				"resource_type": "configuration",
				"sensitivity":   "high",
			},
		}

		evaluationContext := engine.BuildEvaluationContext(authContext)

		// Check that time is included
		assert.Contains(t, evaluationContext, "time")
		assert.NotEmpty(t, evaluationContext["time"])

		// Check that environment attributes are included
		assert.Equal(t, "192.168.1.100", evaluationContext["ip"])
		assert.Equal(t, "TestAgent/1.0", evaluationContext["user_agent"])

		// Check that resource attributes are included
		assert.Equal(t, "configuration", evaluationContext["resource_type"])
		assert.Equal(t, "high", evaluationContext["sensitivity"])

		// Check that tenant and subject info is included
		assert.Equal(t, "tenant1", evaluationContext["tenant_id"])
		assert.Equal(t, "user1", evaluationContext["subject_id"])
	})
}