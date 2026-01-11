// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package rbac

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
)

// ConditionEngine evaluates context-based conditions for permission checks
type ConditionEngine struct {
	timeProvider func() time.Time
}

// NewConditionEngine creates a new condition evaluation engine
func NewConditionEngine() *ConditionEngine {
	return &ConditionEngine{
		timeProvider: time.Now,
	}
}

// EvaluateConditions evaluates all conditions for a conditional permission
func (c *ConditionEngine) EvaluateConditions(ctx context.Context, conditions []*common.Condition, evaluationContext map[string]string) (bool, string) {
	if len(conditions) == 0 {
		return true, "no conditions to evaluate"
	}

	var reasons []string

	for _, condition := range conditions {
		result, reason := c.EvaluateCondition(ctx, condition, evaluationContext)
		if !result {
			return false, fmt.Sprintf("condition failed: %s", reason)
		}
		reasons = append(reasons, reason)
	}

	return true, fmt.Sprintf("all conditions passed: %s", strings.Join(reasons, "; "))
}

// EvaluateCondition evaluates a single condition
func (c *ConditionEngine) EvaluateCondition(ctx context.Context, condition *common.Condition, evaluationContext map[string]string) (bool, string) {
	contextValue, exists := evaluationContext[condition.Type]
	if !exists {
		return false, fmt.Sprintf("missing context value for condition type '%s'", condition.Type)
	}

	switch condition.Type {
	case "time":
		return c.evaluateTimeCondition(condition, contextValue)
	case "ip":
		return c.evaluateIPCondition(condition, contextValue)
	case "device_id":
		return c.evaluateStringCondition(condition, contextValue)
	case "location":
		return c.evaluateStringCondition(condition, contextValue)
	case "user_agent":
		return c.evaluateStringCondition(condition, contextValue)
	case "department":
		return c.evaluateStringCondition(condition, contextValue)
	case "security_level":
		return c.evaluateNumericCondition(condition, contextValue)
	case "mfa_verified":
		return c.evaluateBooleanCondition(condition, contextValue)
	default:
		return false, fmt.Sprintf("unsupported condition type: %s", condition.Type)
	}
}

// evaluateTimeCondition handles time-based conditions
func (c *ConditionEngine) evaluateTimeCondition(condition *common.Condition, contextValue string) (bool, string) {
	currentTime := c.timeProvider()

	switch condition.Operator {
	case common.ConditionOperator_CONDITION_OPERATOR_TIME_WITHIN:
		if len(condition.Values) != 2 {
			return false, "TIME_WITHIN requires exactly 2 values (start and end time)"
		}

		startTime, err := time.Parse(time.RFC3339, condition.Values[0])
		if err != nil {
			return false, fmt.Sprintf("invalid start time format: %v", err)
		}

		endTime, err := time.Parse(time.RFC3339, condition.Values[1])
		if err != nil {
			return false, fmt.Sprintf("invalid end time format: %v", err)
		}

		if currentTime.After(startTime) && currentTime.Before(endTime) {
			return true, fmt.Sprintf("current time %s is within range %s to %s",
				currentTime.Format(time.RFC3339), condition.Values[0], condition.Values[1])
		}

		return false, fmt.Sprintf("current time %s is outside range %s to %s",
			currentTime.Format(time.RFC3339), condition.Values[0], condition.Values[1])

	case common.ConditionOperator_CONDITION_OPERATOR_GREATER_THAN:
		if len(condition.Values) != 1 {
			return false, "GREATER_THAN requires exactly 1 value"
		}

		compareTime, err := time.Parse(time.RFC3339, condition.Values[0])
		if err != nil {
			return false, fmt.Sprintf("invalid time format: %v", err)
		}

		if currentTime.After(compareTime) {
			return true, fmt.Sprintf("current time %s is after %s",
				currentTime.Format(time.RFC3339), condition.Values[0])
		}

		return false, fmt.Sprintf("current time %s is not after %s",
			currentTime.Format(time.RFC3339), condition.Values[0])

	case common.ConditionOperator_CONDITION_OPERATOR_LESS_THAN:
		if len(condition.Values) != 1 {
			return false, "LESS_THAN requires exactly 1 value"
		}

		compareTime, err := time.Parse(time.RFC3339, condition.Values[0])
		if err != nil {
			return false, fmt.Sprintf("invalid time format: %v", err)
		}

		if currentTime.Before(compareTime) {
			return true, fmt.Sprintf("current time %s is before %s",
				currentTime.Format(time.RFC3339), condition.Values[0])
		}

		return false, fmt.Sprintf("current time %s is not before %s",
			currentTime.Format(time.RFC3339), condition.Values[0])

	default:
		return false, fmt.Sprintf("unsupported operator %s for time condition", condition.Operator.String())
	}
}

// evaluateIPCondition handles IP address-based conditions
func (c *ConditionEngine) evaluateIPCondition(condition *common.Condition, contextValue string) (bool, string) {
	clientIP := net.ParseIP(contextValue)
	if clientIP == nil {
		return false, fmt.Sprintf("invalid IP address: %s", contextValue)
	}

	switch condition.Operator {
	case common.ConditionOperator_CONDITION_OPERATOR_IP_IN_RANGE:
		for _, cidr := range condition.Values {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				return false, fmt.Sprintf("invalid CIDR range: %s", cidr)
			}

			if network.Contains(clientIP) {
				return true, fmt.Sprintf("IP %s is in allowed range %s", contextValue, cidr)
			}
		}

		return false, fmt.Sprintf("IP %s is not in any allowed range: %v", contextValue, condition.Values)

	case common.ConditionOperator_CONDITION_OPERATOR_EQUALS:
		for _, allowedIP := range condition.Values {
			if contextValue == allowedIP {
				return true, fmt.Sprintf("IP %s matches allowed IP %s", contextValue, allowedIP)
			}
		}

		return false, fmt.Sprintf("IP %s does not match any allowed IPs: %v", contextValue, condition.Values)

	default:
		return false, fmt.Sprintf("unsupported operator %s for IP condition", condition.Operator.String())
	}
}

// evaluateStringCondition handles string-based conditions
func (c *ConditionEngine) evaluateStringCondition(condition *common.Condition, contextValue string) (bool, string) {
	switch condition.Operator {
	case common.ConditionOperator_CONDITION_OPERATOR_EQUALS:
		for _, value := range condition.Values {
			if contextValue == value {
				return true, fmt.Sprintf("value '%s' equals '%s'", contextValue, value)
			}
		}
		return false, fmt.Sprintf("value '%s' does not equal any of: %v", contextValue, condition.Values)

	case common.ConditionOperator_CONDITION_OPERATOR_NOT_EQUALS:
		for _, value := range condition.Values {
			if contextValue == value {
				return false, fmt.Sprintf("value '%s' should not equal '%s'", contextValue, value)
			}
		}
		return true, fmt.Sprintf("value '%s' does not equal any of: %v", contextValue, condition.Values)

	case common.ConditionOperator_CONDITION_OPERATOR_IN:
		for _, value := range condition.Values {
			if contextValue == value {
				return true, fmt.Sprintf("value '%s' is in allowed list", contextValue)
			}
		}
		return false, fmt.Sprintf("value '%s' is not in allowed list: %v", contextValue, condition.Values)

	case common.ConditionOperator_CONDITION_OPERATOR_NOT_IN:
		for _, value := range condition.Values {
			if contextValue == value {
				return false, fmt.Sprintf("value '%s' should not be in list: %v", contextValue, condition.Values)
			}
		}
		return true, fmt.Sprintf("value '%s' is not in excluded list", contextValue)

	case common.ConditionOperator_CONDITION_OPERATOR_CONTAINS:
		for _, value := range condition.Values {
			if strings.Contains(contextValue, value) {
				return true, fmt.Sprintf("value '%s' contains '%s'", contextValue, value)
			}
		}
		return false, fmt.Sprintf("value '%s' does not contain any of: %v", contextValue, condition.Values)

	case common.ConditionOperator_CONDITION_OPERATOR_REGEX:
		for _, pattern := range condition.Values {
			matched, err := regexp.MatchString(pattern, contextValue)
			if err != nil {
				return false, fmt.Sprintf("invalid regex pattern '%s': %v", pattern, err)
			}
			if matched {
				return true, fmt.Sprintf("value '%s' matches pattern '%s'", contextValue, pattern)
			}
		}
		return false, fmt.Sprintf("value '%s' does not match any pattern: %v", contextValue, condition.Values)

	default:
		return false, fmt.Sprintf("unsupported operator %s for string condition", condition.Operator.String())
	}
}

// evaluateNumericCondition handles numeric conditions
func (c *ConditionEngine) evaluateNumericCondition(condition *common.Condition, contextValue string) (bool, string) {
	contextNum, err := strconv.ParseFloat(contextValue, 64)
	if err != nil {
		return false, fmt.Sprintf("invalid numeric value: %s", contextValue)
	}

	switch condition.Operator {
	case common.ConditionOperator_CONDITION_OPERATOR_EQUALS:
		if len(condition.Values) != 1 {
			return false, "EQUALS requires exactly 1 value for numeric condition"
		}

		compareNum, err := strconv.ParseFloat(condition.Values[0], 64)
		if err != nil {
			return false, fmt.Sprintf("invalid comparison value: %s", condition.Values[0])
		}

		if contextNum == compareNum {
			return true, fmt.Sprintf("value %f equals %f", contextNum, compareNum)
		}
		return false, fmt.Sprintf("value %f does not equal %f", contextNum, compareNum)

	case common.ConditionOperator_CONDITION_OPERATOR_GREATER_THAN:
		if len(condition.Values) != 1 {
			return false, "GREATER_THAN requires exactly 1 value for numeric condition"
		}

		compareNum, err := strconv.ParseFloat(condition.Values[0], 64)
		if err != nil {
			return false, fmt.Sprintf("invalid comparison value: %s", condition.Values[0])
		}

		if contextNum > compareNum {
			return true, fmt.Sprintf("value %f is greater than %f", contextNum, compareNum)
		}
		return false, fmt.Sprintf("value %f is not greater than %f", contextNum, compareNum)

	case common.ConditionOperator_CONDITION_OPERATOR_LESS_THAN:
		if len(condition.Values) != 1 {
			return false, "LESS_THAN requires exactly 1 value for numeric condition"
		}

		compareNum, err := strconv.ParseFloat(condition.Values[0], 64)
		if err != nil {
			return false, fmt.Sprintf("invalid comparison value: %s", condition.Values[0])
		}

		if contextNum < compareNum {
			return true, fmt.Sprintf("value %f is less than %f", contextNum, compareNum)
		}
		return false, fmt.Sprintf("value %f is not less than %f", contextNum, compareNum)

	default:
		return false, fmt.Sprintf("unsupported operator %s for numeric condition", condition.Operator.String())
	}
}

// evaluateBooleanCondition handles boolean conditions
func (c *ConditionEngine) evaluateBooleanCondition(condition *common.Condition, contextValue string) (bool, string) {
	contextBool, err := strconv.ParseBool(contextValue)
	if err != nil {
		return false, fmt.Sprintf("invalid boolean value: %s", contextValue)
	}

	switch condition.Operator {
	case common.ConditionOperator_CONDITION_OPERATOR_EQUALS:
		if len(condition.Values) != 1 {
			return false, "EQUALS requires exactly 1 value for boolean condition"
		}

		compareBool, err := strconv.ParseBool(condition.Values[0])
		if err != nil {
			return false, fmt.Sprintf("invalid comparison value: %s", condition.Values[0])
		}

		if contextBool == compareBool {
			return true, fmt.Sprintf("value %t equals %t", contextBool, compareBool)
		}
		return false, fmt.Sprintf("value %t does not equal %t", contextBool, compareBool)

	default:
		return false, fmt.Sprintf("unsupported operator %s for boolean condition", condition.Operator.String())
	}
}

// BuildEvaluationContext creates an evaluation context from authorization context
func (c *ConditionEngine) BuildEvaluationContext(authContext *common.AuthorizationContext) map[string]string {
	context := make(map[string]string)

	// Add current time
	context["time"] = c.timeProvider().Format(time.RFC3339)

	// Add environment attributes
	for key, value := range authContext.Environment {
		context[key] = value
	}

	// Add resource attributes
	for key, value := range authContext.ResourceAttributes {
		context[key] = value
	}

	// Add tenant and subject info
	context["tenant_id"] = authContext.TenantId
	context["subject_id"] = authContext.SubjectId

	return context
}
