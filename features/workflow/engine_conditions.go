// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package workflow

import (
	"fmt"
	"strings"
)

// evaluateCondition evaluates a condition against current variables
func (e *Engine) evaluateCondition(condition *Condition, variables map[string]interface{}) (bool, error) {
	switch condition.Type {
	case ConditionTypeVariable:
		return e.evaluateVariableCondition(condition, variables)
	case ConditionTypeExpression:
		return e.evaluateExpressionCondition(condition, variables)
	case ConditionTypeAnd:
		return e.evaluateAndCondition(condition, variables)
	case ConditionTypeOr:
		return e.evaluateOrCondition(condition, variables)
	case ConditionTypeNot:
		return e.evaluateNotCondition(condition, variables)
	default:
		// Handle nested conditions using And/Or/Not fields
		if len(condition.And) > 0 {
			return e.evaluateNestedAndConditions(condition.And, variables)
		}
		if len(condition.Or) > 0 {
			return e.evaluateNestedOrConditions(condition.Or, variables)
		}
		if condition.Not != nil {
			result, err := e.evaluateCondition(condition.Not, variables)
			if err != nil {
				return false, err
			}
			return !result, nil
		}
		return false, fmt.Errorf("unknown condition type: %s", condition.Type)
	}
}

// evaluateVariableCondition evaluates a variable-based condition
func (e *Engine) evaluateVariableCondition(condition *Condition, variables map[string]interface{}) (bool, error) {
	value, exists := variables[condition.Variable]

	switch condition.Operator {
	case OperatorExists:
		return exists, nil
	case OperatorEqual:
		return exists && e.compareValues(value, condition.Value, "eq"), nil
	case OperatorNotEqual:
		return !exists || !e.compareValues(value, condition.Value, "eq"), nil
	case OperatorGreaterThan:
		if !exists {
			return false, nil
		}
		return e.compareValues(value, condition.Value, "gt"), nil
	case OperatorLessThan:
		if !exists {
			return false, nil
		}
		return e.compareValues(value, condition.Value, "lt"), nil
	case OperatorContains:
		if !exists {
			return false, nil
		}
		return e.compareValues(value, condition.Value, "contains"), nil
	default:
		return false, fmt.Errorf("unknown operator: %s", condition.Operator)
	}
}

// evaluateAndCondition evaluates logical AND of multiple conditions
func (e *Engine) evaluateAndCondition(condition *Condition, variables map[string]interface{}) (bool, error) {
	if len(condition.And) == 0 {
		return false, fmt.Errorf("and condition requires at least one child condition")
	}
	return e.evaluateNestedAndConditions(condition.And, variables)
}

// evaluateOrCondition evaluates logical OR of multiple conditions
func (e *Engine) evaluateOrCondition(condition *Condition, variables map[string]interface{}) (bool, error) {
	if len(condition.Or) == 0 {
		return false, fmt.Errorf("or condition requires at least one child condition")
	}
	return e.evaluateNestedOrConditions(condition.Or, variables)
}

// evaluateNotCondition evaluates logical NOT of a condition
func (e *Engine) evaluateNotCondition(condition *Condition, variables map[string]interface{}) (bool, error) {
	if condition.Not == nil {
		return false, fmt.Errorf("not condition requires a child condition")
	}
	result, err := e.evaluateCondition(condition.Not, variables)
	if err != nil {
		return false, err
	}
	return !result, nil
}

// evaluateNestedAndConditions evaluates AND conditions with support for up to 5 levels deep
func (e *Engine) evaluateNestedAndConditions(conditions []*Condition, variables map[string]interface{}) (bool, error) {
	for _, cond := range conditions {
		result, err := e.evaluateCondition(cond, variables)
		if err != nil {
			return false, err
		}
		if !result {
			return false, nil
		}
	}
	return true, nil
}

// evaluateNestedOrConditions evaluates OR conditions with support for up to 5 levels deep
func (e *Engine) evaluateNestedOrConditions(conditions []*Condition, variables map[string]interface{}) (bool, error) {
	for _, cond := range conditions {
		result, err := e.evaluateCondition(cond, variables)
		if err != nil {
			return false, err
		}
		if result {
			return true, nil
		}
	}
	return false, nil
}

// evaluateExpressionCondition evaluates complex expression conditions
func (e *Engine) evaluateExpressionCondition(condition *Condition, variables map[string]interface{}) (bool, error) {
	if condition.Expression == "" {
		return false, fmt.Errorf("expression is required for expression conditions")
	}

	// Simple expression evaluator supporting basic logical operations
	return e.evaluateExpression(condition.Expression, variables)
}

// evaluateExpression evaluates a condition expression
func (e *Engine) evaluateExpression(expression string, variables map[string]interface{}) (bool, error) {
	// Replace variables in the expression
	resolvedExpression := e.replaceVariables(expression, variables)

	// Parse and evaluate the expression
	return e.parseExpression(resolvedExpression, variables)
}

// replaceVariables replaces ${variable} placeholders with actual values
func (e *Engine) replaceVariables(expression string, variables map[string]interface{}) string {
	result := expression

	// Simple variable replacement for ${variable_name}
	for varName, varValue := range variables {
		placeholder := fmt.Sprintf("${%s}", varName)
		valueStr := fmt.Sprintf("%v", varValue)
		result = strings.ReplaceAll(result, placeholder, valueStr)
	}

	return result
}

// parseExpression parses and evaluates logical expressions
func (e *Engine) parseExpression(expression string, variables map[string]interface{}) (bool, error) {
	// Remove whitespace
	expr := strings.TrimSpace(expression)

	// Handle simple boolean values
	if expr == "true" {
		return true, nil
	}
	if expr == "false" {
		return false, nil
	}

	// Handle AND operations
	if strings.Contains(expr, " && ") {
		parts := strings.Split(expr, " && ")
		for _, part := range parts {
			result, err := e.parseExpression(strings.TrimSpace(part), variables)
			if err != nil {
				return false, err
			}
			if !result {
				return false, nil
			}
		}
		return true, nil
	}

	// Handle OR operations
	if strings.Contains(expr, " || ") {
		parts := strings.Split(expr, " || ")
		for _, part := range parts {
			result, err := e.parseExpression(strings.TrimSpace(part), variables)
			if err != nil {
				return false, err
			}
			if result {
				return true, nil
			}
		}
		return false, nil
	}

	// Handle NOT operations
	if strings.HasPrefix(expr, "!") {
		innerExpr := strings.TrimSpace(expr[1:])
		result, err := e.parseExpression(innerExpr, variables)
		if err != nil {
			return false, err
		}
		return !result, nil
	}

	// Handle comparison operations
	return e.parseComparison(expr, variables)
}

// parseComparison parses comparison expressions like "var1 == value"
func (e *Engine) parseComparison(expression string, variables map[string]interface{}) (bool, error) {
	// Support different comparison operators
	operators := []string{"==", "!=", ">=", "<=", ">", "<", "contains"}

	for _, op := range operators {
		if strings.Contains(expression, fmt.Sprintf(" %s ", op)) {
			parts := strings.SplitN(expression, fmt.Sprintf(" %s ", op), 2)
			if len(parts) != 2 {
				continue
			}

			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])

			// Get variable value or use literal
			leftValue := e.getValueFromExpression(left, variables)
			rightValue := e.getValueFromExpression(right, variables)

			// Perform comparison
			switch op {
			case "==":
				return leftValue == rightValue, nil
			case "!=":
				return leftValue != rightValue, nil
			case ">":
				return e.numericCompare(leftValue, rightValue) > 0, nil
			case "<":
				return e.numericCompare(leftValue, rightValue) < 0, nil
			case ">=":
				return e.numericCompare(leftValue, rightValue) >= 0, nil
			case "<=":
				return e.numericCompare(leftValue, rightValue) <= 0, nil
			case "contains":
				return e.containsCompare(leftValue, rightValue), nil
			}
		}
	}

	return false, fmt.Errorf("unable to parse expression: %s", expression)
}

// getValueFromExpression extracts value from expression part (variable or literal)
func (e *Engine) getValueFromExpression(expr string, variables map[string]interface{}) interface{} {
	// Remove quotes for string literals
	if (strings.HasPrefix(expr, "\"") && strings.HasSuffix(expr, "\"")) ||
		(strings.HasPrefix(expr, "'") && strings.HasSuffix(expr, "'")) {
		return expr[1 : len(expr)-1]
	}

	// Try to get from variables
	if value, exists := variables[expr]; exists {
		return value
	}

	// Try to parse as number
	if expr == "true" {
		return true
	}
	if expr == "false" {
		return false
	}

	// Try to parse as integer
	if len(expr) > 0 && (expr[0] >= '0' && expr[0] <= '9') {
		// Simple integer parsing
		result := 0
		for _, char := range expr {
			if char >= '0' && char <= '9' {
				result = result*10 + int(char-'0')
			} else {
				// Not a valid number, return as string
				return expr
			}
		}
		return result
	}

	// Return as string literal
	return expr
}

// compareValues performs type-safe comparison between two values
func (e *Engine) compareValues(left, right interface{}, operator string) bool {
	// Handle nil values
	if left == nil && right == nil {
		return operator == "eq"
	}
	if left == nil || right == nil {
		return operator == "ne"
	}

	switch operator {
	case "eq":
		return left == right
	case "gt":
		return e.numericCompare(left, right) > 0
	case "lt":
		return e.numericCompare(left, right) < 0
	case "contains":
		return e.containsCompare(left, right)
	default:
		return false
	}
}

// numericCompare performs numeric comparison, returning -1, 0, 1
func (e *Engine) numericCompare(left, right interface{}) int {
	leftFloat := e.toFloat64(left)
	rightFloat := e.toFloat64(right)

	if leftFloat < rightFloat {
		return -1
	} else if leftFloat > rightFloat {
		return 1
	}
	return 0
}

// toFloat64 converts various numeric types to float64
func (e *Engine) toFloat64(val interface{}) float64 {
	switch v := val.(type) {
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case float32:
		return float64(v)
	case float64:
		return v
	default:
		return 0
	}
}

// containsCompare checks if left contains right
func (e *Engine) containsCompare(left, right interface{}) bool {
	leftStr := fmt.Sprintf("%v", left)
	rightStr := fmt.Sprintf("%v", right)

	// Empty string is contained in everything
	if len(rightStr) == 0 {
		return true
	}

	// Check string containment using strings.Contains
	return strings.Contains(leftStr, rightStr)
}
