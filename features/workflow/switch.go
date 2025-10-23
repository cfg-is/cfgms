// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package workflow

import (
	"context"
	"fmt"
	"reflect"
	"strings"
)

// executeSwitchStep executes a switch step by evaluating the switch condition
// and executing the matching case steps
func (e *Engine) executeSwitchStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Switch == nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			"switch step missing switch configuration",
			step.Name,
			step.Type,
			fmt.Errorf("switch configuration is nil"),
		).WithVariableState(execution.GetVariables())
	}

	switchConfig := step.Switch
	logger := e.logger.WithField("step", step.Name).WithField("step_type", "switch")

	// Evaluate switch value
	var switchValue interface{}
	var err error

	if switchConfig.Variable != "" {
		// Evaluate variable
		switchValue, err = e.evaluateVariable(switchConfig.Variable, execution)
		if err != nil {
			return NewWorkflowError(
				ErrorCodeVariableResolution,
				fmt.Sprintf("failed to resolve switch variable '%s': %v", switchConfig.Variable, err),
				step.Name,
				step.Type,
				err,
			).WithVariableState(execution.GetVariables())
		}
		logger.Debug("Switch variable evaluated",
			"variable", switchConfig.Variable,
			"value", switchValue)
	} else if switchConfig.Expression != "" {
		// For switch expressions, we need a different approach than the boolean evaluateExpression
		switchValue, err = e.evaluateSwitchExpression(switchConfig.Expression, execution.GetVariables())
		if err != nil {
			return NewWorkflowError(
				ErrorCodeVariableResolution,
				fmt.Sprintf("failed to evaluate switch expression '%s': %v", switchConfig.Expression, err),
				step.Name,
				step.Type,
				err,
			).WithVariableState(execution.GetVariables())
		}
		logger.Debug("Switch expression evaluated",
			"expression", switchConfig.Expression,
			"value", switchValue)
	} else {
		return NewWorkflowError(
			ErrorCodeValidation,
			"switch step must specify either 'variable' or 'expression'",
			step.Name,
			step.Type,
			fmt.Errorf("no switch condition specified"),
		).WithVariableState(execution.GetVariables())
	}

	// Find matching case
	var matchedCase *SwitchCase
	for _, switchCase := range switchConfig.Cases {
		matched, err := e.evaluateSwitchCase(switchCase, switchValue, execution)
		if err != nil {
			return NewWorkflowError(
				ErrorCodeConditionEvaluation,
				fmt.Sprintf("failed to evaluate switch case: %v", err),
				step.Name,
				step.Type,
				err,
			).WithVariableState(execution.GetVariables())
		}
		if matched {
			matchedCase = &switchCase
			logger.Debug("Switch case matched",
				"case_value", switchCase.Value,
				"switch_value", switchValue)
			break
		}
	}

	// Execute matched case or default
	if matchedCase != nil {
		logger.InfoCtx(ctx, "Executing matched switch case",
			"operation", "switch_case_execute",
			"case_value", matchedCase.Value,
			"switch_value", switchValue,
			"step_count", len(matchedCase.Steps))

		return e.executeSteps(ctx, matchedCase.Steps, execution)
	} else if len(switchConfig.Default) > 0 {
		logger.InfoCtx(ctx, "Executing default switch case",
			"operation", "switch_default_execute",
			"switch_value", switchValue,
			"step_count", len(switchConfig.Default))

		return e.executeSteps(ctx, switchConfig.Default, execution)
	} else {
		// No match and no default case - this is valid, just continue
		logger.Debug("No switch case matched and no default case",
			"switch_value", switchValue)
		return nil
	}
}

// evaluateSwitchCase evaluates whether a switch case matches the given value
func (e *Engine) evaluateSwitchCase(switchCase SwitchCase, switchValue interface{}, execution *WorkflowExecution) (bool, error) {
	// If the case has a condition, evaluate it
	if switchCase.Condition != nil {
		return e.evaluateCondition(switchCase.Condition, execution.GetVariables())
	}

	// Otherwise, compare values directly using equality
	return e.compareSwitchValues(switchCase.Value, switchValue), nil
}

// compareSwitchValues compares two values for equality, handling type conversion
func (e *Engine) compareSwitchValues(caseValue, switchValue interface{}) bool {
	// Handle nil cases
	if caseValue == nil && switchValue == nil {
		return true
	}
	if caseValue == nil || switchValue == nil {
		return false
	}

	// Direct equality check
	if caseValue == switchValue {
		return true
	}

	// Type-aware comparison using reflection
	caseVal := reflect.ValueOf(caseValue)
	switchVal := reflect.ValueOf(switchValue)

	// Try to convert types for comparison
	if caseVal.Type().ConvertibleTo(switchVal.Type()) {
		convertedCase := caseVal.Convert(switchVal.Type())
		return convertedCase.Interface() == switchValue
	}

	if switchVal.Type().ConvertibleTo(caseVal.Type()) {
		convertedSwitch := switchVal.Convert(caseVal.Type())
		return caseValue == convertedSwitch.Interface()
	}

	// String comparison as fallback
	caseStr := fmt.Sprintf("%v", caseValue)
	switchStr := fmt.Sprintf("%v", switchValue)
	return caseStr == switchStr
}

// evaluateVariable resolves a variable from the execution context
func (e *Engine) evaluateVariable(variableName string, execution *WorkflowExecution) (interface{}, error) {
	value, exists := execution.GetVariable(variableName)
	if !exists {
		return nil, fmt.Errorf("variable '%s' does not exist", variableName)
	}
	return value, nil
}

// evaluateSwitchExpression evaluates an expression for switch statements
// This is different from the boolean evaluateExpression - it returns the actual value
func (e *Engine) evaluateSwitchExpression(expression string, variables map[string]interface{}) (interface{}, error) {
	// Handle simple variable references like ${variable_name}
	if strings.HasPrefix(expression, "${") && strings.HasSuffix(expression, "}") {
		expr := strings.TrimSuffix(strings.TrimPrefix(expression, "${"), "}")

		// Check if it's a simple variable reference (no operators)
		if !strings.Contains(expr, "?") && !strings.Contains(expr, ":") && !strings.Contains(expr, ">") && !strings.Contains(expr, "<") && !strings.Contains(expr, "=") {
			if value, exists := variables[expr]; exists {
				return value, nil
			}
			return nil, fmt.Errorf("variable '%s' not found in expression", expr)
		}

		// Handle ternary expressions
		if strings.Contains(expr, "?") && strings.Contains(expr, ":") {
			return e.evaluateTernaryExpression(expression, variables)
		}
	}

	// Handle simple ternary expressions like ${condition ? value1 : value2}
	if strings.Contains(expression, "?") && strings.Contains(expression, ":") {
		return e.evaluateTernaryExpression(expression, variables)
	}

	// For other expressions, try to use the existing expression evaluation
	// but adapt it for our needs
	resolved := e.replaceVariables(expression, variables)

	// Try to parse as a simple value
	if value, err := e.parseSimpleValue(resolved); err == nil {
		return value, nil
	}

	// For now, return the resolved expression as-is
	return resolved, nil
}

// evaluateTernaryExpression evaluates ternary expressions (including nested ones)
func (e *Engine) evaluateTernaryExpression(expression string, variables map[string]interface{}) (interface{}, error) {
	// Remove ${ and } if present
	expr := expression
	if strings.HasPrefix(expr, "${") && strings.HasSuffix(expr, "}") {
		expr = strings.TrimSuffix(strings.TrimPrefix(expr, "${"), "}")
	}

	// Find the main ? that's not inside parentheses
	questionPos := e.findMainOperator(expr, '?')
	if questionPos == -1 {
		return nil, fmt.Errorf("invalid ternary expression format: no ? found")
	}

	condition := strings.TrimSpace(expr[:questionPos])
	remainder := strings.TrimSpace(expr[questionPos+1:])

	// Find the main : that separates true and false values
	colonPos := e.findMainOperator(remainder, ':')
	if colonPos == -1 {
		return nil, fmt.Errorf("invalid ternary expression format: no : found")
	}

	trueValue := strings.TrimSpace(remainder[:colonPos])
	falseValue := strings.TrimSpace(remainder[colonPos+1:])

	// Evaluate condition
	conditionResult, err := e.evaluateSimpleCondition(condition, variables)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate condition: %v", err)
	}

	// Return appropriate value (handle nested ternary expressions)
	if conditionResult {
		return e.parseOrEvaluateValue(trueValue, variables)
	}
	return e.parseOrEvaluateValue(falseValue, variables)
}

// findMainOperator finds the position of an operator not inside parentheses
func (e *Engine) findMainOperator(expr string, operator rune) int {
	level := 0
	for i, r := range expr {
		switch r {
		case '(':
			level++
		case ')':
			level--
		default:
			if r == operator && level == 0 {
				return i
			}
		}
	}
	return -1
}

// parseOrEvaluateValue parses a value or evaluates it if it's an expression
func (e *Engine) parseOrEvaluateValue(value string, variables map[string]interface{}) (interface{}, error) {
	value = strings.TrimSpace(value)

	// If it's a nested ternary expression
	if strings.Contains(value, "?") && strings.Contains(value, ":") {
		return e.evaluateTernaryExpression("${"+value+"}", variables)
	}

	// Try to parse as a simple value
	return e.parseSimpleValue(value)
}

// evaluateSimpleCondition evaluates simple boolean conditions
func (e *Engine) evaluateSimpleCondition(condition string, variables map[string]interface{}) (bool, error) {
	// Handle simple comparisons like "cpu_usage > 80"
	for _, op := range []string{" >= ", " <= ", " > ", " < ", " == ", " != "} {
		if strings.Contains(condition, op) {
			parts := strings.Split(condition, op)
			if len(parts) != 2 {
				continue
			}

			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])

			leftVal, err := e.parseVariableOrValue(left, variables)
			if err != nil {
				return false, err
			}

			rightVal, err := e.parseVariableOrValue(right, variables)
			if err != nil {
				return false, err
			}

			return e.compareWithOperator(leftVal, rightVal, strings.TrimSpace(op))
		}
	}

	// Handle simple variable reference
	value, err := e.parseVariableOrValue(condition, variables)
	if err != nil {
		return false, err
	}

	// Convert to boolean
	return e.convertToBool(value), nil
}

// parseVariableOrValue parses a value string, handling variables and literals
func (e *Engine) parseVariableOrValue(valueStr string, variables map[string]interface{}) (interface{}, error) {
	valueStr = strings.TrimSpace(valueStr)

	// Check if it's a variable reference
	if val, exists := variables[valueStr]; exists {
		return val, nil
	}

	return e.parseSimpleValue(valueStr)
}

// parseSimpleValue parses a literal value
func (e *Engine) parseSimpleValue(valueStr string) (interface{}, error) {
	valueStr = strings.TrimSpace(valueStr)

	// Check if it's a quoted string
	if strings.HasPrefix(valueStr, "'") && strings.HasSuffix(valueStr, "'") {
		return strings.Trim(valueStr, "'"), nil
	}
	if strings.HasPrefix(valueStr, "\"") && strings.HasSuffix(valueStr, "\"") {
		return strings.Trim(valueStr, "\""), nil
	}

	// Try to parse as number
	if strings.Contains(valueStr, ".") {
		if f, err := e.parseFloat(valueStr); err == nil {
			return f, nil
		}
	} else {
		if i, err := e.parseInteger(valueStr); err == nil {
			return int64(i), nil
		}
	}

	// Try to parse as boolean
	if valueStr == "true" {
		return true, nil
	}
	if valueStr == "false" {
		return false, nil
	}

	// Return as string
	return valueStr, nil
}

// compareWithOperator compares two values with the given operator
func (e *Engine) compareWithOperator(left, right interface{}, operator string) (bool, error) {
	switch operator {
	case "==":
		return e.compareSwitchValues(left, right), nil
	case "!=":
		return !e.compareSwitchValues(left, right), nil
	case ">":
		return e.compareNumbers(left, right, func(a, b float64) bool { return a > b })
	case ">=":
		return e.compareNumbers(left, right, func(a, b float64) bool { return a >= b })
	case "<":
		return e.compareNumbers(left, right, func(a, b float64) bool { return a < b })
	case "<=":
		return e.compareNumbers(left, right, func(a, b float64) bool { return a <= b })
	default:
		return false, fmt.Errorf("unsupported operator: %s", operator)
	}
}

// compareNumbers compares two values as numbers
func (e *Engine) compareNumbers(left, right interface{}, compare func(float64, float64) bool) (bool, error) {
	leftNum := e.toFloat64(left)
	rightNum := e.toFloat64(right)
	return compare(leftNum, rightNum), nil
}

// Helper functions for type conversion

func (e *Engine) convertToBool(value interface{}) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return v != "" && v != "false" && v != "0"
	case int, int8, int16, int32, int64:
		return reflect.ValueOf(v).Int() != 0
	case uint, uint8, uint16, uint32, uint64:
		return reflect.ValueOf(v).Uint() != 0
	case float32, float64:
		return reflect.ValueOf(v).Float() != 0
	default:
		return value != nil
	}
}

// parseFloat is a helper for parsing float values in expressions
func (e *Engine) parseFloat(s string) (float64, error) {
	// Simple float parsing - in production, use strconv.ParseFloat
	if f, err := fmt.Sscanf(s, "%f", new(float64)); err == nil && f == 1 {
		var result float64
		_, _ = fmt.Sscanf(s, "%f", &result)
		return result, nil
	}
	return 0, fmt.Errorf("invalid float: %s", s)
}
