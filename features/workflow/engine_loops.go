// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"fmt"
	"strings"
)

// executeForStep executes a for loop workflow step
func (e *Engine) executeForStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Loop == nil {
		return fmt.Errorf("loop configuration is required for for steps")
	}

	if step.Loop.Type != LoopTypeFor {
		return fmt.Errorf("for step requires loop type 'for', got '%s'", step.Loop.Type)
	}

	if step.Loop.Variable == "" {
		return fmt.Errorf("loop variable is required for for loops")
	}

	// Get start, end, and step values
	start, err := e.resolveLoopValue(step.Loop.Start, execution)
	if err != nil {
		return fmt.Errorf("invalid start value: %w", err)
	}

	end, err := e.resolveLoopValue(step.Loop.End, execution)
	if err != nil {
		return fmt.Errorf("invalid end value: %w", err)
	}

	stepValue := 1
	if step.Loop.Step != nil {
		resolvedStep, err := e.resolveLoopValue(step.Loop.Step, execution)
		if err != nil {
			return fmt.Errorf("invalid step value: %w", err)
		}
		stepValue = resolvedStep
	}

	// Safety check for maximum iterations
	maxIterations := step.Loop.MaxIterations
	if maxIterations == 0 {
		maxIterations = 1000 // Default safety limit
	}

	e.logger.Info("Starting for loop",
		"step", step.Name,
		"variable", step.Loop.Variable,
		"start", start,
		"end", end,
		"step", stepValue)

	// Execute loop
	iterations := 0
	for i := start; (stepValue > 0 && i <= end) || (stepValue < 0 && i >= end); i += stepValue {
		iterations++
		if iterations > maxIterations {
			return fmt.Errorf("for loop exceeded maximum iterations: %d", maxIterations)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Set loop variable safely
		execution.SetVariable(step.Loop.Variable, i)

		// Execute child steps
		if err := e.executeSteps(ctx, step.Steps, execution); err != nil {
			// Check if it's a loop control error
			if loopErr, isLoopControl := err.(*LoopControlError); isLoopControl {
				switch loopErr.Type {
				case LoopControlBreak:
					// Break out of the loop
					e.logger.Debug("Breaking out of for loop", "step", loopErr.StepName, "iteration", i)
					goto forLoopComplete // Use goto to break out of the for loop
				case LoopControlContinue:
					// Continue to next iteration
					e.logger.Debug("Continuing for loop", "step", loopErr.StepName, "iteration", i)
					continue
				}
			}
			return fmt.Errorf("for loop iteration %d failed: %w", i, err)
		}
	}

forLoopComplete:
	e.logger.Info("For loop completed",
		"step", step.Name,
		"iterations", iterations)

	return nil
}

// executeWhileStep executes a while loop workflow step
func (e *Engine) executeWhileStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Loop == nil {
		return fmt.Errorf("loop configuration is required for while steps")
	}

	if step.Loop.Type != LoopTypeWhile {
		return fmt.Errorf("while step requires loop type 'while', got '%s'", step.Loop.Type)
	}

	if step.Loop.Condition == nil {
		return fmt.Errorf("condition is required for while loops")
	}

	// Safety check for maximum iterations
	maxIterations := step.Loop.MaxIterations
	if maxIterations == 0 {
		maxIterations = 1000 // Default safety limit
	}

	e.logger.Info("Starting while loop",
		"step", step.Name,
		"max_iterations", maxIterations)

	// Execute loop
	iterations := 0
whileLoopExecute:
	for {
		iterations++
		if iterations > maxIterations {
			return fmt.Errorf("while loop exceeded maximum iterations: %d", maxIterations)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Get variables safely
		e.mutex.Lock()
		variablesCopy := make(map[string]interface{})
		for k, v := range execution.Variables {
			variablesCopy[k] = v
		}
		e.mutex.Unlock()

		// Evaluate condition
		shouldContinue, err := e.evaluateCondition(step.Loop.Condition, variablesCopy)
		if err != nil {
			return fmt.Errorf("failed to evaluate while condition: %w", err)
		}

		if !shouldContinue {
			break
		}

		// Execute child steps
		if err := e.executeSteps(ctx, step.Steps, execution); err != nil {
			// Check if it's a loop control error
			if loopErr, isLoopControl := err.(*LoopControlError); isLoopControl {
				switch loopErr.Type {
				case LoopControlBreak:
					// Break out of the loop
					e.logger.Debug("Breaking out of while loop", "step", loopErr.StepName, "iteration", iterations)
					goto whileLoopComplete
				case LoopControlContinue:
					// Continue to next iteration
					e.logger.Debug("Continuing while loop", "step", loopErr.StepName, "iteration", iterations)
					continue whileLoopExecute
				}
			}
			return fmt.Errorf("while loop iteration %d failed: %w", iterations, err)
		}
	}
whileLoopComplete:

	e.logger.Info("While loop completed",
		"step", step.Name,
		"iterations", iterations)

	return nil
}

// executeForeachStep executes a foreach loop workflow step
func (e *Engine) executeForeachStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Loop == nil {
		return fmt.Errorf("loop configuration is required for foreach steps")
	}

	if step.Loop.Type != LoopTypeForeach {
		return fmt.Errorf("foreach step requires loop type 'foreach', got '%s'", step.Loop.Type)
	}

	if step.Loop.Variable == "" {
		return fmt.Errorf("loop variable is required for foreach loops")
	}

	// Get collection to iterate over
	var items []interface{}
	var err error

	if step.Loop.ItemsVariable != "" {
		// Get items from variable
		itemsVar, exists := execution.GetVariable(step.Loop.ItemsVariable)

		if !exists {
			return fmt.Errorf("items variable '%s' not found", step.Loop.ItemsVariable)
		}

		items, err = e.convertToSlice(itemsVar)
		if err != nil {
			return fmt.Errorf("items variable '%s' is not a valid collection: %w", step.Loop.ItemsVariable, err)
		}
	} else if step.Loop.Items != nil {
		// Use direct items
		items, err = e.convertToSlice(step.Loop.Items)
		if err != nil {
			return fmt.Errorf("items is not a valid collection: %w", err)
		}
	} else {
		return fmt.Errorf("either items or items_variable is required for foreach loops")
	}

	// Safety check for maximum iterations
	maxIterations := step.Loop.MaxIterations
	if maxIterations == 0 {
		maxIterations = 1000 // Default safety limit
	}

	if len(items) > maxIterations {
		return fmt.Errorf("foreach loop collection size (%d) exceeds maximum iterations: %d", len(items), maxIterations)
	}

	e.logger.Info("Starting foreach loop",
		"step", step.Name,
		"variable", step.Loop.Variable,
		"items_count", len(items))

	// Execute loop
foreachLoopExecute:
	for index, item := range items {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Set loop variables safely
		execution.SetVariable(step.Loop.Variable, item)
		if step.Loop.IndexVariable != "" {
			execution.SetVariable(step.Loop.IndexVariable, index)
		}

		// Execute child steps
		if err := e.executeSteps(ctx, step.Steps, execution); err != nil {
			// Check if it's a loop control error
			if loopErr, isLoopControl := err.(*LoopControlError); isLoopControl {
				switch loopErr.Type {
				case LoopControlBreak:
					// Break out of the loop
					e.logger.Debug("Breaking out of foreach loop", "step", loopErr.StepName, "iteration", index)
					goto foreachLoopComplete
				case LoopControlContinue:
					// Continue to next iteration
					e.logger.Debug("Continuing foreach loop", "step", loopErr.StepName, "iteration", index)
					continue foreachLoopExecute
				}
			}
			return fmt.Errorf("foreach loop iteration %d failed: %w", index, err)
		}
	}
foreachLoopComplete:

	e.logger.Info("Foreach loop completed",
		"step", step.Name,
		"iterations", len(items))

	return nil
}

// resolveLoopValue resolves a loop value from variables or returns the literal value
func (e *Engine) resolveLoopValue(value interface{}, execution *WorkflowExecution) (int, error) {
	if value == nil {
		return 0, fmt.Errorf("value cannot be nil")
	}

	// If it's already an int, return it
	if intVal, ok := value.(int); ok {
		return intVal, nil
	}

	// If it's a string, check if it's a variable reference
	if strVal, ok := value.(string); ok {
		if strings.HasPrefix(strVal, "${") && strings.HasSuffix(strVal, "}") {
			// Variable reference
			varName := strVal[2 : len(strVal)-1]
			varValue, exists := execution.GetVariable(varName)

			if !exists {
				return 0, fmt.Errorf("variable '%s' not found", varName)
			}

			if intVal, ok := varValue.(int); ok {
				return intVal, nil
			}

			return 0, fmt.Errorf("variable '%s' is not an integer", varName)
		}

		// Try to parse as integer
		if intVal, err := e.parseInteger(strVal); err == nil {
			return intVal, nil
		}
	}

	// Try direct conversion
	if intVal, err := e.convertToInt(value); err == nil {
		return intVal, nil
	}

	return 0, fmt.Errorf("cannot convert value to integer: %v", value)
}

// convertToSlice converts various types to []interface{}
func (e *Engine) convertToSlice(value interface{}) ([]interface{}, error) {
	if value == nil {
		return nil, fmt.Errorf("value cannot be nil")
	}

	// If it's already a slice of interfaces, return it
	if slice, ok := value.([]interface{}); ok {
		return slice, nil
	}

	// If it's a slice of strings, convert it
	if strSlice, ok := value.([]string); ok {
		result := make([]interface{}, len(strSlice))
		for i, s := range strSlice {
			result[i] = s
		}
		return result, nil
	}

	// If it's a slice of ints, convert it
	if intSlice, ok := value.([]int); ok {
		result := make([]interface{}, len(intSlice))
		for i, n := range intSlice {
			result[i] = n
		}
		return result, nil
	}

	return nil, fmt.Errorf("value is not a valid collection type")
}

// convertToInt converts various numeric types to int
func (e *Engine) convertToInt(value interface{}) (int, error) {
	switch v := value.(type) {
	case int:
		return v, nil
	case int32:
		return int(v), nil
	case int64:
		return int(v), nil
	case float32:
		return int(v), nil
	case float64:
		return int(v), nil
	default:
		return 0, fmt.Errorf("cannot convert %T to int", value)
	}
}

// parseInteger parses a string as an integer (simple implementation)
func (e *Engine) parseInteger(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty string")
	}

	result := 0
	negative := false
	start := 0

	if s[0] == '-' {
		negative = true
		start = 1
	}

	for i := start; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("invalid character '%c' in number", s[i])
		}
		result = result*10 + int(s[i]-'0')
	}

	if negative {
		result = -result
	}

	return result, nil
}
