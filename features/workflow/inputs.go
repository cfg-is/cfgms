// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// InputType is the declared type of a workflow input.
type InputType string

const (
	// InputTypeString accepts any string value.
	InputTypeString InputType = "string"
	// InputTypeEnum accepts a string that is one of InputSpec.Options.
	InputTypeEnum InputType = "enum"
	// InputTypeBool accepts a boolean value.
	InputTypeBool InputType = "bool"
)

// InputSpec declares one typed input of a workflow. Inputs are data: their
// values are merged into the execution variables and are never evaluated as
// templates or code.
type InputSpec struct {
	Name        string      `yaml:"name" json:"name"`
	Type        InputType   `yaml:"type" json:"type"`
	Required    bool        `yaml:"required,omitempty" json:"required,omitempty"`
	Default     interface{} `yaml:"default,omitempty" json:"default,omitempty"`
	Options     []string    `yaml:"options,omitempty" json:"options,omitempty"`
	Description string      `yaml:"description,omitempty" json:"description,omitempty"`
}

// InputFieldError describes one input that violates its declaration. It names
// the field and the rule broken, never the supplied value.
type InputFieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// InputsError is returned when supplied inputs violate a workflow's declared
// inputs. It carries every violation, not just the first.
type InputsError struct {
	Fields []InputFieldError `json:"fields"`
}

func (e *InputsError) Error() string {
	parts := make([]string, len(e.Fields))
	for i, f := range e.Fields {
		parts[i] = f.Field + ": " + f.Message
	}
	return "invalid workflow inputs: " + strings.Join(parts, "; ")
}

// AsInputsError extracts an *InputsError from err's chain.
func AsInputsError(err error) (*InputsError, bool) {
	var ie *InputsError
	if errors.As(err, &ie) {
		return ie, true
	}
	return nil, false
}

var inputNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// reservedInputNames are names the engine owns; an input may not be declared
// with one (compared case-insensitively, ignoring '_' and '-'), so a supplied
// value can never shadow engine state such as the authenticated tenant
// (Issue #4338).
var reservedInputNames = map[string]bool{
	"tenantid": true, "tenant": true, "executionid": true, "workflowname": true,
	"workflow": true, "execution": true, "step": true, "steps": true,
	"variables": true, "inputs": true,
}

func isReservedInputName(name string) bool {
	n := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(name))
	return reservedInputNames[n]
}

// checkInputValue verifies v against spec's type, returning a message naming
// the rule broken (never the value).
func checkInputValue(spec InputSpec, v interface{}) string {
	switch spec.Type {
	case InputTypeBool:
		if _, ok := v.(bool); !ok {
			return "must be a boolean"
		}
	case InputTypeString:
		if _, ok := v.(string); !ok {
			return "must be a string"
		}
	case InputTypeEnum:
		s, ok := v.(string)
		if !ok {
			return "must be a string"
		}
		for _, o := range spec.Options {
			if o == s {
				return ""
			}
		}
		return "must be one of the declared options"
	}
	return ""
}

// ValidateInputSpecs checks the declaration itself: names, types, options and defaults.
func ValidateInputSpecs(specs []InputSpec) error {
	seen := make(map[string]bool, len(specs))
	for _, s := range specs {
		if s.Name == "" {
			return fmt.Errorf("input name is required")
		}
		if !inputNamePattern.MatchString(s.Name) {
			return fmt.Errorf("input %q: name must match %s", s.Name, inputNamePattern)
		}
		if isReservedInputName(s.Name) {
			return fmt.Errorf("input %q: name is reserved by the workflow engine", s.Name)
		}
		if seen[s.Name] {
			return fmt.Errorf("duplicate input name: %s", s.Name)
		}
		seen[s.Name] = true
		switch s.Type {
		case InputTypeString, InputTypeBool:
		case InputTypeEnum:
			if len(s.Options) == 0 {
				return fmt.Errorf("input %q: enum requires at least one option", s.Name)
			}
		default:
			return fmt.Errorf("input %q: unknown type %q (want string, enum or bool)", s.Name, s.Type)
		}
		if s.Type != InputTypeEnum && len(s.Options) > 0 {
			return fmt.Errorf("input %q: options are only valid for enum inputs", s.Name)
		}
		if s.Default != nil {
			if msg := checkInputValue(s, s.Default); msg != "" {
				return fmt.Errorf("input %q: default %s", s.Name, msg)
			}
		}
	}
	return nil
}

// ResolveInputs validates supplied against the declared inputs and returns the
// supplied values with defaults applied for omitted optional inputs. Values
// for names that are not declared pass through unchanged, preserving the
// free-form Variables semantics. A violation returns an *InputsError listing
// every offending field.
func (w Workflow) ResolveInputs(supplied map[string]interface{}) (map[string]interface{}, error) {
	resolved := make(map[string]interface{}, len(supplied)+len(w.Inputs))
	for k, v := range supplied {
		resolved[k] = v
	}
	var bad []InputFieldError
	for _, spec := range w.Inputs {
		v, ok := supplied[spec.Name]
		if !ok || v == nil {
			switch {
			case spec.Default != nil:
				resolved[spec.Name] = spec.Default
			case spec.Required:
				bad = append(bad, InputFieldError{Field: spec.Name, Message: "is required"})
			default:
				delete(resolved, spec.Name)
			}
			continue
		}
		if msg := checkInputValue(spec, v); msg != "" {
			bad = append(bad, InputFieldError{Field: spec.Name, Message: msg})
		}
	}
	if len(bad) > 0 {
		sort.SliceStable(bad, func(i, j int) bool { return bad[i].Field < bad[j].Field })
		return nil, &InputsError{Fields: bad}
	}
	return resolved, nil
}
