// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package script

import (
	"context"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// ParamSource identifies where a parameter value originates at execution time.
type ParamSource string

const (
	// ParamSourceSecretStore resolves the value from the steward secret store.
	ParamSourceSecretStore ParamSource = "secret-store"
	// ParamSourceLiteral uses the value field directly (non-secret runtime variable).
	ParamSourceLiteral ParamSource = "literal"
)

// ParamBinding declares how a single script parameter receives its value.
// Secret-store bindings are resolved at execution time; the value never touches
// the command line or script block content.
type ParamBinding struct {
	// Name is the parameter name (determines env var identifier).
	Name string `yaml:"name" json:"name"`
	// From identifies the value source ("secret-store" or "literal").
	From ParamSource `yaml:"from" json:"from"`
	// Key is the secret store lookup key (required when From == "secret-store").
	Key string `yaml:"key,omitempty" json:"key,omitempty"`
	// Value is the literal value (required when From == "literal").
	Value string `yaml:"value,omitempty" json:"value,omitempty"`
}

// ResolvedParam is a parameter with its value resolved and ready for injection.
type ResolvedParam struct {
	// Name is the parameter name.
	Name string
	// Value is the resolved plaintext value.
	Value string
	// IsSecret indicates whether this value came from the secret store.
	IsSecret bool
}

// ResolveSecretBindings resolves all parameter bindings, fetching secrets from
// the store as needed. If any secret-store key is missing the entire resolution
// fails — callers must not execute the script when this returns an error.
func ResolveSecretBindings(ctx context.Context, store interfaces.SecretStore, bindings []ParamBinding) ([]ResolvedParam, error) {
	resolved := make([]ResolvedParam, 0, len(bindings))

	for _, binding := range bindings {
		switch binding.From {
		case ParamSourceSecretStore:
			if binding.Key == "" {
				return nil, fmt.Errorf("param %q: key is required for from: secret-store", binding.Name)
			}
			secret, err := store.GetSecret(ctx, binding.Key)
			if err != nil {
				return nil, fmt.Errorf("secret resolution failed for param %q (key %q): %w", binding.Name, binding.Key, err)
			}
			resolved = append(resolved, ResolvedParam{
				Name:     binding.Name,
				Value:    secret.Value,
				IsSecret: true,
			})
		case ParamSourceLiteral:
			resolved = append(resolved, ResolvedParam{
				Name:     binding.Name,
				Value:    binding.Value,
				IsSecret: false,
			})
		default:
			return nil, fmt.Errorf("param %q: unknown source %q (must be %q or %q)",
				binding.Name, binding.From, ParamSourceSecretStore, ParamSourceLiteral)
		}
	}

	return resolved, nil
}

// SecretEnvVarName returns the environment variable name for a resolved secret param.
//   - PowerShell / CMD: CFGMS_SECRET_<PARAM_UPPER>  — avoids Event 4688 command-line leakage
//   - Bash / Zsh / Sh / Python: <PARAM_UPPER>       — 12-factor standard
func SecretEnvVarName(shell ShellType, paramName string) string {
	upper := strings.ToUpper(paramName)
	switch shell {
	case ShellPowerShell, ShellCmd:
		return "CFGMS_SECRET_" + upper
	default:
		return upper
	}
}
