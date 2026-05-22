// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package run

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	script "github.com/cfgis/cfgms/features/modules/script"
	"github.com/cfgis/cfgms/pkg/logging"
)

// capturingLogger records all log entries in memory for inspection.
// It implements the full logging.Logger interface so it can substitute
// for any logger in tests.
type capturingLogger struct {
	entries []string
}

func (l *capturingLogger) append(level, msg string, keysAndValues ...interface{}) {
	var sb strings.Builder
	sb.WriteString(level)
	sb.WriteString(" ")
	sb.WriteString(msg)
	for i := 0; i+1 < len(keysAndValues); i += 2 {
		fmt.Fprintf(&sb, " %v=%v", keysAndValues[i], keysAndValues[i+1])
	}
	l.entries = append(l.entries, sb.String())
}

func (l *capturingLogger) Debug(msg string, kv ...interface{}) { l.append("DEBUG", msg, kv...) }
func (l *capturingLogger) Info(msg string, kv ...interface{})  { l.append("INFO", msg, kv...) }
func (l *capturingLogger) Warn(msg string, kv ...interface{})  { l.append("WARN", msg, kv...) }
func (l *capturingLogger) Error(msg string, kv ...interface{}) { l.append("ERROR", msg, kv...) }
func (l *capturingLogger) Fatal(msg string, kv ...interface{}) { l.append("FATAL", msg, kv...) }

func (l *capturingLogger) DebugCtx(_ context.Context, msg string, kv ...interface{}) {
	l.append("DEBUG", msg, kv...)
}
func (l *capturingLogger) InfoCtx(_ context.Context, msg string, kv ...interface{}) {
	l.append("INFO", msg, kv...)
}
func (l *capturingLogger) WarnCtx(_ context.Context, msg string, kv ...interface{}) {
	l.append("WARN", msg, kv...)
}
func (l *capturingLogger) ErrorCtx(_ context.Context, msg string, kv ...interface{}) {
	l.append("ERROR", msg, kv...)
}
func (l *capturingLogger) FatalCtx(_ context.Context, msg string, kv ...interface{}) {
	l.append("FATAL", msg, kv...)
}

var _ logging.Logger = (*capturingLogger)(nil)

func (l *capturingLogger) combined() string {
	return strings.Join(l.entries, "\n")
}

// sampleScriptMeta returns a ScriptMetadata with three parameters for testing resolution.
func sampleScriptMeta() *script.ScriptMetadata {
	return &script.ScriptMetadata{
		ID:       "script-test",
		Name:     "Test Script",
		Version:  &script.Version{Major: 1},
		Shell:    script.ShellBash,
		Platform: []string{"linux"},
		Parameters: []script.ScriptParameter{
			{
				Name:     "runtime_param",
				Type:     "string",
				Required: true,
				Default:  nil,
				DNAPath:  "device.runtime",
			},
			{
				Name:    "dna_param",
				Type:    "string",
				DNAPath: "device.os",
			},
			{
				Name:    "default_param",
				Type:    "string",
				Default: "fallback-value",
			},
		},
	}
}

// [REQUIRED TEST] Verifies that runtime overrides, DNA bindings, and static defaults
// each resolve correctly for the parameter they own.
func TestResolveParams_ThreeSourceCombined(t *testing.T) {
	meta := sampleScriptMeta()

	runtimeParams := map[string]string{
		"runtime_param": "runtime-value",
	}
	// Admin binding: for "dna_param", use path "device.operating_system" (overrides DNAPath)
	platformBindings := map[string]string{
		"dna_param": "device.operating_system",
	}
	stewardDNA := map[string]string{
		"device.os":               "linux",        // matches DNAPath (but admin binding takes precedence)
		"device.operating_system": "ubuntu-20.04", // matches admin binding path
		"device.runtime":          "go-1.21",
	}

	resolved, err := ResolveParams(nil, meta, platformBindings, runtimeParams, stewardDNA)
	require.NoError(t, err)

	// Priority 1: runtime override wins for runtime_param
	assert.Equal(t, "runtime-value", resolved["runtime_param"],
		"runtime_param must come from runtimeParams")

	// Priority 2a: admin binding wins for dna_param (uses device.operating_system, not device.os)
	assert.Equal(t, "ubuntu-20.04", resolved["dna_param"],
		"dna_param must use admin-configured binding path, not DNAPath")

	// Priority 3: default for default_param
	assert.Equal(t, "fallback-value", resolved["default_param"],
		"default_param must come from ScriptParameter.Default")
}

// [REQUIRED TEST] A required parameter with no value from any source returns an error.
func TestResolveParams_MissingRequired_ReturnsError(t *testing.T) {
	meta := &script.ScriptMetadata{
		ID:       "script-req",
		Name:     "Required Param Script",
		Version:  &script.Version{Major: 1},
		Shell:    script.ShellBash,
		Platform: []string{"linux"},
		Parameters: []script.ScriptParameter{
			{Name: "required_field", Type: "string", Required: true},
		},
	}

	_, err := ResolveParams(nil, meta, nil, nil, nil)
	require.Error(t, err, "should fail when required parameter has no value")
	assert.Contains(t, err.Error(), "required_field",
		"error must name the missing required parameter")
}

// [REQUIRED TEST] Verify that resolved parameter VALUES never appear in log output;
// only parameter names and source key paths are logged.
func TestResolveParams_NoValuesInLogs(t *testing.T) {
	logger := &capturingLogger{}

	meta := sampleScriptMeta()
	runtimeParams := map[string]string{
		"runtime_param": "secret-runtime-value",
	}
	platformBindings := map[string]string{
		"dna_param": "device.os",
	}
	stewardDNA := map[string]string{
		"device.os":      "secret-os-value",
		"device.runtime": "secret-runtime-value",
	}

	resolved, err := ResolveParams(logger, meta, platformBindings, runtimeParams, stewardDNA)
	require.NoError(t, err)
	require.NotEmpty(t, resolved)

	logOutput := logger.combined()

	// Values must not appear anywhere in log output.
	assert.NotContains(t, logOutput, "secret-runtime-value",
		"runtime param value must not appear in logs")
	assert.NotContains(t, logOutput, "secret-os-value",
		"DNA-sourced param value must not appear in logs")
	assert.NotContains(t, logOutput, "fallback-value",
		"default param value must not appear in logs")

	// Param names and source paths are allowed (and expected).
	assert.Contains(t, logOutput, "runtime_param",
		"param name must appear in log for traceability")
	assert.Contains(t, logOutput, "dna_param",
		"param name must appear in log for traceability")
}

// TestResolveParams_RuntimeOverrideTakesPriority verifies the runtime override wins
// over both DNA binding and the static default for the same parameter.
func TestResolveParams_RuntimeOverrideTakesPriority(t *testing.T) {
	meta := &script.ScriptMetadata{
		ID:       "script-prio",
		Name:     "Priority Test",
		Version:  &script.Version{Major: 1},
		Shell:    script.ShellBash,
		Platform: []string{"linux"},
		Parameters: []script.ScriptParameter{
			{Name: "p", Type: "string", DNAPath: "dna.p", Default: "default-p"},
		},
	}

	resolved, err := ResolveParams(
		nil,
		meta,
		map[string]string{"p": "dna.p"}, // admin binding
		map[string]string{"p": "runtime-wins"},
		map[string]string{"dna.p": "dna-value"},
	)
	require.NoError(t, err)
	assert.Equal(t, "runtime-wins", resolved["p"],
		"runtime override must win over DNA and default")
}

// TestResolveParams_AdminBindingTakesPriorityOverDNAPath verifies that
// ParamPlatformBindings overrides ScriptParameter.DNAPath for the same parameter.
func TestResolveParams_AdminBindingTakesPriorityOverDNAPath(t *testing.T) {
	meta := &script.ScriptMetadata{
		ID:       "script-binding",
		Name:     "Binding Priority Test",
		Version:  &script.Version{Major: 1},
		Shell:    script.ShellBash,
		Platform: []string{"linux"},
		Parameters: []script.ScriptParameter{
			{Name: "param", Type: "string", DNAPath: "dna.author_path"},
		},
	}

	stewardDNA := map[string]string{
		"dna.author_path": "author-value",
		"dna.admin_path":  "admin-value",
	}
	// Admin binding overrides the author's DNAPath
	platformBindings := map[string]string{
		"param": "dna.admin_path",
	}

	resolved, err := ResolveParams(nil, meta, platformBindings, nil, stewardDNA)
	require.NoError(t, err)
	assert.Equal(t, "admin-value", resolved["param"],
		"admin-configured DNA path must take precedence over author DNAPath")
}

// TestResolveParams_DNAPathFallback verifies the author-defined DNAPath is used
// when no admin binding is configured for that parameter.
func TestResolveParams_DNAPathFallback(t *testing.T) {
	meta := &script.ScriptMetadata{
		ID:       "script-dnapath",
		Name:     "DNA Path Fallback Test",
		Version:  &script.Version{Major: 1},
		Shell:    script.ShellBash,
		Platform: []string{"linux"},
		Parameters: []script.ScriptParameter{
			{Name: "os", Type: "string", DNAPath: "device.os"},
		},
	}

	stewardDNA := map[string]string{"device.os": "linux"}

	resolved, err := ResolveParams(nil, meta, nil, nil, stewardDNA)
	require.NoError(t, err)
	assert.Equal(t, "linux", resolved["os"],
		"parameter must resolve from ScriptParameter.DNAPath when no admin binding")
}

// TestResolveParams_StaticDefault verifies the static default is used when no
// runtime override or DNA binding exists.
func TestResolveParams_StaticDefault(t *testing.T) {
	meta := &script.ScriptMetadata{
		ID:       "script-default",
		Name:     "Default Test",
		Version:  &script.Version{Major: 1},
		Shell:    script.ShellBash,
		Platform: []string{"linux"},
		Parameters: []script.ScriptParameter{
			{Name: "timeout", Type: "int", Default: 30},
		},
	}

	resolved, err := ResolveParams(nil, meta, nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "30", resolved["timeout"],
		"parameter must resolve to string representation of Default value")
}

// TestResolveParams_OptionalParam_NoValueOmitted verifies that optional parameters
// with no value from any source are omitted from the resolved map (not an error).
func TestResolveParams_OptionalParam_NoValueOmitted(t *testing.T) {
	meta := &script.ScriptMetadata{
		ID:       "script-optional",
		Name:     "Optional Param Test",
		Version:  &script.Version{Major: 1},
		Shell:    script.ShellBash,
		Platform: []string{"linux"},
		Parameters: []script.ScriptParameter{
			{Name: "opt", Type: "string", Required: false},
		},
	}

	resolved, err := ResolveParams(nil, meta, nil, nil, nil)
	require.NoError(t, err)
	_, present := resolved["opt"]
	assert.False(t, present, "optional param with no value must be omitted, not an error")
}

// TestResolveParams_NilMetadata_PassesThroughRuntimeParams verifies that when
// no script metadata is available (e.g. inline command runs), runtime params
// are returned unchanged.
func TestResolveParams_NilMetadata_PassesThroughRuntimeParams(t *testing.T) {
	runtimeParams := map[string]string{"key": "value", "env": "prod"}

	resolved, err := ResolveParams(nil, nil, nil, runtimeParams, nil)
	require.NoError(t, err)
	assert.Equal(t, runtimeParams, resolved,
		"nil metadata must pass runtime params through unchanged")
}

// TestResolveParams_AdminBindingPathMissing_FallsBackToDNAPath verifies that when
// the admin-configured DNA path key is not present in the steward's DNA attributes,
// resolution falls back to the author's DNAPath.
func TestResolveParams_AdminBindingPathMissing_FallsBackToDNAPath(t *testing.T) {
	meta := &script.ScriptMetadata{
		ID:       "script-fallback",
		Name:     "Admin Binding Fallback",
		Version:  &script.Version{Major: 1},
		Shell:    script.ShellBash,
		Platform: []string{"linux"},
		Parameters: []script.ScriptParameter{
			{Name: "p", Type: "string", DNAPath: "dna.fallback"},
		},
	}

	// Admin path is configured but not present in steward DNA
	platformBindings := map[string]string{"p": "dna.admin_missing"}
	stewardDNA := map[string]string{"dna.fallback": "fallback-from-dnapath"}

	resolved, err := ResolveParams(nil, meta, platformBindings, nil, stewardDNA)
	require.NoError(t, err)
	assert.Equal(t, "fallback-from-dnapath", resolved["p"],
		"when admin binding path is missing from DNA, must fall back to DNAPath")
}

// TestResolveParams_ExtraRuntimeParams_PassedThrough verifies that runtime params
// that are not declared in the script metadata are still included in the output.
func TestResolveParams_ExtraRuntimeParams_PassedThrough(t *testing.T) {
	meta := &script.ScriptMetadata{
		ID:       "script-extra",
		Name:     "Extra Params Test",
		Version:  &script.Version{Major: 1},
		Shell:    script.ShellBash,
		Platform: []string{"linux"},
		Parameters: []script.ScriptParameter{
			{Name: "declared", Type: "string", Default: "default-val"},
		},
	}

	runtimeParams := map[string]string{
		"declared":   "runtime-override",
		"undeclared": "extra-value",
	}

	resolved, err := ResolveParams(nil, meta, nil, runtimeParams, nil)
	require.NoError(t, err)
	assert.Equal(t, "runtime-override", resolved["declared"])
	assert.Equal(t, "extra-value", resolved["undeclared"],
		"undeclared runtime params must pass through to resolved map")
}

// TestResolveParams_EmptyRuntimeAndDNA_UsesDefault verifies that with empty runtime
// params and empty DNA, only the static default is used.
func TestResolveParams_EmptyRuntimeAndDNA_UsesDefault(t *testing.T) {
	meta := &script.ScriptMetadata{
		ID:       "script-empty",
		Name:     "Empty Sources Test",
		Version:  &script.Version{Major: 1},
		Shell:    script.ShellBash,
		Platform: []string{"linux"},
		Parameters: []script.ScriptParameter{
			{Name: "p", Type: "string", Default: "static-default"},
		},
	}

	resolved, err := ResolveParams(nil, meta, map[string]string{}, map[string]string{}, map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, "static-default", resolved["p"])
}
