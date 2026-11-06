// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func approvalFixture() *VersionedScript {
	return &VersionedScript{
		Metadata: &ScriptMetadata{
			ID:      "disk-cleanup",
			Version: &Version{Major: 1, Minor: 2, Patch: 3},
			Shell:   ShellBash,
			Timeout: 5 * time.Minute,
			Parameters: []ScriptParameter{
				{Name: "mode", Type: "string", Default: "safe", AllowedValues: []string{"safe", "fast"}, DNAPath: "OS.Version"},
			},
		},
		Content: "echo hi",
		Hash:    "abc123",
	}
}

func TestScriptApprovalHash_Deterministic(t *testing.T) {
	a := ScriptApprovalHash("msp", approvalFixture())
	b := ScriptApprovalHash("msp", approvalFixture())
	require.NotEmpty(t, a)
	assert.Equal(t, a, b)
}

func TestScriptApprovalHash_ChangesOnEveryBoundField(t *testing.T) {
	base := ScriptApprovalHash("msp", approvalFixture())
	mutations := map[string]func(*VersionedScript){
		"shell":          func(v *VersionedScript) { v.Metadata.Shell = ShellPowerShell },
		"timeout":        func(v *VersionedScript) { v.Metadata.Timeout = time.Hour },
		"allowed values": func(v *VersionedScript) { v.Metadata.Parameters[0].AllowedValues = []string{"safe", "fast", "rm"} },
		"param type":     func(v *VersionedScript) { v.Metadata.Parameters[0].Type = "int" },
		"param default":  func(v *VersionedScript) { v.Metadata.Parameters[0].Default = "fast" },
		"param dna path": func(v *VersionedScript) { v.Metadata.Parameters[0].DNAPath = "OS.Name" },
		"param required": func(v *VersionedScript) { v.Metadata.Parameters[0].Required = true },
		"param added": func(v *VersionedScript) {
			v.Metadata.Parameters = append(v.Metadata.Parameters, ScriptParameter{Name: "x", Type: "string"})
		},
		"content hash": func(v *VersionedScript) { v.Hash = "def456" },
		"script id":    func(v *VersionedScript) { v.Metadata.ID = "other" },
		"version":      func(v *VersionedScript) { v.Metadata.Version = &Version{Major: 1, Minor: 2, Patch: 4} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			v := approvalFixture()
			mutate(v)
			assert.NotEqual(t, base, ScriptApprovalHash("msp", v))
		})
	}
}

func TestScriptApprovalHash_OwnerTenantIsBound(t *testing.T) {
	assert.NotEqual(t, ScriptApprovalHash("msp", approvalFixture()), ScriptApprovalHash("client-1", approvalFixture()))
}

func TestScriptApprovalHash_DescriptionIgnored(t *testing.T) {
	v := approvalFixture()
	v.Metadata.Parameters[0].Description = "docs only"
	assert.Equal(t, ScriptApprovalHash("msp", approvalFixture()), ScriptApprovalHash("msp", v))
}

func TestScriptApprovalHash_MapDefaultStable(t *testing.T) {
	a, b := approvalFixture(), approvalFixture()
	a.Metadata.Parameters[0].Default = map[string]any{"a": 1, "b": 2}
	b.Metadata.Parameters[0].Default = map[string]any{"b": 2, "a": 1}
	assert.Equal(t, ScriptApprovalHash("msp", a), ScriptApprovalHash("msp", b))
}

func TestScriptApprovalHash_NoMetadataIsEmpty(t *testing.T) {
	assert.Empty(t, ScriptApprovalHash("msp", nil))
	assert.Empty(t, ScriptApprovalHash("msp", &VersionedScript{Hash: "x"}))
}

func TestApprovalDigest_FieldBoundaries(t *testing.T) {
	assert.NotEqual(t, ApprovalDigest("d", "ab", "c"), ApprovalDigest("d", "a", "bc"))
	assert.NotEqual(t, ApprovalDigest("d1", "x"), ApprovalDigest("d2", "x"))
}

func TestScriptApprovalHash_UnencodableDefaultIsEmpty(t *testing.T) {
	v := approvalFixture()
	v.Metadata.Parameters[0].Default = make(chan int)
	assert.Empty(t, ScriptApprovalHash("msp", v))
}
