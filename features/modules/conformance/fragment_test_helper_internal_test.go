// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package conformance

// Internal tests for checkObserveReadOnly — the unexported two-layer logic
// behind AssertObserveReadOnly. Testing the logic function directly avoids the
// *testing.T mock constraint (testing.TB's unexported private() method prevents
// external implementations) while still covering both the passing and failing
// cases that the acceptance criteria require.

import (
	"testing"

	"github.com/cfgis/cfgms/features/modules"
)

// TestCheckObserveReadOnly_Pass_ReadOnlyEnvelope verifies that an envelope with
// only reads_paths declared (no writes_paths) produces no violations.
func TestCheckObserveReadOnly_Pass_ReadOnlyEnvelope(t *testing.T) {
	t.Helper()
	envelope := &modules.BehavioralEnvelope{
		ReadsPaths: []string{"/etc/hosts", "/etc/ssl/certs"},
	}
	commands := []string{
		"Get-Cluster -Name cfg-lab",
		"Get-VM",
		"Get-VMSwitch",
	}
	violations := checkObserveReadOnly(envelope, commands)
	if len(violations) > 0 {
		t.Errorf("expected no violations for a read-only envelope, got %v", violations)
	}
}

// TestCheckObserveReadOnly_Pass_NilEnvelope verifies that a nil envelope (no
// behavioral_envelope in module.yaml) is treated as no declared writes.
func TestCheckObserveReadOnly_Pass_NilEnvelope(t *testing.T) {
	violations := checkObserveReadOnly(nil, nil)
	if len(violations) > 0 {
		t.Errorf("expected no violations for nil envelope, got %v", violations)
	}
}

// TestCheckObserveReadOnly_Fail_WritesPaths verifies that a non-empty
// writes_paths in the envelope produces a Layer 1 violation (ADR-024 §4).
func TestCheckObserveReadOnly_Fail_WritesPaths(t *testing.T) {
	envelope := &modules.BehavioralEnvelope{
		WritesPaths: []string{"/var/lib/cfgms", "/etc/cfgms.conf"},
	}
	violations := checkObserveReadOnly(envelope, nil)
	if len(violations) == 0 {
		t.Errorf("expected a violation for envelope with writes_paths, got none")
	}
	// Must reference the declared paths so a reader can see what was flagged.
	for _, v := range violations {
		if len(v) == 0 {
			t.Errorf("violation message must not be empty")
		}
	}
}

// TestCheckObserveReadOnly_Fail_NewVerb verifies that a command containing
// "New-" is caught by the Layer 2 verb-prefix check (ADR-024 §4).
func TestCheckObserveReadOnly_Fail_NewVerb(t *testing.T) {
	envelope := &modules.BehavioralEnvelope{}
	commands := []string{
		"Get-VM",
		"New-VM -Name web-01 -Generation 2",
	}
	violations := checkObserveReadOnly(envelope, commands)
	if len(violations) == 0 {
		t.Errorf("expected a violation for command with New- verb, got none")
	}
}

// TestCheckObserveReadOnly_Fail_SetVerb verifies that a command containing
// "Set-" is caught by the Layer 2 verb-prefix check.
func TestCheckObserveReadOnly_Fail_SetVerb(t *testing.T) {
	envelope := &modules.BehavioralEnvelope{}
	commands := []string{"Set-VM -Name web-01 -ProcessorCount 4"}
	violations := checkObserveReadOnly(envelope, commands)
	if len(violations) == 0 {
		t.Errorf("expected a violation for command with Set- verb, got none")
	}
}

// TestCheckObserveReadOnly_Fail_RemoveVerb verifies that a command containing
// "Remove-" is caught by the Layer 2 verb-prefix check.
func TestCheckObserveReadOnly_Fail_RemoveVerb(t *testing.T) {
	envelope := &modules.BehavioralEnvelope{}
	commands := []string{"Remove-VM -Name web-01"}
	violations := checkObserveReadOnly(envelope, commands)
	if len(violations) == 0 {
		t.Errorf("expected a violation for command with Remove- verb, got none")
	}
}

// TestCheckObserveReadOnly_Fail_AddVerb verifies that a command containing
// "Add-" is caught by the Layer 2 verb-prefix check.
func TestCheckObserveReadOnly_Fail_AddVerb(t *testing.T) {
	envelope := &modules.BehavioralEnvelope{}
	commands := []string{"Add-VMNetworkAdapter -VMName web-01"}
	violations := checkObserveReadOnly(envelope, commands)
	if len(violations) == 0 {
		t.Errorf("expected a violation for command with Add- verb, got none")
	}
}

// TestCheckObserveReadOnly_Fail_BothLayers verifies that violations from both
// layers are accumulated when an envelope declares writes_paths AND a command
// contains a mutating verb.
func TestCheckObserveReadOnly_Fail_BothLayers(t *testing.T) {
	envelope := &modules.BehavioralEnvelope{
		WritesPaths: []string{"/etc/foo"},
	}
	commands := []string{"Set-Item -Path /etc/foo -Value bar"}
	violations := checkObserveReadOnly(envelope, commands)
	if len(violations) < 2 {
		t.Errorf("expected at least 2 violations (one per layer), got %d: %v", len(violations), violations)
	}
}
