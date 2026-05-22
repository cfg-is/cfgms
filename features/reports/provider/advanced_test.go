// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package provider

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/pkg/dna/drift"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestAdvancedProvider returns an AdvancedProvider with enough state for
// scoring tests (no storage.Manager or drift.Detector needed).
func newTestAdvancedProvider() *AdvancedProvider {
	logger := logging.NewNoopLogger()
	return &AdvancedProvider{
		DataProvider: &DataProvider{logger: logger},
		logger:       logger,
	}
}

// okRecords returns n DNA records all in "ok" status.
func okRecords(n int) []storage.DNARecord {
	recs := make([]storage.DNARecord, n)
	for i := range recs {
		recs[i] = storage.DNARecord{DeviceID: "device", Status: "ok"}
	}
	return recs
}

// --- CIS ---

func TestCalculateCISScore_NoData(t *testing.T) {
	p := newTestAdvancedProvider()
	score := p.calculateCISScore(nil, nil)
	// No config events → configScore=100; no DNA records → deviceScore=100; CIS=100
	assert.Equal(t, 100.0, score)
}

func TestCalculateCISScore_AllConfigFailures(t *testing.T) {
	p := newTestAdvancedProvider()

	entries := []business.AuditEntry{
		{EventType: business.AuditEventConfiguration, Result: business.AuditResultFailure},
		{EventType: business.AuditEventConfiguration, Result: business.AuditResultFailure},
	}

	score := p.calculateCISScore(nil, entries)
	// 0/2 config successes → configScore=0; no DNA records → deviceScore=100
	// CIS = 0*0.6 + 100*0.4 = 40
	assert.InDelta(t, 40.0, score, 0.01)
}

func TestCalculateCISScore_AllHealthyDevices(t *testing.T) {
	p := newTestAdvancedProvider()

	records := []storage.DNARecord{
		{DeviceID: "d1", Status: "ok"},
		{DeviceID: "d2", Status: "ok"},
		{DeviceID: "d3", Status: ""},
	}
	entries := []business.AuditEntry{
		{EventType: business.AuditEventConfiguration, Result: business.AuditResultSuccess},
	}

	score := p.calculateCISScore(records, entries)
	// 1/1 config success → configScore=100; 0/3 drifted → deviceScore=100; CIS=100
	assert.InDelta(t, 100.0, score, 0.01)
}

func TestCalculateCISScore_SomeDriftedDevices(t *testing.T) {
	p := newTestAdvancedProvider()

	records := []storage.DNARecord{
		{DeviceID: "d1", Status: "ok"},
		{DeviceID: "d2", Status: "error"},   // drifted
		{DeviceID: "d3", Status: "warning"}, // drifted
		{DeviceID: "d4", Status: "ok"},
	}

	score := p.calculateCISScore(records, nil)
	// No config events → configScore=100; 2/4 drifted → deviceScore=50
	// CIS = 100*0.6 + 50*0.4 = 80
	assert.InDelta(t, 80.0, score, 0.01)
}

func TestCalculateCISScore_MixedConfigAndDevices(t *testing.T) {
	p := newTestAdvancedProvider()

	records := []storage.DNARecord{
		{DeviceID: "d1", Status: "ok"},
		{DeviceID: "d2", Status: "error"}, // drifted
	}
	entries := []business.AuditEntry{
		{EventType: business.AuditEventConfiguration, Result: business.AuditResultSuccess},
		{EventType: business.AuditEventConfiguration, Result: business.AuditResultFailure},
	}

	score := p.calculateCISScore(records, entries)
	// configScore=50; deviceScore=50; CIS=50*0.6+50*0.4=50
	assert.InDelta(t, 50.0, score, 0.01)
}

// --- HIPAA ---

func TestCalculateHIPAAScore_AllAuthSuccesses(t *testing.T) {
	p := newTestAdvancedProvider()

	entries := []business.AuditEntry{
		{EventType: business.AuditEventAuthentication, Result: business.AuditResultSuccess},
		{EventType: business.AuditEventAuthentication, Result: business.AuditResultSuccess},
		{EventType: business.AuditEventAuthorization, Result: business.AuditResultSuccess},
	}

	score := p.calculateHIPAAScore(nil, entries)
	assert.InDelta(t, 100.0, score, 0.01)
}

func TestCalculateHIPAAScore_HalfAuthFailures(t *testing.T) {
	p := newTestAdvancedProvider()

	entries := []business.AuditEntry{
		{EventType: business.AuditEventAuthentication, Result: business.AuditResultSuccess},
		{EventType: business.AuditEventAuthentication, Result: business.AuditResultFailure},
		{EventType: business.AuditEventAuthorization, Result: business.AuditResultSuccess},
		{EventType: business.AuditEventAuthorization, Result: business.AuditResultError},
	}

	score := p.calculateHIPAAScore(nil, entries)
	// 2 failures out of 4 auth events → 50%
	assert.InDelta(t, 50.0, score, 0.01)
}

func TestCalculateHIPAAScore_FallbackToGeneralWithDNAData(t *testing.T) {
	p := newTestAdvancedProvider()

	// Non-auth events only, with healthy DNA records
	records := okRecords(4)
	entries := []business.AuditEntry{
		{EventType: business.AuditEventConfiguration, Result: business.AuditResultSuccess},
	}

	// No auth events → falls back to calculateGeneralComplianceScore
	score := p.calculateHIPAAScore(records, entries)
	assert.InDelta(t, 100.0, score, 0.01)
}

func TestCalculateHIPAAScore_AuthOnlyIsMeasured(t *testing.T) {
	p := newTestAdvancedProvider()

	// Mix of auth and non-auth; only auth events count toward HIPAA score
	entries := []business.AuditEntry{
		{EventType: business.AuditEventAuthentication, Result: business.AuditResultSuccess},
		{EventType: business.AuditEventAuthentication, Result: business.AuditResultFailure},
		{EventType: business.AuditEventConfiguration, Result: business.AuditResultFailure}, // ignored
		{EventType: business.AuditEventConfiguration, Result: business.AuditResultFailure}, // ignored
	}

	score := p.calculateHIPAAScore(nil, entries)
	// Only the 2 auth events matter: 1 success / 2 = 50%
	assert.InDelta(t, 50.0, score, 0.01)
}

// --- PCI-DSS ---

func TestCalculatePCIDSSScore_NoCriticalOrHigh(t *testing.T) {
	p := newTestAdvancedProvider()

	records := okRecords(2)
	entries := []business.AuditEntry{
		{EventType: business.AuditEventConfiguration, Severity: business.AuditSeverityLow, Result: business.AuditResultSuccess},
		{EventType: business.AuditEventConfiguration, Severity: business.AuditSeverityLow, Result: business.AuditResultSuccess},
	}

	score := p.calculatePCIDSSScore(records, entries)
	// No critical or high entries → penalty = 0; base ≈ 100
	assert.InDelta(t, 100.0, score, 0.01)
}

func TestCalculatePCIDSSScore_CriticalEventsReduceScore(t *testing.T) {
	p := newTestAdvancedProvider()

	records := okRecords(4)
	// 1 critical out of 2 total
	entries := []business.AuditEntry{
		{EventType: business.AuditEventSecurityEvent, Severity: business.AuditSeverityCritical, Result: business.AuditResultFailure},
		{EventType: business.AuditEventConfiguration, Severity: business.AuditSeverityLow, Result: business.AuditResultSuccess},
	}

	score := p.calculatePCIDSSScore(records, entries)
	assert.Greater(t, score, 0.0, "score must be positive")
	// Score should be less than the base (penalty applied)
	base := p.calculateGeneralComplianceScore(records, entries)
	assert.Less(t, score, base, "PCI-DSS critical penalty must reduce the score")
}

func TestCalculatePCIDSSScore_HighSeverityPenaltyLessThanCritical(t *testing.T) {
	p := newTestAdvancedProvider()

	records := okRecords(4)
	entriesHigh := []business.AuditEntry{
		{EventType: business.AuditEventSecurityEvent, Severity: business.AuditSeverityHigh, Result: business.AuditResultSuccess},
		{EventType: business.AuditEventConfiguration, Severity: business.AuditSeverityLow, Result: business.AuditResultSuccess},
	}
	entriesCritical := []business.AuditEntry{
		{EventType: business.AuditEventSecurityEvent, Severity: business.AuditSeverityCritical, Result: business.AuditResultSuccess},
		{EventType: business.AuditEventConfiguration, Severity: business.AuditSeverityLow, Result: business.AuditResultSuccess},
	}

	scoreHigh := p.calculatePCIDSSScore(records, entriesHigh)
	scoreCritical := p.calculatePCIDSSScore(records, entriesCritical)

	assert.Greater(t, scoreHigh, scoreCritical, "high-severity penalty must be smaller than critical")
}

func TestCalculatePCIDSSScore_FloorAtZero(t *testing.T) {
	p := newTestAdvancedProvider()

	entries := make([]business.AuditEntry, 10)
	for i := range entries {
		entries[i] = business.AuditEntry{
			EventType: business.AuditEventSecurityEvent,
			Severity:  business.AuditSeverityCritical,
			Result:    business.AuditResultFailure,
		}
	}

	score := p.calculatePCIDSSScore(nil, entries)
	assert.GreaterOrEqual(t, score, 0.0, "PCI-DSS score must not go below 0")
}

// --- hasDrift ---

func TestHasDrift_OKStatus(t *testing.T) {
	p := newTestAdvancedProvider()
	assert.False(t, p.hasDrift(storage.DNARecord{Status: "ok"}))
}

func TestHasDrift_EmptyStatus(t *testing.T) {
	p := newTestAdvancedProvider()
	assert.False(t, p.hasDrift(storage.DNARecord{Status: ""}))
}

func TestHasDrift_ErrorStatus(t *testing.T) {
	p := newTestAdvancedProvider()
	assert.True(t, p.hasDrift(storage.DNARecord{Status: "error"}))
}

func TestHasDrift_WarningStatus(t *testing.T) {
	p := newTestAdvancedProvider()
	assert.True(t, p.hasDrift(storage.DNARecord{Status: "warning"}))
}

// --- generateComplianceControls ---

func TestGenerateComplianceControls_AllHealthy(t *testing.T) {
	p := newTestAdvancedProvider()
	records := []storage.DNARecord{
		{DeviceID: "d1", Status: "ok"},
		{DeviceID: "d2", Status: "ok"},
	}

	controls := p.generateComplianceControls("CIS", records)
	require.Len(t, controls, 2)
	assert.Equal(t, "compliant", controls[0].Status)
	assert.InDelta(t, 100.0, controls[0].Score, 0.01)
}

func TestGenerateComplianceControls_SomeDrift(t *testing.T) {
	p := newTestAdvancedProvider()
	records := []storage.DNARecord{
		{DeviceID: "d1", Status: "ok"},
		{DeviceID: "d2", Status: "ok"},
		{DeviceID: "d3", Status: "error"},
		{DeviceID: "d4", Status: "error"},
	}

	controls := p.generateComplianceControls("HIPAA", records)
	require.Len(t, controls, 2)
	// 2/4 drifted → configScore=50.0 < 80.0 → non_compliant
	assert.Equal(t, "non_compliant", controls[0].Status)
	assert.InDelta(t, 50.0, controls[0].Score, 0.01)
}

// --- isCriticalDrift ---

func TestIsCriticalDrift_Critical(t *testing.T) {
	p := newTestAdvancedProvider()
	event := drift.DriftEvent{Severity: drift.SeverityCritical, Timestamp: time.Now()}
	assert.True(t, p.isCriticalDrift(event))
}

func TestIsCriticalDrift_Warning(t *testing.T) {
	p := newTestAdvancedProvider()
	event := drift.DriftEvent{Severity: drift.SeverityWarning, Timestamp: time.Now()}
	assert.True(t, p.isCriticalDrift(event))
}

func TestIsCriticalDrift_Info(t *testing.T) {
	p := newTestAdvancedProvider()
	event := drift.DriftEvent{Severity: drift.SeverityInfo, Timestamp: time.Now()}
	assert.False(t, p.isCriticalDrift(event))
}
