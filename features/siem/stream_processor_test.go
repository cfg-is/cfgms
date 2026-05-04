// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package siem

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// newTestAuditManager creates a real audit.Manager backed by OSS storage in a temp dir.
func newTestAuditManager(t *testing.T) *audit.Manager {
	t.Helper()
	return pkgtesting.SetupTestAuditManager(t)
}

// TestStreamProcessor_SecurityEventAuditEmission verifies that a pattern match
// produces an AuditEventSecurityEvent entry with rule_id in the audit store.
func TestStreamProcessor_SecurityEventAuditEmission(t *testing.T) {
	auditManager := newTestAuditManager(t)

	config := createTestConfig()
	patternMatcher := NewPatternMatcher()
	eventCorrelator := NewEventCorrelator(5 * time.Minute)
	ruleManager := NewRuleManager(patternMatcher, eventCorrelator)
	sp := NewStreamProcessor(config, patternMatcher, eventCorrelator, ruleManager, auditManager)

	ctx := context.Background()
	require.NoError(t, sp.Start(ctx))
	t.Cleanup(func() { _ = sp.Stop(ctx) })

	ruleID := "audit-test-rule"
	err := patternMatcher.AddPattern(&DetectionPattern{
		ID:          ruleID,
		Name:        "Audit Emission Test Pattern",
		Pattern:     "AUDIT_EMISSION_TEST",
		PatternType: PatternTypeContains,
		Fields:      []string{"message"},
		Enabled:     true,
		Priority:    1,
		CreatedAt:   time.Now(),
	})
	require.NoError(t, err)

	entry := interfaces.LogEntry{
		Timestamp:   time.Now(),
		Level:       "ERROR",
		Message:     "AUDIT_EMISSION_TEST detected suspicious activity",
		ServiceName: "test-service",
		TenantID:    "audit-test-tenant",
		Fields:      map[string]interface{}{"host": "10.0.0.1", "count": 3},
	}
	require.NoError(t, sp.ProcessEntry(ctx, entry))

	// Poll until the SIEM pipeline and audit drain goroutine have completed.
	// The SIEM pipeline is fully async (batch collector → distributor → worker → audit queue → drain),
	// so flush alone is insufficient without first waiting for pattern matching to emit to the queue.
	var entries []*business.AuditEntry
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		flushCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_ = auditManager.Flush(flushCtx)
		cancel()

		entries, err = auditManager.QueryEntries(ctx, &business.AuditFilter{
			TenantID:   "audit-test-tenant",
			EventTypes: []business.AuditEventType{business.AuditEventSecurityEvent},
		})
		require.NoError(t, err)
		if len(entries) >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	require.GreaterOrEqual(t, len(entries), 1,
		"expected at least one AuditEventSecurityEvent in the audit store")

	found := false
	for _, e := range entries {
		assert.Equal(t, business.AuditEventSecurityEvent, e.EventType)
		if e.Details != nil {
			if v, ok := e.Details["rule_id"]; ok && v == ruleID {
				found = true
				break
			}
		}
	}
	assert.True(t, found, "expected an audit entry with rule_id=%q", ruleID)
}

// TestStreamProcessor_SecurityEventAuditNilManager verifies that nil auditManager
// is handled gracefully — pattern matches are still processed without panics.
func TestStreamProcessor_SecurityEventAuditNilManager(t *testing.T) {
	config := createTestConfig()
	patternMatcher := NewPatternMatcher()
	eventCorrelator := NewEventCorrelator(5 * time.Minute)
	ruleManager := NewRuleManager(patternMatcher, eventCorrelator)
	sp := NewStreamProcessor(config, patternMatcher, eventCorrelator, ruleManager, nil)

	ctx := context.Background()
	require.NoError(t, sp.Start(ctx))
	t.Cleanup(func() { _ = sp.Stop(ctx) })

	require.NoError(t, patternMatcher.AddPattern(&DetectionPattern{
		ID:          "nil-manager-rule",
		Pattern:     "NIL_MANAGER_TEST",
		PatternType: PatternTypeContains,
		Fields:      []string{"message"},
		Enabled:     true,
		CreatedAt:   time.Now(),
	}))

	entry := interfaces.LogEntry{
		Timestamp:   time.Now(),
		Level:       "ERROR",
		Message:     "NIL_MANAGER_TEST event",
		ServiceName: "test-service",
		TenantID:    "test-tenant",
	}
	require.NoError(t, sp.ProcessEntry(ctx, entry))

	// Allow processing to complete without panicking
	time.Sleep(200 * time.Millisecond)

	metrics, err := sp.GetMetrics(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, metrics.EntriesProcessed, int64(1))
}

// TestSanitizedFields verifies that user-controlled values are sanitized against log injection.
func TestSanitizedFields(t *testing.T) {
	// Build a long value that exceeds the 1024-char truncation threshold
	longValue := make([]byte, 1200)
	for i := range longValue {
		longValue[i] = 'a'
	}

	fields := map[string]interface{}{
		"newline_injection": "before\nINJECTED_LINE", // CWE-117 log forgery via newline
		"ansi_escape":       "\x1b[31mRED\x1b[0m",    // ANSI color escape sequences
		"cr_injection":      "before\roverwritten",   // CWE-117 via carriage return
		"long_value":        string(longValue),       // must be truncated
		"safe_value":        "10.0.0.1",              // safe passthrough
		"numeric":           42,                      // numeric converted to string
	}

	result := sanitizedFields(fields)
	require.NotNil(t, result)
	assert.Len(t, result, len(fields))

	// Newline and carriage return injection must be neutralized
	assert.NotContains(t, result["newline_injection"], "\n",
		"newline must be replaced by sanitizer")
	assert.NotContains(t, result["cr_injection"], "\r",
		"carriage return must be replaced by sanitizer")

	// ANSI escape (\x1b) must be neutralized
	assert.NotContains(t, result["ansi_escape"], "\x1b",
		"ANSI escape must be replaced by sanitizer")

	// Long values must be truncated (SanitizeLogValue caps at 1024 chars)
	sanitized, ok := result["long_value"].(string)
	require.True(t, ok)
	assert.Less(t, len(sanitized), 1200, "long value must be truncated")
	assert.Contains(t, sanitized, "[truncated]", "truncated marker must be appended")

	// Safe ASCII passes through
	assert.Equal(t, "10.0.0.1", result["safe_value"])

	// Numeric value converted to string without control chars
	numStr, ok := result["numeric"].(string)
	require.True(t, ok)
	assert.Equal(t, "42", numStr)
}

// TestSanitizedFields_Nil verifies that nil input returns nil.
func TestSanitizedFields_Nil(t *testing.T) {
	assert.Nil(t, sanitizedFields(nil))
}
