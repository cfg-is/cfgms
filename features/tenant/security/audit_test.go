// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package security

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"

	// Register storage providers
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// newTestAuditManager creates a real audit.Manager backed by OSS storage for tests.
// Registers cleanup via tb.Cleanup. Accepts testing.TB so it works in both
// *testing.T and *testing.B contexts.
func newTestAuditManager(tb testing.TB) *audit.Manager {
	tb.Helper()
	tmpDir := tb.TempDir()
	sm, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = sm.Close() })

	mgr, err := audit.NewManager(sm.GetAuditStore(), "tenant-security-test")
	require.NoError(tb, err)
	tb.Cleanup(func() {
		// 30s gives the drain goroutine enough time to flush queued entries on
		// slow CI runners (Windows especially). The flatfile store performs a
		// sequential GetLastAuditEntry scan per entry — for tests that write
		// 1000+ entries this can take well over 5 s on Windows CI.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = mgr.Stop(ctx)
	})
	return mgr
}

// newTestAuditLogger creates a TenantSecurityAuditLogger backed by a real audit.Manager.
// Accepts testing.TB so it works in both *testing.T and *testing.B contexts.
func newTestAuditLogger(tb testing.TB) *TenantSecurityAuditLogger {
	tb.Helper()
	return NewTenantSecurityAuditLogger(newTestAuditManager(tb))
}

// newTenantSecurityAuditLoggerWithCap creates a logger with a custom in-memory cap.
// Use this in cap-eviction and FIFO tests to avoid writing thousands of durable entries
// on slow platforms (Windows CI): a small cap like 10–12 exercises the same eviction
// logic as cap=1000 but with far fewer flatfile writes.
func newTenantSecurityAuditLoggerWithCap(tb testing.TB, cap int) *TenantSecurityAuditLogger {
	tb.Helper()
	mgr := newTestAuditManager(tb)
	return &TenantSecurityAuditLogger{
		auditManager: mgr,
		entries:      make([]TenantSecurityAuditEntry, 0, cap),
		cap:          cap,
		logger:       slog.Default(),
	}
}

// TestTenantSecurityAuditLogger_ForwardsToAuditManager verifies that each of the
// four core Log* methods writes a durable event to pkg/audit.Manager.
func TestTenantSecurityAuditLogger_ForwardsToAuditManager(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()
	sm, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	auditMgr, err := audit.NewManager(sm.GetAuditStore(), "tenant-security-test")
	require.NoError(t, err)
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = auditMgr.Stop(stopCtx)
	})

	logger := NewTenantSecurityAuditLogger(auditMgr)

	t.Run("LogIsolationRuleChange", func(t *testing.T) {
		newRule := &IsolationRule{
			TenantID:        "tenant-iso",
			ComplianceLevel: ComplianceLevelBasic,
			DataResidency:   DataResidencyRule{RequireEncryption: true, EncryptionLevel: "standard"},
		}
		err := logger.LogIsolationRuleChange(ctx, "create", "tenant-iso", newRule, nil)
		require.NoError(t, err)

		flushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		require.NoError(t, auditMgr.Flush(flushCtx))

		entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{
			TenantID:      "tenant-iso",
			Actions:       []string{"tenant.isolation.rule_change"},
			ResourceTypes: []string{"isolation_rule"},
		})
		require.NoError(t, err)
		assert.Len(t, entries, 1, "expected one durable audit entry for isolation rule change")
	})

	t.Run("LogAccessAttempt", func(t *testing.T) {
		request := &TenantAccessRequest{
			SubjectID:       "user-abc",
			SubjectTenantID: "tenant-access",
			TargetTenantID:  "tenant-access",
			ResourceID:      "resource-1",
			AccessLevel:     CrossTenantLevelRead,
			Context:         map[string]string{},
		}
		response := &TenantAccessResponse{
			Granted: true,
			Reason:  "allowed",
		}
		err := logger.LogAccessAttempt(ctx, request, response)
		require.NoError(t, err)

		flushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		require.NoError(t, auditMgr.Flush(flushCtx))

		entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{
			TenantID:      "tenant-access",
			Actions:       []string{"tenant.access.attempt"},
			ResourceTypes: []string{"tenant_access"},
		})
		require.NoError(t, err)
		assert.Len(t, entries, 1, "expected one durable audit entry for access attempt")
		assert.Equal(t, string(business.AuditResultSuccess), string(entries[0].Result))
	})

	t.Run("LogAccessAttempt_Denied", func(t *testing.T) {
		request := &TenantAccessRequest{
			SubjectID:       "user-denied",
			SubjectTenantID: "tenant-denied",
			TargetTenantID:  "tenant-denied",
			ResourceID:      "resource-2",
			AccessLevel:     CrossTenantLevelRead,
			Context:         map[string]string{},
		}
		response := &TenantAccessResponse{
			Granted: false,
			Reason:  "no permission",
		}
		err := logger.LogAccessAttempt(ctx, request, response)
		require.NoError(t, err)

		flushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		require.NoError(t, auditMgr.Flush(flushCtx))

		entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{
			TenantID:      "tenant-denied",
			Actions:       []string{"tenant.access.attempt"},
			ResourceTypes: []string{"tenant_access"},
		})
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, string(business.AuditResultDenied), string(entries[0].Result))
	})

	t.Run("LogPolicyViolation", func(t *testing.T) {
		err := logger.LogPolicyViolation(ctx, "tenant-pol", "subject-x", "policy-123", "exceeded quota", map[string]interface{}{
			"quota_type": "api_calls",
		})
		require.NoError(t, err)

		flushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		require.NoError(t, auditMgr.Flush(flushCtx))

		entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{
			TenantID:      "tenant-pol",
			Actions:       []string{"tenant.policy.violation"},
			ResourceTypes: []string{"policy"},
		})
		require.NoError(t, err)
		assert.Len(t, entries, 1, "expected one durable audit entry for policy violation")
		assert.Equal(t, string(business.AuditResultError), string(entries[0].Result))
	})

	t.Run("LogComplianceViolation", func(t *testing.T) {
		err := logger.LogComplianceViolation(ctx, "tenant-comp", "HIPAA", "§164.312(a)(1)", "missing access control")
		require.NoError(t, err)

		flushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		require.NoError(t, auditMgr.Flush(flushCtx))

		entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{
			TenantID:      "tenant-comp",
			Actions:       []string{"tenant.compliance.violation"},
			ResourceTypes: []string{"compliance_framework"},
		})
		require.NoError(t, err)
		assert.Len(t, entries, 1, "expected one durable audit entry for compliance violation")
		assert.Equal(t, string(business.AuditResultError), string(entries[0].Result))
	})
}

// TestTenantSecurityAuditLogger_CapEviction verifies that writing 1100 entries leaves
// exactly 1000 in memory (oldest 100 dropped) while all 1100 are in durable storage.
func TestTenantSecurityAuditLogger_CapEviction(t *testing.T) {
	ctx := context.Background()
	const writeCount = 1100

	tmpDir := t.TempDir()
	sm, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	auditMgr, err := audit.NewManager(sm.GetAuditStore(), "tenant-security-cap-test")
	require.NoError(t, err)
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = auditMgr.Stop(stopCtx)
	})

	logger := NewTenantSecurityAuditLogger(auditMgr)

	// Write in batches (each < the audit queue capacity of 1024) with a flush
	// between them, so no entries are dropped from the durable store.
	// Batch size is kept well under 1024 to avoid queue pressure.
	const batchSize = 200
	for i := 0; i < writeCount; i++ {
		err := logger.LogPolicyViolation(ctx,
			"tenant-cap",
			fmt.Sprintf("subject-%d", i),
			fmt.Sprintf("policy-%d", i),
			fmt.Sprintf("violation-%d", i),
			nil,
		)
		require.NoError(t, err)

		if (i+1)%batchSize == 0 {
			midFlushCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			require.NoError(t, auditMgr.Flush(midFlushCtx))
			cancel()
		}
	}

	// In-memory window must be capped at 1000.
	logger.mutex.RLock()
	inMemoryLen := len(logger.entries)
	logger.mutex.RUnlock()
	assert.Equal(t, defaultInMemoryAuditCap, inMemoryLen,
		"in-memory window should be capped at %d after %d writes", defaultInMemoryAuditCap, writeCount)

	// Durable store must contain all 1100 entries.
	// Use a 60-second timeout to match mid-batch flushes; macOS CI flatfile I/O
	// is slow enough that 10 seconds is insufficient for this volume.
	flushCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	require.NoError(t, auditMgr.Flush(flushCtx))

	durableEntries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{
		TenantID:      "tenant-cap",
		Actions:       []string{"tenant.policy.violation"},
		ResourceTypes: []string{"policy"},
		Limit:         writeCount + 100,
	})
	require.NoError(t, err)
	assert.Equal(t, writeCount, len(durableEntries),
		"durable store must contain all %d entries (cap is in-memory only)", writeCount)
}

// TestTenantSecurityAuditLogger_FIFOEvictionOrder verifies that after cap eviction
// the oldest entries are dropped and the newest are retained.
//
// Uses a small cap (10) so only 60 entries reach the durable store.  Writing 1050
// entries on Windows CI caused the flatfile drain goroutine to exceed its 30-second
// Stop timeout, leaving file handles open and failing TempDir cleanup.
func TestTenantSecurityAuditLogger_FIFOEvictionOrder(t *testing.T) {
	ctx := context.Background()
	const smallCap = 10
	const extraWrites = 50
	writeCount := smallCap + extraWrites

	logger := newTenantSecurityAuditLoggerWithCap(t, smallCap)

	for i := 0; i < writeCount; i++ {
		err := logger.LogPolicyViolation(ctx,
			"tenant-fifo",
			fmt.Sprintf("subject-%d", i),
			fmt.Sprintf("policy-%d", i),
			fmt.Sprintf("violation-%d", i),
			nil,
		)
		require.NoError(t, err)
	}

	logger.mutex.RLock()
	entries := make([]TenantSecurityAuditEntry, len(logger.entries))
	copy(entries, logger.entries)
	logger.mutex.RUnlock()

	require.Equal(t, smallCap, len(entries))

	// The first retained entry should reference policy-50 (oldest 50 were evicted).
	assert.Contains(t, entries[0].Details["policy_id"], "policy-50",
		"oldest %d entries should have been evicted; first retained entry should be policy-50", extraWrites)
	// The last entry should be the most recently written.
	assert.Contains(t, entries[smallCap-1].Details["policy_id"], fmt.Sprintf("policy-%d", writeCount-1),
		"last in-memory entry should be the most recently written")
}

// TestTenantSecurityAuditLogger_AuditFailurePreservesInMemory verifies that when
// RecordEvent fails the in-memory append still happens.
func TestTenantSecurityAuditLogger_AuditFailurePreservesInMemory(t *testing.T) {
	ctx := context.Background()

	// Use a real but stopped audit manager so RecordEvent will fail.
	auditMgr := newTestAuditManager(t)
	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	require.NoError(t, auditMgr.Stop(stopCtx))

	logger := NewTenantSecurityAuditLogger(auditMgr)

	// LogPolicyViolation should not return an error even if RecordEvent fails.
	err := logger.LogPolicyViolation(ctx, "tenant-fail", "subj", "pol", "violation", nil)
	require.NoError(t, err, "audit manager failure must not surface as an error to caller")

	logger.mutex.RLock()
	n := len(logger.entries)
	logger.mutex.RUnlock()
	assert.Equal(t, 1, n, "in-memory entry should exist even when durable write fails")
}

// TestTenantSecurityAuditLogger_CapAppliesToAllSixMethods verifies that the cap is
// enforced uniformly across all six Log* methods including the two vulnerability methods.
//
// Uses a small cap (12, divisible by 6) so only 22 entries reach the durable store.
// Writing 1010 entries on Windows CI caused the same flatfile-drain timeout issue as
// TestTenantSecurityAuditLogger_FIFOEvictionOrder.
func TestTenantSecurityAuditLogger_CapAppliesToAllSixMethods(t *testing.T) {
	ctx := context.Background()
	const smallCap = 12 // divisible by 6 — every method gets at least two writes
	logger := newTenantSecurityAuditLoggerWithCap(t, smallCap)

	// Write smallCap+10 entries via all six methods to exceed the cap.
	for i := 0; i < smallCap+10; i++ {
		switch i % 6 {
		case 0:
			require.NoError(t, logger.LogPolicyViolation(ctx, "t", "s", fmt.Sprintf("p-%d", i), "v", nil))
		case 1:
			require.NoError(t, logger.LogComplianceViolation(ctx, "t", "HIPAA", "req", fmt.Sprintf("v-%d", i)))
		case 2:
			require.NoError(t, logger.LogAccessAttempt(ctx, &TenantAccessRequest{
				SubjectID: "s", SubjectTenantID: "t", TargetTenantID: "t",
				Context: map[string]string{},
			}, &TenantAccessResponse{Granted: true}))
		case 3:
			require.NoError(t, logger.LogIsolationRuleChange(ctx, "update", "t",
				&IsolationRule{TenantID: "t", ComplianceLevel: ComplianceLevelBasic,
					DataResidency: DataResidencyRule{EncryptionLevel: "standard"}}, nil))
		case 4:
			require.NoError(t, logger.LogVulnerabilityStatusChange(ctx, fmt.Sprintf("vuln-%d", i), "t", "open"))
		case 5:
			require.NoError(t, logger.LogRemediationAction(ctx, fmt.Sprintf("vuln-%d", i), "patch"))
		}
	}

	logger.mutex.RLock()
	n := len(logger.entries)
	logger.mutex.RUnlock()
	assert.Equal(t, smallCap, n,
		"cap must apply uniformly across all six Log* methods")
}
