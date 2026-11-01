// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package security_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant/security"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// newTestAuditManager creates a real audit.Manager backed by OSS storage for tests.
// Accepts testing.TB so it works in both *testing.T and *testing.B contexts.
func newTestAuditManager(tb testing.TB) *audit.Manager {
	tb.Helper()
	if t, ok := tb.(*testing.T); ok {
		return pkgtesting.SetupTestAuditManager(t)
	}
	// *testing.B path: construct directly; providers are registered via pkgtesting import.
	tmpDir := tb.TempDir()
	sm, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	if err != nil {
		tb.Fatalf("CreateOSSStorageManager: %v", err)
	}
	tb.Cleanup(func() { _ = sm.Close() })
	mgr, err := audit.NewManager(sm.GetAuditStore(), "tenant-security-test")
	if err != nil {
		tb.Fatalf("audit.NewManager: %v", err)
	}
	tb.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = mgr.Stop(ctx)
	})
	return mgr
}

// newTestAuditLogger creates a TenantSecurityAuditLogger backed by a real audit.Manager.
func newTestAuditLogger(tb testing.TB) *security.TenantSecurityAuditLogger {
	tb.Helper()
	return security.NewTenantSecurityAuditLogger(newTestAuditManager(tb))
}

func TestBreachDetector_RecordAccess(t *testing.T) {
	auditLogger := newTestAuditLogger(t)
	bd := security.NewBreachDetector(auditLogger, nil)
	ctx := context.Background()

	tests := []struct {
		name    string
		event   *security.AccessEvent
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid access event",
			event: &security.AccessEvent{
				ID:           "event-001",
				TenantID:     "550e8400-e29b-41d4-a716-446655440000",
				UserID:       "user-123",
				Operation:    "read",
				Resource:     "/api/v1/configs",
				SourceIP:     "192.168.1.100",
				UserAgent:    "Mozilla/5.0 (compatible; CFGMS-Client/1.0)",
				Timestamp:    time.Now(),
				Success:      true,
				ResponseTime: time.Millisecond * 250,
				DataSize:     1024,
			},
			wantErr: false,
		},
		{
			name: "invalid tenant ID",
			event: &security.AccessEvent{
				ID:        "event-002",
				TenantID:  "invalid-tenant",
				Operation: "read",
				Resource:  "/api/v1/configs",
				SourceIP:  "192.168.1.100",
				UserAgent: "Test-Agent",
				Timestamp: time.Now(),
				Success:   true,
			},
			wantErr: true,
			errMsg:  "invalid access event",
		},
		{
			name: "invalid IP address",
			event: &security.AccessEvent{
				ID:        "event-003",
				TenantID:  "550e8400-e29b-41d4-a716-446655440000",
				Operation: "read",
				Resource:  "/api/v1/configs",
				SourceIP:  "invalid-ip",
				UserAgent: "Test-Agent",
				Timestamp: time.Now(),
				Success:   true,
			},
			wantErr: true,
			errMsg:  "invalid access event",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := bd.RecordAccess(ctx, tt.event)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)

				// Verify the event was recorded via the public risk score API.
				riskScore := bd.GetTenantRiskScore(tt.event.TenantID)
				assert.GreaterOrEqual(t, riskScore, 0.0)
				assert.LessOrEqual(t, riskScore, 1.0)
			}
		})
	}
}

func TestBreachDetector_VolumeSpike(t *testing.T) {
	auditLogger := newTestAuditLogger(t)
	bd := security.NewBreachDetector(auditLogger, nil)
	ctx := context.Background()

	tenantID := "550e8400-e29b-41d4-a716-446655440000"

	// Create baseline with normal activity (50 requests over time)
	baseTime := time.Now().Add(-2 * time.Hour)
	for i := 0; i < 50; i++ {
		event := &security.AccessEvent{
			ID:        fmt.Sprintf("baseline-event-%d", i),
			TenantID:  tenantID,
			Operation: "read",
			Resource:  "/api/v1/configs",
			SourceIP:  "192.168.1.100",
			UserAgent: "Normal-Client/1.0",
			Timestamp: baseTime.Add(time.Duration(i) * time.Minute),
			Success:   true,
		}
		err := bd.RecordAccess(ctx, event)
		require.NoError(t, err)
	}

	// Create volume spike (many requests in current hour)
	now := time.Now()
	for i := 0; i < 160; i++ { // Increased to 160 to exceed threshold of 150
		event := &security.AccessEvent{
			ID:        fmt.Sprintf("spike-event-%d", i),
			TenantID:  tenantID,
			Operation: "read",
			Resource:  "/api/v1/configs",
			SourceIP:  "192.168.1.100",
			UserAgent: "Normal-Client/1.0",
			Timestamp: now, // Same timestamp to ensure all events are in the same hour
			Success:   true,
		}
		err := bd.RecordAccess(ctx, event)
		require.NoError(t, err)
	}

	// Volume spike detection raises the risk score
	riskScore := bd.GetTenantRiskScore(tenantID)
	assert.Greater(t, riskScore, 0.0, "Risk score should increase after volume spike")
}

func TestBreachDetector_FailedLoginDetection(t *testing.T) {
	auditLogger := newTestAuditLogger(t)
	bd := security.NewBreachDetector(auditLogger, nil)
	ctx := context.Background()

	tenantID := "550e8400-e29b-41d4-a716-446655440000"

	// Create multiple failed login attempts
	baseTime := time.Now()
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}

	for i := 0; i < 15; i++ {
		event := &security.AccessEvent{
			ID:        fmt.Sprintf("failed-login-%d", i),
			TenantID:  tenantID,
			Operation: "login",
			Resource:  "/auth/login",
			SourceIP:  ips[i%len(ips)],
			UserAgent: "Attacker-Bot/1.0",
			Timestamp: baseTime.Add(time.Duration(i) * time.Minute),
			Success:   false,
		}
		err := bd.RecordAccess(ctx, event)
		require.NoError(t, err)
	}

	// Failed login spike detection raises the risk score
	riskScore := bd.GetTenantRiskScore(tenantID)
	assert.Greater(t, riskScore, 0.0, "Risk score should increase after failed login spike")
}

func TestBreachDetector_NewLocationDetection(t *testing.T) {
	auditLogger := newTestAuditLogger(t)
	bd := security.NewBreachDetector(auditLogger, nil)
	ctx := context.Background()

	tenantID := "550e8400-e29b-41d4-a716-446655440000"

	// Establish baseline with typical IP
	baseTime := time.Now().Add(-1 * time.Hour)
	for i := 0; i < 20; i++ {
		event := &security.AccessEvent{
			ID:        fmt.Sprintf("baseline-event-%d", i),
			TenantID:  tenantID,
			Operation: "read",
			Resource:  "/api/v1/configs",
			SourceIP:  "198.51.100.10", // Typical IP (public for clear detection)
			UserAgent: "Normal-Client/1.0",
			Timestamp: baseTime.Add(time.Duration(i) * time.Minute),
			Success:   true,
		}
		err := bd.RecordAccess(ctx, event)
		require.NoError(t, err)
	}

	// Capture risk score before the new location event
	riskScoreBefore := bd.GetTenantRiskScore(tenantID)

	// Access from new location (external IP)
	event := &security.AccessEvent{
		ID:        "new-location-event",
		TenantID:  tenantID,
		Operation: "read",
		Resource:  "/api/v1/configs",
		SourceIP:  "203.0.113.50", // New external IP
		UserAgent: "Normal-Client/1.0",
		Timestamp: time.Now(),
		Success:   true,
	}
	err := bd.RecordAccess(ctx, event)
	require.NoError(t, err)

	// New location access should increase risk score
	riskScoreAfter := bd.GetTenantRiskScore(tenantID)
	assert.Greater(t, riskScoreAfter, riskScoreBefore, "New location access should increase risk score")
}

func TestBreachDetector_TimePatternDetection(t *testing.T) {
	auditLogger := newTestAuditLogger(t)
	bd := security.NewBreachDetector(auditLogger, nil)
	ctx := context.Background()

	tenantID := "550e8400-e29b-41d4-a716-446655440000"

	// Establish baseline during business hours (9 AM - 5 PM).
	// Use absolute clock hours via time.Date so updateActiveHours converges to 9-17.
	// time.Now().Add(N*time.Hour) was wrong here: it adds N hours to the current
	// clock time (yesterday-at-now-hour + N), not "yesterday at hour N" — when the
	// test ran at 14:35 the baseline populated hours 23,0-7 instead of 9-17 and the
	// 2 AM "out-of-hours" event below fell inside the detected active range.
	yesterday := time.Now().Add(-24 * time.Hour)
	for hour := 9; hour <= 17; hour++ {
		for i := 0; i < 5; i++ {
			event := &security.AccessEvent{
				ID:        fmt.Sprintf("business-hours-%d-%d", hour, i),
				TenantID:  tenantID,
				Operation: "read",
				Resource:  "/api/v1/configs",
				SourceIP:  "192.168.1.100",
				UserAgent: "Business-Client/1.0",
				Timestamp: time.Date(yesterday.Year(), yesterday.Month(), yesterday.Day(), hour, i*10, 0, 0, yesterday.Location()),
				Success:   true,
			}
			err := bd.RecordAccess(ctx, event)
			require.NoError(t, err)
		}
	}

	// Capture risk score before the out-of-hours event
	riskScoreBefore := bd.GetTenantRiskScore(tenantID)

	// Access outside business hours — use hour 2 which is always outside the 9–17 active window
	now := time.Now()
	twoAM := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, now.Location())
	event := &security.AccessEvent{
		ID:        "outside-hours-event",
		TenantID:  tenantID,
		Operation: "read",
		Resource:  "/api/v1/sensitive-data",
		SourceIP:  "192.168.1.100",
		UserAgent: "Business-Client/1.0",
		Timestamp: twoAM,
		Success:   true,
	}
	err := bd.RecordAccess(ctx, event)
	require.NoError(t, err)

	// Out-of-hours access should increase risk score above the business-hours baseline
	riskScoreAfter := bd.GetTenantRiskScore(tenantID)
	assert.Greater(t, riskScoreAfter, riskScoreBefore, "out-of-hours access should increase risk score")
}

func TestBreachDetector_CredentialStuffingPattern(t *testing.T) {
	auditLogger := newTestAuditLogger(t)
	bd := security.NewBreachDetector(auditLogger, nil)
	ctx := context.Background()

	tenantID := "550e8400-e29b-41d4-a716-446655440000"

	// Simulate credential stuffing attack: many failed logins from different IPs
	baseTime := time.Now()
	for i := 0; i < 25; i++ {
		event := &security.AccessEvent{
			ID:        fmt.Sprintf("credential-stuffing-%d", i),
			TenantID:  tenantID,
			Operation: "login",
			Resource:  "/auth/login",
			SourceIP:  fmt.Sprintf("10.0.%d.%d", i/10, i%10+1),
			UserAgent: "Bot-Scanner/1.0",
			Timestamp: baseTime.Add(time.Duration(i) * time.Second * 10),
			Success:   false,
		}
		err := bd.RecordAccess(ctx, event)
		require.NoError(t, err)
	}

	// Check for credential stuffing detection via public API
	indicators := bd.GetActiveBreachIndicators(tenantID)
	found := false
	for _, indicator := range indicators {
		if indicator.Type == security.BreachCredentialStuffing {
			found = true
			assert.Equal(t, security.SeverityHigh, indicator.Severity)
			assert.Contains(t, indicator.Description, "Credential stuffing")
			assert.GreaterOrEqual(t, indicator.Confidence, 0.8)
			break
		}
	}
	assert.True(t, found, "Credential stuffing should be detected")
}

func TestBreachDetector_AccountTakeoverPattern(t *testing.T) {
	auditLogger := newTestAuditLogger(t)
	bd := security.NewBreachDetector(auditLogger, nil)
	ctx := context.Background()

	tenantID := "550e8400-e29b-41d4-a716-446655440000"

	// Establish baseline with normal access
	baseTime := time.Now().Add(-2 * time.Hour)
	for i := 0; i < 10; i++ {
		event := &security.AccessEvent{
			ID:        fmt.Sprintf("normal-access-%d", i),
			TenantID:  tenantID,
			Operation: "read",
			Resource:  "/api/v1/configs",
			SourceIP:  "192.168.1.100",
			UserAgent: "Normal-Client/1.0",
			Timestamp: baseTime.Add(time.Duration(i) * time.Minute * 5),
			Success:   true,
		}
		err := bd.RecordAccess(ctx, event)
		require.NoError(t, err)
	}

	// Simulate account takeover: failed attempts followed by success from new location.
	// Use 10 failures (== FailedLoginThreshold) so that when the success event is
	// processed, isFailedLoginSpike fires and analyzeBreachIndicators runs with the
	// full attack context visible in profile.RecentActivity.
	attackTime := time.Now().Add(-30 * time.Minute)

	// Failed attempts (must meet FailedLoginThreshold=10 to trigger analysis)
	for i := 0; i < 10; i++ {
		event := &security.AccessEvent{
			ID:        fmt.Sprintf("takeover-failed-%d", i),
			TenantID:  tenantID,
			Operation: "login",
			Resource:  "/auth/login",
			SourceIP:  "203.0.113.100", // Attacker IP
			UserAgent: "Malicious-Client/1.0",
			Timestamp: attackTime.Add(time.Duration(i) * time.Minute),
			Success:   false,
		}
		err := bd.RecordAccess(ctx, event)
		require.NoError(t, err)
	}

	// Successful login from new location
	event := &security.AccessEvent{
		ID:        "takeover-success",
		TenantID:  tenantID,
		Operation: "login",
		Resource:  "/auth/login",
		SourceIP:  "203.0.113.100", // Same attacker IP
		UserAgent: "Malicious-Client/1.0",
		Timestamp: attackTime.Add(6 * time.Minute),
		Success:   true,
	}
	err := bd.RecordAccess(ctx, event)
	require.NoError(t, err)

	// Check for account takeover detection via public API
	indicators := bd.GetActiveBreachIndicators(tenantID)
	found := false
	for _, indicator := range indicators {
		if indicator.Type == security.BreachAccountTakeover {
			found = true
			assert.Equal(t, security.SeverityCritical, indicator.Severity)
			assert.Contains(t, indicator.Description, "account takeover")
			assert.GreaterOrEqual(t, indicator.Confidence, 0.8)
			break
		}
	}
	assert.True(t, found, "Account takeover should be detected")
}

func TestBreachDetector_DataExfiltrationPattern(t *testing.T) {
	auditLogger := newTestAuditLogger(t)
	bd := security.NewBreachDetector(auditLogger, nil)
	ctx := context.Background()

	tenantID := "550e8400-e29b-41d4-a716-446655440000"

	// Simulate data exfiltration: large amounts of data accessed
	baseTime := time.Now()
	for i := 0; i < 10; i++ {
		event := &security.AccessEvent{
			ID:        fmt.Sprintf("data-access-%d", i),
			TenantID:  tenantID,
			Operation: "export",
			Resource:  fmt.Sprintf("/api/v1/data/export/%d", i),
			SourceIP:  "192.168.1.100",
			UserAgent: "Data-Client/1.0",
			Timestamp: baseTime.Add(time.Duration(i) * time.Minute),
			Success:   true,
			DataSize:  20 * 1024 * 1024, // 20MB per request
		}
		err := bd.RecordAccess(ctx, event)
		require.NoError(t, err)
	}

	// Add a new-location event after the data exports so detectSuspiciousActivities
	// fires and causes analyzeBreachIndicators to evaluate the exfiltration pattern.
	trigger := &security.AccessEvent{
		ID:        "exfil-trigger",
		TenantID:  tenantID,
		Operation: "read",
		Resource:  "/api/v1/status",
		SourceIP:  "198.51.100.1", // region_a — new location never seen before
		UserAgent: "Trigger-Client/1.0",
		Timestamp: baseTime.Add(11 * time.Minute),
		Success:   true,
		DataSize:  0,
	}
	require.NoError(t, bd.RecordAccess(ctx, trigger))

	// Check for data exfiltration detection via public API
	indicators := bd.GetActiveBreachIndicators(tenantID)
	found := false
	for _, indicator := range indicators {
		if indicator.Type == security.BreachDataExfiltration {
			found = true
			assert.Equal(t, security.SeverityCritical, indicator.Severity)
			assert.Contains(t, indicator.Description, "data exfiltration")
			assert.GreaterOrEqual(t, indicator.Confidence, 0.7)
			break
		}
	}
	assert.True(t, found, "Data exfiltration should be detected")
}

func TestBreachDetector_BotActivityPattern(t *testing.T) {
	auditLogger := newTestAuditLogger(t)
	bd := security.NewBreachDetector(auditLogger, nil)
	ctx := context.Background()

	tenantID := "550e8400-e29b-41d4-a716-446655440000"

	// Simulate bot activity: very consistent timing patterns
	baseTime := time.Now()
	for i := 0; i < 15; i++ {
		event := &security.AccessEvent{
			ID:        fmt.Sprintf("bot-request-%d", i),
			TenantID:  tenantID,
			Operation: "read",
			Resource:  "/api/v1/data",
			SourceIP:  "192.168.1.100",
			UserAgent: "Bot-Scanner/1.0",
			Timestamp: baseTime.Add(time.Duration(i) * time.Second * 10), // Exactly 10 seconds apart
			Success:   true,
		}
		err := bd.RecordAccess(ctx, event)
		require.NoError(t, err)
	}

	// Add a new-location trigger event exactly 10 s after the last bot event.
	// This fires isNewGeographicLocation → analyzeBreachIndicators, which then
	// checks isBotActivityPattern against the last 10 events (bot events 6–14
	// plus this trigger, all 10 s apart → variance ≈ 0 < 5 s threshold).
	botTrigger := &security.AccessEvent{
		ID:        "bot-trigger",
		TenantID:  tenantID,
		Operation: "read",
		Resource:  "/api/v1/status",
		SourceIP:  "198.51.100.1", // region_a — new location never seen before
		UserAgent: "Trigger-Client/1.0",
		Timestamp: baseTime.Add(time.Duration(15) * time.Second * 10),
		Success:   true,
		DataSize:  0,
	}
	require.NoError(t, bd.RecordAccess(ctx, botTrigger))

	// Check for bot activity detection via public API
	indicators := bd.GetActiveBreachIndicators(tenantID)
	found := false
	for _, indicator := range indicators {
		if indicator.Type == security.BreachBotActivity {
			found = true
			assert.Equal(t, security.SeverityMedium, indicator.Severity)
			assert.Contains(t, indicator.Description, "bot activity")
			assert.GreaterOrEqual(t, indicator.Confidence, 0.7)
			break
		}
	}
	assert.True(t, found, "Bot activity should be detected")
}

func TestBreachDetector_RiskScoreCalculation(t *testing.T) {
	auditLogger := newTestAuditLogger(t)
	bd := security.NewBreachDetector(auditLogger, nil)
	ctx := context.Background()

	tenantID := "550e8400-e29b-41d4-a716-446655440000"

	// Record normal activity (should have low risk)
	event := &security.AccessEvent{
		ID:        "normal-event",
		TenantID:  tenantID,
		Operation: "read",
		Resource:  "/api/v1/configs",
		SourceIP:  "192.168.1.100",
		UserAgent: "Normal-Client/1.0",
		Timestamp: time.Now(),
		Success:   true,
	}
	err := bd.RecordAccess(ctx, event)
	require.NoError(t, err)

	// Initially low risk
	riskScore := bd.GetTenantRiskScore(tenantID)
	assert.LessOrEqual(t, riskScore, 0.3)

	// Add suspicious activity.
	// Use a fixed base time so all event timestamps are exactly 1 minute apart
	// regardless of goroutine scheduling jitter. isBotActivityPattern computes
	// interval variance; if time.Now() is called fresh each iteration the ms-
	// level jitter introduced by the audit manager's background goroutine can
	// inflate the squared-nanosecond variance above the 5-second threshold and
	// cause the bot-activity breach indicator to not fire.
	baseTime := time.Now()
	for i := 0; i < 15; i++ {
		suspiciousEvent := &security.AccessEvent{
			ID:        fmt.Sprintf("suspicious-event-%d", i),
			TenantID:  tenantID,
			Operation: "login",
			Resource:  "/auth/login",
			SourceIP:  fmt.Sprintf("10.0.0.%d", i+1),
			UserAgent: "Attacker-Bot/1.0",
			Timestamp: baseTime.Add(time.Duration(i) * time.Minute),
			Success:   false,
		}
		err := bd.RecordAccess(ctx, suspiciousEvent)
		require.NoError(t, err)
	}

	// Risk should increase significantly
	riskScore = bd.GetTenantRiskScore(tenantID)
	assert.GreaterOrEqual(t, riskScore, 0.5)

	// Breach detection in RecordAccess is synchronous; indicators are set before
	// RecordAccess returns. Eventually is retained as a belt-and-suspenders guard
	// with a generous timeout that accommodates any slow CI environment.
	var indicators []*security.BreachIndicator
	require.Eventually(t, func() bool {
		indicators = bd.GetActiveBreachIndicators(tenantID)
		return len(indicators) > 0
	}, 10*time.Second, 50*time.Millisecond, "Should have active breach indicators after recording suspicious events")
	assert.NotEmpty(t, indicators)
}

func TestBreachDetector_AlertCallback(t *testing.T) {
	auditLogger := newTestAuditLogger(t)
	bd := security.NewBreachDetector(auditLogger, nil)
	ctx := context.Background()

	var mutex sync.Mutex
	alertTriggered := false
	var triggeredActivity *security.SuspiciousActivity
	var triggeredIndicator *security.BreachIndicator

	// Register alert callback with proper synchronization
	bd.RegisterAlertCallback(func(ctx context.Context, activity *security.SuspiciousActivity, indicator *security.BreachIndicator) {
		mutex.Lock()
		defer mutex.Unlock()
		alertTriggered = true
		triggeredActivity = activity
		triggeredIndicator = indicator
	})

	tenantID := "550e8400-e29b-41d4-a716-446655440000"

	// Generate activity that should trigger alert
	for i := 0; i < 25; i++ {
		event := &security.AccessEvent{
			ID:        fmt.Sprintf("alert-event-%d", i),
			TenantID:  tenantID,
			Operation: "login",
			Resource:  "/auth/login",
			SourceIP:  fmt.Sprintf("10.0.%d.%d", i/10, i%10+1),
			UserAgent: "Alert-Bot/1.0",
			Timestamp: time.Now().Add(time.Duration(i) * time.Second * 5),
			Success:   false,
		}
		err := bd.RecordAccess(ctx, event)
		require.NoError(t, err)
	}

	// triggerAlerts fires callbacks in goroutines; poll until the callback lands.
	require.Eventually(t, func() bool {
		mutex.Lock()
		defer mutex.Unlock()
		return alertTriggered
	}, 5*time.Second, 10*time.Millisecond, "Alert callback should be triggered")

	mutex.Lock()
	activity := triggeredActivity
	indicator := triggeredIndicator
	mutex.Unlock()

	assert.NotNil(t, activity)
	assert.NotNil(t, indicator)
}

func TestBreachDetector_BaselineEstablishment(t *testing.T) {
	auditLogger := newTestAuditLogger(t)
	bd := security.NewBreachDetector(auditLogger, nil)
	ctx := context.Background()

	tenantID := "550e8400-e29b-41d4-a716-446655440000"

	// Record insufficient events for baseline
	for i := 0; i < 10; i++ {
		event := &security.AccessEvent{
			ID:        fmt.Sprintf("baseline-event-%d", i),
			TenantID:  tenantID,
			Operation: "read",
			Resource:  "/api/v1/configs",
			SourceIP:  "192.168.1.100",
			UserAgent: "Normal-Client/1.0",
			Timestamp: time.Now().Add(time.Duration(-i) * time.Minute),
			Success:   true,
		}
		err := bd.RecordAccess(ctx, event)
		require.NoError(t, err)
	}

	// Before baseline: 10 normal events should not produce any breach indicators
	preIndicators := bd.GetActiveBreachIndicators(tenantID)
	assert.Empty(t, preIndicators, "10 normal events should not trigger breach indicators")
	riskScorePre := bd.GetTenantRiskScore(tenantID)
	assert.GreaterOrEqual(t, riskScorePre, 0.0)

	// Record enough events to establish baseline (requires ≥50)
	for i := 10; i < 60; i++ {
		event := &security.AccessEvent{
			ID:        fmt.Sprintf("baseline-event-%d", i),
			TenantID:  tenantID,
			Operation: "read",
			Resource:  "/api/v1/configs",
			SourceIP:  "192.168.1.100",
			UserAgent: "Normal-Client/1.0",
			Timestamp: time.Now().Add(time.Duration(-i) * time.Minute),
			Success:   true,
		}
		err := bd.RecordAccess(ctx, event)
		require.NoError(t, err)
	}

	// After 60 normal events: no breach indicators (baseline should not produce false positives)
	indicators := bd.GetActiveBreachIndicators(tenantID)
	assert.Empty(t, indicators, "60 normal same-origin events should not trigger breach indicators")
	riskScore := bd.GetTenantRiskScore(tenantID)
	assert.GreaterOrEqual(t, riskScore, 0.0)
	assert.LessOrEqual(t, riskScore, 1.0)
}

func TestBreachDetector_DeviceFingerprinting(t *testing.T) {
	auditLogger := newTestAuditLogger(t)
	bd := security.NewBreachDetector(auditLogger, nil)
	ctx := context.Background()

	tenantID := "550e8400-e29b-41d4-a716-446655440000"

	// Record events from same device
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	for i := 0; i < 5; i++ {
		event := &security.AccessEvent{
			ID:        fmt.Sprintf("device-event-%d", i),
			TenantID:  tenantID,
			Operation: "read",
			Resource:  "/api/v1/configs",
			SourceIP:  "192.168.1.100",
			UserAgent: userAgent,
			Timestamp: time.Now().Add(time.Duration(-i) * time.Minute),
			Success:   true,
		}
		err := bd.RecordAccess(ctx, event)
		require.NoError(t, err)
	}

	// Consistent single-device activity should not trigger breach indicators (no false positives)
	indicators := bd.GetActiveBreachIndicators(tenantID)
	assert.Empty(t, indicators, "consistent single-device activity should not trigger breach indicators")
	riskScore := bd.GetTenantRiskScore(tenantID)
	assert.GreaterOrEqual(t, riskScore, 0.0)
	assert.LessOrEqual(t, riskScore, 1.0)
}

func TestBreachDetector_TimePatternAnalysis(t *testing.T) {
	auditLogger := newTestAuditLogger(t)
	bd := security.NewBreachDetector(auditLogger, nil)
	ctx := context.Background()

	tenantID := "550e8400-e29b-41d4-a716-446655440000"

	// Record events during business hours over multiple days (8-hour window: 9-16)
	baseDate := time.Now().Add(-7 * 24 * time.Hour)
	for day := 0; day < 7; day++ {
		for hour := 9; hour <= 16; hour++ {
			dayStart := time.Date(baseDate.Year(), baseDate.Month(), baseDate.Day()+day, hour, 0, 0, 0, baseDate.Location())
			event := &security.AccessEvent{
				ID:        fmt.Sprintf("time-event-%d-%d", day, hour),
				TenantID:  tenantID,
				Operation: "read",
				Resource:  "/api/v1/configs",
				SourceIP:  "192.168.1.100",
				UserAgent: "Business-Client/1.0",
				Timestamp: dayStart,
				Success:   true,
			}
			err := bd.RecordAccess(ctx, event)
			require.NoError(t, err)
		}
	}

	// Regular business-hours activity should not trigger breach indicators
	indicators := bd.GetActiveBreachIndicators(tenantID)
	assert.Empty(t, indicators, "business-hours activity should not trigger breach indicators")

	// After establishing time patterns, out-of-hours access should increase risk score
	riskScoreBefore := bd.GetTenantRiskScore(tenantID)
	now := time.Now()
	outOfHours := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, now.Location())
	oohEvent := &security.AccessEvent{
		ID:        "out-of-hours-event",
		TenantID:  tenantID,
		Operation: "read",
		Resource:  "/api/v1/configs",
		SourceIP:  "192.168.1.100",
		UserAgent: "Business-Client/1.0",
		Timestamp: outOfHours,
		Success:   true,
	}
	err := bd.RecordAccess(ctx, oohEvent)
	require.NoError(t, err)
	riskScoreAfter := bd.GetTenantRiskScore(tenantID)
	assert.Greater(t, riskScoreAfter, riskScoreBefore, "out-of-hours access should increase risk score after time patterns are established")
}

// Benchmark tests for performance validation
func BenchmarkBreachDetector_RecordAccess(b *testing.B) {
	auditLogger := newTestAuditLogger(b)
	bd := security.NewBreachDetector(auditLogger, nil)
	ctx := context.Background()

	event := &security.AccessEvent{
		ID:        "benchmark-event",
		TenantID:  "550e8400-e29b-41d4-a716-446655440000",
		Operation: "read",
		Resource:  "/api/v1/configs",
		SourceIP:  "192.168.1.100",
		UserAgent: "Benchmark-Client/1.0",
		Timestamp: time.Now(),
		Success:   true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event.ID = fmt.Sprintf("benchmark-event-%d", i)
		event.Timestamp = time.Now()
		_ = bd.RecordAccess(ctx, event)
	}
}
