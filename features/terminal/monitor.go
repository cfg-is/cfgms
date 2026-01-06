// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package terminal

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// SessionMonitor provides real-time monitoring and control of terminal sessions
type SessionMonitor struct {
	sessions      map[string]*MonitoredSession
	sessionsMutex sync.RWMutex

	securityValidator *SecurityValidator
	auditChannel      chan *CommandAuditEvent
	alertChannel      chan *SecurityAlert

	// Monitoring configuration
	config *MonitorConfig

	// Control channels
	stopChannel chan struct{}
	terminated  chan struct{}

	// Callbacks
	onSessionAlert func(*SecurityAlert) error
}

// MonitoredSession represents a session under security monitoring
type MonitoredSession struct {
	Session         *Session
	SecurityContext *SessionSecurityContext
	Monitor         *SessionActivityMonitor

	// Security state
	ThreatLevel        ThreatLevel          `json:"threat_level"`
	AlertCount         int                  `json:"alert_count"`
	BlockedCommands    int                  `json:"blocked_commands"`
	SuspiciousActivity []SuspiciousActivity `json:"suspicious_activity"`

	// Activity tracking
	LastActivity    time.Time `json:"last_activity"`
	CommandCount    int       `json:"command_count"`
	DataTransferred int64     `json:"data_transferred"`

	// Control
	AutoTerminate   bool   `json:"auto_terminate"`
	TerminateReason string `json:"terminate_reason,omitempty"`

	mutex sync.RWMutex
}

// ThreatLevel represents the assessed threat level of a session
type ThreatLevel string

const (
	ThreatLevelLow      ThreatLevel = "low"      // Normal activity
	ThreatLevelMedium   ThreatLevel = "medium"   // Some suspicious activity
	ThreatLevelHigh     ThreatLevel = "high"     // High risk activity detected
	ThreatLevelCritical ThreatLevel = "critical" // Immediate threat - auto-terminate
)

// SuspiciousActivity represents a detected suspicious activity
type SuspiciousActivity struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Severity    FilterSeverity         `json:"severity"`
	Timestamp   time.Time              `json:"timestamp"`
	Context     map[string]interface{} `json:"context"`
	Resolved    bool                   `json:"resolved"`
}

// SessionActivityMonitor tracks activity patterns for a specific session
type SessionActivityMonitor struct {
	sessionID       string
	commandHistory  []CommandHistory
	anomalyDetector *AnomalyDetector

	// Metrics
	startTime   time.Time
	lastCommand time.Time

	mutex sync.RWMutex
}

// CommandHistory tracks executed commands for pattern analysis
type CommandHistory struct {
	Command    string        `json:"command"`
	Timestamp  time.Time     `json:"timestamp"`
	Success    bool          `json:"success"`
	ExitCode   int           `json:"exit_code"`
	Duration   time.Duration `json:"duration"`
	Privileged bool          `json:"privileged"`
}

// AccessPattern represents detected access patterns
type AccessPattern struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Frequency   int                    `json:"frequency"`
	LastSeen    time.Time              `json:"last_seen"`
	Risk        FilterSeverity         `json:"risk"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AnomalyDetector detects unusual patterns in session activity
type AnomalyDetector struct {
	baselineMetrics BaselineMetrics
	anomalyRules    []AnomalyRule
}

// BaselineMetrics represents normal behavior patterns
type BaselineMetrics struct {
	AvgCommandRate     float64        `json:"avg_command_rate"`
	AvgSessionDuration time.Duration  `json:"avg_session_duration"`
	CommonCommands     map[string]int `json:"common_commands"`
	TypicalHours       []int          `json:"typical_hours"`
}

// CurrentMetrics represents current session metrics
type CurrentMetrics struct {
	CommandRate         float64        `json:"command_rate"`
	SessionDuration     time.Duration  `json:"session_duration"`
	CommandDistribution map[string]int `json:"command_distribution"`
	CurrentHour         int            `json:"current_hour"`
}

// AnomalyRule defines rules for detecting anomalous behavior
type AnomalyRule struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Threshold   float64 `json:"threshold"`
	Metric      string  `json:"metric"`
	Action      string  `json:"action"`
}

// MonitorConfig contains configuration for session monitoring
type MonitorConfig struct {
	// Monitoring intervals
	MonitorInterval    time.Duration `json:"monitor_interval"`
	AlertCheckInterval time.Duration `json:"alert_check_interval"`
	MetricsInterval    time.Duration `json:"metrics_interval"`

	// Thresholds
	MaxCommandRate     float64       `json:"max_command_rate"`     // Commands per minute
	MaxFailureRate     float64       `json:"max_failure_rate"`     // Failed commands per minute
	MaxSessionDuration time.Duration `json:"max_session_duration"` // Maximum session time
	MaxIdleTime        time.Duration `json:"max_idle_time"`        // Maximum idle time

	// Auto-termination settings
	AutoTerminateOnCritical   bool `json:"auto_terminate_on_critical"`
	AutoTerminateOnSuspicious bool `json:"auto_terminate_on_suspicious"`
	MaxSuspiciousActivities   int  `json:"max_suspicious_activities"`

	// Alert settings
	AlertOnPrivilegeEscalation bool `json:"alert_on_privilege_escalation"`
	AlertOnSuspiciousCommands  bool `json:"alert_on_suspicious_commands"`
	AlertOnAnomalousPatterns   bool `json:"alert_on_anomalous_patterns"`
}

// NewSessionMonitor creates a new session monitor with the given configuration
func NewSessionMonitor(validator *SecurityValidator, config *MonitorConfig) *SessionMonitor {
	if config == nil {
		config = DefaultMonitorConfig()
	}

	return &SessionMonitor{
		sessions:          make(map[string]*MonitoredSession),
		securityValidator: validator,
		auditChannel:      make(chan *CommandAuditEvent, 1000),
		alertChannel:      make(chan *SecurityAlert, 500),
		config:            config,
		stopChannel:       make(chan struct{}),
		terminated:        make(chan struct{}),
	}
}

// Start begins monitoring sessions
func (sm *SessionMonitor) Start(ctx context.Context) error {
	go sm.monitorLoop(ctx)
	go sm.alertProcessor(ctx)
	return nil
}

// Stop stops the session monitor
func (sm *SessionMonitor) Stop() error {
	close(sm.stopChannel)

	// Wait for termination with timeout
	select {
	case <-sm.terminated:
		return nil
	case <-time.After(10 * time.Second):
		return fmt.Errorf("timeout waiting for session monitor to stop")
	}
}

// AddSession adds a session for monitoring
func (sm *SessionMonitor) AddSession(session *Session, securityContext *SessionSecurityContext) error {
	sm.sessionsMutex.Lock()
	defer sm.sessionsMutex.Unlock()

	activityMonitor := &SessionActivityMonitor{
		sessionID: session.ID,
		startTime: time.Now(),
		anomalyDetector: &AnomalyDetector{
			baselineMetrics: sm.getBaselineMetrics(securityContext.UserID),
			anomalyRules:    sm.getAnomalyRules(),
		},
	}

	monitoredSession := &MonitoredSession{
		Session:         session,
		SecurityContext: securityContext,
		Monitor:         activityMonitor,
		ThreatLevel:     ThreatLevelLow,
		LastActivity:    time.Now(),
	}

	sm.sessions[session.ID] = monitoredSession

	return nil
}

// RemoveSession removes a session from monitoring
func (sm *SessionMonitor) RemoveSession(sessionID string) error {
	sm.sessionsMutex.Lock()
	defer sm.sessionsMutex.Unlock()

	delete(sm.sessions, sessionID)
	return nil
}

// TerminateSession forcibly terminates a session
func (sm *SessionMonitor) TerminateSession(ctx context.Context, sessionID string, reason string) error {
	sm.sessionsMutex.Lock()
	defer sm.sessionsMutex.Unlock()

	monitoredSession, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	// Mark session for termination
	monitoredSession.mutex.Lock()
	monitoredSession.AutoTerminate = true
	monitoredSession.TerminateReason = reason
	monitoredSession.mutex.Unlock()

	// Close the actual session
	if err := monitoredSession.Session.Close(ctx); err != nil {
		return fmt.Errorf("failed to close session: %w", err)
	}

	// Generate security alert
	alert := &SecurityAlert{
		Type:        "session_terminated",
		Severity:    FilterSeverityHigh,
		SessionID:   sessionID,
		UserID:      monitoredSession.SecurityContext.UserID,
		StewardID:   monitoredSession.SecurityContext.StewardID,
		TenantID:    monitoredSession.SecurityContext.TenantID,
		Message:     fmt.Sprintf("Session terminated: %s", reason),
		Timestamp:   time.Now(),
		ActionTaken: "session_terminated",
	}

	// Send alert
	select {
	case sm.alertChannel <- alert:
	default:
		// Channel full, log but don't block
	}

	// Remove from monitoring
	delete(sm.sessions, sessionID)

	return nil
}

// GetSessionInfo returns monitoring information for a session
func (sm *SessionMonitor) GetSessionInfo(sessionID string) (*MonitoredSession, error) {
	sm.sessionsMutex.RLock()
	defer sm.sessionsMutex.RUnlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	// Return a copy to avoid race conditions
	return &MonitoredSession{
		Session:         session.Session,
		SecurityContext: session.SecurityContext,
		ThreatLevel:     session.ThreatLevel,
		AlertCount:      session.AlertCount,
		BlockedCommands: session.BlockedCommands,
		LastActivity:    session.LastActivity,
		CommandCount:    session.CommandCount,
		DataTransferred: session.DataTransferred,
	}, nil
}

// GetActiveSessions returns all currently monitored sessions
func (sm *SessionMonitor) GetActiveSessions() []*MonitoredSession {
	sm.sessionsMutex.RLock()
	defer sm.sessionsMutex.RUnlock()

	sessions := make([]*MonitoredSession, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}

	return sessions
}

// RecordCommand records a command execution for monitoring
func (sm *SessionMonitor) RecordCommand(sessionID string, command string, success bool, exitCode int, duration time.Duration) error {
	sm.sessionsMutex.RLock()
	session, exists := sm.sessions[sessionID]
	sm.sessionsMutex.RUnlock()

	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	session.mutex.Lock()
	defer session.mutex.Unlock()

	// Update session metrics
	session.LastActivity = time.Now()
	session.CommandCount++

	// Record in activity monitor
	cmdHistory := CommandHistory{
		Command:    command,
		Timestamp:  time.Now(),
		Success:    success,
		ExitCode:   exitCode,
		Duration:   duration,
		Privileged: sm.isPrivilegedCommand(command),
	}

	session.Monitor.mutex.Lock()
	session.Monitor.commandHistory = append(session.Monitor.commandHistory, cmdHistory)
	session.Monitor.lastCommand = time.Now()
	session.Monitor.mutex.Unlock()

	// Check for anomalies
	if err := sm.checkForAnomalies(session); err != nil {
		return fmt.Errorf("anomaly detection failed: %w", err)
	}

	return nil
}

// monitorLoop is the main monitoring loop
func (sm *SessionMonitor) monitorLoop(ctx context.Context) {
	defer close(sm.terminated)

	ticker := time.NewTicker(sm.config.MonitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sm.stopChannel:
			return
		case <-ticker.C:
			sm.performMonitoringCheck()
		}
	}
}

// performMonitoringCheck performs regular monitoring checks on all sessions
func (sm *SessionMonitor) performMonitoringCheck() {
	sm.sessionsMutex.RLock()
	sessions := make([]*MonitoredSession, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	sm.sessionsMutex.RUnlock()

	for _, session := range sessions {
		sm.checkSessionHealth(session)
		sm.checkSessionTimeouts(session)
		sm.updateThreatLevel(session)
	}
}

// checkSessionHealth checks the health and activity of a session
func (sm *SessionMonitor) checkSessionHealth(session *MonitoredSession) {
	now := time.Now()

	// Gather data under lock
	session.mutex.RLock()
	lastActivity := session.LastActivity
	createdAt := session.Session.CreatedAt
	session.mutex.RUnlock()

	// Check for idle timeout (without holding lock)
	if now.Sub(lastActivity) > sm.config.MaxIdleTime {
		sm.generateAlert(session, "session_idle_timeout", FilterSeverityMedium,
			fmt.Sprintf("Session idle for %v", now.Sub(lastActivity)))
	}

	// Check session duration (without holding lock)
	sessionDuration := now.Sub(createdAt)
	if sessionDuration > sm.config.MaxSessionDuration {
		sm.generateAlert(session, "session_duration_exceeded", FilterSeverityHigh,
			fmt.Sprintf("Session duration %v exceeds maximum %v", sessionDuration, sm.config.MaxSessionDuration))
	}
}

// checkSessionTimeouts handles session timeout policies
func (sm *SessionMonitor) checkSessionTimeouts(session *MonitoredSession) {
	// Implementation for checking various timeout conditions
}

// updateThreatLevel updates the threat level based on recent activity
func (sm *SessionMonitor) updateThreatLevel(session *MonitoredSession) {
	session.mutex.Lock()
	// Note: we unlock manually before calling generateAlert to avoid deadlock

	// Calculate threat level based on various factors
	threatLevel := ThreatLevelLow

	// Check alert count
	if session.AlertCount > 5 {
		threatLevel = ThreatLevelHigh
	} else if session.AlertCount > 2 {
		threatLevel = ThreatLevelMedium
	}

	// Check blocked commands
	if session.BlockedCommands > 3 {
		threatLevel = ThreatLevelCritical
	}

	// Check for recent suspicious activity
	recentSuspicious := 0
	cutoff := time.Now().Add(-10 * time.Minute)
	for _, activity := range session.SuspiciousActivity {
		if activity.Timestamp.After(cutoff) && !activity.Resolved {
			recentSuspicious++
		}
	}

	if recentSuspicious > 2 {
		threatLevel = ThreatLevelCritical
	}

	// Update threat level
	oldLevel := session.ThreatLevel
	session.ThreatLevel = threatLevel

	// Auto-terminate if critical and configured to do so
	if threatLevel == ThreatLevelCritical && sm.config.AutoTerminateOnCritical {
		session.AutoTerminate = true
		session.TerminateReason = "Critical threat level reached"

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := sm.TerminateSession(ctx, session.Session.ID, "Critical threat level - auto-terminated"); err != nil {
				// Log error but continue - critical security action
				_ = err // Explicitly ignore termination errors during security response
			}
		}()
	}

	// Check if alert should be generated (before releasing lock)
	shouldAlert := threatLevel > oldLevel

	// Release the lock before calling generateAlert to avoid deadlock
	session.mutex.Unlock()

	// Generate alert if threat level increased (without holding lock)
	if shouldAlert {
		sm.generateAlert(session, "threat_level_increased", FilterSeverityHigh,
			fmt.Sprintf("Threat level increased from %s to %s", oldLevel, threatLevel))
	}

	// Note: we've already unlocked, so remove the defer unlock
}

// checkForAnomalies checks for anomalous patterns in session activity
func (sm *SessionMonitor) checkForAnomalies(session *MonitoredSession) error {
	session.Monitor.mutex.RLock()
	defer session.Monitor.mutex.RUnlock()

	// Update current metrics
	sm.updateCurrentMetrics(session.Monitor)

	// Run anomaly detection rules
	for _, rule := range session.Monitor.anomalyDetector.anomalyRules {
		if anomaly := sm.detectAnomaly(session.Monitor, rule); anomaly {
			sm.recordSuspiciousActivity(session, rule.Name, rule.Description, FilterSeverityMedium)
		}
	}

	return nil
}

// generateAlert generates a security alert for a session
func (sm *SessionMonitor) generateAlert(session *MonitoredSession, alertType string, severity FilterSeverity, message string) {
	session.mutex.Lock()
	session.AlertCount++
	session.mutex.Unlock()

	alert := &SecurityAlert{
		Type:        alertType,
		Severity:    severity,
		SessionID:   session.Session.ID,
		UserID:      session.SecurityContext.UserID,
		StewardID:   session.SecurityContext.StewardID,
		TenantID:    session.SecurityContext.TenantID,
		Message:     message,
		Timestamp:   time.Now(),
		ActionTaken: "alert_generated",
	}

	select {
	case sm.alertChannel <- alert:
	default:
		// Channel full, could log warning
	}
}

// alertProcessor processes security alerts
func (sm *SessionMonitor) alertProcessor(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case alert := <-sm.alertChannel:
			if sm.onSessionAlert != nil {
				if err := sm.onSessionAlert(alert); err != nil {
					// Log error but continue processing alerts
					_ = err // Explicitly ignore alert callback errors
				}
			}
		}
	}
}

// Helper functions

func (sm *SessionMonitor) isPrivilegedCommand(command string) bool {
	privilegedCommands := []string{"sudo", "su", "doas", "runas"}
	for _, privCmd := range privilegedCommands {
		if strings.Contains(command, privCmd) {
			return true
		}
	}
	return false
}

func (sm *SessionMonitor) getBaselineMetrics(userID string) BaselineMetrics {
	// In a real implementation, this would load from historical data
	return BaselineMetrics{
		AvgCommandRate:     10.0, // 10 commands per minute
		AvgSessionDuration: 30 * time.Minute,
		CommonCommands:     map[string]int{"ls": 50, "cd": 30, "cat": 20},
		TypicalHours:       []int{9, 10, 11, 14, 15, 16},
	}
}

func (sm *SessionMonitor) getAnomalyRules() []AnomalyRule {
	return []AnomalyRule{
		{
			ID:          "high_command_rate",
			Name:        "High Command Rate",
			Description: "Command rate exceeds normal baseline",
			Threshold:   3.0, // 3x normal rate
			Metric:      "command_rate",
			Action:      "alert",
		},
		{
			ID:          "unusual_hours",
			Name:        "Unusual Hours",
			Description: "Activity outside typical hours",
			Metric:      "current_hour",
			Action:      "audit",
		},
	}
}

func (sm *SessionMonitor) updateCurrentMetrics(monitor *SessionActivityMonitor) {
	// Update current metrics based on recent activity
	// Implementation would calculate real-time metrics
}

func (sm *SessionMonitor) detectAnomaly(monitor *SessionActivityMonitor, rule AnomalyRule) bool {
	// Implementation would check if current metrics trigger the anomaly rule
	return false
}

func (sm *SessionMonitor) recordSuspiciousActivity(session *MonitoredSession, activityType, description string, severity FilterSeverity) {
	session.mutex.Lock()
	defer session.mutex.Unlock()

	activity := SuspiciousActivity{
		Type:        activityType,
		Description: description,
		Severity:    severity,
		Timestamp:   time.Now(),
		Resolved:    false,
	}

	session.SuspiciousActivity = append(session.SuspiciousActivity, activity)
}

// DefaultMonitorConfig returns default monitoring configuration
func DefaultMonitorConfig() *MonitorConfig {
	return &MonitorConfig{
		MonitorInterval:            30 * time.Second,
		AlertCheckInterval:         10 * time.Second,
		MetricsInterval:            60 * time.Second,
		MaxCommandRate:             100.0, // 100 commands per minute max
		MaxFailureRate:             10.0,  // 10 failed commands per minute max
		MaxSessionDuration:         4 * time.Hour,
		MaxIdleTime:                30 * time.Minute,
		AutoTerminateOnCritical:    true,
		AutoTerminateOnSuspicious:  false,
		MaxSuspiciousActivities:    5,
		AlertOnPrivilegeEscalation: true,
		AlertOnSuspiciousCommands:  true,
		AlertOnAnomalousPatterns:   true,
	}
}
