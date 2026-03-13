// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package risk

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/logging"
)

var monitoringLogger = logging.NewModuleLogger("rbac-risk", "monitoring")

// ContinuousRiskMonitor monitors risk levels for active sessions
type ContinuousRiskMonitor struct {
	activeMonitoring   map[string]*SessionRiskMonitoring // sessionID -> monitoring data
	monitoringMutex    sync.RWMutex
	riskEngine         *RiskAssessmentEngine
	riskThresholds     *RiskThresholds
	eventCallbacks     []RiskEventCallback
	monitoringInterval time.Duration
	started            bool
	stopChannel        chan struct{}
}

// SessionRiskMonitoring contains monitoring data for a specific session
type SessionRiskMonitoring struct {
	SessionID         string                    `json:"session_id"`
	UserID            string                    `json:"user_id"`
	TenantID          string                    `json:"tenant_id"`
	CurrentRiskLevel  RiskLevel                 `json:"current_risk_level"`
	RiskScore         float64                   `json:"risk_score"`
	LastAssessment    time.Time                 `json:"last_assessment"`
	RiskTrend         []RiskTrendPoint          `json:"risk_trend"`
	ThresholdBreaches []RiskThresholdBreach     `json:"threshold_breaches"`
	AdaptiveControls  []AdaptiveControlInstance `json:"adaptive_controls"`
	NextReassessment  time.Time                 `json:"next_reassessment"`
	MonitoringStarted time.Time                 `json:"monitoring_started"`
}

// RiskTrendPoint represents a point in the risk trend
type RiskTrendPoint struct {
	Timestamp time.Time `json:"timestamp"`
	RiskScore float64   `json:"risk_score"`
	RiskLevel RiskLevel `json:"risk_level"`
	Trigger   string    `json:"trigger"` // What triggered this assessment
}

// RiskThresholdBreach represents a risk threshold breach
type RiskThresholdBreach struct {
	Timestamp     time.Time `json:"timestamp"`
	PreviousLevel RiskLevel `json:"previous_level"`
	NewLevel      RiskLevel `json:"new_level"`
	TriggerEvent  string    `json:"trigger_event"`
	ActionTaken   string    `json:"action_taken"`
	Severity      string    `json:"severity"`
}

// RiskThresholds defines thresholds for risk level changes
type RiskThresholds struct {
	SignificantIncrease float64       `json:"significant_increase"` // % increase to trigger reassessment
	RapidEscalation     float64       `json:"rapid_escalation"`     // % increase in short time to trigger immediate action
	TimeWindow          time.Duration `json:"time_window"`          // Time window for rapid escalation
	CriticalThreshold   float64       `json:"critical_threshold"`   // Absolute score threshold for critical action
}

// RiskEventCallback is called when significant risk events occur
type RiskEventCallback func(sessionID string, event *RiskEvent) error

// RiskEvent represents a significant risk event
type RiskEvent struct {
	EventID       string                 `json:"event_id"`
	SessionID     string                 `json:"session_id"`
	EventType     RiskEventType          `json:"event_type"`
	Timestamp     time.Time              `json:"timestamp"`
	RiskScore     float64                `json:"risk_score"`
	RiskLevel     RiskLevel              `json:"risk_level"`
	PreviousScore float64                `json:"previous_score"`
	PreviousLevel RiskLevel              `json:"previous_level"`
	Trigger       string                 `json:"trigger"`
	Context       map[string]interface{} `json:"context"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// RiskEventType defines types of risk events
type RiskEventType string

const (
	RiskEventTypeThresholdBreach     RiskEventType = "threshold_breach"
	RiskEventTypeRapidEscalation     RiskEventType = "rapid_escalation"
	RiskEventTypePatternAnomaly      RiskEventType = "pattern_anomaly"
	RiskEventTypeContextualChange    RiskEventType = "contextual_change"
	RiskEventTypeBehavioralDeviation RiskEventType = "behavioral_deviation"
	RiskEventTypeEnvironmentalShift  RiskEventType = "environmental_shift"
)

// NewContinuousRiskMonitor creates a new continuous risk monitor
func NewContinuousRiskMonitor(riskEngine *RiskAssessmentEngine) *ContinuousRiskMonitor {
	return &ContinuousRiskMonitor{
		activeMonitoring:   make(map[string]*SessionRiskMonitoring),
		riskEngine:         riskEngine,
		riskThresholds:     getDefaultRiskThresholds(),
		eventCallbacks:     make([]RiskEventCallback, 0),
		monitoringInterval: 30 * time.Second,
		stopChannel:        make(chan struct{}),
	}
}

// StartMonitoring starts risk monitoring for a session
func (crm *ContinuousRiskMonitor) StartMonitoring(ctx context.Context, sessionID, userID, tenantID string, initialRisk *RiskAssessmentResult) error {
	crm.monitoringMutex.Lock()
	defer crm.monitoringMutex.Unlock()

	// Create session risk monitoring
	monitoring := &SessionRiskMonitoring{
		SessionID:         sessionID,
		UserID:            userID,
		TenantID:          tenantID,
		CurrentRiskLevel:  initialRisk.RiskLevel,
		RiskScore:         initialRisk.OverallRiskScore,
		LastAssessment:    time.Now(),
		RiskTrend:         make([]RiskTrendPoint, 0),
		ThresholdBreaches: make([]RiskThresholdBreach, 0),
		AdaptiveControls:  make([]AdaptiveControlInstance, 0),
		NextReassessment:  time.Now().Add(crm.monitoringInterval),
		MonitoringStarted: time.Now(),
	}

	// Add initial trend point
	monitoring.RiskTrend = append(monitoring.RiskTrend, RiskTrendPoint{
		Timestamp: time.Now(),
		RiskScore: initialRisk.OverallRiskScore,
		RiskLevel: initialRisk.RiskLevel,
		Trigger:   "session_start",
	})

	crm.activeMonitoring[sessionID] = monitoring

	// Start monitoring loop if not already started
	if !crm.started {
		crm.started = true
		go crm.monitoringLoop(ctx)
	}

	return nil
}

// StopMonitoring stops risk monitoring for a session
func (crm *ContinuousRiskMonitor) StopMonitoring(ctx context.Context, sessionID string) error {
	crm.monitoringMutex.Lock()
	defer crm.monitoringMutex.Unlock()

	delete(crm.activeMonitoring, sessionID)
	return nil
}

// ReassessRisk performs dynamic risk reassessment for a session
func (crm *ContinuousRiskMonitor) ReassessRisk(ctx context.Context, sessionID, trigger string) (*RiskAssessmentResult, error) {
	crm.monitoringMutex.Lock()
	monitoring, exists := crm.activeMonitoring[sessionID]
	crm.monitoringMutex.Unlock()

	if !exists {
		return nil, fmt.Errorf("session %s not under monitoring", sessionID)
	}

	// Create risk assessment request based on current session context
	// In a real implementation, this would gather current context data
	riskRequest := &RiskAssessmentRequest{
		AccessRequest: &common.AccessRequest{
			SubjectId: monitoring.UserID,
			TenantId:  monitoring.TenantID,
		},
		UserContext:        &UserContext{UserID: monitoring.UserID},
		SessionContext:     &SessionContext{SessionID: sessionID},
		RequiredConfidence: 70.0,
	}

	// Perform risk assessment
	riskResult, err := crm.riskEngine.EvaluateRisk(ctx, riskRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to reassess risk for session %s: %w", sessionID, err)
	}

	// Update monitoring data
	crm.monitoringMutex.Lock()
	defer crm.monitoringMutex.Unlock()

	previousScore := monitoring.RiskScore
	previousLevel := monitoring.CurrentRiskLevel

	monitoring.RiskScore = riskResult.OverallRiskScore
	monitoring.CurrentRiskLevel = riskResult.RiskLevel
	monitoring.LastAssessment = time.Now()
	monitoring.NextReassessment = time.Now().Add(crm.monitoringInterval)

	// Add trend point
	monitoring.RiskTrend = append(monitoring.RiskTrend, RiskTrendPoint{
		Timestamp: time.Now(),
		RiskScore: riskResult.OverallRiskScore,
		RiskLevel: riskResult.RiskLevel,
		Trigger:   trigger,
	})

	// Check for threshold breaches
	if crm.hasSignificantRiskChange(previousScore, riskResult.OverallRiskScore, previousLevel, riskResult.RiskLevel) {
		breach := RiskThresholdBreach{
			Timestamp:     time.Now(),
			PreviousLevel: previousLevel,
			NewLevel:      riskResult.RiskLevel,
			TriggerEvent:  trigger,
			Severity:      crm.calculateBreachSeverity(previousLevel, riskResult.RiskLevel),
		}

		monitoring.ThresholdBreaches = append(monitoring.ThresholdBreaches, breach)

		// Create risk event
		event := &RiskEvent{
			EventID:       fmt.Sprintf("risk_event_%d", time.Now().UnixNano()),
			SessionID:     sessionID,
			EventType:     RiskEventTypeThresholdBreach,
			Timestamp:     time.Now(),
			RiskScore:     riskResult.OverallRiskScore,
			RiskLevel:     riskResult.RiskLevel,
			PreviousScore: previousScore,
			PreviousLevel: previousLevel,
			Trigger:       trigger,
			Context: map[string]interface{}{
				"monitoring_duration": time.Since(monitoring.MonitoringStarted).String(),
				"trend_count":         len(monitoring.RiskTrend),
			},
		}

		// Notify callbacks
		crm.notifyRiskEvent(sessionID, event)
	}

	return riskResult, nil
}

// GetSessionStatus returns current risk monitoring status for a session
func (crm *ContinuousRiskMonitor) GetSessionStatus(ctx context.Context, sessionID string) (*SessionRiskMonitoring, error) {
	crm.monitoringMutex.RLock()
	defer crm.monitoringMutex.RUnlock()

	monitoring, exists := crm.activeMonitoring[sessionID]
	if !exists {
		return nil, fmt.Errorf("session %s not under monitoring", sessionID)
	}

	// Return a copy to prevent external modification
	statusCopy := *monitoring
	return &statusCopy, nil
}

// RegisterCallback registers a risk event callback
func (crm *ContinuousRiskMonitor) RegisterCallback(callback RiskEventCallback) {
	crm.monitoringMutex.Lock()
	defer crm.monitoringMutex.Unlock()
	crm.eventCallbacks = append(crm.eventCallbacks, callback)
}

// monitoringLoop runs continuous risk monitoring
func (crm *ContinuousRiskMonitor) monitoringLoop(ctx context.Context) {
	ticker := time.NewTicker(crm.monitoringInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-crm.stopChannel:
			return
		case <-ticker.C:
			crm.performScheduledAssessments(ctx)
		}
	}
}

// performScheduledAssessments performs scheduled risk assessments
func (crm *ContinuousRiskMonitor) performScheduledAssessments(ctx context.Context) {
	crm.monitoringMutex.RLock()
	sessionsToAssess := make([]string, 0)
	now := time.Now()

	for sessionID, monitoring := range crm.activeMonitoring {
		if now.After(monitoring.NextReassessment) {
			sessionsToAssess = append(sessionsToAssess, sessionID)
		}
	}
	crm.monitoringMutex.RUnlock()

	// Perform reassessments outside the lock
	for _, sessionID := range sessionsToAssess {
		_, err := crm.ReassessRisk(ctx, sessionID, "scheduled_assessment")
		if err != nil {
			// Log error but continue with other sessions
			monitoringLogger.Warn("failed to reassess risk for session", "session_id", sessionID, "error", err)
		}
	}
}

// hasSignificantRiskChange determines if there was a significant risk change
func (crm *ContinuousRiskMonitor) hasSignificantRiskChange(previousScore, newScore float64, previousLevel, newLevel RiskLevel) bool {
	// Check for risk level change
	if previousLevel != newLevel {
		return true
	}

	// Check for significant score increase
	if newScore > previousScore {
		increasePercent := (newScore - previousScore) / previousScore * 100
		if increasePercent >= crm.riskThresholds.SignificantIncrease {
			return true
		}
	}

	// Check for critical threshold breach
	if newScore >= crm.riskThresholds.CriticalThreshold {
		return true
	}

	return false
}

// calculateBreachSeverity calculates the severity of a risk threshold breach
func (crm *ContinuousRiskMonitor) calculateBreachSeverity(previousLevel, newLevel RiskLevel) string {
	if newLevel == RiskLevelExtreme {
		return "critical"
	}
	if newLevel == RiskLevelCritical {
		return "high"
	}
	if newLevel == RiskLevelHigh && previousLevel <= RiskLevelModerate {
		return "medium"
	}
	return "low"
}

// notifyRiskEvent notifies all registered callbacks of a risk event
func (crm *ContinuousRiskMonitor) notifyRiskEvent(sessionID string, event *RiskEvent) {
	for _, callback := range crm.eventCallbacks {
		go func(cb RiskEventCallback) {
			if err := cb(sessionID, event); err != nil {
				monitoringLogger.Warn("risk event callback failed", "error", err)
			}
		}(callback)
	}
}

// getDefaultRiskThresholds returns default risk thresholds
func getDefaultRiskThresholds() *RiskThresholds {
	return &RiskThresholds{
		SignificantIncrease: 20.0, // 20% increase
		RapidEscalation:     50.0, // 50% increase in short time
		TimeWindow:          5 * time.Minute,
		CriticalThreshold:   80.0, // Score of 80+ is critical
	}
}
