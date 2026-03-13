// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package risk

import (
	"sync"
	"time"
)

// SessionRiskTracker tracks risk changes across sessions
type SessionRiskTracker struct {
	riskHistory     map[string][]RiskAssessmentResult // userID -> historical risk assessments
	historyMutex    sync.RWMutex
	maxHistorySize  int
	patternAnalyzer *RiskPatternAnalyzer
}

// UserRiskPattern represents a user's risk behavior pattern
type UserRiskPattern struct {
	UserID         string             `json:"user_id"`
	BaselineRisk   float64            `json:"baseline_risk"`
	RecentActivity []RiskEvent        `json:"recent_activity"`
	BehaviorTrends map[string]float64 `json:"behavior_trends"`
	AnomalyScore   float64            `json:"anomaly_score"`
	LastUpdated    time.Time          `json:"last_updated"`
}

// RiskPatternAnalyzer analyzes risk patterns for behavioral insights
type RiskPatternAnalyzer struct {
	patterns       map[string]*UserRiskPattern // userID -> risk pattern
	analysisWindow time.Duration
	confidence     float64
}

// NewSessionRiskTracker creates a new session risk tracker
func NewSessionRiskTracker() *SessionRiskTracker {
	return &SessionRiskTracker{
		riskHistory:    make(map[string][]RiskAssessmentResult),
		maxHistorySize: 100, // Keep last 100 assessments per user
		patternAnalyzer: &RiskPatternAnalyzer{
			patterns:       make(map[string]*UserRiskPattern),
			analysisWindow: 24 * time.Hour,
			confidence:     80.0,
		},
	}
}

// TrackRiskAssessment tracks a risk assessment result
func (srt *SessionRiskTracker) TrackRiskAssessment(userID string, result *RiskAssessmentResult) {
	srt.historyMutex.Lock()
	defer srt.historyMutex.Unlock()

	if srt.riskHistory[userID] == nil {
		srt.riskHistory[userID] = make([]RiskAssessmentResult, 0)
	}

	// Add new assessment
	srt.riskHistory[userID] = append(srt.riskHistory[userID], *result)

	// Maintain history size limit
	if len(srt.riskHistory[userID]) > srt.maxHistorySize {
		srt.riskHistory[userID] = srt.riskHistory[userID][1:]
	}
}

// GetRiskHistory returns risk history for a user
func (srt *SessionRiskTracker) GetRiskHistory(userID string) []RiskAssessmentResult {
	srt.historyMutex.RLock()
	defer srt.historyMutex.RUnlock()

	history, exists := srt.riskHistory[userID]
	if !exists {
		return []RiskAssessmentResult{}
	}

	// Return a copy
	historyCopy := make([]RiskAssessmentResult, len(history))
	copy(historyCopy, history)
	return historyCopy
}
