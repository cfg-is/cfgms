package continuous

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ContextMonitor provides continuous monitoring of authorization context and compliance
type ContextMonitor struct {
	// Core dependencies
	riskManager RiskManager

	// Context tracking
	contextStore map[string]*AuthorizationContext // sessionID -> context
	contextMutex sync.RWMutex

	// Monitoring configuration
	checkInterval   time.Duration
	complianceRules []ComplianceRule
	contextRules    []ContextRule

	// Change detection
	changeDetector *ContextChangeDetector

	// Control
	started         bool
	stopChannel     chan struct{}
	monitoringGroup sync.WaitGroup

	// Statistics
	stats ContextMonitorStats
}

// AuthorizationContext represents the complete authorization context for a session
type AuthorizationContext struct {
	SessionID string `json:"session_id"`
	SubjectID string `json:"subject_id"`
	TenantID  string `json:"tenant_id"`

	// Environment context
	Environment EnvironmentContext `json:"environment"`

	// Security context
	SecurityContext SecurityContext `json:"security_context"`

	// Compliance context
	ComplianceContext ComplianceContext `json:"compliance_context"`

	// Risk context
	RiskContext RiskContext `json:"risk_context"`

	// Temporal context
	CreatedAt   time.Time `json:"created_at"`
	LastUpdated time.Time `json:"last_updated"`
	LastChecked time.Time `json:"last_checked"`

	// Change tracking
	Changes       []ContextChange `json:"changes"`
	ChangeCounter int             `json:"change_counter"`

	mutex sync.RWMutex
}

// EnvironmentContext contains environmental factors affecting authorization
type EnvironmentContext struct {
	IPAddress      string       `json:"ip_address"`
	Location       *GeoLocation `json:"location,omitempty"`
	Device         *DeviceInfo  `json:"device,omitempty"`
	Network        *NetworkInfo `json:"network,omitempty"`
	UserAgent      string       `json:"user_agent"`
	Platform       string       `json:"platform"`
	TimeZone       string       `json:"time_zone"`
	BusinessHours  bool         `json:"business_hours"`
	TrustedNetwork bool         `json:"trusted_network"`

	// VPN/Proxy detection
	VPNDetected   bool `json:"vpn_detected"`
	ProxyDetected bool `json:"proxy_detected"`
	TorDetected   bool `json:"tor_detected"`

	LastVerified time.Time `json:"last_verified"`
}

// SecurityContext contains security-specific context information
type SecurityContext struct {
	AuthMethod       string        `json:"auth_method"`
	MFAVerified      bool          `json:"mfa_verified"`
	MFAMethod        string        `json:"mfa_method,omitempty"`
	CertificateValid bool          `json:"certificate_valid"`
	SessionAge       time.Duration `json:"session_age"`

	// Device trust
	DeviceTrusted    bool `json:"device_trusted"`
	DeviceRegistered bool `json:"device_registered"`
	DeviceCompliant  bool `json:"device_compliant"`

	// Behavioral indicators
	BehaviorScore      float64  `json:"behavior_score"`
	AnomalousActivity  bool     `json:"anomalous_activity"`
	SuspiciousPatterns []string `json:"suspicious_patterns"`

	// Threat intelligence
	ThreatIndicators []ThreatIndicator `json:"threat_indicators"`

	LastAssessment time.Time `json:"last_assessment"`
}

// ComplianceContext contains regulatory and policy compliance information
type ComplianceContext struct {
	RequiredFrameworks []string          `json:"required_frameworks"`
	ActiveFrameworks   []string          `json:"active_frameworks"`
	ComplianceStatus   ComplianceStatus  `json:"compliance_status"`
	PolicyViolations   []PolicyViolation `json:"policy_violations"`

	// Data handling requirements
	DataClassification string        `json:"data_classification"`
	DataRetention      time.Duration `json:"data_retention"`
	EncryptionRequired bool          `json:"encryption_required"`

	// Audit requirements
	AuditLevel     AuditLevel    `json:"audit_level"`
	AuditRetention time.Duration `json:"audit_retention"`

	LastCompliance time.Time `json:"last_compliance_check"`
}

// RiskContext contains risk assessment information
type RiskContext struct {
	CurrentRiskLevel RiskLevel    `json:"current_risk_level"`
	RiskScore        float64      `json:"risk_score"`
	RiskFactors      []RiskFactor `json:"risk_factors"`
	RiskTrends       []RiskTrend  `json:"risk_trends"`

	// Risk thresholds
	RiskThresholds  RiskThresholds `json:"risk_thresholds"`
	ThresholdBreach bool           `json:"threshold_breach"`

	LastAssessment time.Time `json:"last_assessment"`
	NextAssessment time.Time `json:"next_assessment"`
}

// Supporting types

type GeoLocation struct {
	Country      string  `json:"country"`
	Region       string  `json:"region"`
	City         string  `json:"city"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	Accuracy     int     `json:"accuracy"`
	ISP          string  `json:"isp"`
	Organization string  `json:"organization"`
}

type DeviceInfo struct {
	DeviceID       string    `json:"device_id"`
	DeviceType     string    `json:"device_type"`
	OS             string    `json:"os"`
	OSVersion      string    `json:"os_version"`
	Browser        string    `json:"browser"`
	BrowserVersion string    `json:"browser_version"`
	Fingerprint    string    `json:"fingerprint"`
	Registered     bool      `json:"registered"`
	Trusted        bool      `json:"trusted"`
	LastSeen       time.Time `json:"last_seen"`
}

type NetworkInfo struct {
	ISP            string  `json:"isp"`
	ASN            string  `json:"asn"`
	Organization   string  `json:"organization"`
	ConnectionType string  `json:"connection_type"`
	ThreatScore    float64 `json:"threat_score"`
	Blacklisted    bool    `json:"blacklisted"`
}

type ThreatIndicator struct {
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Source      string    `json:"source"`
	Confidence  float64   `json:"confidence"`
	DetectedAt  time.Time `json:"detected_at"`
}

type ComplianceStatus struct {
	Overall      bool            `json:"overall"`
	Frameworks   map[string]bool `json:"frameworks"`
	Requirements map[string]bool `json:"requirements"`
	LastCheck    time.Time       `json:"last_check"`
}

type AuditLevel string

const (
	AuditLevelMinimal       AuditLevel = "minimal"
	AuditLevelStandard      AuditLevel = "standard"
	AuditLevelDetailed      AuditLevel = "detailed"
	AuditLevelComprehensive AuditLevel = "comprehensive"
)

type RiskTrend struct {
	Timestamp time.Time `json:"timestamp"`
	RiskLevel RiskLevel `json:"risk_level"`
	Score     float64   `json:"score"`
	Change    float64   `json:"change"`
}

type RiskThresholds struct {
	Low      float64 `json:"low"`
	Medium   float64 `json:"medium"`
	High     float64 `json:"high"`
	Critical float64 `json:"critical"`
	Extreme  float64 `json:"extreme"`
}

// Context change tracking
type ContextChange struct {
	ChangeID   string                 `json:"change_id"`
	ChangeType ContextChangeType      `json:"change_type"`
	Field      string                 `json:"field"`
	OldValue   interface{}            `json:"old_value"`
	NewValue   interface{}            `json:"new_value"`
	Timestamp  time.Time              `json:"timestamp"`
	Impact     ChangeImpact           `json:"impact"`
	Details    map[string]interface{} `json:"details"`
}

type ContextChangeType string

const (
	ContextChangeEnvironment ContextChangeType = "environment"
	ContextChangeSecurity    ContextChangeType = "security"
	ContextChangeCompliance  ContextChangeType = "compliance"
	ContextChangeRisk        ContextChangeType = "risk"
)

type ChangeImpact string

const (
	ChangeImpactMinimal  ChangeImpact = "minimal"
	ChangeImpactLow      ChangeImpact = "low"
	ChangeImpactMedium   ChangeImpact = "medium"
	ChangeImpactHigh     ChangeImpact = "high"
	ChangeImpactCritical ChangeImpact = "critical"
)

// Rules for context monitoring
type ComplianceRule struct {
	RuleID      string           `json:"rule_id"`
	Name        string           `json:"name"`
	Framework   string           `json:"framework"`
	Requirement string           `json:"requirement"`
	Condition   string           `json:"condition"`
	Action      ComplianceAction `json:"action"`
	Severity    string           `json:"severity"`
	Enabled     bool             `json:"enabled"`
}

type ContextRule struct {
	RuleID    string        `json:"rule_id"`
	Name      string        `json:"name"`
	Category  string        `json:"category"`
	Condition string        `json:"condition"`
	Threshold float64       `json:"threshold"`
	Action    ContextAction `json:"action"`
	Enabled   bool          `json:"enabled"`
}

type ComplianceAction string

const (
	ComplianceActionAlert     ComplianceAction = "alert"
	ComplianceActionAudit     ComplianceAction = "audit"
	ComplianceActionBlock     ComplianceAction = "block"
	ComplianceActionTerminate ComplianceAction = "terminate"
)

type ContextAction string

const (
	ContextActionMonitor   ContextAction = "monitor"
	ContextActionAlert     ContextAction = "alert"
	ContextActionReassess  ContextAction = "reassess"
	ContextActionChallenge ContextAction = "challenge"
	ContextActionTerminate ContextAction = "terminate"
)

// Context change detector
type ContextChangeDetector struct {
	thresholds ChangeDetectionThresholds
	patterns   []ChangePattern
	analyzer   *ChangeAnalyzer
}

type ChangeDetectionThresholds struct {
	LocationChange    float64 `json:"location_change"` // km
	IPAddressChange   bool    `json:"ip_address_change"`
	DeviceChange      bool    `json:"device_change"`
	BehaviorDeviation float64 `json:"behavior_deviation"` // score threshold
	RiskIncrease      float64 `json:"risk_increase"`      // score delta
}

type ChangePattern struct {
	PatternID   string   `json:"pattern_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Indicators  []string `json:"indicators"`
	Threshold   float64  `json:"threshold"`
	Action      string   `json:"action"`
}

type ChangeAnalyzer struct {
	analysisQueue chan *ContextChange
	analyzer      func(*ContextChange) (*ChangeAnalysis, error)
}

type ChangeAnalysis struct {
	ChangeID        string    `json:"change_id"`
	Risk            float64   `json:"risk"`
	Confidence      float64   `json:"confidence"`
	Anomalous       bool      `json:"anomalous"`
	Patterns        []string  `json:"patterns"`
	Recommendations []string  `json:"recommendations"`
	AnalyzedAt      time.Time `json:"analyzed_at"`
}

// Statistics
type ContextMonitorStats struct {
	TotalContexts         int                         `json:"total_contexts"`
	ActiveContexts        int                         `json:"active_contexts"`
	ContextChanges        int64                       `json:"context_changes"`
	ComplianceViolations  int64                       `json:"compliance_violations"`
	RiskThresholdBreaches int64                       `json:"risk_threshold_breaches"`
	AverageCheckLatencyMs float64                     `json:"average_check_latency_ms"`
	ChangesByType         map[ContextChangeType]int64 `json:"changes_by_type"`
	ViolationsByFramework map[string]int64            `json:"violations_by_framework"`
	LastMonitoringRun     time.Time                   `json:"last_monitoring_run"`

	mutex sync.RWMutex
}

// NewContextMonitor creates a new context monitor
func NewContextMonitor(riskManager RiskManager, checkInterval time.Duration) *ContextMonitor {
	return &ContextMonitor{
		riskManager:     riskManager,
		contextStore:    make(map[string]*AuthorizationContext),
		checkInterval:   checkInterval,
		complianceRules: getDefaultComplianceRules(),
		contextRules:    getDefaultContextRules(),
		changeDetector:  NewContextChangeDetector(),
		stopChannel:     make(chan struct{}),
		stats: ContextMonitorStats{
			ChangesByType:         make(map[ContextChangeType]int64),
			ViolationsByFramework: make(map[string]int64),
		},
	}
}

// Start initializes and starts the context monitor
func (cm *ContextMonitor) Start(ctx context.Context) error {
	cm.contextMutex.Lock()
	defer cm.contextMutex.Unlock()

	if cm.started {
		return fmt.Errorf("context monitor is already started")
	}

	// Start monitoring processes
	cm.monitoringGroup.Add(2)
	go cm.contextMonitoringLoop(ctx)
	go cm.complianceMonitoringLoop(ctx)

	cm.started = true
	return nil
}

// Stop gracefully stops the context monitor
func (cm *ContextMonitor) Stop() error {
	cm.contextMutex.Lock()
	defer cm.contextMutex.Unlock()

	if !cm.started {
		return fmt.Errorf("context monitor is not started")
	}

	// Signal shutdown
	close(cm.stopChannel)

	// Wait for monitoring to complete
	cm.monitoringGroup.Wait()

	cm.started = false
	return nil
}

// RegisterContext registers a new authorization context for monitoring
func (cm *ContextMonitor) RegisterContext(ctx context.Context, sessionID string, initialContext *AuthorizationContext) error {
	cm.contextMutex.Lock()
	defer cm.contextMutex.Unlock()

	if initialContext == nil {
		initialContext = &AuthorizationContext{
			SessionID:   sessionID,
			CreatedAt:   time.Now(),
			LastUpdated: time.Now(),
			Changes:     make([]ContextChange, 0),
		}
	}

	initialContext.SessionID = sessionID
	initialContext.CreatedAt = time.Now()
	initialContext.LastUpdated = time.Now()

	cm.contextStore[sessionID] = initialContext

	// Update statistics
	cm.updateStats()

	return nil
}

// UpdateContext updates the authorization context for a session
func (cm *ContextMonitor) UpdateContext(ctx context.Context, sessionID string, updates map[string]interface{}) error {
	cm.contextMutex.Lock()
	defer cm.contextMutex.Unlock()

	authContext, exists := cm.contextStore[sessionID]
	if !exists {
		return fmt.Errorf("context for session %s not found", sessionID)
	}

	authContext.mutex.Lock()
	defer authContext.mutex.Unlock()

	// Track changes
	changes := make([]ContextChange, 0)

	for field, newValue := range updates {
		oldValue := cm.getFieldValue(authContext, field)
		if cm.hasValueChanged(oldValue, newValue) {
			change := ContextChange{
				ChangeID:   fmt.Sprintf("change-%d", time.Now().UnixNano()),
				ChangeType: cm.determineChangeType(field),
				Field:      field,
				OldValue:   oldValue,
				NewValue:   newValue,
				Timestamp:  time.Now(),
				Impact:     cm.assessChangeImpact(field, oldValue, newValue),
			}
			changes = append(changes, change)

			// Apply the change
			cm.setFieldValue(authContext, field, newValue)
		}
	}

	// Record changes
	authContext.Changes = append(authContext.Changes, changes...)
	authContext.ChangeCounter += len(changes)
	authContext.LastUpdated = time.Now()

	// Analyze changes for anomalies
	for _, change := range changes {
		cm.analyzeChange(ctx, &change)
	}

	// Update statistics
	cm.stats.mutex.Lock()
	cm.stats.ContextChanges += int64(len(changes))
	for _, change := range changes {
		cm.stats.ChangesByType[change.ChangeType]++
	}
	cm.stats.mutex.Unlock()

	return nil
}

// CheckSessionContext performs a comprehensive context check for a session
func (cm *ContextMonitor) CheckSessionContext(ctx context.Context, session *AuthorizedSession) error {
	cm.contextMutex.RLock()
	authContext, exists := cm.contextStore[session.SessionID]
	cm.contextMutex.RUnlock()

	if !exists {
		// Create context if it doesn't exist
		return cm.RegisterContext(ctx, session.SessionID, nil)
	}

	startTime := time.Now()

	// Update environment context
	if err := cm.updateEnvironmentContext(ctx, authContext, session); err != nil {
		return fmt.Errorf("failed to update environment context: %w", err)
	}

	// Update security context
	if err := cm.updateSecurityContext(ctx, authContext, session); err != nil {
		return fmt.Errorf("failed to update security context: %w", err)
	}

	// Update risk context
	if err := cm.updateRiskContext(ctx, authContext, session); err != nil {
		return fmt.Errorf("failed to update risk context: %w", err)
	}

	// Check compliance
	if err := cm.checkCompliance(ctx, authContext, session); err != nil {
		return fmt.Errorf("failed to check compliance: %w", err)
	}

	// Update check timestamp
	authContext.mutex.Lock()
	authContext.LastChecked = time.Now()
	authContext.mutex.Unlock()

	// Update monitoring statistics
	checkLatency := time.Since(startTime)
	cm.updateCheckLatency(checkLatency)

	return nil
}

// GetContextStatus returns the current context status for a session
func (cm *ContextMonitor) GetContextStatus(ctx context.Context, sessionID string) (*ContextStatus, error) {
	cm.contextMutex.RLock()
	defer cm.contextMutex.RUnlock()

	authContext, exists := cm.contextStore[sessionID]
	if !exists {
		return nil, fmt.Errorf("context for session %s not found", sessionID)
	}

	authContext.mutex.RLock()
	defer authContext.mutex.RUnlock()

	return &ContextStatus{
		Valid:          cm.isContextValid(authContext),
		LastValidated:  authContext.LastUpdated,
		ChangeDetected: authContext.ChangeCounter > 0,
	}, nil
}

// RemoveContext removes a context from monitoring
func (cm *ContextMonitor) RemoveContext(ctx context.Context, sessionID string) error {
	cm.contextMutex.Lock()
	defer cm.contextMutex.Unlock()

	delete(cm.contextStore, sessionID)

	// Update statistics
	cm.updateStats()

	return nil
}

// GetMonitoringStats returns current monitoring statistics
func (cm *ContextMonitor) GetMonitoringStats() *ContextMonitorStats {
	cm.stats.mutex.RLock()
	defer cm.stats.mutex.RUnlock()

	// Return a copy
	stats := ContextMonitorStats{
		TotalContexts:         cm.stats.TotalContexts,
		ActiveContexts:        cm.stats.ActiveContexts,
		ContextChanges:        cm.stats.ContextChanges,
		ComplianceViolations:  cm.stats.ComplianceViolations,
		RiskThresholdBreaches: cm.stats.RiskThresholdBreaches,
		AverageCheckLatencyMs: cm.stats.AverageCheckLatencyMs,
		ChangesByType:         make(map[ContextChangeType]int64),
		ViolationsByFramework: make(map[string]int64),
		LastMonitoringRun:     cm.stats.LastMonitoringRun,
	}

	// Copy maps
	for k, v := range cm.stats.ChangesByType {
		stats.ChangesByType[k] = v
	}
	for k, v := range cm.stats.ViolationsByFramework {
		stats.ViolationsByFramework[k] = v
	}

	return &stats
}

// Background monitoring processes

// contextMonitoringLoop continuously monitors authorization contexts
func (cm *ContextMonitor) contextMonitoringLoop(ctx context.Context) {
	defer cm.monitoringGroup.Done()

	ticker := time.NewTicker(cm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cm.stopChannel:
			return
		case <-ticker.C:
			cm.performContextChecks(ctx)
		}
	}
}

// complianceMonitoringLoop monitors compliance requirements
func (cm *ContextMonitor) complianceMonitoringLoop(ctx context.Context) {
	defer cm.monitoringGroup.Done()

	ticker := time.NewTicker(1 * time.Minute) // More frequent compliance checks
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cm.stopChannel:
			return
		case <-ticker.C:
			cm.performComplianceChecks(ctx)
		}
	}
}

// Helper methods (implementation stubs - would need full implementation)

func (cm *ContextMonitor) performContextChecks(ctx context.Context) {
	cm.contextMutex.RLock()
	contexts := make([]*AuthorizationContext, 0, len(cm.contextStore))
	for _, authContext := range cm.contextStore {
		contexts = append(contexts, authContext)
	}
	cm.contextMutex.RUnlock()

	for _, authContext := range contexts {
		// Check if context needs updating
		if time.Since(authContext.LastChecked) > cm.checkInterval {
			// Perform context checks (implementation would be more detailed)
			_ = authContext // Placeholder for context validation logic
		}
	}

	cm.stats.mutex.Lock()
	cm.stats.LastMonitoringRun = time.Now()
	cm.stats.mutex.Unlock()
}

func (cm *ContextMonitor) performComplianceChecks(ctx context.Context) {
	// Implementation would check compliance rules against contexts
}

func (cm *ContextMonitor) updateEnvironmentContext(ctx context.Context, authContext *AuthorizationContext, session *AuthorizedSession) error {
	// Implementation would update environment context from session metadata
	return nil
}

func (cm *ContextMonitor) updateSecurityContext(ctx context.Context, authContext *AuthorizationContext, session *AuthorizedSession) error {
	// Implementation would update security context
	return nil
}

func (cm *ContextMonitor) updateRiskContext(ctx context.Context, authContext *AuthorizationContext, session *AuthorizedSession) error {
	// Implementation would call risk manager for updated risk assessment
	return nil
}

func (cm *ContextMonitor) checkCompliance(ctx context.Context, authContext *AuthorizationContext, session *AuthorizedSession) error {
	// Implementation would check compliance rules
	return nil
}

func (cm *ContextMonitor) updateStats() {
	cm.stats.mutex.Lock()
	defer cm.stats.mutex.Unlock()

	cm.stats.ActiveContexts = len(cm.contextStore)
	cm.stats.TotalContexts = cm.stats.ActiveContexts
}

func (cm *ContextMonitor) updateCheckLatency(latency time.Duration) {
	cm.stats.mutex.Lock()
	defer cm.stats.mutex.Unlock()

	// Update average latency using exponential moving average
	alpha := 0.1
	newLatency := float64(latency.Milliseconds())
	cm.stats.AverageCheckLatencyMs = (1-alpha)*cm.stats.AverageCheckLatencyMs + alpha*newLatency
}

// Utility methods (stubs)

func (cm *ContextMonitor) getFieldValue(context *AuthorizationContext, field string) interface{} {
	// Implementation would extract field value from context
	return nil
}

func (cm *ContextMonitor) setFieldValue(context *AuthorizationContext, field string, value interface{}) {
	// Implementation would set field value in context
}

func (cm *ContextMonitor) hasValueChanged(oldValue, newValue interface{}) bool {
	// Implementation would compare values
	return oldValue != newValue
}

func (cm *ContextMonitor) determineChangeType(field string) ContextChangeType {
	// Implementation would determine change type based on field
	return ContextChangeEnvironment
}

func (cm *ContextMonitor) assessChangeImpact(field string, oldValue, newValue interface{}) ChangeImpact {
	// Implementation would assess the impact of the change
	return ChangeImpactMedium
}

func (cm *ContextMonitor) analyzeChange(ctx context.Context, change *ContextChange) {
	// Implementation would analyze change for anomalies
}

func (cm *ContextMonitor) isContextValid(context *AuthorizationContext) bool {
	// Implementation would validate context
	return true
}

// Factory functions

func NewContextChangeDetector() *ContextChangeDetector {
	return &ContextChangeDetector{
		thresholds: ChangeDetectionThresholds{
			LocationChange:    50.0, // 50km
			IPAddressChange:   true,
			DeviceChange:      true,
			BehaviorDeviation: 2.0,
			RiskIncrease:      0.2,
		},
		patterns: getDefaultChangePatterns(),
		analyzer: NewChangeAnalyzer(),
	}
}

func NewChangeAnalyzer() *ChangeAnalyzer {
	return &ChangeAnalyzer{
		analysisQueue: make(chan *ContextChange, 100),
		analyzer: func(change *ContextChange) (*ChangeAnalysis, error) {
			// Default analyzer implementation
			return &ChangeAnalysis{
				ChangeID:        change.ChangeID,
				Risk:            0.5,
				Confidence:      0.8,
				Anomalous:       false,
				Patterns:        []string{},
				Recommendations: []string{},
				AnalyzedAt:      time.Now(),
			}, nil
		},
	}
}

// Default rules and patterns (would be loaded from configuration)

func getDefaultComplianceRules() []ComplianceRule {
	return []ComplianceRule{
		{
			RuleID:      "gdpr-data-access",
			Name:        "GDPR Data Access Monitoring",
			Framework:   "GDPR",
			Requirement: "Data access logging",
			Condition:   "data_classification == 'personal'",
			Action:      ComplianceActionAudit,
			Severity:    "high",
			Enabled:     true,
		},
	}
}

func getDefaultContextRules() []ContextRule {
	return []ContextRule{
		{
			RuleID:    "location-change",
			Name:      "Location Change Detection",
			Category:  "environment",
			Condition: "location_change > 100", // 100km
			Threshold: 100.0,
			Action:    ContextActionChallenge,
			Enabled:   true,
		},
	}
}

func getDefaultChangePatterns() []ChangePattern {
	return []ChangePattern{
		{
			PatternID:   "impossible-travel",
			Name:        "Impossible Travel",
			Description: "Location changes that are impossible given time constraints",
			Indicators:  []string{"location_change", "time_delta"},
			Threshold:   0.8,
			Action:      "challenge",
		},
	}
}
