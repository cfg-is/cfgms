// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package zerotrust

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// PolicyLifecycleManager provides comprehensive policy lifecycle management
type PolicyLifecycleManager struct {
	engine *ZeroTrustPolicyEngine

	// Policy storage and versioning
	policies       map[string]*PolicyVersion   // policyID -> current version
	policyVersions map[string][]*PolicyVersion // policyID -> all versions

	// Policy indexing for efficient lookups
	policiesByTenant   map[string][]*PolicyVersion // tenantID -> policies
	policiesBySubject  map[string][]*PolicyVersion // subjectPattern -> policies
	policiesByResource map[string][]*PolicyVersion // resourcePattern -> policies

	// Event handling
	eventHandlers []PolicyEventHandler
	eventQueue    chan *PolicyEvent

	// Configuration
	config *PolicyLifecycleConfig

	// Synchronization
	mutex       sync.RWMutex
	started     bool
	stopChannel chan struct{}
	eventGroup  sync.WaitGroup
}

// PolicyVersion represents a versioned policy with lifecycle metadata
type PolicyVersion struct {
	Policy  *ZeroTrustPolicy    `json:"policy"`
	Version string              `json:"version"`
	Status  PolicyVersionStatus `json:"status"`

	// Lifecycle timestamps
	CreatedAt     time.Time `json:"created_at"`
	ActivatedAt   time.Time `json:"activated_at,omitempty"`
	DeactivatedAt time.Time `json:"deactivated_at,omitempty"`
	RetiredAt     time.Time `json:"retired_at,omitempty"`

	// Version metadata
	ChangeLog  string    `json:"change_log,omitempty"`
	CreatedBy  string    `json:"created_by"`
	ApprovedBy string    `json:"approved_by,omitempty"`
	ApprovedAt time.Time `json:"approved_at,omitempty"`

	// Validation and testing
	ValidatedAt time.Time          `json:"validated_at,omitempty"`
	TestResults *PolicyTestResults `json:"test_results,omitempty"`

	// Dependencies and conflicts
	Dependencies []string `json:"dependencies,omitempty"`
	Conflicts    []string `json:"conflicts,omitempty"`
}

// PolicyVersionStatus defines the status of a policy version
type PolicyVersionStatus string

const (
	PolicyVersionStatusDraft      PolicyVersionStatus = "draft"      // Being developed
	PolicyVersionStatusPending    PolicyVersionStatus = "pending"    // Awaiting approval
	PolicyVersionStatusApproved   PolicyVersionStatus = "approved"   // Approved for deployment
	PolicyVersionStatusActive     PolicyVersionStatus = "active"     // Currently enforced
	PolicyVersionStatusDeprecated PolicyVersionStatus = "deprecated" // Being phased out
	PolicyVersionStatusRetired    PolicyVersionStatus = "retired"    // No longer used
	PolicyVersionStatusFailed     PolicyVersionStatus = "failed"     // Failed validation
)

// PolicyTestResults contains results from policy testing and validation
type PolicyTestResults struct {
	TestSuite    string        `json:"test_suite"`
	TestsRun     int           `json:"tests_run"`
	TestsPassed  int           `json:"tests_passed"`
	TestsFailed  int           `json:"tests_failed"`
	Coverage     float64       `json:"coverage"`
	TestDuration time.Duration `json:"test_duration"`

	// Detailed results
	TestCases        []*PolicyTestCase `json:"test_cases"`
	ValidationErrors []ValidationError `json:"validation_errors"`

	// Performance metrics
	EvaluationTime time.Duration `json:"evaluation_time"`
	MemoryUsage    int64         `json:"memory_usage"`
}

// PolicyTestCase represents a single test case result
type PolicyTestCase struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Passed      bool          `json:"passed"`
	Error       string        `json:"error,omitempty"`
	Duration    time.Duration `json:"duration"`

	// Test data
	Input          *ZeroTrustAccessRequest  `json:"input"`
	ExpectedResult *ZeroTrustAccessResponse `json:"expected_result"`
	ActualResult   *ZeroTrustAccessResponse `json:"actual_result"`
}

// PolicyEventHandler handles policy lifecycle events
type PolicyEventHandler interface {
	HandleEvent(ctx context.Context, event *PolicyEvent) error
	GetEventTypes() []PolicyEventType
}

// PolicyEvent represents a policy lifecycle event
type PolicyEvent struct {
	EventID   string          `json:"event_id"`
	EventType PolicyEventType `json:"event_type"`
	EventTime time.Time       `json:"event_time"`

	// Policy information
	PolicyID      string `json:"policy_id"`
	PolicyVersion string `json:"policy_version"`

	// Event details
	Actor       string                 `json:"actor"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`

	// Before/after states for changes
	OldState interface{} `json:"old_state,omitempty"`
	NewState interface{} `json:"new_state,omitempty"`
}

// PolicyEventType defines types of policy lifecycle events
type PolicyEventType string

const (
	PolicyEventCreated     PolicyEventType = "created"
	PolicyEventUpdated     PolicyEventType = "updated"
	PolicyEventActivated   PolicyEventType = "activated"
	PolicyEventDeactivated PolicyEventType = "deactivated"
	PolicyEventRetired     PolicyEventType = "retired"
	PolicyEventTested      PolicyEventType = "tested"
	PolicyEventValidated   PolicyEventType = "validated"
	PolicyEventApproved    PolicyEventType = "approved"
	PolicyEventRejected    PolicyEventType = "rejected"
)

// PolicyLifecycleConfig provides configuration for policy lifecycle management
type PolicyLifecycleConfig struct {
	// Versioning settings
	EnableVersioning     bool `json:"enable_versioning"`
	MaxVersionsPerPolicy int  `json:"max_versions_per_policy"`
	AutoIncrementVersion bool `json:"auto_increment_version"`

	// Approval workflow
	RequireApproval   bool `json:"require_approval"`
	RequireTesting    bool `json:"require_testing"`
	RequireValidation bool `json:"require_validation"`

	// Event processing
	EnableEventProcessing  bool          `json:"enable_event_processing"`
	EventBufferSize        int           `json:"event_buffer_size"`
	EventProcessingTimeout time.Duration `json:"event_processing_timeout"`

	// Retention policies
	RetentionPolicyDays    int  `json:"retention_policy_days"`
	ArchiveRetiredPolicies bool `json:"archive_retired_policies"`
}

// NewPolicyLifecycleManager creates a new policy lifecycle manager
func NewPolicyLifecycleManager(engine *ZeroTrustPolicyEngine) *PolicyLifecycleManager {
	config := &PolicyLifecycleConfig{
		EnableVersioning:       true,
		MaxVersionsPerPolicy:   10,
		AutoIncrementVersion:   true,
		RequireApproval:        false, // Can be enabled for production
		RequireTesting:         true,
		RequireValidation:      true,
		EnableEventProcessing:  true,
		EventBufferSize:        1000,
		EventProcessingTimeout: 30 * time.Second,
		RetentionPolicyDays:    365,
		ArchiveRetiredPolicies: true,
	}

	return &PolicyLifecycleManager{
		engine:             engine,
		policies:           make(map[string]*PolicyVersion),
		policyVersions:     make(map[string][]*PolicyVersion),
		policiesByTenant:   make(map[string][]*PolicyVersion),
		policiesBySubject:  make(map[string][]*PolicyVersion),
		policiesByResource: make(map[string][]*PolicyVersion),
		eventHandlers:      make([]PolicyEventHandler, 0),
		eventQueue:         make(chan *PolicyEvent, config.EventBufferSize),
		config:             config,
		stopChannel:        make(chan struct{}),
	}
}

// Start initializes the policy lifecycle manager
func (p *PolicyLifecycleManager) Start(ctx context.Context) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.started {
		return fmt.Errorf("policy lifecycle manager is already started")
	}

	// Start event processing goroutine
	if p.config.EnableEventProcessing {
		p.eventGroup.Add(1)
		go p.eventProcessingLoop(ctx)
	}

	p.started = true
	return nil
}

// Stop gracefully stops the policy lifecycle manager
func (p *PolicyLifecycleManager) Stop() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if !p.started {
		return fmt.Errorf("policy lifecycle manager is not started")
	}

	// Signal shutdown
	close(p.stopChannel)

	// Wait for event processing to complete
	p.eventGroup.Wait()

	p.started = false
	return nil
}

// CreatePolicy creates a new policy in draft status
func (p *PolicyLifecycleManager) CreatePolicy(ctx context.Context, policy *ZeroTrustPolicy, createdBy string) (*PolicyVersion, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Validate policy
	if policy.ID == "" {
		return nil, fmt.Errorf("policy ID is required")
	}

	// Check if policy already exists
	if _, exists := p.policies[policy.ID]; exists {
		return nil, fmt.Errorf("policy with ID %s already exists", policy.ID)
	}

	// Create initial version
	version := &PolicyVersion{
		Policy:       policy,
		Version:      "v1.0.0",
		Status:       PolicyVersionStatusDraft,
		CreatedAt:    time.Now(),
		CreatedBy:    createdBy,
		Dependencies: make([]string, 0),
		Conflicts:    make([]string, 0),
	}

	// Store policy version
	p.policies[policy.ID] = version
	p.policyVersions[policy.ID] = []*PolicyVersion{version}

	// Update indexes
	p.updateIndexes(version)

	// Emit event
	event := &PolicyEvent{
		EventID:       fmt.Sprintf("create-%s-%d", policy.ID, time.Now().UnixNano()),
		EventType:     PolicyEventCreated,
		EventTime:     time.Now(),
		PolicyID:      policy.ID,
		PolicyVersion: version.Version,
		Actor:         createdBy,
		Description:   "Policy created in draft status",
		NewState:      version,
	}

	p.emitEvent(event)

	return version, nil
}

// UpdatePolicy creates a new version of an existing policy
func (p *PolicyLifecycleManager) UpdatePolicy(ctx context.Context, policyID string, updatedPolicy *ZeroTrustPolicy, updatedBy string, changeLog string) (*PolicyVersion, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Get current policy version
	currentVersion, exists := p.policies[policyID]
	if !exists {
		return nil, fmt.Errorf("policy %s not found", policyID)
	}

	// Generate new version number
	newVersionNumber := p.generateNextVersion(policyID)

	// Create new version
	newVersion := &PolicyVersion{
		Policy:       updatedPolicy,
		Version:      newVersionNumber,
		Status:       PolicyVersionStatusDraft,
		CreatedAt:    time.Now(),
		CreatedBy:    updatedBy,
		ChangeLog:    changeLog,
		Dependencies: make([]string, 0),
		Conflicts:    make([]string, 0),
	}

	// Add to version history
	p.policyVersions[policyID] = append(p.policyVersions[policyID], newVersion)

	// Clean up old versions if necessary
	p.cleanupOldVersions(policyID)

	// Update current pointer (new version starts as draft)
	// Current active version remains unchanged until new version is activated

	// Update indexes
	p.updateIndexes(newVersion)

	// Emit event
	event := &PolicyEvent{
		EventID:       fmt.Sprintf("update-%s-%d", policyID, time.Now().UnixNano()),
		EventType:     PolicyEventUpdated,
		EventTime:     time.Now(),
		PolicyID:      policyID,
		PolicyVersion: newVersion.Version,
		Actor:         updatedBy,
		Description:   fmt.Sprintf("Policy updated: %s", changeLog),
		OldState:      currentVersion,
		NewState:      newVersion,
	}

	p.emitEvent(event)

	return newVersion, nil
}

// ActivatePolicy activates a policy version for enforcement
func (p *PolicyLifecycleManager) ActivatePolicy(ctx context.Context, policyID string, version string, activatedBy string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Find the policy version
	versions, exists := p.policyVersions[policyID]
	if !exists {
		return fmt.Errorf("policy %s not found", policyID)
	}

	var targetVersion *PolicyVersion
	for _, v := range versions {
		if v.Version == version {
			targetVersion = v
			break
		}
	}

	if targetVersion == nil {
		return fmt.Errorf("policy version %s not found for policy %s", version, policyID)
	}

	// Check if version can be activated
	if targetVersion.Status != PolicyVersionStatusApproved &&
		targetVersion.Status != PolicyVersionStatusDraft &&
		p.config.RequireApproval {
		return fmt.Errorf("policy version %s is not approved for activation", version)
	}

	// Deactivate current active version
	currentActive := p.policies[policyID]
	if currentActive != nil && currentActive.Status == PolicyVersionStatusActive {
		currentActive.Status = PolicyVersionStatusDeprecated
		currentActive.DeactivatedAt = time.Now()
	}

	// Activate new version
	targetVersion.Status = PolicyVersionStatusActive
	targetVersion.ActivatedAt = time.Now()
	p.policies[policyID] = targetVersion

	// Emit event
	event := &PolicyEvent{
		EventID:       fmt.Sprintf("activate-%s-%d", policyID, time.Now().UnixNano()),
		EventType:     PolicyEventActivated,
		EventTime:     time.Now(),
		PolicyID:      policyID,
		PolicyVersion: version,
		Actor:         activatedBy,
		Description:   "Policy version activated for enforcement",
		OldState:      currentActive,
		NewState:      targetVersion,
	}

	p.emitEvent(event)

	return nil
}

// DeactivatePolicy deactivates a policy
func (p *PolicyLifecycleManager) DeactivatePolicy(ctx context.Context, policyID string, deactivatedBy string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Get current policy version
	currentVersion, exists := p.policies[policyID]
	if !exists {
		return fmt.Errorf("policy %s not found", policyID)
	}

	if currentVersion.Status != PolicyVersionStatusActive {
		return fmt.Errorf("policy %s is not active", policyID)
	}

	oldStatus := currentVersion.Status
	currentVersion.Status = PolicyVersionStatusDeprecated
	currentVersion.DeactivatedAt = time.Now()

	// Emit event
	event := &PolicyEvent{
		EventID:       fmt.Sprintf("deactivate-%s-%d", policyID, time.Now().UnixNano()),
		EventType:     PolicyEventDeactivated,
		EventTime:     time.Now(),
		PolicyID:      policyID,
		PolicyVersion: currentVersion.Version,
		Actor:         deactivatedBy,
		Description:   "Policy deactivated",
		OldState:      oldStatus,
		NewState:      currentVersion.Status,
	}

	p.emitEvent(event)

	return nil
}

// GetPolicy retrieves the current active policy version
func (p *PolicyLifecycleManager) GetPolicy(policyID string) (*PolicyVersion, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	version, exists := p.policies[policyID]
	if !exists {
		return nil, fmt.Errorf("policy %s not found", policyID)
	}

	return version, nil
}

// ListPolicies returns all active policies matching the given criteria
func (p *PolicyLifecycleManager) ListPolicies(criteria *PolicyListCriteria) ([]*PolicyVersion, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	var result []*PolicyVersion

	for _, version := range p.policies {
		if p.matchesCriteria(version, criteria) {
			result = append(result, version)
		}
	}

	// Sort by priority and creation time
	sort.Slice(result, func(i, j int) bool {
		if result[i].Policy.Priority != result[j].Policy.Priority {
			return result[i].Policy.Priority > result[j].Policy.Priority
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})

	return result, nil
}

// PolicyListCriteria defines criteria for listing policies
type PolicyListCriteria struct {
	Status        []PolicyVersionStatus `json:"status,omitempty"`
	TenantIDs     []string              `json:"tenant_ids,omitempty"`
	CreatedBy     string                `json:"created_by,omitempty"`
	CreatedAfter  time.Time             `json:"created_after,omitempty"`
	CreatedBefore time.Time             `json:"created_before,omitempty"`
	PolicyTypes   []string              `json:"policy_types,omitempty"`
}

// Helper methods

func (p *PolicyLifecycleManager) generateNextVersion(policyID string) string {
	versions := p.policyVersions[policyID]
	if len(versions) == 0 {
		return "v1.0.0"
	}

	// For simplicity, just increment patch version
	return fmt.Sprintf("v1.0.%d", len(versions))
}

func (p *PolicyLifecycleManager) cleanupOldVersions(policyID string) {
	if p.config.MaxVersionsPerPolicy <= 0 {
		return
	}

	versions := p.policyVersions[policyID]
	if len(versions) <= p.config.MaxVersionsPerPolicy {
		return
	}

	// Keep the most recent versions
	keepCount := p.config.MaxVersionsPerPolicy
	p.policyVersions[policyID] = versions[len(versions)-keepCount:]
}

func (p *PolicyLifecycleManager) updateIndexes(version *PolicyVersion) {
	policy := version.Policy

	// Index by tenant
	for _, tenantID := range policy.Scope.TenantIDs {
		p.policiesByTenant[tenantID] = append(p.policiesByTenant[tenantID], version)
	}

	// Index by subject IDs (simplified)
	for _, subjectID := range policy.Scope.SubjectIDs {
		p.policiesBySubject[subjectID] = append(p.policiesBySubject[subjectID], version)
	}

	// Index by resource types
	for _, resourceType := range policy.Scope.ResourceTypes {
		p.policiesByResource[resourceType] = append(p.policiesByResource[resourceType], version)
	}
}

func (p *PolicyLifecycleManager) matchesCriteria(version *PolicyVersion, criteria *PolicyListCriteria) bool {
	if criteria == nil {
		return true
	}

	// Check status
	if len(criteria.Status) > 0 {
		found := false
		for _, status := range criteria.Status {
			if version.Status == status {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check tenant IDs
	if len(criteria.TenantIDs) > 0 {
		found := false
		for _, tenantID := range criteria.TenantIDs {
			for _, policyTenantID := range version.Policy.Scope.TenantIDs {
				if policyTenantID == tenantID {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check created by
	if criteria.CreatedBy != "" && version.CreatedBy != criteria.CreatedBy {
		return false
	}

	// Check created after/before
	if !criteria.CreatedAfter.IsZero() && version.CreatedAt.Before(criteria.CreatedAfter) {
		return false
	}

	if !criteria.CreatedBefore.IsZero() && version.CreatedAt.After(criteria.CreatedBefore) {
		return false
	}

	return true
}

func (p *PolicyLifecycleManager) emitEvent(event *PolicyEvent) {
	if !p.config.EnableEventProcessing {
		return
	}

	select {
	case p.eventQueue <- event:
		// Event queued successfully
	default:
		// Queue is full, log warning (in real implementation)
		// For now, we just drop the event
	}
}

func (p *PolicyLifecycleManager) eventProcessingLoop(ctx context.Context) {
	defer p.eventGroup.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChannel:
			return
		case event := <-p.eventQueue:
			p.processEvent(ctx, event)
		}
	}
}

func (p *PolicyLifecycleManager) processEvent(ctx context.Context, event *PolicyEvent) {
	// Process event with timeout
	eventCtx, cancel := context.WithTimeout(ctx, p.config.EventProcessingTimeout)
	defer cancel()

	// Notify all registered event handlers
	for _, handler := range p.eventHandlers {
		// Check if handler is interested in this event type
		interestedTypes := handler.GetEventTypes()
		interested := false
		for _, eventType := range interestedTypes {
			if eventType == event.EventType {
				interested = true
				break
			}
		}

		if interested {
			if err := handler.HandleEvent(eventCtx, event); err != nil {
				// Log error and continue with other handlers
				_ = err // Prevent unused variable warning
			}
		}
	}
}

// RegisterEventHandler registers a new event handler
func (p *PolicyLifecycleManager) RegisterEventHandler(handler PolicyEventHandler) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.eventHandlers = append(p.eventHandlers, handler)
}

// UnregisterEventHandler removes an event handler
func (p *PolicyLifecycleManager) UnregisterEventHandler(handler PolicyEventHandler) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for i, h := range p.eventHandlers {
		if h == handler {
			p.eventHandlers = append(p.eventHandlers[:i], p.eventHandlers[i+1:]...)
			break
		}
	}
}
