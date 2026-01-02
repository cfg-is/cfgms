// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package failsafe

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/rbac/jit"
)

// FailsafeJITAccessManager provides fail-secure behavior for JIT access operations
// When the underlying JIT manager is unavailable, it automatically revokes temporary permissions
type FailsafeJITAccessManager struct {
	underlying  *jit.JITAccessManager
	healthCheck *JITHealthChecker
	failureMode JITFailureMode
	mutex       sync.RWMutex
	metrics     *JITFailsafeMetrics

	// Active grants tracking for automatic revocation
	activeGrants map[string]*jit.JITAccessGrant
	grantsMutex  sync.RWMutex
}

// JITFailureMode defines how the failsafe JIT manager behaves during failures
type JITFailureMode string

const (
	// JITFailureModeAutoRevoke automatically revokes all active grants during failures
	JITFailureModeAutoRevoke JITFailureMode = "auto_revoke"
	// JITFailureModeRejectNew rejects new requests and maintains existing grants during failures
	JITFailureModeRejectNew JITFailureMode = "reject_new"
	// JITFailureModeEmergencyOnly allows only emergency access requests during failures
	JITFailureModeEmergencyOnly JITFailureMode = "emergency_only"
)

// JITHealthChecker monitors the health of the underlying JIT access manager
type JITHealthChecker struct {
	jitManager             *jit.JITAccessManager
	lastHealthCheck        time.Time
	healthCheckInterval    time.Duration
	consecutiveFailures    int
	maxConsecutiveFailures int
	isHealthy              bool
	mutex                  sync.RWMutex
}

// JITFailsafeMetrics tracks JIT failsafe operation metrics
type JITFailsafeMetrics struct {
	TotalRequests       int64
	FailedRequests      int64
	RejectedByFailsafe  int64
	AutoRevokedGrants   int64
	HealthCheckFailures int64
	RecoveryEvents      int64
	mutex               sync.RWMutex
}

// NewFailsafeJITAccessManager creates a new failsafe JIT access manager
func NewFailsafeJITAccessManager(underlying *jit.JITAccessManager) *FailsafeJITAccessManager {
	healthChecker := &JITHealthChecker{
		jitManager:             underlying,
		healthCheckInterval:    60 * time.Second, // Longer interval for JIT operations
		maxConsecutiveFailures: 3,
		isHealthy:              true,
		mutex:                  sync.RWMutex{},
	}

	fjam := &FailsafeJITAccessManager{
		underlying:  underlying,
		healthCheck: healthChecker,
		failureMode: JITFailureModeAutoRevoke, // Default to auto-revoke for security
		mutex:       sync.RWMutex{},
		metrics: &JITFailsafeMetrics{
			mutex: sync.RWMutex{},
		},
		activeGrants: make(map[string]*jit.JITAccessGrant),
		grantsMutex:  sync.RWMutex{},
	}

	// Start health checking in background
	go fjam.startHealthChecking()

	return fjam
}

// SetFailureMode sets the failure behavior mode
func (fjam *FailsafeJITAccessManager) SetFailureMode(mode JITFailureMode) {
	fjam.mutex.Lock()
	defer fjam.mutex.Unlock()
	fjam.failureMode = mode
}

// IsHealthy returns the current health status of the underlying JIT manager
func (fjam *FailsafeJITAccessManager) IsHealthy() bool {
	fjam.healthCheck.mutex.RLock()
	defer fjam.healthCheck.mutex.RUnlock()
	return fjam.healthCheck.isHealthy
}

// GetMetrics returns the current JIT failsafe metrics
func (fjam *FailsafeJITAccessManager) GetMetrics() *JITFailsafeMetrics {
	fjam.metrics.mutex.RLock()
	defer fjam.metrics.mutex.RUnlock()
	return &JITFailsafeMetrics{
		TotalRequests:       fjam.metrics.TotalRequests,
		FailedRequests:      fjam.metrics.FailedRequests,
		RejectedByFailsafe:  fjam.metrics.RejectedByFailsafe,
		AutoRevokedGrants:   fjam.metrics.AutoRevokedGrants,
		HealthCheckFailures: fjam.metrics.HealthCheckFailures,
		RecoveryEvents:      fjam.metrics.RecoveryEvents,
	}
}

// RequestAccess implements fail-secure JIT access request handling
func (fjam *FailsafeJITAccessManager) RequestAccess(ctx context.Context, req *jit.JITAccessRequestSpec) (*jit.JITAccessRequest, error) {
	fjam.metrics.mutex.Lock()
	fjam.metrics.TotalRequests++
	fjam.metrics.mutex.Unlock()

	if !fjam.IsHealthy() {
		return fjam.handleRequestDuringFailure(ctx, req)
	}

	request, err := fjam.underlying.RequestAccess(ctx, req)
	if err != nil {
		fjam.metrics.mutex.Lock()
		fjam.metrics.FailedRequests++
		fjam.metrics.mutex.Unlock()

		// Mark as unhealthy and handle failure
		fjam.markUnhealthy()
		return fjam.handleRequestDuringFailure(ctx, req)
	}

	// Track granted access for potential revocation
	if request.GrantedAccess != nil {
		fjam.trackActiveGrant(request.GrantedAccess)
	}

	return request, nil
}

// handleRequestDuringFailure handles JIT access requests when the system is unhealthy
func (fjam *FailsafeJITAccessManager) handleRequestDuringFailure(ctx context.Context, req *jit.JITAccessRequestSpec) (*jit.JITAccessRequest, error) {
	fjam.metrics.mutex.Lock()
	fjam.metrics.RejectedByFailsafe++
	fjam.metrics.mutex.Unlock()

	// Read failure mode with proper locking to avoid race condition
	fjam.mutex.RLock()
	mode := fjam.failureMode
	fjam.mutex.RUnlock()

	switch mode {
	case JITFailureModeAutoRevoke:
		// Revoke all existing grants and deny new requests
		fjam.revokeAllActiveGrants(ctx, "JIT system failure - auto-revoke mode")
		return nil, fmt.Errorf("JIT access request denied: system is unhealthy and in auto-revoke mode")

	case JITFailureModeRejectNew:
		// Reject new requests but maintain existing grants
		return nil, fmt.Errorf("JIT access request denied: system is unhealthy, rejecting new requests")

	case JITFailureModeEmergencyOnly:
		// Allow only emergency requests
		if !req.EmergencyAccess {
			return nil, fmt.Errorf("JIT access request denied: system is unhealthy, only emergency access allowed")
		}
		// Create a minimal emergency grant
		return fjam.createEmergencyAccessRequest(ctx, req)

	default:
		return nil, fmt.Errorf("JIT access request denied: system is unhealthy")
	}
}

// createEmergencyAccessRequest creates a minimal emergency access request during system failure
func (fjam *FailsafeJITAccessManager) createEmergencyAccessRequest(ctx context.Context, req *jit.JITAccessRequestSpec) (*jit.JITAccessRequest, error) {
	now := time.Now()
	requestID := fmt.Sprintf("emergency-%d", now.UnixNano())

	// Create emergency request with limited duration
	emergencyRequest := &jit.JITAccessRequest{
		ID:              requestID,
		RequesterID:     req.RequesterID,
		TargetID:        req.TargetID,
		TenantID:        req.TenantID,
		Permissions:     req.Permissions,
		Roles:           req.Roles,
		ResourceIDs:     req.ResourceIDs,
		RequestedFor:    req.RequestedFor,
		Duration:        minDuration(req.Duration, 30*time.Minute), // Max 30 minutes for emergency
		Justification:   fmt.Sprintf("EMERGENCY ACCESS: %s (System degraded)", req.Justification),
		EmergencyAccess: true,
		Status:          jit.JITAccessRequestStatusApproved,
		CreatedAt:       now,
		ExpiresAt:       now.Add(minDuration(req.Duration, 30*time.Minute)),
		ApprovedBy:      "system-failsafe",
		ApprovalReason:  "Emergency access granted during JIT system failure",
		RequestTTL:      now.Add(1 * time.Hour),
	}

	// Create a corresponding grant
	emergencyGrant := &jit.JITAccessGrant{
		ID:                 requestID + "-grant",
		RequestID:          requestID,
		RequesterID:        req.RequesterID,
		TargetID:           req.TargetID,
		TenantID:           req.TenantID,
		Permissions:        req.Permissions,
		Roles:              req.Roles,
		ResourceIDs:        req.ResourceIDs,
		ApprovedBy:         "system-failsafe",
		ApprovalReason:     "Emergency failsafe grant",
		GrantedAt:          now,
		ExpiresAt:          emergencyRequest.ExpiresAt,
		Status:             jit.JITAccessGrantStatusActive,
		MaxExtensions:      0, // No extensions allowed for emergency grants
		ExtensionsUsed:     0,
		ActivationMethod:   jit.ActivationMethodImmediate,
		DeactivationMethod: jit.DeactivationMethodAutomatic,
		Conditions: []jit.AccessCondition{
			{
				Type:  jit.ConditionTypeEmergencyAccess,
				Value: "true",
			},
			{
				Type:  jit.ConditionTypeFailsafeMode,
				Value: "true",
			},
		},
	}

	emergencyRequest.GrantedAccess = emergencyGrant

	// Track the emergency grant for cleanup
	fjam.trackActiveGrant(emergencyGrant)

	// Schedule automatic revocation
	go fjam.scheduleEmergencyRevocation(ctx, emergencyGrant)

	return emergencyRequest, nil
}

// ApproveRequest implements fail-secure JIT access approval
func (fjam *FailsafeJITAccessManager) ApproveRequest(ctx context.Context, requestID, approverID, reason string) (*jit.JITAccessGrant, error) {
	fjam.metrics.mutex.Lock()
	fjam.metrics.TotalRequests++
	fjam.metrics.mutex.Unlock()

	if !fjam.IsHealthy() {
		fjam.metrics.mutex.Lock()
		fjam.metrics.RejectedByFailsafe++
		fjam.metrics.mutex.Unlock()
		return nil, fmt.Errorf("JIT access approval denied: system is unhealthy")
	}

	grant, err := fjam.underlying.ApproveRequest(ctx, requestID, approverID, reason)
	if err != nil {
		fjam.metrics.mutex.Lock()
		fjam.metrics.FailedRequests++
		fjam.metrics.mutex.Unlock()

		fjam.markUnhealthy()
		return nil, fmt.Errorf("JIT access approval failed, system marked unhealthy: %w", err)
	}

	// Track the granted access
	fjam.trackActiveGrant(grant)

	return grant, nil
}

// RevokeAccess implements fail-secure JIT access revocation
func (fjam *FailsafeJITAccessManager) RevokeAccess(ctx context.Context, grantID, revokerID, reason string) error {
	fjam.metrics.mutex.Lock()
	fjam.metrics.TotalRequests++
	fjam.metrics.mutex.Unlock()

	// Allow revocations even when system is unhealthy (fail-secure behavior)
	if !fjam.IsHealthy() {
		// Remove from our tracked grants
		fjam.removeTrackedGrant(grantID)
		// Continue with revocation attempt for safety
	}

	err := fjam.underlying.RevokeAccess(ctx, grantID, revokerID, reason)
	if err != nil {
		fjam.metrics.mutex.Lock()
		fjam.metrics.FailedRequests++
		fjam.metrics.mutex.Unlock()

		if fjam.IsHealthy() {
			fjam.markUnhealthy()
		}

		// Even if the underlying revocation failed, remove from tracking
		fjam.removeTrackedGrant(grantID)
		return fmt.Errorf("JIT access revocation may have failed: %w", err)
	}

	// Remove from tracked grants
	fjam.removeTrackedGrant(grantID)

	return nil
}

// GetActiveGrants returns active grants with health check
func (fjam *FailsafeJITAccessManager) GetActiveGrants(ctx context.Context, subjectID, tenantID string) ([]*jit.JITAccessGrant, error) {
	fjam.metrics.mutex.Lock()
	fjam.metrics.TotalRequests++
	fjam.metrics.mutex.Unlock()

	if !fjam.IsHealthy() {
		// Return only our tracked grants when system is unhealthy
		return fjam.getTrackedActiveGrants(subjectID, tenantID), nil
	}

	grants, err := fjam.underlying.GetActiveGrants(ctx, subjectID, tenantID)
	if err != nil {
		fjam.metrics.mutex.Lock()
		fjam.metrics.FailedRequests++
		fjam.metrics.mutex.Unlock()

		fjam.markUnhealthy()
		// Fallback to tracked grants
		return fjam.getTrackedActiveGrants(subjectID, tenantID), fmt.Errorf("JIT get active grants failed, using fallback: %w", err)
	}

	return grants, nil
}

// Helper methods

// trackActiveGrant adds a grant to the tracking system
func (fjam *FailsafeJITAccessManager) trackActiveGrant(grant *jit.JITAccessGrant) {
	fjam.grantsMutex.Lock()
	defer fjam.grantsMutex.Unlock()
	fjam.activeGrants[grant.ID] = grant
}

// removeTrackedGrant removes a grant from the tracking system
func (fjam *FailsafeJITAccessManager) removeTrackedGrant(grantID string) {
	fjam.grantsMutex.Lock()
	defer fjam.grantsMutex.Unlock()
	delete(fjam.activeGrants, grantID)
}

// getTrackedActiveGrants returns tracked grants for a subject
func (fjam *FailsafeJITAccessManager) getTrackedActiveGrants(subjectID, tenantID string) []*jit.JITAccessGrant {
	fjam.grantsMutex.RLock()
	defer fjam.grantsMutex.RUnlock()

	var grants []*jit.JITAccessGrant
	now := time.Now()

	for _, grant := range fjam.activeGrants {
		if (grant.RequesterID == subjectID || grant.TargetID == subjectID) &&
			grant.TenantID == tenantID &&
			grant.Status == jit.JITAccessGrantStatusActive &&
			grant.ExpiresAt.After(now) {
			grants = append(grants, grant)
		}
	}

	return grants
}

// revokeAllActiveGrants revokes all tracked active grants
func (fjam *FailsafeJITAccessManager) revokeAllActiveGrants(ctx context.Context, reason string) {
	fjam.grantsMutex.Lock()
	grantsToRevoke := make([]*jit.JITAccessGrant, 0, len(fjam.activeGrants))
	for _, grant := range fjam.activeGrants {
		if grant.Status == jit.JITAccessGrantStatusActive {
			grantsToRevoke = append(grantsToRevoke, grant)
		}
	}
	fjam.grantsMutex.Unlock()

	for _, grant := range grantsToRevoke {
		// Try to revoke via underlying manager first
		err := fjam.underlying.RevokeAccess(ctx, grant.ID, "system-failsafe", reason)
		if err != nil {
			// If underlying revocation fails, at least update our tracking
			fjam.grantsMutex.Lock()
			if trackedGrant, exists := fjam.activeGrants[grant.ID]; exists {
				trackedGrant.Status = jit.JITAccessGrantStatusRevoked
				now := time.Now()
				trackedGrant.RevokedAt = &now
				trackedGrant.RevokedBy = "system-failsafe"
				trackedGrant.RevocationReason = reason
			}
			fjam.grantsMutex.Unlock()
		}

		fjam.metrics.mutex.Lock()
		fjam.metrics.AutoRevokedGrants++
		fjam.metrics.mutex.Unlock()
	}
}

// scheduleEmergencyRevocation schedules automatic revocation of emergency grants
func (fjam *FailsafeJITAccessManager) scheduleEmergencyRevocation(ctx context.Context, grant *jit.JITAccessGrant) {
	duration := time.Until(grant.ExpiresAt)
	if duration > 0 {
		time.Sleep(duration)
	}

	// Revoke the emergency grant
	fjam.removeTrackedGrant(grant.ID)

	// Update grant status
	fjam.grantsMutex.Lock()
	if trackedGrant, exists := fjam.activeGrants[grant.ID]; exists {
		trackedGrant.Status = jit.JITAccessGrantStatusExpired
		now := time.Now()
		trackedGrant.DeactivatedAt = &now
	}
	fjam.grantsMutex.Unlock()
}

// startHealthChecking runs continuous health checks in background
func (fjam *FailsafeJITAccessManager) startHealthChecking() {
	ticker := time.NewTicker(fjam.healthCheck.healthCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		fjam.performHealthCheck()
	}
}

// performHealthCheck checks the health of the underlying JIT manager
func (fjam *FailsafeJITAccessManager) performHealthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second) // JIT operations may take longer
	defer cancel()

	// Try to get active grants to verify system health
	_, err := fjam.underlying.GetActiveGrants(ctx, "__health_check__", "__health_check__")

	fjam.healthCheck.mutex.Lock()
	defer fjam.healthCheck.mutex.Unlock()

	fjam.healthCheck.lastHealthCheck = time.Now()

	if err != nil {
		fjam.healthCheck.consecutiveFailures++
		fjam.metrics.mutex.Lock()
		fjam.metrics.HealthCheckFailures++
		fjam.metrics.mutex.Unlock()

		if fjam.healthCheck.consecutiveFailures >= fjam.healthCheck.maxConsecutiveFailures {
			wasHealthy := fjam.healthCheck.isHealthy
			fjam.healthCheck.isHealthy = false

			if wasHealthy {
				// JIT manager just became unhealthy - trigger failure mode
				go fjam.handleSystemFailure()
			}
		}
	} else {
		// Health check succeeded
		wasHealthy := fjam.healthCheck.isHealthy
		fjam.healthCheck.consecutiveFailures = 0
		fjam.healthCheck.isHealthy = true

		if !wasHealthy {
			// JIT manager recovered
			fjam.metrics.mutex.Lock()
			fjam.metrics.RecoveryEvents++
			fjam.metrics.mutex.Unlock()
		}
	}
}

// handleSystemFailure handles system failure based on the configured failure mode
func (fjam *FailsafeJITAccessManager) handleSystemFailure() {
	ctx := context.Background()

	// Read failure mode with proper locking to avoid race condition
	fjam.mutex.RLock()
	mode := fjam.failureMode
	fjam.mutex.RUnlock()

	switch mode {
	case JITFailureModeAutoRevoke:
		fjam.revokeAllActiveGrants(ctx, "JIT system failure - auto-revoke mode activated")
	case JITFailureModeRejectNew:
		// No immediate action needed - just reject new requests
	case JITFailureModeEmergencyOnly:
		// No immediate action needed - allow emergency requests only
	}
}

// markUnhealthy marks the JIT manager as unhealthy due to operational failure
func (fjam *FailsafeJITAccessManager) markUnhealthy() {
	fjam.healthCheck.mutex.Lock()
	defer fjam.healthCheck.mutex.Unlock()

	fjam.healthCheck.consecutiveFailures++
	if fjam.healthCheck.consecutiveFailures >= fjam.healthCheck.maxConsecutiveFailures {
		wasHealthy := fjam.healthCheck.isHealthy
		fjam.healthCheck.isHealthy = false

		if wasHealthy {
			// Trigger failure handling
			go fjam.handleSystemFailure()
		}
	}
}

// Helper function to get minimum duration
func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// Additional methods can be wrapped as needed based on the JIT interface
// For now, we've covered the core security-critical operations
