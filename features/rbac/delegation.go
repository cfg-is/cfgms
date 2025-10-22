package rbac

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/api/proto/common"
)

// DelegationManager handles permission delegation operations
type DelegationManager struct {
	delegations map[string]*common.PermissionDelegation
	rbacManager RBACManager
}

// NewDelegationManager creates a new permission delegation manager
func NewDelegationManager(rbacManager RBACManager) *DelegationManager {
	return &DelegationManager{
		delegations: make(map[string]*common.PermissionDelegation),
		rbacManager: rbacManager,
	}
}

// CreateDelegation creates a new permission delegation
func (d *DelegationManager) CreateDelegation(ctx context.Context, req *DelegationRequest) (*common.PermissionDelegation, error) {
	// Validate the delegation request
	if err := d.validateDelegationRequest(ctx, req); err != nil {
		return nil, fmt.Errorf("invalid delegation request: %w", err)
	}

	// Check if delegator has the permissions they're trying to delegate
	for _, permID := range req.PermissionIDs {
		hasPermission, err := d.checkDelegatorPermission(ctx, req.DelegatorID, permID, req.TenantID)
		if err != nil {
			return nil, fmt.Errorf("failed to check delegator permission: %w", err)
		}
		if !hasPermission {
			return nil, fmt.Errorf("delegator %s does not have permission %s to delegate", req.DelegatorID, permID)
		}
	}

	// Create the delegation
	delegation := &common.PermissionDelegation{
		Id:            uuid.New().String(),
		DelegatorId:   req.DelegatorID,
		DelegateeId:   req.DelegateeID,
		PermissionIds: req.PermissionIDs,
		Scope:         req.Scope,
		ExpiresAt:     req.ExpiresAt,
		CreatedAt:     time.Now().Unix(),
		TenantId:      req.TenantID,
		Revoked:       false,
	}

	// Store the delegation
	d.delegations[delegation.Id] = delegation

	return delegation, nil
}

// RevokeDelegation revokes an existing permission delegation
func (d *DelegationManager) RevokeDelegation(ctx context.Context, delegationID string, revokerID string) error {
	delegation, exists := d.delegations[delegationID]
	if !exists {
		return fmt.Errorf("delegation %s not found", delegationID)
	}

	// Check if the revoker has the authority to revoke this delegation
	if delegation.DelegatorId != revokerID {
		// Check if revoker is a system admin or has delegation management permission
		hasRevokePermission, err := d.checkRevocationPermission(ctx, revokerID, delegation.TenantId)
		if err != nil {
			return fmt.Errorf("failed to check revocation permission: %w", err)
		}
		if !hasRevokePermission {
			return fmt.Errorf("user %s does not have permission to revoke delegation %s", revokerID, delegationID)
		}
	}

	delegation.Revoked = true
	return nil
}

// GetDelegation retrieves a delegation by ID
func (d *DelegationManager) GetDelegation(ctx context.Context, delegationID string) (*common.PermissionDelegation, error) {
	delegation, exists := d.delegations[delegationID]
	if !exists {
		return nil, fmt.Errorf("delegation %s not found", delegationID)
	}
	return delegation, nil
}

// ListDelegations lists delegations for a subject (as delegator or delegatee)
func (d *DelegationManager) ListDelegations(ctx context.Context, subjectID string, tenantID string) ([]*common.PermissionDelegation, error) {
	var result []*common.PermissionDelegation

	for _, delegation := range d.delegations {
		if delegation.TenantId != tenantID {
			continue
		}

		if delegation.DelegatorId == subjectID || delegation.DelegateeId == subjectID {
			result = append(result, delegation)
		}
	}

	return result, nil
}

// GetActiveDelegations returns active (non-expired, non-revoked) delegations for a delegatee
func (d *DelegationManager) GetActiveDelegations(ctx context.Context, delegateeID string, tenantID string) ([]*common.PermissionDelegation, error) {
	var result []*common.PermissionDelegation
	currentTime := time.Now().Unix()

	for _, delegation := range d.delegations {
		if delegation.TenantId != tenantID || delegation.DelegateeId != delegateeID {
			continue
		}

		// Skip revoked delegations
		if delegation.Revoked {
			continue
		}

		// Skip expired delegations
		if delegation.ExpiresAt > 0 && delegation.ExpiresAt < currentTime {
			continue
		}

		result = append(result, delegation)
	}

	return result, nil
}

// CheckDelegatedPermission checks if a subject has a permission through delegation
func (d *DelegationManager) CheckDelegatedPermission(ctx context.Context, subjectID, permissionID, resourceID, tenantID string, resourceAttributes map[string]string) (bool, string, error) {
	delegations, err := d.GetActiveDelegations(ctx, subjectID, tenantID)
	if err != nil {
		return false, "", err
	}

	scopeEngine := NewScopeEngine()

	for _, delegation := range delegations {
		// Check if this delegation includes the requested permission
		hasPermission := false
		for _, delegatedPerm := range delegation.PermissionIds {
			if delegatedPerm == permissionID {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			continue
		}

		// Check if the resource is within the delegation scope
		if delegation.Scope != nil {
			allowed, reason := scopeEngine.EvaluateScope(ctx, delegation.Scope, resourceID, resourceAttributes)
			if !allowed {
				continue // This delegation doesn't cover the resource
			}

			return true, fmt.Sprintf("permission granted through delegation %s: %s", delegation.Id, reason), nil
		}

		// No scope restrictions, permission is granted
		return true, fmt.Sprintf("permission granted through delegation %s (no scope restrictions)", delegation.Id), nil
	}

	return false, "no active delegations grant this permission", nil
}

// CleanupExpiredDelegations removes expired delegations
func (d *DelegationManager) CleanupExpiredDelegations(ctx context.Context) error {
	currentTime := time.Now().Unix()

	for id, delegation := range d.delegations {
		if delegation.ExpiresAt > 0 && delegation.ExpiresAt < currentTime {
			delete(d.delegations, id)
		}
	}

	return nil
}

// DelegationRequest represents a request to create a permission delegation
type DelegationRequest struct {
	DelegatorID   string                  `json:"delegator_id"`
	DelegateeID   string                  `json:"delegatee_id"`
	PermissionIDs []string                `json:"permission_ids"`
	Scope         *common.PermissionScope `json:"scope"`
	ExpiresAt     int64                   `json:"expires_at"`
	TenantID      string                  `json:"tenant_id"`
}

// validateDelegationRequest validates a delegation request
func (d *DelegationManager) validateDelegationRequest(ctx context.Context, req *DelegationRequest) error {
	if req.DelegatorID == "" {
		return fmt.Errorf("delegator ID cannot be empty")
	}

	if req.DelegateeID == "" {
		return fmt.Errorf("delegatee ID cannot be empty")
	}

	if req.DelegatorID == req.DelegateeID {
		return fmt.Errorf("cannot delegate to oneself")
	}

	if len(req.PermissionIDs) == 0 {
		return fmt.Errorf("must specify at least one permission to delegate")
	}

	if req.TenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	// Check if delegatee exists
	_, err := d.rbacManager.GetSubject(ctx, req.DelegateeID)
	if err != nil {
		return fmt.Errorf("delegatee %s not found: %w", req.DelegateeID, err)
	}

	// Validate expiration time
	if req.ExpiresAt > 0 && req.ExpiresAt <= time.Now().Unix() {
		return fmt.Errorf("expiration time must be in the future")
	}

	// Validate scope if provided
	if req.Scope != nil {
		scopeEngine := NewScopeEngine()
		if err := scopeEngine.ValidateScope(ctx, req.Scope); err != nil {
			return fmt.Errorf("invalid delegation scope: %w", err)
		}
	}

	return nil
}

// checkDelegatorPermission checks if the delegator has the permission they're trying to delegate
func (d *DelegationManager) checkDelegatorPermission(ctx context.Context, delegatorID, permissionID, tenantID string) (bool, error) {
	request := &common.AccessRequest{
		SubjectId:    delegatorID,
		PermissionId: permissionID,
		TenantId:     tenantID,
	}

	response, err := d.rbacManager.CheckPermission(ctx, request)
	if err != nil {
		return false, err
	}

	return response.Granted, nil
}

// checkRevocationPermission checks if a user can revoke a delegation
func (d *DelegationManager) checkRevocationPermission(ctx context.Context, revokerID, tenantID string) (bool, error) {
	request := &common.AccessRequest{
		SubjectId:    revokerID,
		PermissionId: "delegation.revoke",
		TenantId:     tenantID,
	}

	response, err := d.rbacManager.CheckPermission(ctx, request)
	if err != nil {
		return false, err
	}

	return response.Granted, nil
}

// GetDelegationStats returns statistics about delegations
func (d *DelegationManager) GetDelegationStats(ctx context.Context, tenantID string) (*DelegationStats, error) {
	stats := &DelegationStats{
		TenantID:           tenantID,
		TotalDelegations:   0,
		ActiveDelegations:  0,
		ExpiredDelegations: 0,
		RevokedDelegations: 0,
	}

	currentTime := time.Now().Unix()

	for _, delegation := range d.delegations {
		if delegation.TenantId != tenantID {
			continue
		}

		stats.TotalDelegations++

		if delegation.Revoked {
			stats.RevokedDelegations++
		} else if delegation.ExpiresAt > 0 && delegation.ExpiresAt < currentTime {
			stats.ExpiredDelegations++
		} else {
			stats.ActiveDelegations++
		}
	}

	return stats, nil
}

// DelegationStats represents delegation statistics for a tenant
type DelegationStats struct {
	TenantID           string `json:"tenant_id"`
	TotalDelegations   int    `json:"total_delegations"`
	ActiveDelegations  int    `json:"active_delegations"`
	ExpiredDelegations int    `json:"expired_delegations"`
	RevokedDelegations int    `json:"revoked_delegations"`
}
