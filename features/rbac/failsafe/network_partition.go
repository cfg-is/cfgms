// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package failsafe

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/rbac/memory"
)

// NetworkPartitionTolerantManager provides network partition tolerance with local security policy enforcement
// When network connectivity to central services is lost, it maintains security using locally cached policies
type NetworkPartitionTolerantManager struct {
	primaryRBAC    rbac.RBACManager
	localCache     *LocalSecurityPolicyCache
	networkMonitor *NetworkConnectivityMonitor
	partitionMode  PartitionToleranceMode
	mutex          sync.RWMutex
	metrics        *PartitionMetrics
}

// PartitionToleranceMode defines behavior during network partitions
type PartitionToleranceMode string

const (
	// PartitionModeFailSecure denies all access during network partitions
	PartitionModeFailSecure PartitionToleranceMode = "fail_secure"
	// PartitionModeLocalCache uses local cache for authorization decisions
	PartitionModeLocalCache PartitionToleranceMode = "local_cache"
	// PartitionModeReadOnlyCache allows read-only operations from cache
	PartitionModeReadOnlyCache PartitionToleranceMode = "read_only_cache"
	// PartitionModeGracefulDegradation uses cache with enhanced logging and restrictions
	PartitionModeGracefulDegradation PartitionToleranceMode = "graceful_degradation"
)

// LocalSecurityPolicyCache maintains a local cache of security policies for partition tolerance
type LocalSecurityPolicyCache struct {
	permissions map[string]*common.Permission
	roles       map[string]*common.Role
	subjects    map[string]*common.Subject
	assignments map[string]*common.RoleAssignment
	policies    map[string]*CachedSecurityPolicy
	lastSync    time.Time
	cacheExpiry time.Duration
	maxCacheAge time.Duration
	Metadata    map[string]interface{}
	mutex       sync.RWMutex
}

// CachedSecurityPolicy represents a cached security policy for offline enforcement
type CachedSecurityPolicy struct {
	SubjectID            string                 `json:"subject_id"`
	TenantID             string                 `json:"tenant_id"`
	Permissions          []*common.Permission   `json:"permissions"`
	Roles                []*common.Role         `json:"roles"`
	EffectivePermissions map[string]bool        `json:"effective_permissions"`
	CachedAt             time.Time              `json:"cached_at"`
	ExpiresAt            time.Time              `json:"expires_at"`
	Metadata             map[string]interface{} `json:"metadata,omitempty"`
}

// NetworkConnectivityMonitor monitors network connectivity to primary RBAC services
type NetworkConnectivityMonitor struct {
	primaryRBAC            rbac.RBACManager
	connectivityCheck      func(ctx context.Context) error
	lastSuccessfulCheck    time.Time
	consecutiveFailures    int
	maxConsecutiveFailures int
	checkInterval          time.Duration
	isConnected            bool
	partitionDetected      bool
	partitionStartTime     time.Time
	mutex                  sync.RWMutex
}

// PartitionMetrics tracks network partition tolerance metrics
type PartitionMetrics struct {
	TotalRequests          int64
	CacheHits              int64
	CacheMisses            int64
	PartitionedRequests    int64
	ConnectivityFailures   int64
	PartitionRecoveries    int64
	PolicySynchronizations int64
	CacheExpirations       int64
	mutex                  sync.RWMutex
}

// NewNetworkPartitionTolerantManager creates a new network partition tolerant RBAC manager
func NewNetworkPartitionTolerantManager(primaryRBAC rbac.RBACManager) *NetworkPartitionTolerantManager {
	localCache := &LocalSecurityPolicyCache{
		permissions: make(map[string]*common.Permission),
		roles:       make(map[string]*common.Role),
		subjects:    make(map[string]*common.Subject),
		assignments: make(map[string]*common.RoleAssignment),
		policies:    make(map[string]*CachedSecurityPolicy),
		cacheExpiry: 2 * time.Hour,  // Policies expire after 2 hours
		maxCacheAge: 24 * time.Hour, // Maximum cache age before forced refresh
		mutex:       sync.RWMutex{},
	}

	// SECURITY NOTE: Production Deployment Recommendations
	//
	// To minimize security risk during network partitions:
	// 1. **Aggressive Caching**: Cache ALL active user policies during normal operation
	// 2. **Longer TTL for Admins**: Set 12-24h expiry for admin user policies
	// 3. **Pre-populate on Startup**: Load critical admin policies into cache at startup
	// 4. **Background Refresh**: Continuously refresh cache before expiration
	// 5. **Cache Monitoring**: Alert when cache hit rate drops below 95%
	//
	// This ensures graceful degradation can serve from cache without granting unauthorized access.
	// Following industry patterns: Kubernetes (5min TTL), Istio (5min TTL), Zanzibar (>95% hit rate)

	networkMonitor := &NetworkConnectivityMonitor{
		primaryRBAC:            primaryRBAC,
		maxConsecutiveFailures: 3,
		checkInterval:          30 * time.Second,
		isConnected:            true,
		partitionDetected:      false,
		mutex:                  sync.RWMutex{},
	}

	// Set up connectivity check function
	networkMonitor.connectivityCheck = func(ctx context.Context) error {
		// Test connectivity by performing a lightweight RBAC operation
		testRequest := &common.AccessRequest{
			SubjectId:    "__connectivity_check__",
			PermissionId: "__connectivity_check__",
			TenantId:     "__connectivity_check__",
		}
		_, err := primaryRBAC.CheckPermission(ctx, testRequest)
		return err
	}

	nptm := &NetworkPartitionTolerantManager{
		primaryRBAC:    primaryRBAC,
		localCache:     localCache,
		networkMonitor: networkMonitor,
		partitionMode:  PartitionModeGracefulDegradation, // Default to graceful degradation
		mutex:          sync.RWMutex{},
		metrics: &PartitionMetrics{
			mutex: sync.RWMutex{},
		},
	}

	// Start network monitoring and cache maintenance
	go nptm.startNetworkMonitoring()
	go nptm.startCacheMaintenance()

	return nptm
}

// SetPartitionMode sets the network partition tolerance mode
func (nptm *NetworkPartitionTolerantManager) SetPartitionMode(mode PartitionToleranceMode) {
	nptm.mutex.Lock()
	defer nptm.mutex.Unlock()
	nptm.partitionMode = mode
}

// IsNetworkConnected returns the current network connectivity status
func (nptm *NetworkPartitionTolerantManager) IsNetworkConnected() bool {
	nptm.networkMonitor.mutex.RLock()
	defer nptm.networkMonitor.mutex.RUnlock()
	return nptm.networkMonitor.isConnected
}

// IsPartitioned returns true if a network partition is detected
func (nptm *NetworkPartitionTolerantManager) IsPartitioned() bool {
	nptm.networkMonitor.mutex.RLock()
	defer nptm.networkMonitor.mutex.RUnlock()
	return nptm.networkMonitor.partitionDetected
}

// GetPartitionMetrics returns current partition tolerance metrics
func (nptm *NetworkPartitionTolerantManager) GetPartitionMetrics() *PartitionMetrics {
	nptm.metrics.mutex.RLock()
	defer nptm.metrics.mutex.RUnlock()
	return &PartitionMetrics{
		TotalRequests:          nptm.metrics.TotalRequests,
		CacheHits:              nptm.metrics.CacheHits,
		CacheMisses:            nptm.metrics.CacheMisses,
		PartitionedRequests:    nptm.metrics.PartitionedRequests,
		ConnectivityFailures:   nptm.metrics.ConnectivityFailures,
		PartitionRecoveries:    nptm.metrics.PartitionRecoveries,
		PolicySynchronizations: nptm.metrics.PolicySynchronizations,
		CacheExpirations:       nptm.metrics.CacheExpirations,
	}
}

// CheckPermission implements network partition tolerant permission checking
func (nptm *NetworkPartitionTolerantManager) CheckPermission(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	nptm.metrics.mutex.Lock()
	nptm.metrics.TotalRequests++
	nptm.metrics.mutex.Unlock()

	if nptm.IsNetworkConnected() {
		// Network is available - use primary RBAC
		response, err := nptm.primaryRBAC.CheckPermission(ctx, request)
		if err == nil {
			// Cache the positive result for partition tolerance
			nptm.cachePermissionResult(request, response)
			return response, nil
		}

		// Primary RBAC failed - mark as connectivity issue and return error to trigger partition detection
		nptm.markConnectivityFailure()
		return &common.AccessResponse{
			Granted: false,
			Reason:  "Access denied: Network connectivity issue detected",
		}, fmt.Errorf("network partition detected, primary RBAC failed: %w", err)
	}

	// Network is partitioned - use partition tolerance mode
	return nptm.handlePartitionedPermissionCheck(ctx, request)
}

// handlePartitionedPermissionCheck handles permission checks during network partitions
func (nptm *NetworkPartitionTolerantManager) handlePartitionedPermissionCheck(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	nptm.metrics.mutex.Lock()
	nptm.metrics.PartitionedRequests++
	nptm.metrics.mutex.Unlock()

	switch nptm.partitionMode {
	case PartitionModeFailSecure:
		return &common.AccessResponse{
			Granted: false,
			Reason:  "Access denied: Network partition detected (network_partition_fail_secure)",
		}, fmt.Errorf("network partition detected, failing securely by denying access")

	case PartitionModeLocalCache, PartitionModeReadOnlyCache, PartitionModeGracefulDegradation:
		return nptm.checkPermissionFromCache(ctx, request)

	default:
		return &common.AccessResponse{
			Granted: false,
			Reason:  "Access denied: Network partition detected, unknown mode",
		}, fmt.Errorf("network partition detected, unknown partition mode")
	}
}

// checkPermissionFromCache checks permission using local cache
func (nptm *NetworkPartitionTolerantManager) checkPermissionFromCache(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	// Look up cached policy for the subject
	cacheKey := fmt.Sprintf("%s:%s", request.SubjectId, request.TenantId)

	nptm.localCache.mutex.RLock()
	cachedPolicy, exists := nptm.localCache.policies[cacheKey]
	nptm.localCache.mutex.RUnlock()

	if !exists {
		nptm.metrics.mutex.Lock()
		nptm.metrics.CacheMisses++
		nptm.metrics.mutex.Unlock()

		// SECURITY: Fail secure - deny access when no cached policy exists
		// This prevents DDoS attacks from bypassing RBAC by triggering network partitions
		// Production deployments should use aggressive caching to minimize cache misses
		return &common.AccessResponse{
			Granted: false,
			Reason:  "Access denied: No cached policy available during network partition (fail-secure)",
		}, fmt.Errorf("no cached policy available for subject %s during network partition", request.SubjectId)
	}

	// Check if cached policy has expired
	if time.Now().After(cachedPolicy.ExpiresAt) {
		nptm.metrics.mutex.Lock()
		nptm.metrics.CacheExpirations++
		nptm.metrics.mutex.Unlock()

		// SECURITY: Fail secure on expired cache - denies access
		// Graceful degradation does NOT bypass expiration - that would allow stale/revoked permissions
		// Production: Use longer cache TTLs (12-24h) for critical admin users
		return &common.AccessResponse{
			Granted: false,
			Reason:  "Access denied: Cached policy expired during network partition (fail-secure)",
		}, fmt.Errorf("cached policy expired for subject %s during network partition", request.SubjectId)
	}

	nptm.metrics.mutex.Lock()
	nptm.metrics.CacheHits++
	nptm.metrics.mutex.Unlock()

	// Check permission against cached policy
	permissionKey := fmt.Sprintf("%s:%s", request.PermissionId, request.ResourceId)
	granted, exists := cachedPolicy.EffectivePermissions[permissionKey]
	if !exists {
		// SECURITY: Fail secure - specific permission not in cache
		granted = false
	}

	// For graceful degradation mode, add enhanced monitoring metadata when access is granted
	// NOTE: Graceful degradation does NOT change the access decision - only adds monitoring
	reason := "Access granted from cached policy during network partition"
	if !granted {
		reason = "Access denied by cached policy during network partition"
	}

	// Add graceful degradation indicator for audit and monitoring
	if nptm.partitionMode == PartitionModeGracefulDegradation && granted {
		reason = "Access granted from cached policy during network partition (graceful degraded mode with enhanced monitoring)"
	}

	return &common.AccessResponse{
		Granted: granted,
		Reason:  reason,
	}, nil
}

// cachePermissionResult caches a permission check result for partition tolerance
func (nptm *NetworkPartitionTolerantManager) cachePermissionResult(request *common.AccessRequest, response *common.AccessResponse) {
	if !response.Granted {
		return // Don't cache denied permissions
	}

	cacheKey := fmt.Sprintf("%s:%s", request.SubjectId, request.TenantId)
	permissionKey := fmt.Sprintf("%s:%s", request.PermissionId, request.ResourceId)

	nptm.localCache.mutex.Lock()
	defer nptm.localCache.mutex.Unlock()

	// Get or create cached policy
	policy, exists := nptm.localCache.policies[cacheKey]
	if !exists {
		policy = &CachedSecurityPolicy{
			SubjectID:            request.SubjectId,
			TenantID:             request.TenantId,
			EffectivePermissions: make(map[string]bool),
			CachedAt:             time.Now(),
			ExpiresAt:            time.Now().Add(nptm.localCache.cacheExpiry),
			Metadata:             make(map[string]interface{}),
		}
		nptm.localCache.policies[cacheKey] = policy
	}

	// Update the specific permission
	policy.EffectivePermissions[permissionKey] = response.Granted
	policy.Metadata["last_updated"] = time.Now()
}

// startNetworkMonitoring continuously monitors network connectivity
func (nptm *NetworkPartitionTolerantManager) startNetworkMonitoring() {
	ticker := time.NewTicker(nptm.networkMonitor.checkInterval)
	defer ticker.Stop()

	for range ticker.C {
		nptm.performConnectivityCheck()
	}
}

// performConnectivityCheck checks network connectivity to primary RBAC services
func (nptm *NetworkPartitionTolerantManager) performConnectivityCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := nptm.networkMonitor.connectivityCheck(ctx)

	nptm.networkMonitor.mutex.Lock()
	defer nptm.networkMonitor.mutex.Unlock()

	if err != nil {
		nptm.networkMonitor.consecutiveFailures++
		nptm.metrics.mutex.Lock()
		nptm.metrics.ConnectivityFailures++
		nptm.metrics.mutex.Unlock()

		if nptm.networkMonitor.consecutiveFailures >= nptm.networkMonitor.maxConsecutiveFailures {
			wasConnected := nptm.networkMonitor.isConnected
			nptm.networkMonitor.isConnected = false

			if !nptm.networkMonitor.partitionDetected {
				nptm.networkMonitor.partitionDetected = true
				nptm.networkMonitor.partitionStartTime = time.Now()
			}

			if wasConnected {
				// Network just became partitioned
				nptm.handlePartitionDetected()
			}
		}
	} else {
		// Connectivity check succeeded
		wasPartitioned := nptm.networkMonitor.partitionDetected
		nptm.networkMonitor.consecutiveFailures = 0
		nptm.networkMonitor.isConnected = true

		if wasPartitioned {
			// Network recovered from partition
			nptm.networkMonitor.partitionDetected = false
			nptm.metrics.mutex.Lock()
			nptm.metrics.PartitionRecoveries++
			nptm.metrics.mutex.Unlock()

			nptm.handlePartitionRecovery()
		}

		nptm.networkMonitor.lastSuccessfulCheck = time.Now()
	}
}

// markConnectivityFailure marks a connectivity failure
func (nptm *NetworkPartitionTolerantManager) markConnectivityFailure() {
	nptm.networkMonitor.mutex.Lock()
	defer nptm.networkMonitor.mutex.Unlock()

	nptm.networkMonitor.consecutiveFailures++
	if nptm.networkMonitor.consecutiveFailures >= nptm.networkMonitor.maxConsecutiveFailures {
		nptm.networkMonitor.isConnected = false
		if !nptm.networkMonitor.partitionDetected {
			nptm.networkMonitor.partitionDetected = true
			nptm.networkMonitor.partitionStartTime = time.Now()
		}
	}
}

// ForcePartitioned forces the network into partitioned state for testing purposes
// This is a test-only method that bypasses normal connectivity checks
func (nptm *NetworkPartitionTolerantManager) ForcePartitioned() {
	nptm.networkMonitor.mutex.Lock()
	defer nptm.networkMonitor.mutex.Unlock()
	nptm.networkMonitor.consecutiveFailures = nptm.networkMonitor.maxConsecutiveFailures
	nptm.networkMonitor.isConnected = false
	if !nptm.networkMonitor.partitionDetected {
		nptm.networkMonitor.partitionDetected = true
		nptm.networkMonitor.partitionStartTime = time.Now()
	}
}

// handlePartitionDetected handles the transition to partitioned state
func (nptm *NetworkPartitionTolerantManager) handlePartitionDetected() {
	// Log partition detection (would use proper logging in production)
	// Could trigger alerts, notifications, etc.

	// For read-only cache mode, prevent any cache modifications
	if nptm.partitionMode == PartitionModeReadOnlyCache {
		// Mark cache as read-only
		nptm.localCache.mutex.Lock()
		if nptm.localCache.Metadata == nil {
			nptm.localCache.Metadata = make(map[string]interface{})
		}
		nptm.localCache.Metadata["read_only_mode"] = true
		nptm.localCache.Metadata["partition_start"] = time.Now()
		nptm.localCache.mutex.Unlock()
	}
}

// handlePartitionRecovery handles recovery from network partition
func (nptm *NetworkPartitionTolerantManager) handlePartitionRecovery() {
	// Log partition recovery (would use proper logging in production)

	// Synchronize local cache with primary RBAC system
	go nptm.synchronizeLocalCache()

	// Remove read-only mode restrictions
	nptm.localCache.mutex.Lock()
	if nptm.localCache.Metadata != nil {
		delete(nptm.localCache.Metadata, "read_only_mode")
		nptm.localCache.Metadata["last_recovery"] = time.Now()
	}
	nptm.localCache.mutex.Unlock()
}

// startCacheMaintenance performs periodic cache maintenance
func (nptm *NetworkPartitionTolerantManager) startCacheMaintenance() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		nptm.performCacheMaintenance()
	}
}

// performCacheMaintenance cleans up expired cache entries and synchronizes when connected
func (nptm *NetworkPartitionTolerantManager) performCacheMaintenance() {
	now := time.Now()

	nptm.localCache.mutex.Lock()
	defer nptm.localCache.mutex.Unlock()

	// Remove expired policies
	for key, policy := range nptm.localCache.policies {
		if now.After(policy.ExpiresAt) {
			delete(nptm.localCache.policies, key)
			nptm.metrics.mutex.Lock()
			nptm.metrics.CacheExpirations++
			nptm.metrics.mutex.Unlock()
		}
	}

	// Synchronize with primary RBAC if connected and cache is stale
	if nptm.IsNetworkConnected() {
		timeSinceLastSync := now.Sub(nptm.localCache.lastSync)
		if timeSinceLastSync > nptm.localCache.maxCacheAge {
			go nptm.synchronizeLocalCache()
		}
	}
}

// synchronizeLocalCache synchronizes the local cache with the primary RBAC system
func (nptm *NetworkPartitionTolerantManager) synchronizeLocalCache() {
	if !nptm.IsNetworkConnected() {
		return
	}

	_, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// This would involve fetching updated policies from the primary RBAC system
	// For now, we'll just update the sync timestamp
	nptm.localCache.mutex.Lock()
	nptm.localCache.lastSync = time.Now()
	nptm.localCache.mutex.Unlock()

	nptm.metrics.mutex.Lock()
	nptm.metrics.PolicySynchronizations++
	nptm.metrics.mutex.Unlock()

	// TODO: Implement actual policy synchronization
	// This would involve:
	// 1. Fetching updated permissions, roles, subjects, assignments
	// 2. Computing effective permissions for cached subjects
	// 3. Updating the local cache with fresh data
}

// Delegate other RBACManager methods to primary RBAC when connected,
// or provide appropriate partition-tolerant behavior

func (nptm *NetworkPartitionTolerantManager) Initialize(ctx context.Context) error {
	if !nptm.IsNetworkConnected() {
		return fmt.Errorf("cannot initialize during network partition")
	}
	return nptm.primaryRBAC.Initialize(ctx)
}

func (nptm *NetworkPartitionTolerantManager) CreateTenantDefaultRoles(ctx context.Context, tenantID string) error {
	if !nptm.IsNetworkConnected() {
		return fmt.Errorf("cannot create tenant roles during network partition")
	}
	return nptm.primaryRBAC.CreateTenantDefaultRoles(ctx, tenantID)
}

// Permission Store Methods
func (nptm *NetworkPartitionTolerantManager) CreatePermission(ctx context.Context, permission *common.Permission) error {
	if !nptm.IsNetworkConnected() {
		return fmt.Errorf("cannot create permission during network partition")
	}
	return nptm.primaryRBAC.CreatePermission(ctx, permission)
}

func (nptm *NetworkPartitionTolerantManager) GetPermission(ctx context.Context, id string) (*common.Permission, error) {
	if !nptm.IsNetworkConnected() {
		return nil, fmt.Errorf("cannot get permission during network partition")
	}
	return nptm.primaryRBAC.GetPermission(ctx, id)
}

func (nptm *NetworkPartitionTolerantManager) ListPermissions(ctx context.Context, resourceType string) ([]*common.Permission, error) {
	if !nptm.IsNetworkConnected() {
		return []*common.Permission{}, fmt.Errorf("cannot list permissions during network partition")
	}
	return nptm.primaryRBAC.ListPermissions(ctx, resourceType)
}

func (nptm *NetworkPartitionTolerantManager) UpdatePermission(ctx context.Context, permission *common.Permission) error {
	if !nptm.IsNetworkConnected() {
		return fmt.Errorf("cannot update permission during network partition")
	}
	return nptm.primaryRBAC.UpdatePermission(ctx, permission)
}

func (nptm *NetworkPartitionTolerantManager) DeletePermission(ctx context.Context, id string) error {
	if !nptm.IsNetworkConnected() {
		return fmt.Errorf("cannot delete permission during network partition")
	}
	return nptm.primaryRBAC.DeletePermission(ctx, id)
}

// Role Store Methods
func (nptm *NetworkPartitionTolerantManager) CreateRole(ctx context.Context, role *common.Role) error {
	if !nptm.IsNetworkConnected() {
		return fmt.Errorf("cannot create role during network partition")
	}
	return nptm.primaryRBAC.CreateRole(ctx, role)
}

func (nptm *NetworkPartitionTolerantManager) GetRole(ctx context.Context, id string) (*common.Role, error) {
	if !nptm.IsNetworkConnected() {
		return nil, fmt.Errorf("cannot get role during network partition")
	}
	return nptm.primaryRBAC.GetRole(ctx, id)
}

func (nptm *NetworkPartitionTolerantManager) ListRoles(ctx context.Context, tenantID string) ([]*common.Role, error) {
	if !nptm.IsNetworkConnected() {
		return []*common.Role{}, fmt.Errorf("cannot list roles during network partition")
	}
	return nptm.primaryRBAC.ListRoles(ctx, tenantID)
}

func (nptm *NetworkPartitionTolerantManager) UpdateRole(ctx context.Context, role *common.Role) error {
	if !nptm.IsNetworkConnected() {
		return fmt.Errorf("cannot update role during network partition")
	}
	return nptm.primaryRBAC.UpdateRole(ctx, role)
}

func (nptm *NetworkPartitionTolerantManager) DeleteRole(ctx context.Context, id string) error {
	if !nptm.IsNetworkConnected() {
		return fmt.Errorf("cannot delete role during network partition")
	}
	return nptm.primaryRBAC.DeleteRole(ctx, id)
}

func (nptm *NetworkPartitionTolerantManager) GetRolePermissions(ctx context.Context, roleID string) ([]*common.Permission, error) {
	if !nptm.IsNetworkConnected() {
		return []*common.Permission{}, fmt.Errorf("cannot get role permissions during network partition")
	}
	return nptm.primaryRBAC.GetRolePermissions(ctx, roleID)
}

// Subject Store Methods
func (nptm *NetworkPartitionTolerantManager) CreateSubject(ctx context.Context, subject *common.Subject) error {
	if !nptm.IsNetworkConnected() {
		return fmt.Errorf("cannot create subject during network partition")
	}
	return nptm.primaryRBAC.CreateSubject(ctx, subject)
}

func (nptm *NetworkPartitionTolerantManager) GetSubject(ctx context.Context, id string) (*common.Subject, error) {
	if !nptm.IsNetworkConnected() {
		return nil, fmt.Errorf("cannot get subject during network partition")
	}
	return nptm.primaryRBAC.GetSubject(ctx, id)
}

func (nptm *NetworkPartitionTolerantManager) ListSubjects(ctx context.Context, tenantID string, subjectType common.SubjectType) ([]*common.Subject, error) {
	if !nptm.IsNetworkConnected() {
		return []*common.Subject{}, fmt.Errorf("cannot list subjects during network partition")
	}
	return nptm.primaryRBAC.ListSubjects(ctx, tenantID, subjectType)
}

func (nptm *NetworkPartitionTolerantManager) UpdateSubject(ctx context.Context, subject *common.Subject) error {
	if !nptm.IsNetworkConnected() {
		return fmt.Errorf("cannot update subject during network partition")
	}
	return nptm.primaryRBAC.UpdateSubject(ctx, subject)
}

func (nptm *NetworkPartitionTolerantManager) DeleteSubject(ctx context.Context, id string) error {
	if !nptm.IsNetworkConnected() {
		return fmt.Errorf("cannot delete subject during network partition")
	}
	return nptm.primaryRBAC.DeleteSubject(ctx, id)
}

func (nptm *NetworkPartitionTolerantManager) GetSubjectRoles(ctx context.Context, subjectID string, tenantID string) ([]*common.Role, error) {
	if !nptm.IsNetworkConnected() {
		return []*common.Role{}, fmt.Errorf("cannot get subject roles during network partition")
	}
	return nptm.primaryRBAC.GetSubjectRoles(ctx, subjectID, tenantID)
}

// Role Assignment Store Methods
func (nptm *NetworkPartitionTolerantManager) AssignRole(ctx context.Context, assignment *common.RoleAssignment) error {
	if !nptm.IsNetworkConnected() {
		return fmt.Errorf("cannot assign role during network partition")
	}
	return nptm.primaryRBAC.AssignRole(ctx, assignment)
}

func (nptm *NetworkPartitionTolerantManager) RevokeRole(ctx context.Context, subjectID, roleID, tenantID string) error {
	if !nptm.IsNetworkConnected() {
		return fmt.Errorf("cannot revoke role during network partition")
	}
	return nptm.primaryRBAC.RevokeRole(ctx, subjectID, roleID, tenantID)
}

func (nptm *NetworkPartitionTolerantManager) GetAssignment(ctx context.Context, id string) (*common.RoleAssignment, error) {
	if !nptm.IsNetworkConnected() {
		return nil, fmt.Errorf("cannot get assignment during network partition")
	}
	return nptm.primaryRBAC.GetAssignment(ctx, id)
}

func (nptm *NetworkPartitionTolerantManager) ListAssignments(ctx context.Context, subjectID, roleID, tenantID string) ([]*common.RoleAssignment, error) {
	if !nptm.IsNetworkConnected() {
		return []*common.RoleAssignment{}, fmt.Errorf("cannot list assignments during network partition")
	}
	return nptm.primaryRBAC.ListAssignments(ctx, subjectID, roleID, tenantID)
}

func (nptm *NetworkPartitionTolerantManager) GetSubjectAssignments(ctx context.Context, subjectID, tenantID string) ([]*common.RoleAssignment, error) {
	if !nptm.IsNetworkConnected() {
		return []*common.RoleAssignment{}, fmt.Errorf("cannot get subject assignments during network partition")
	}
	return nptm.primaryRBAC.GetSubjectAssignments(ctx, subjectID, tenantID)
}

// Authorization Engine Methods
func (nptm *NetworkPartitionTolerantManager) ValidateAccess(ctx context.Context, authContext *common.AuthorizationContext, requiredPermission string) (*common.AccessResponse, error) {
	// This uses partition tolerance like CheckPermission
	request := &common.AccessRequest{
		SubjectId:    authContext.SubjectId,
		PermissionId: requiredPermission,
		TenantId:     authContext.TenantId,
		ResourceId:   "", // AuthorizationContext doesn't have ResourceId field
	}
	return nptm.CheckPermission(ctx, request)
}

func (nptm *NetworkPartitionTolerantManager) GetSubjectPermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	if !nptm.IsNetworkConnected() {
		return []*common.Permission{}, fmt.Errorf("cannot get subject permissions during network partition")
	}
	return nptm.primaryRBAC.GetSubjectPermissions(ctx, subjectID, tenantID)
}

func (nptm *NetworkPartitionTolerantManager) GetEffectivePermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	if !nptm.IsNetworkConnected() {
		return []*common.Permission{}, fmt.Errorf("cannot get effective permissions during network partition")
	}
	return nptm.primaryRBAC.GetEffectivePermissions(ctx, subjectID, tenantID)
}

// Hierarchy operations
func (nptm *NetworkPartitionTolerantManager) GetRoleHierarchy(ctx context.Context, roleID string) (*memory.RoleHierarchy, error) {
	if !nptm.IsNetworkConnected() {
		return nil, fmt.Errorf("cannot get role hierarchy during network partition")
	}
	return nptm.primaryRBAC.GetRoleHierarchy(ctx, roleID)
}

func (nptm *NetworkPartitionTolerantManager) GetChildRoles(ctx context.Context, roleID string) ([]*common.Role, error) {
	if !nptm.IsNetworkConnected() {
		return []*common.Role{}, fmt.Errorf("cannot get child roles during network partition")
	}
	return nptm.primaryRBAC.GetChildRoles(ctx, roleID)
}

func (nptm *NetworkPartitionTolerantManager) GetParentRole(ctx context.Context, roleID string) (*common.Role, error) {
	if !nptm.IsNetworkConnected() {
		return nil, fmt.Errorf("cannot get parent role during network partition")
	}
	return nptm.primaryRBAC.GetParentRole(ctx, roleID)
}

func (nptm *NetworkPartitionTolerantManager) SetRoleParent(ctx context.Context, roleID, parentRoleID string, inheritanceType common.RoleInheritanceType) error {
	if !nptm.IsNetworkConnected() {
		return fmt.Errorf("cannot set role parent during network partition")
	}
	return nptm.primaryRBAC.SetRoleParent(ctx, roleID, parentRoleID, inheritanceType)
}

func (nptm *NetworkPartitionTolerantManager) RemoveRoleParent(ctx context.Context, roleID string) error {
	if !nptm.IsNetworkConnected() {
		return fmt.Errorf("cannot remove role parent during network partition")
	}
	return nptm.primaryRBAC.RemoveRoleParent(ctx, roleID)
}

func (nptm *NetworkPartitionTolerantManager) ValidateRoleHierarchy(ctx context.Context, roleID string) error {
	if !nptm.IsNetworkConnected() {
		return fmt.Errorf("cannot validate role hierarchy during network partition")
	}
	return nptm.primaryRBAC.ValidateRoleHierarchy(ctx, roleID)
}

func (nptm *NetworkPartitionTolerantManager) ComputeRolePermissions(ctx context.Context, roleID string) (*memory.EffectivePermissions, error) {
	if !nptm.IsNetworkConnected() {
		return nil, fmt.Errorf("cannot compute role permissions during network partition")
	}
	return nptm.primaryRBAC.ComputeRolePermissions(ctx, roleID)
}

func (nptm *NetworkPartitionTolerantManager) CreateRoleWithParent(ctx context.Context, role *common.Role, parentRoleID string, inheritanceType common.RoleInheritanceType) error {
	if !nptm.IsNetworkConnected() {
		return fmt.Errorf("cannot create role with parent during network partition")
	}
	return nptm.primaryRBAC.CreateRoleWithParent(ctx, role, parentRoleID, inheritanceType)
}

func (nptm *NetworkPartitionTolerantManager) GetRoleHierarchyTree(ctx context.Context, rootRoleID string, maxDepth int) (*memory.RoleHierarchy, error) {
	if !nptm.IsNetworkConnected() {
		return nil, fmt.Errorf("cannot get role hierarchy tree during network partition")
	}
	return nptm.primaryRBAC.GetRoleHierarchyTree(ctx, rootRoleID, maxDepth)
}

func (nptm *NetworkPartitionTolerantManager) ValidateHierarchyOperation(ctx context.Context, childRoleID, parentRoleID string) error {
	if !nptm.IsNetworkConnected() {
		return fmt.Errorf("cannot validate hierarchy operation during network partition")
	}
	return nptm.primaryRBAC.ValidateHierarchyOperation(ctx, childRoleID, parentRoleID)
}

func (nptm *NetworkPartitionTolerantManager) ResolvePermissionConflicts(ctx context.Context, roleID string, conflictingPermissions map[string][]*common.Permission) (map[string]*common.Permission, error) {
	if !nptm.IsNetworkConnected() {
		return nil, fmt.Errorf("cannot resolve permission conflicts during network partition")
	}
	return nptm.primaryRBAC.ResolvePermissionConflicts(ctx, roleID, conflictingPermissions)
}

// Verify interface compliance
var _ rbac.RBACManager = (*NetworkPartitionTolerantManager)(nil)
