// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	common "github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	fleetStorage "github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ControllerService implements the Controller service
type ControllerService struct {
	logger     logging.Logger
	mu         sync.RWMutex
	stewards   map[string]*StewardInfo
	dnaStorage *fleetStorage.Manager
}

// StewardInfo holds connection/heartbeat state for a registered steward.
// Full DNA is persisted to durable storage; this struct tracks only live state.
type StewardInfo struct {
	ID            string
	TenantID      string // Multi-tenant support
	Version       string
	DNA           *common.DNA
	LastHeartbeat time.Time
	Status        string
	Metrics       map[string]string
	Token         string
}

// NewControllerService creates a new Controller service without DNA storage.
// Use NewControllerServiceWithStorage to enable durable DNA persistence.
func NewControllerService(logger logging.Logger) *ControllerService {
	return &ControllerService{
		logger:   logger,
		stewards: make(map[string]*StewardInfo),
	}
}

// NewControllerServiceWithStorage creates a new Controller service with a durable
// DNA storage backend. DNA is written on every heartbeat and full sync, and
// reloaded from storage on controller startup to warm the in-memory registry.
func NewControllerServiceWithStorage(logger logging.Logger, storage *fleetStorage.Manager) *ControllerService {
	svc := &ControllerService{
		logger:     logger,
		stewards:   make(map[string]*StewardInfo),
		dnaStorage: storage,
	}
	return svc
}

// LoadFromStorage warms the in-memory steward registry by loading the latest
// DNA record for every device persisted in the fleet storage backend. Call
// this once during controller startup, after NewControllerServiceWithStorage.
func (s *ControllerService) LoadFromStorage(ctx context.Context) error {
	if s.dnaStorage == nil {
		return nil
	}

	deviceIDs, err := s.dnaStorage.ListAllDeviceIDs(ctx)
	if err != nil {
		return fmt.Errorf("failed to list device IDs from storage: %w", err)
	}

	s.logger.Info("Loading steward registry from DNA storage", "device_count", len(deviceIDs))

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, deviceID := range deviceIDs {
		record, err := s.dnaStorage.GetLatest(ctx, deviceID)
		if err != nil {
			s.logger.Warn("Failed to load DNA for device from storage",
				"device_id", deviceID, "error", err)
			continue
		}

		// Populate in-memory entry only if not already present (live steward takes precedence)
		if _, exists := s.stewards[deviceID]; !exists {
			s.stewards[deviceID] = &StewardInfo{
				ID:            deviceID,
				TenantID:      record.TenantID,
				DNA:           record.DNA,
				LastHeartbeat: record.StoredAt,
				Status:        record.Status,
				Metrics:       make(map[string]string),
			}
		}
	}

	s.logger.Info("Steward registry warm-load complete", "loaded", len(deviceIDs))
	return nil
}

// Authenticate handles authentication requests
func (s *ControllerService) Authenticate(ctx context.Context, creds *common.Credentials) (*common.Token, error) {
	s.logger.Info("Authentication request received",
		"tenant_id", creds.TenantId,
		"client_id", creds.ClientId,
		"cert_subject", creds.Certificate)

	// Validate tenant ID
	tenantID := creds.TenantId
	if tenantID == "" {
		tenantID = "default" // Default to "default" tenant if not specified
	}

	// Basic authentication implementation
	// In a real implementation, this would validate certificates and tenant access
	token, err := s.generateToken()
	if err != nil {
		s.logger.Error("Failed to generate authentication token", "error", err)
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	s.logger.Info("Authentication successful",
		"tenant_id", tenantID,
		"client_id", creds.ClientId,
		"token", token[:16]+"...")
	return &common.Token{
		AccessToken: token,
		ExpiresAt:   time.Now().Add(24 * time.Hour).Unix(),
	}, nil
}

// AcceptRegistration handles steward registration requests
func (s *ControllerService) AcceptRegistration(ctx context.Context, req *controller.RegisterRequest) (*controller.RegisterResponse, error) {
	// Extract tenant information from gRPC metadata
	tenantID := s.extractTenantID(ctx)

	s.logger.Info("Registration request received",
		"tenant_id", logging.SanitizeLogValue(tenantID),
		"version", logging.SanitizeLogValue(req.Version),
		"is_reconnection", req.IsReconnection,
		"steward_dna_id", logging.SanitizeLogValue(req.InitialDna.Id))

	var stewardID string
	var syncStatus *common.SyncStatus
	var requiresDNAResync, requiresConfigResync bool

	// Handle reconnection vs new registration
	if req.IsReconnection {
		// For reconnections, try to find existing steward by DNA ID
		if existingSteward := s.findStewardByDNAId(req.InitialDna.Id); existingSteward != nil {
			stewardID = existingSteward.ID
			s.logger.Info("Reconnection detected", "steward_id", stewardID)

			// Verify sync status
			syncStatus, requiresDNAResync, requiresConfigResync = s.verifySyncStatus(existingSteward, req)
		} else {
			s.logger.Warn("Reconnection claimed but no existing steward found", "dna_id", logging.SanitizeLogValue(req.InitialDna.Id))
			// Treat as new registration
			req.IsReconnection = false
		}
	}

	if !req.IsReconnection {
		// Generate a unique steward ID for new registration
		var err error
		stewardID, err = s.generateStewardID()
		if err != nil {
			s.logger.Error("Failed to generate steward ID", "error", err)
			return nil, fmt.Errorf("registration failed: %w", err)
		}

		// For new registrations, sync is considered good initially
		syncStatus = &common.SyncStatus{
			LastSyncTime:    req.InitialDna.LastSyncTime,
			SyncFingerprint: req.InitialDna.SyncFingerprint,
			IsInSync:        true,
			Reason:          "New registration",
		}
	}

	// Generate authentication token
	token, err := s.generateToken()
	if err != nil {
		s.logger.Error("Failed to generate token for steward", "steward_id", stewardID, "error", err)
		return nil, fmt.Errorf("registration failed: %w", err)
	}

	// Store/update steward information
	s.mu.Lock()
	s.stewards[stewardID] = &StewardInfo{
		ID:            stewardID,
		TenantID:      tenantID,
		Version:       req.Version,
		DNA:           req.InitialDna,
		LastHeartbeat: time.Now(),
		Status:        "registered",
		Metrics:       make(map[string]string),
		Token:         token,
	}
	s.mu.Unlock()

	// Persist initial DNA to durable storage
	s.storeDNA(ctx, stewardID, tenantID, req.InitialDna, "registered")

	s.logger.Info("Steward registration completed",
		"steward_id", stewardID,
		"version", logging.SanitizeLogValue(req.Version),
		"requires_dna_resync", requiresDNAResync,
		"requires_config_resync", requiresConfigResync)

	return &controller.RegisterResponse{
		StewardId: stewardID,
		Status: &common.Status{
			Code:    common.Status_OK,
			Message: "Registration successful",
		},
		Token: &common.Token{
			AccessToken: token,
			ExpiresAt:   time.Now().Add(24 * time.Hour).Unix(),
		},
		SyncStatus:           syncStatus,
		RequiresDnaResync:    requiresDNAResync,
		RequiresConfigResync: requiresConfigResync,
	}, nil
}

// ProcessHeartbeat handles heartbeat requests from stewards.
// When a heartbeat includes DNA updates, the DNA is written to durable storage.
func (s *ControllerService) ProcessHeartbeat(ctx context.Context, req *controller.HeartbeatRequest) (*common.Status, error) {
	s.logger.Debug("Heartbeat received", "steward_id", logging.SanitizeLogValue(req.StewardId), "status", logging.SanitizeLogValue(req.Status))

	s.mu.Lock()
	defer s.mu.Unlock()

	steward, exists := s.stewards[req.StewardId]
	if !exists {
		s.logger.Warn("Heartbeat from unknown steward", "steward_id", logging.SanitizeLogValue(req.StewardId))
		return &common.Status{
			Code:    common.Status_NOT_FOUND,
			Message: "Steward not found",
		}, nil
	}

	// Update live connection state (heartbeat tracks only status/metrics, not full DNA)
	steward.LastHeartbeat = time.Now()
	steward.Status = req.Status
	steward.Metrics = req.Metrics

	// Persist updated status to durable storage if DNA is known for this steward.
	// Full DNA snapshots are written by SyncDNA; here we only update status on
	// existing records when the steward's DNA is already stored.
	if steward.DNA != nil {
		s.storeDNA(ctx, req.StewardId, steward.TenantID, steward.DNA, req.Status)
	}

	s.logger.Debug("Heartbeat processed successfully", "steward_id", logging.SanitizeLogValue(req.StewardId))

	return &common.Status{
		Code:    common.Status_OK,
		Message: "Heartbeat processed",
	}, nil
}

// SyncDNA handles DNA synchronization requests.
// The full DNA snapshot is written to durable storage on every sync.
func (s *ControllerService) SyncDNA(ctx context.Context, dna *common.DNA) (*common.Status, error) {
	s.logger.Debug("DNA sync request received", "steward_id", logging.SanitizeLogValue(dna.Id))

	s.mu.Lock()
	defer s.mu.Unlock()

	steward, exists := s.stewards[dna.Id]
	if !exists {
		s.logger.Warn("DNA sync from unknown steward", "steward_id", logging.SanitizeLogValue(dna.Id))
		return &common.Status{
			Code:    common.Status_NOT_FOUND,
			Message: "Steward not found",
		}, nil
	}

	// Update in-memory DNA
	steward.DNA = dna

	// Persist full DNA snapshot to durable storage
	s.storeDNA(ctx, dna.Id, steward.TenantID, dna, steward.Status)

	s.logger.Debug("DNA synchronized successfully", "steward_id", logging.SanitizeLogValue(dna.Id))

	return &common.Status{
		Code:    common.Status_OK,
		Message: "DNA synchronized",
	}, nil
}

// GetStewardDNA retrieves DNA information for a specific steward
func (s *ControllerService) GetStewardDNA(ctx context.Context, req *controller.StewardRequest) (*common.DNA, error) {
	s.logger.Debug("DNA retrieval request", "steward_id", logging.SanitizeLogValue(req.StewardId))

	s.mu.RLock()
	defer s.mu.RUnlock()

	steward, exists := s.stewards[req.StewardId]
	if !exists {
		s.logger.Warn("DNA request for unknown steward", "steward_id", logging.SanitizeLogValue(req.StewardId))
		return nil, fmt.Errorf("steward not found: %s", logging.SanitizeLogValue(req.StewardId))
	}

	s.logger.Debug("DNA retrieved successfully", "steward_id", logging.SanitizeLogValue(req.StewardId))
	return steward.DNA, nil
}

// storeDNA writes a DNA snapshot to durable storage. It is safe to call
// concurrently; errors are logged but do not propagate to callers.
func (s *ControllerService) storeDNA(ctx context.Context, stewardID, tenantID string, dna *common.DNA, status string) {
	if s.dnaStorage == nil || dna == nil {
		return
	}
	opts := &fleetStorage.StoreOptions{
		TenantID: tenantID,
		Status:   status,
	}
	if err := s.dnaStorage.Store(ctx, stewardID, dna, opts); err != nil {
		s.logger.Error("Failed to persist DNA to fleet storage",
			"steward_id", stewardID,
			"tenant_id", tenantID,
			"error", err)
	}
}

// generateStewardID generates a unique steward ID
func (s *ControllerService) generateStewardID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "steward-" + hex.EncodeToString(bytes), nil
}

// generateToken generates a secure random token
func (s *ControllerService) generateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GetStewardCount returns the number of registered stewards
func (s *ControllerService) GetStewardCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.stewards)
}

// GetStewardInfo returns information about a specific steward
func (s *ControllerService) GetStewardInfo(stewardID string) (*StewardInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	info, exists := s.stewards[stewardID]
	return info, exists
}

// RegisterSteward records or updates a steward that registered via the HTTP path.
// It is idempotent: calling it twice with the same stewardID overwrites the entry.
func (s *ControllerService) RegisterSteward(stewardID, tenantID, transportAddr, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stewards[stewardID] = &StewardInfo{
		ID:            stewardID,
		TenantID:      tenantID,
		LastHeartbeat: time.Now(),
		Status:        status,
		Metrics:       make(map[string]string),
	}
	return nil
}

// GetAllStewards returns a list of all registered stewards
func (s *ControllerService) GetAllStewards() []*StewardInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stewards := make([]*StewardInfo, 0, len(s.stewards))
	for _, info := range s.stewards {
		stewards = append(stewards, info)
	}
	return stewards
}

// findStewardByDNAId finds an existing steward by DNA ID
func (s *ControllerService) findStewardByDNAId(dnaId string) *StewardInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, steward := range s.stewards {
		if steward.DNA != nil && steward.DNA.Id == dnaId {
			return steward
		}
	}
	return nil
}

// verifySyncStatus compares client and server sync state
func (s *ControllerService) verifySyncStatus(existingSteward *StewardInfo, req *controller.RegisterRequest) (*common.SyncStatus, bool, bool) {
	requiresDNAResync := false
	requiresConfigResync := false

	// Compare sync fingerprints
	serverFingerprint := existingSteward.DNA.SyncFingerprint
	clientFingerprint := req.ExpectedSyncFingerprint

	syncStatus := &common.SyncStatus{
		LastSyncTime:    existingSteward.DNA.LastSyncTime,
		SyncFingerprint: serverFingerprint,
		IsInSync:        serverFingerprint == clientFingerprint,
	}

	if !syncStatus.IsInSync {
		// Determine what needs resyncing
		if existingSteward.DNA.AttributeCount != req.InitialDna.AttributeCount {
			requiresDNAResync = true
			syncStatus.Reason = "DNA attribute count mismatch"
		} else if existingSteward.DNA.ConfigHash != req.InitialDna.ConfigHash {
			requiresConfigResync = true
			syncStatus.Reason = "Configuration hash mismatch"
		} else {
			// General sync mismatch
			requiresDNAResync = true
			requiresConfigResync = true
			syncStatus.Reason = "Sync fingerprint mismatch"
		}
	} else {
		syncStatus.Reason = "In sync"
	}

	s.logger.Info("Sync verification completed",
		"steward_id", existingSteward.ID,
		"in_sync", syncStatus.IsInSync,
		"reason", syncStatus.Reason,
		"server_fingerprint", serverFingerprint,
		"client_fingerprint", clientFingerprint)

	return syncStatus, requiresDNAResync, requiresConfigResync
}

// extractTenantID extracts tenant ID from context
func (s *ControllerService) extractTenantID(ctx context.Context) string {
	// Extract tenant ID from context value (set by auth middleware)
	if tenantID, ok := ctx.Value(ctxkeys.TenantID).(string); ok && tenantID != "" {
		return tenantID
	}

	s.logger.Debug("No tenant ID in context, using default tenant")
	return "default"
}
