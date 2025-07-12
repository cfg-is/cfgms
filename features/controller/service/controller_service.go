package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc/metadata"

	common "github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ControllerService implements the Controller gRPC service
type ControllerService struct {
	controller.UnimplementedControllerServer
	
	logger   logging.Logger
	mu       sync.RWMutex
	stewards map[string]*StewardInfo
}

// StewardInfo holds information about a registered steward
type StewardInfo struct {
	ID              string
	TenantID        string  // Multi-tenant support
	Version         string
	DNA             *common.DNA
	LastHeartbeat   time.Time
	Status          string
	Metrics         map[string]string
	Token           string
}

// NewControllerService creates a new Controller service
func NewControllerService(logger logging.Logger) *ControllerService {
	return &ControllerService{
		logger:   logger,
		stewards: make(map[string]*StewardInfo),
	}
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
		"tenant_id", tenantID,
		"version", req.Version, 
		"is_reconnection", req.IsReconnection,
		"steward_dna_id", req.InitialDna.Id)
	
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
			s.logger.Warn("Reconnection claimed but no existing steward found", "dna_id", req.InitialDna.Id)
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
	
	s.logger.Info("Steward registration completed", 
		"steward_id", stewardID, 
		"version", req.Version,
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
		SyncStatus:          syncStatus,
		RequiresDnaResync:   requiresDNAResync,
		RequiresConfigResync: requiresConfigResync,
	}, nil
}

// ProcessHeartbeat handles heartbeat requests from stewards
func (s *ControllerService) ProcessHeartbeat(ctx context.Context, req *controller.HeartbeatRequest) (*common.Status, error) {
	s.logger.Debug("Heartbeat received", "steward_id", req.StewardId, "status", req.Status)
	
	s.mu.Lock()
	defer s.mu.Unlock()
	
	steward, exists := s.stewards[req.StewardId]
	if !exists {
		s.logger.Warn("Heartbeat from unknown steward", "steward_id", req.StewardId)
		return &common.Status{
			Code:    common.Status_NOT_FOUND,
			Message: "Steward not found",
		}, nil
	}
	
	// Update steward heartbeat information
	steward.LastHeartbeat = time.Now()
	steward.Status = req.Status
	steward.Metrics = req.Metrics
	
	s.logger.Debug("Heartbeat processed successfully", "steward_id", req.StewardId)
	
	return &common.Status{
		Code:    common.Status_OK,
		Message: "Heartbeat processed",
	}, nil
}

// SyncDNA handles DNA synchronization requests
func (s *ControllerService) SyncDNA(ctx context.Context, dna *common.DNA) (*common.Status, error) {
	s.logger.Debug("DNA sync request received", "steward_id", dna.Id)
	
	s.mu.Lock()
	defer s.mu.Unlock()
	
	steward, exists := s.stewards[dna.Id]
	if !exists {
		s.logger.Warn("DNA sync from unknown steward", "steward_id", dna.Id)
		return &common.Status{
			Code:    common.Status_NOT_FOUND,
			Message: "Steward not found",
		}, nil
	}
	
	// Update steward DNA
	steward.DNA = dna
	
	s.logger.Debug("DNA synchronized successfully", "steward_id", dna.Id)
	
	return &common.Status{
		Code:    common.Status_OK,
		Message: "DNA synchronized",
	}, nil
}

// GetStewardDNA retrieves DNA information for a specific steward
func (s *ControllerService) GetStewardDNA(ctx context.Context, req *controller.StewardRequest) (*common.DNA, error) {
	s.logger.Debug("DNA retrieval request", "steward_id", req.StewardId)
	
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	steward, exists := s.stewards[req.StewardId]
	if !exists {
		s.logger.Warn("DNA request for unknown steward", "steward_id", req.StewardId)
		return nil, fmt.Errorf("steward not found: %s", req.StewardId)
	}
	
	s.logger.Debug("DNA retrieved successfully", "steward_id", req.StewardId)
	return steward.DNA, nil
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

// extractTenantID extracts tenant ID from gRPC metadata
func (s *ControllerService) extractTenantID(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		s.logger.Debug("No metadata found in context, using default tenant")
		return "default"
	}
	
	values := md.Get("tenant-id")
	if len(values) > 0 && values[0] != "" {
		return values[0]
	}
	
	s.logger.Debug("No tenant-id in metadata, using default tenant")
	return "default"
}