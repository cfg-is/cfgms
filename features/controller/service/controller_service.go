package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	proto "github.com/cfgis/cfgms/api/proto"
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
	Version         string
	DNA             *proto.DNA
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
func (s *ControllerService) Authenticate(ctx context.Context, creds *proto.Credentials) (*proto.Token, error) {
	s.logger.Info("Authentication request received", "cert_subject", creds.Certificate)
	
	// Basic authentication implementation
	// In a real implementation, this would validate certificates
	token, err := s.generateToken()
	if err != nil {
		s.logger.Error("Failed to generate authentication token", "error", err)
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	
	s.logger.Info("Authentication successful", "token", token[:16]+"...")
	return &proto.Token{
		AccessToken: token,
		ExpiresAt:   time.Now().Add(24 * time.Hour).Unix(),
	}, nil
}

// AcceptRegistration handles steward registration requests
func (s *ControllerService) AcceptRegistration(ctx context.Context, req *controller.RegisterRequest) (*controller.RegisterResponse, error) {
	s.logger.Info("Registration request received", "version", req.Version)
	
	// Generate a unique steward ID
	stewardID, err := s.generateStewardID()
	if err != nil {
		s.logger.Error("Failed to generate steward ID", "error", err)
		return nil, fmt.Errorf("registration failed: %w", err)
	}
	
	// Generate authentication token
	token, err := s.generateToken()
	if err != nil {
		s.logger.Error("Failed to generate token for steward", "steward_id", stewardID, "error", err)
		return nil, fmt.Errorf("registration failed: %w", err)
	}
	
	// Store steward information
	s.mu.Lock()
	s.stewards[stewardID] = &StewardInfo{
		ID:            stewardID,
		Version:       req.Version,
		DNA:           req.InitialDna,
		LastHeartbeat: time.Now(),
		Status:        "registered",
		Metrics:       make(map[string]string),
		Token:         token,
	}
	s.mu.Unlock()
	
	s.logger.Info("Steward registered successfully", "steward_id", stewardID, "version", req.Version)
	
	return &controller.RegisterResponse{
		StewardId: stewardID,
		Status: &proto.Status{
			Code:    proto.Status_OK,
			Message: "Registration successful",
		},
		Token: &proto.Token{
			AccessToken: token,
			ExpiresAt:   time.Now().Add(24 * time.Hour).Unix(),
		},
	}, nil
}

// ProcessHeartbeat handles heartbeat requests from stewards
func (s *ControllerService) ProcessHeartbeat(ctx context.Context, req *controller.HeartbeatRequest) (*proto.Status, error) {
	s.logger.Debug("Heartbeat received", "steward_id", req.StewardId, "status", req.Status)
	
	s.mu.Lock()
	defer s.mu.Unlock()
	
	steward, exists := s.stewards[req.StewardId]
	if !exists {
		s.logger.Warn("Heartbeat from unknown steward", "steward_id", req.StewardId)
		return &proto.Status{
			Code:    proto.Status_NOT_FOUND,
			Message: "Steward not found",
		}, nil
	}
	
	// Update steward heartbeat information
	steward.LastHeartbeat = time.Now()
	steward.Status = req.Status
	steward.Metrics = req.Metrics
	
	s.logger.Debug("Heartbeat processed successfully", "steward_id", req.StewardId)
	
	return &proto.Status{
		Code:    proto.Status_OK,
		Message: "Heartbeat processed",
	}, nil
}

// SyncDNA handles DNA synchronization requests
func (s *ControllerService) SyncDNA(ctx context.Context, dna *proto.DNA) (*proto.Status, error) {
	s.logger.Debug("DNA sync request received", "steward_id", dna.Id)
	
	s.mu.Lock()
	defer s.mu.Unlock()
	
	steward, exists := s.stewards[dna.Id]
	if !exists {
		s.logger.Warn("DNA sync from unknown steward", "steward_id", dna.Id)
		return &proto.Status{
			Code:    proto.Status_NOT_FOUND,
			Message: "Steward not found",
		}, nil
	}
	
	// Update steward DNA
	steward.DNA = dna
	
	s.logger.Debug("DNA synchronized successfully", "steward_id", dna.Id)
	
	return &proto.Status{
		Code:    proto.Status_OK,
		Message: "DNA synchronized",
	}, nil
}

// GetStewardDNA retrieves DNA information for a specific steward
func (s *ControllerService) GetStewardDNA(ctx context.Context, req *controller.StewardRequest) (*proto.DNA, error) {
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