// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	common "github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	controllerconfig "github.com/cfgis/cfgms/features/controller/config"
	fleetStorage "github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/features/controller/tagstore"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"google.golang.org/protobuf/proto"
)

// ErrStewardNotInRegistry reports that a steward has no entry in the live
// in-memory registry. UpdateStewardTenant returns it (wrapped) after the durable
// device_tenant mapping has been written successfully, so callers can tell an
// offline steward — benign, the durable mapping is authoritative — apart from a
// failure to persist the move, which is not benign (Issue #3324).
var ErrStewardNotInRegistry = errors.New("steward not present in live registry")

// ControllerService implements the Controller service
type ControllerService struct {
	logger     logging.Logger
	mu         sync.RWMutex
	stewards   map[string]*StewardInfo
	dnaStorage *fleetStorage.Manager

	// stewardStore is the durable fleet registry (Issue #3403). Wired via
	// SetStewardStore after construction. Nil when the storage backend does not
	// provide one (e.g. in-memory-only test setups).
	stewardStore business.StewardStore

	ringMu     sync.RWMutex
	ringConfig controllerconfig.DeploymentRingConfig

	// postDNASyncHook is called at the end of SyncDNA after durable storage
	// write.  Set via SetPostDNASyncHook following the late-wiring idiom used
	// by signingRotationSvc.SetPublisher and heartbeat.Service.SetOnDNAHashMismatch.
	postDNASyncHook func(stewardID string, dna *common.DNA)

	// tagStore is the durable controller-side tag store (Issue #2542).
	// Tags are controller-owned and survive DNA refreshes.  Wired in via
	// SetTagStore following the late-wiring idiom; nil until wired.
	tagStore *tagstore.Store
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

	// Hidden is the operator-controlled fleet-view visibility flag (Issue #2944).
	// Orthogonal to Status: hiding a steward does not change its lifecycle state.
	Hidden bool
}

// maxVersionLen is the maximum number of bytes stored for a steward-supplied
// Version string. Caps memory amplification at 50k-steward scale against a
// malicious or buggy steward sending an oversized value (threat model: stewards
// on compromised hosts).
const maxVersionLen = 64

// cloneDNA returns a deep copy of a DNA proto message, or nil if dna is nil.
// Safe to call under s.mu.RLock() — proto.Clone reads only, never writes.
func cloneDNA(dna *common.DNA) *common.DNA {
	if dna == nil {
		return nil
	}
	return proto.Clone(dna).(*common.DNA)
}

// copyMetrics returns a shallow copy of a string→string metrics map.
func copyMetrics(m map[string]string) map[string]string {
	copied := make(map[string]string, len(m))
	for k, v := range m {
		copied[k] = v
	}
	return copied
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
//
// Issue #3403: also warm-loads enrolled stewards from the durable StewardStore
// that have no DNA history yet (enrolled but never connected). This ensures a
// steward that received its mTLS cert but never ran a gRPC check-in survives a
// controller restart and remains visible in GET /api/v1/stewards.
func (s *ControllerService) LoadFromStorage(ctx context.Context) error {
	if s.dnaStorage == nil && s.stewardStore == nil {
		return nil
	}

	// Tenant comes from the dedicated device_tenant mapping (Issue #3324),
	// independent of dna_history, so tenant resolution survives retiring the
	// flat DNARecord write path.
	var tenantMap map[string]string
	var deviceIDs []string
	if s.dnaStorage != nil {
		var err error
		tenantMap, err = s.dnaStorage.ListDeviceTenants(ctx)
		if err != nil {
			return fmt.Errorf("failed to list device tenants from storage: %w", err)
		}

		// Enumerate devices that have DNA history records.
		deviceIDs, err = s.dnaStorage.ListAllDeviceIDs(ctx)
		if err != nil {
			return fmt.Errorf("failed to list device IDs from storage: %w", err)
		}
	}

	// Build union of all known devices from DNA sources.
	allDevices := make(map[string]struct{}, len(tenantMap)+len(deviceIDs))
	for id := range tenantMap {
		allDevices[id] = struct{}{}
	}
	for _, id := range deviceIDs {
		allDevices[id] = struct{}{}
	}

	// Also include stewards that are in the durable fleet registry but have no
	// DNA history yet — enrolled (cert issued) but never connected (Issue #3403).
	// These are the stewards that caused the cfg-lab incident: visible in
	// StewardStore but absent from DNA storage after a backend migration.
	var stewardStoreRecords []*business.StewardRecord
	if s.stewardStore != nil {
		var listErr error
		stewardStoreRecords, listErr = s.stewardStore.ListStewards(ctx)
		if listErr != nil {
			s.logger.Warn("Failed to list stewards from durable store during warm-load",
				"error", logging.SanitizeLogValue(listErr.Error()))
		} else {
			for _, rec := range stewardStoreRecords {
				allDevices[rec.ID] = struct{}{}
			}
		}
	}

	// Build a quick lookup for StewardStore records by ID.
	stewardStoreByID := make(map[string]*business.StewardRecord, len(stewardStoreRecords))
	for _, rec := range stewardStoreRecords {
		stewardStoreByID[rec.ID] = rec
	}

	s.logger.Info("Loading steward registry from storage", "device_count", len(allDevices))

	s.mu.Lock()
	defer s.mu.Unlock()

	for deviceID := range allDevices {
		// Live steward takes precedence over persisted state.
		if _, exists := s.stewards[deviceID]; exists {
			continue
		}

		// Tenant from the dedicated mapping is the authoritative source (Issue #3324).
		var tenantID string
		if tenantMap != nil {
			tenantID = tenantMap[deviceID]
		}

		// DNA data is loaded from the flat store. GetLatestByDeviceID is used here
		// for DNA only, not for tenant resolution (Issue #3324).
		var dna *common.DNA
		var storedAt time.Time
		var status string
		if s.dnaStorage != nil {
			record, err := s.dnaStorage.GetLatestByDeviceID(ctx, deviceID)
			if err != nil {
				s.logger.Warn("Failed to load DNA for device from storage",
					"device_id", logging.SanitizeLogValue(deviceID),
					"error", logging.SanitizeLogValue(err.Error()))
			}

			if record != nil {
				dna = record.DNA
				storedAt = record.StoredAt
				status = record.Status
				// Fallback: devices registered before the device_tenant migration may
				// have no mapping entry yet. The SQL migration seeds device_tenant from
				// dna_history on first startup, so this path only applies during the
				// narrow window between a dna_history write and a controller restart
				// (e.g. SetDeviceTenant failed or the process crashed after Store).
				if tenantID == "" {
					tenantID = record.TenantID
				}
			}
		}

		// Merge StewardStore data for this device. StewardStore is the authoritative
		// source for lifecycle status (Issue #3403): decommission only writes to
		// StewardStore, not to DNA, so a DNA-derived status such as "active" can be
		// stale after a deregister or revoke. Always prefer the StewardStore status
		// when it is set. For enrolled-but-never-connected stewards it is the only
		// source.
		if sr, ok := stewardStoreByID[deviceID]; ok {
			if tenantID == "" {
				tenantID = sr.TenantID
			}
			if sr.Status != "" {
				status = string(sr.Status)
			}
			if storedAt.IsZero() {
				storedAt = sr.RegisteredAt
			}
		}

		// Skip devices with no resolvable tenant: inserting a fabricated entry with
		// empty tenantID violates the no-fabrication contract (Issue #2008).
		if tenantID == "" {
			s.logger.Warn("Skipping device with unresolvable tenant during warm-load",
				"device_id", logging.SanitizeLogValue(deviceID))
			continue
		}

		if dna == nil {
			dna = &common.DNA{Id: deviceID}
		}

		s.stewards[deviceID] = &StewardInfo{
			ID:            deviceID,
			TenantID:      tenantID,
			DNA:           dna,
			LastHeartbeat: storedAt,
			Status:        status,
			Metrics:       make(map[string]string),
		}
	}

	s.logger.Info("Steward registry warm-load complete", "loaded", len(allDevices))
	return nil
}

// StorageReady is the controller's real-state readiness check: a bounded
// round-trip to the durable DNA fleet store. Unlike an object-presence
// (liveness) check, a nil return proves the controller can actually reach and
// query its durable backend — so a candidate that bound its API port but cannot
// serve from storage is detectable by the blue/green cutover smoketest
// (Issue #2012). Returns an error when no durable storage is configured or the
// round-trip fails.
func (s *ControllerService) StorageReady(ctx context.Context) error {
	if s.dnaStorage == nil {
		return fmt.Errorf("dna storage not configured")
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := s.dnaStorage.Ping(probeCtx); err != nil {
		return fmt.Errorf("dna storage round-trip failed: %w", err)
	}
	return nil
}

// reconnectionAdmissibleStatus reports whether a durable steward record in the
// given lifecycle state may be adopted by a caller-asserted reconnection.
// Terminal and out-of-band states are excluded: revoked is permanently denied
// re-entry, deregistered records are retained for audit only, and
// archived/dormant stewards must come back through the registration-refresh
// flow (ADR-010 §3/§4) rather than through Register. Same admissible set as the
// approval gate in pkg/controlplane/providers/grpc/approval.go.
func reconnectionAdmissibleStatus(status business.StewardStatus) bool {
	switch status {
	case business.StewardStatusRegistered, business.StewardStatusActive, business.StewardStatusLost:
		return true
	default:
		return false
	}
}

// AcceptRegistration handles steward registration requests
func (s *ControllerService) AcceptRegistration(ctx context.Context, req *controller.RegisterRequest) (*controller.RegisterResponse, error) {
	// Treat nil InitialDna as an empty snapshot so callers that omit it get a
	// clean integrity-rejection path rather than a nil-dereference panic.
	if req.InitialDna == nil {
		req.InitialDna = &common.DNA{}
	}

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
	now := time.Now()

	// Handle reconnection vs new registration
	if req.IsReconnection {
		// For reconnections, try to find existing steward by DNA ID
		if existingSteward := s.findStewardByDNAId(req.InitialDna.Id); existingSteward != nil {
			stewardID = existingSteward.ID
			s.logger.Info("Reconnection detected", "steward_id", stewardID)

			// Verify sync status
			syncStatus, requiresDNAResync, requiresConfigResync = s.verifySyncStatus(existingSteward, req)
		} else {
			// Not in the in-memory registry. Check the durable StewardStore before
			// treating as a new registration and minting a fresh ID (Issue #3403).
			// This covers the scenario where a controller restarted after a backend
			// migration that wiped DNA storage but left StewardStore intact.
			//
			// req.InitialDna.Id is caller-asserted, so a record found under it may
			// only be adopted after two gates — otherwise the writes further down
			// (in-memory TenantID and the durable device_tenant mapping, both set
			// from the CALLER's context tenant) would rebind someone else's steward:
			//
			//  1. Lifecycle. Only registered|active|lost may re-enter the fleet.
			//     GetSteward returns records in every state, including revoked
			//     ("permanently denied re-entry") and deregistered; the caller must
			//     apply the revocation gate itself (ADR-010 §3, StewardStore docs).
			//     Same admissible set as the reference gate in
			//     pkg/controlplane/providers/grpc/approval.go.
			//  2. Tenant. The record's tenant must equal the caller's context tenant,
			//     so a caller in tenant A cannot assert a tenant-B steward ID.
			//
			// A failed gate falls through to req.IsReconnection = false: a fresh ID is
			// minted by generateStewardID() and the named record is left untouched.
			var resolved *business.StewardRecord
			if s.stewardStore != nil {
				sr, storeErr := s.stewardStore.GetSteward(ctx, req.InitialDna.Id)
				switch {
				case storeErr != nil || sr == nil:
					// No durable record (or the store is unreachable): treat as new.
				case !reconnectionAdmissibleStatus(sr.Status):
					s.logger.Warn("Reconnection refused: steward lifecycle state forbids re-entry",
						"dna_id", logging.SanitizeLogValue(req.InitialDna.Id),
						"status", logging.SanitizeLogValue(string(sr.Status)))
				case sr.TenantID != tenantID:
					s.logger.Warn("Reconnection refused: steward belongs to a different tenant",
						"dna_id", logging.SanitizeLogValue(req.InitialDna.Id),
						"request_tenant_id", logging.SanitizeLogValue(tenantID))
				default:
					resolved = sr
				}
			}

			if resolved != nil {
				s.logger.Info("Reconnection: resolved steward from durable fleet store",
					"steward_id", logging.SanitizeLogValue(resolved.ID))
				stewardID = resolved.ID
				// Rehydrate into memory so subsequent lookups succeed.
				s.mu.Lock()
				if _, ok := s.stewards[stewardID]; !ok {
					dna := &common.DNA{Id: stewardID}
					s.stewards[stewardID] = &StewardInfo{
						ID:            stewardID,
						TenantID:      resolved.TenantID,
						DNA:           dna,
						LastHeartbeat: now,
						Status:        string(resolved.Status),
						Metrics:       make(map[string]string),
					}
				}
				s.mu.Unlock()
				syncStatus = &common.SyncStatus{
					LastSyncTime:    req.InitialDna.LastSyncTime,
					SyncFingerprint: req.InitialDna.SyncFingerprint,
					IsInSync:        true,
					Reason:          "Reconnection after restart (StewardStore fallback)",
				}
			} else {
				s.logger.Warn("Reconnection claimed but no existing steward found", "dna_id", logging.SanitizeLogValue(req.InitialDna.Id))
				// Treat as new registration
				req.IsReconnection = false
			}
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

	// Validate DNA integrity. A degenerate snapshot (empty or missing core
	// identity fields) must not clobber good DNA, so we leave the DNA field nil
	// on the StewardInfo and skip the durable write. The registration itself
	// still succeeds structurally — the steward gets its ID and token.
	dnaCheck := checkDNAIntegrity(req.InitialDna, configTypeFullOSDevice)
	if !dnaCheck.valid {
		s.logger.Warn("dna_integrity_rejected",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"missing_fields", dnaCheck.missingFields)
	}

	var registrationDNA *common.DNA
	if dnaCheck.valid {
		registrationDNA = req.InitialDna
	}

	// Store/update steward information
	s.mu.Lock()
	s.stewards[stewardID] = &StewardInfo{
		ID:            stewardID,
		TenantID:      tenantID,
		Version:       req.Version,
		DNA:           registrationDNA,
		LastHeartbeat: time.Now(),
		Status:        "registered",
		Metrics:       make(map[string]string),
		Token:         token,
	}
	s.mu.Unlock()

	// Persist the authoritative tenant mapping at registration time (Issue #3324).
	// Written unconditionally — the tenant mapping must exist even when DNA is
	// invalid, so that a later lookupDurableTenant can resolve the tenant.
	s.setDeviceTenant(ctx, stewardID, tenantID)

	// Persist initial DNA to durable storage only when the snapshot is valid.
	if dnaCheck.valid {
		s.storeDNA(ctx, stewardID, tenantID, req.InitialDna, "registered")
	}

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

	// Validate DNA integrity before writing. A degenerate snapshot (empty or
	// missing hostname/os) must not overwrite the prior last-known-good DNA;
	// the snapshot is also not appended to history.
	dnaCheck := checkDNAIntegrity(dna, configTypeFullOSDevice)
	if !dnaCheck.valid {
		s.logger.Warn("dna_integrity_rejected",
			"steward_id", logging.SanitizeLogValue(dna.Id),
			"missing_fields", dnaCheck.missingFields)
		return &common.Status{
			Code:    common.Status_OK,
			Message: "DNA rejected: degenerate snapshot (missing core identity fields)",
		}, nil
	}

	// Update in-memory DNA
	steward.DNA = dna

	// Persist full DNA snapshot to durable storage
	s.storeDNA(ctx, dna.Id, steward.TenantID, dna, steward.Status)

	// Fire post-sync hook (Issue #2524).  Called unconditionally — storeDNA
	// logs its own errors and never returns one to callers.
	if s.postDNASyncHook != nil {
		s.postDNASyncHook(dna.Id, dna)
	}

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

// GetStewardInfo returns information about a specific steward. The returned
// value is a copy-on-read: the DNA pointer is deep-cloned and the Metrics map
// is shallow-copied under the read lock, so callers can safely read (or
// marshal) the result concurrently with SyncDNA writes.
func (s *ControllerService) GetStewardInfo(stewardID string) (*StewardInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	info, exists := s.stewards[stewardID]
	if !exists {
		return nil, false
	}
	copied := *info
	copied.DNA = cloneDNA(info.DNA)
	copied.Metrics = copyMetrics(info.Metrics)
	return &copied, true
}

// TenantForDevice returns the tenant that owns deviceID, where a device ID is a
// steward ID. known is false when the steward is not in the registry, so callers
// enforcing a tenant boundary treat unknown devices as out of scope rather than
// unowned. This satisfies the reports API's DeviceTenantResolver, making the
// steward registry the single authority for device→tenant ownership.
func (s *ControllerService) TenantForDevice(deviceID string) (tenantID string, known bool) {
	if s == nil {
		return "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	info, exists := s.stewards[deviceID]
	if !exists {
		return "", false
	}
	return info.TenantID, true
}

// RecordHeartbeat advances the live heartbeat state for a registered steward in
// the in-memory registry that the steward API serves (handlers_stewards.go ->
// GetStewardInfo). It is the bridge from the control-plane heartbeat dispatch
// into that registry.
//
// Without this bridge the registry is only ever populated by registration and
// warm-load (LastHeartbeat = record.StoredAt), so GET /api/v1/stewards/{id}
// reports a last_seen frozen at registration time and a status stuck at
// "registered" even while the steward is actively heartbeating (Issue #1986).
//
// On the first heartbeat a freshly-registered steward is promoted to "active",
// mirroring the durable StewardStore lifecycle. A zero ts falls back to now.
// Returns false when the steward is unknown to this controller (e.g. a heartbeat
// arriving before warm-load or for a deregistered steward).
func (s *ControllerService) RecordHeartbeat(stewardID, version string, ts time.Time) bool {
	if ts.IsZero() {
		ts = time.Now()
	}
	if len(version) > maxVersionLen {
		version = version[:maxVersionLen]
	}

	// Fast path: the steward is already in the registry. Hold the lock only long
	// enough to mutate the in-memory entry; never call storage under s.mu.
	s.mu.Lock()
	if steward, exists := s.stewards[stewardID]; exists {
		steward.LastHeartbeat = ts
		if version != "" {
			steward.Version = version
		}
		// Promote registered -> active on the first heartbeat. Leave any other
		// lifecycle status (e.g. an operator-set state) untouched.
		if steward.Status == "" || steward.Status == "registered" {
			steward.Status = "active"
		}
		s.mu.Unlock()
		return true
	}
	s.mu.Unlock()

	// BACKSTOP (Issue #2008): a steward that reconnected via cert-reuse never
	// re-runs HTTP registration, so it can heartbeat while absent from this
	// registry (e.g. after a controller restart that warm-loaded nothing for it).
	// Self-heal by adding it — but ONLY when we can resolve its tenant
	// authoritatively from the durable device-tenant mapping (Issue #3324). The
	// tenant drives exec cross-tenant scoping and config storage location, so
	// fabricating an entry with a wrong or empty tenant is worse than leaving it
	// absent. When no durable tenant is available we decline here and let the
	// connect hook handle it, preserving the no-fabrication contract.
	//
	// Both lookups are blocking storage I/O — run OUTSIDE s.mu to keep the whole
	// registry from serializing behind storage at fleet scale (50k+ stewards,
	// amplified under heartbeat flapping).
	tenantID, ok := s.lookupDurableTenant(stewardID)
	if !ok {
		return false
	}

	// Fetch DNA separately so it has its own storage source (Issue #3324).
	dna := s.lookupDurableDNA(stewardID)

	// Re-acquire and double-check: a concurrent connect-hook upsert or another
	// heartbeat may have inserted the steward while the lock was released. Refresh
	// the existing entry rather than overwriting it.
	s.mu.Lock()
	if steward, exists := s.stewards[stewardID]; exists {
		steward.LastHeartbeat = ts
		if version != "" {
			steward.Version = version
		}
		if steward.Status == "" || steward.Status == "registered" {
			steward.Status = "active"
		}
		s.mu.Unlock()
		return true
	}
	s.stewards[stewardID] = &StewardInfo{
		ID:            stewardID,
		TenantID:      tenantID,
		Version:       version,
		DNA:           dna,
		LastHeartbeat: ts,
		Status:        "active",
		Metrics:       make(map[string]string),
	}
	s.mu.Unlock()

	// Persist so the durable record's timestamp is refreshed consistently with
	// EnsureSteward. storeDNA runs outside s.mu.
	s.storeDNA(context.Background(), stewardID, tenantID, dna, "active")
	return true
}

// EnsureSteward upserts a steward into the in-memory admin registry on an
// authenticated (re)connect (Issue #2008). It is the PRIMARY fix for the
// cert-reuse reconnect gap: the steward's normal reconnect reuses its existing
// certificate and returns WITHOUT calling HTTP /register, so RegisterSteward —
// the only other live-path writer — never runs. Wired to the gRPC OnConnect hook
// (server.go), it fires on every successful ControlChannel registration with the
// mTLS-authenticated CN, making a reconnecting steward visible to
// list/status/exec without waiting for a second controller restart.
//
// Behaviour:
//   - Absent: add a "active" entry. Tenant is resolved authoritatively from
//     durable storage; the supplied tenantID is used only as a fallback and is
//     never preferred over a storage-derived value. DNA is persisted (mirroring
//     RegisterSteward) so the entry survives a later controller restart.
//   - Present: refresh LastHeartbeat and promote registered -> active.
//
// Idempotent: repeated calls do not duplicate the entry.
//
// "Truly new" steward (no durable record AND no supplied tenant): no-op. A
// genuinely new steward reaches the controller through HTTP registration first,
// which mints its durable record; declining here avoids creating an entry with
// an unknown tenant that would corrupt cross-tenant exec scoping.
func (s *ControllerService) EnsureSteward(stewardID, tenantID, status string) {
	if stewardID == "" {
		return
	}
	if status == "" {
		status = "active"
	}
	now := time.Now()

	// Resolve the authoritative tenant from the durable device-tenant mapping
	// (Issue #3324). The storage-derived tenant always wins over the caller-supplied
	// value — the connect hook only knows the mTLS CN, never a tenant.
	durableTenant, haveDurable := s.lookupDurableTenant(stewardID)
	if haveDurable {
		tenantID = durableTenant
	}

	// Fetch DNA separately — it has its own storage source (Issue #3324). Runs
	// outside s.mu so storage I/O does not serialize the whole registry.
	var durableDNA *common.DNA
	if haveDurable {
		durableDNA = s.lookupDurableDNA(stewardID)
	}

	s.mu.Lock()
	if existing, ok := s.stewards[stewardID]; ok {
		existing.LastHeartbeat = now
		promoted := existing.Status == "" || existing.Status == "registered"
		if promoted {
			existing.Status = "active"
		}
		existingTenant := existing.TenantID
		s.mu.Unlock()

		// Persist the status promotion and last-seen to the durable fleet store so
		// GET /api/v1/stewards shows "active" after a first connect (Issue #3403).
		if promoted && s.stewardStore != nil {
			if storeErr := s.stewardStore.UpdateStewardStatus(context.Background(), stewardID, business.StewardStatusActive); storeErr != nil && storeErr != business.ErrStewardNotFound {
				s.logger.Warn("EnsureSteward: failed to persist status promotion to fleet store",
					"steward_id", logging.SanitizeLogValue(stewardID),
					"error", logging.SanitizeLogValue(storeErr.Error()))
			}
		}
		_ = existingTenant
		return
	}

	if !haveDurable && tenantID == "" {
		// Truly new steward we have no authoritative tenant for: decline rather
		// than fabricate an entry with an unknown tenant. HTTP registration is
		// the correct first-contact path and will populate the registry.
		s.mu.Unlock()
		s.logger.Debug("EnsureSteward declined: no durable tenant for unknown steward",
			"steward_id", logging.SanitizeLogValue(stewardID))
		return
	}

	dna := durableDNA
	if dna == nil {
		dna = &common.DNA{Id: stewardID}
	}
	s.stewards[stewardID] = &StewardInfo{
		ID:            stewardID,
		TenantID:      tenantID,
		DNA:           dna,
		LastHeartbeat: now,
		Status:        status,
		Metrics:       make(map[string]string),
	}
	s.mu.Unlock()

	// Persist the tenant mapping so lookupDurableTenant resolves correctly
	// after a controller restart (Issue #3324). Mirrors RegisterSteward's
	// durable write; self-heals any device_tenant gap for backward-compat
	// devices that connected before their device_tenant row was written.
	s.setDeviceTenant(context.Background(), stewardID, tenantID)
	s.storeDNA(context.Background(), stewardID, tenantID, dna, status)

	// Update the persistent fleet store status when this is a reconnect of a
	// known enrolled steward (Issue #3403). Only promote from non-terminal states
	// (registered, lost, active); terminal states (deregistered, revoked, archived,
	// dormant) must not be overwritten even if the approval checker failed to block
	// the connection — defence-in-depth. ErrStewardNotFound is benign.
	if s.stewardStore != nil {
		if sr, getErr := s.stewardStore.GetSteward(context.Background(), stewardID); getErr == nil {
			switch sr.Status {
			case business.StewardStatusDeregistered, business.StewardStatusRevoked,
				business.StewardStatusArchived, business.StewardStatusDormant:
				// Terminal: do not promote.
			default:
				if storeErr := s.stewardStore.UpdateStewardStatus(context.Background(), stewardID, business.StewardStatus(status)); storeErr != nil && storeErr != business.ErrStewardNotFound {
					s.logger.Warn("EnsureSteward: failed to update fleet store status on reconnect",
						"steward_id", logging.SanitizeLogValue(stewardID),
						"error", logging.SanitizeLogValue(storeErr.Error()))
				}
			}
		}
	}

	s.logger.Info("Steward ensured in registry on authenticated connect",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"tenant_id", logging.SanitizeLogValue(tenantID),
		"status", logging.SanitizeLogValue(status))
}

// SetRingConfig updates the deployment ring set. If the ring set has changed,
// an audit log entry is written with actor, before-state, and after-state.
// Ring-set mutation in this story happens only via controller config reload or restart.
func (s *ControllerService) SetRingConfig(rings controllerconfig.DeploymentRingConfig) {
	s.ringMu.Lock()
	prev := s.ringConfig
	s.ringConfig = rings
	s.ringMu.Unlock()
	s.logRingSetChange(prev, rings)
}

// GetRingConfig returns the current deployment ring configuration.
func (s *ControllerService) GetRingConfig() controllerconfig.DeploymentRingConfig {
	s.ringMu.RLock()
	defer s.ringMu.RUnlock()
	return s.ringConfig
}

// logRingSetChange emits a structured audit entry when the ring set changes.
// actor is always "controller" (ring changes come from config reload/restart).
func (s *ControllerService) logRingSetChange(prev, next controllerconfig.DeploymentRingConfig) {
	if ringConfigEqual(prev, next) {
		return
	}
	s.logger.Info("ring_set_changed",
		"actor", "controller",
		"before", ringConfigSummary(prev),
		"after", ringConfigSummary(next),
	)
}

// ringConfigSummary produces a compact human-readable representation for audit log entries.
func ringConfigSummary(rc controllerconfig.DeploymentRingConfig) string {
	parts := make([]string, len(rc.Rings))
	for i, r := range rc.Rings {
		if r.DesiredVersion != "" {
			parts[i] = r.Name + "=" + r.DesiredVersion
		} else {
			parts[i] = r.Name
		}
	}
	return fmt.Sprintf("[%s] fallback=%s", strings.Join(parts, ","), rc.FallbackRing)
}

// ringConfigEqual returns true when two ring configs are semantically identical
// (same ring order, names, versions, and fallback ring).
func ringConfigEqual(a, b controllerconfig.DeploymentRingConfig) bool {
	if a.FallbackRing != b.FallbackRing || len(a.Rings) != len(b.Rings) {
		return false
	}
	for i := range a.Rings {
		if a.Rings[i].Name != b.Rings[i].Name || a.Rings[i].DesiredVersion != b.Rings[i].DesiredVersion {
			return false
		}
	}
	return true
}

// lookupDurableTenant resolves a steward's authoritative tenant from the durable
// device-tenant mapping (Issue #3324). The tenant is written only at registration
// time by the controller, never accepted from steward input, preserving the
// cross-tenant exec scoping invariant (Issue #2008).
//
// Returns ok=false when there is no durable backend or no mapping for the steward;
// callers must treat that as "tenant unknown" and decline to fabricate a
// tenant-scoped registry entry.
func (s *ControllerService) lookupDurableTenant(stewardID string) (tenantID string, ok bool) {
	if s.dnaStorage == nil {
		return "", false
	}
	tid, found, err := s.dnaStorage.GetDeviceTenant(context.Background(), stewardID)
	if err != nil || !found {
		return "", false
	}
	return tid, true
}

// lookupDurableDNA retrieves the last-known DNA snapshot from the flat store.
// Used by EnsureSteward and RecordHeartbeat to seed a new registry entry's DNA
// field; separate from lookupDurableTenant so DNA and tenant have independent
// sources (Issue #3324).
func (s *ControllerService) lookupDurableDNA(stewardID string) *common.DNA {
	if s.dnaStorage == nil {
		return nil
	}
	record, err := s.dnaStorage.GetLatestByDeviceID(context.Background(), stewardID)
	if err != nil || record == nil {
		return nil
	}
	return record.DNA
}

// persistDeviceTenant writes the durable (stewardID → tenantID) mapping that
// lookupDurableTenant treats as authoritative (Issue #3324). It is a no-op when
// no durable backend is configured or the tenant is unknown — there is nothing
// authoritative to record in either case, and writing an empty tenant would make
// the mapping claim a device belongs to no tenant.
func (s *ControllerService) persistDeviceTenant(ctx context.Context, stewardID, tenantID string) error {
	if s.dnaStorage == nil || tenantID == "" {
		return nil
	}
	return s.dnaStorage.SetDeviceTenant(ctx, stewardID, tenantID)
}

// setDeviceTenant durably persists the (stewardID → tenantID) mapping at
// registration time (Issue #3324). Errors are logged but not propagated —
// a failure here degrades restart-recovery; the registration itself succeeds.
func (s *ControllerService) setDeviceTenant(ctx context.Context, stewardID, tenantID string) {
	if err := s.persistDeviceTenant(ctx, stewardID, tenantID); err != nil {
		s.logger.Error("Failed to persist device tenant mapping",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// RegisterSteward records or updates a steward that registered via the HTTP path.
// It is idempotent: calling it twice with the same stewardID overwrites the entry.
//
// The steward is also persisted to durable DNA storage. Registration is the only
// live-path entry point into the registry, so without this write the registry is
// memory-only and a controller restart loses every steward (LoadFromStorage finds
// device_count: 0). Persisting here lets the next startup warm-load the steward
// before it reconnects, so GET /api/v1/stewards/{id} keeps returning it.
func (s *ControllerService) RegisterSteward(stewardID, tenantID, transportAddr, status string) error {
	return s.RegisterStewardWithAttributes(stewardID, tenantID, transportAddr, status, nil)
}

// RegisterStewardWithAttributes is like RegisterSteward but seeds initial DNA attributes
// (e.g. hostname, os) so the controller is not identity-blind before the first DNA sync
// (Issue #2640). Pass nil initialAttrs to get identical behaviour to RegisterSteward.
func (s *ControllerService) RegisterStewardWithAttributes(stewardID, tenantID, transportAddr, status string, initialAttrs map[string]string) error {
	dna := &common.DNA{Id: stewardID}
	if len(initialAttrs) > 0 {
		dna.Attributes = make(map[string]string, len(initialAttrs))
		for k, v := range initialAttrs {
			dna.Attributes[k] = v
		}
	}

	s.mu.Lock()
	s.stewards[stewardID] = &StewardInfo{
		ID:            stewardID,
		TenantID:      tenantID,
		DNA:           dna,
		LastHeartbeat: time.Now(),
		Status:        status,
		Metrics:       make(map[string]string),
	}
	s.mu.Unlock()

	s.storeDNA(context.Background(), stewardID, tenantID, dna, status)
	s.setDeviceTenant(context.Background(), stewardID, tenantID)
	return nil
}

// SetStewardDNA sets the in-memory DNA pointer for a registered steward,
// replacing whatever was there (including to nil). Returns false if the
// steward is not present in the registry.
func (s *ControllerService) SetStewardDNA(stewardID string, dna *common.DNA) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	steward, exists := s.stewards[stewardID]
	if !exists {
		return false
	}
	steward.DNA = dna
	return true
}

// UpdateStewardStatus updates the status of a registered steward in the
// in-memory registry only.
// Returns an error if the steward is not found.
func (s *ControllerService) UpdateStewardStatus(stewardID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	steward, exists := s.stewards[stewardID]
	if !exists {
		return fmt.Errorf("steward %s not found", stewardID)
	}
	steward.Status = status
	return nil
}

// UpdateStewardStatusDurable updates the steward's status in both the
// in-memory registry and the durable DNA storage so a controller restart
// warm-loads the correct status (Issue #3403). It is a best-effort call:
// a missing in-memory entry is logged and the DNA write is skipped; a DNA
// write failure is logged but does not fail the caller.
func (s *ControllerService) UpdateStewardStatusDurable(stewardID, tenantID, status string) error {
	s.mu.Lock()
	steward, exists := s.stewards[stewardID]
	var dna *common.DNA
	if exists {
		steward.Status = status
		dna = cloneDNA(steward.DNA)
	}
	s.mu.Unlock()

	if !exists {
		s.logger.Warn("UpdateStewardStatusDurable: steward not in registry, skipping DNA update",
			"steward_id", logging.SanitizeLogValue(stewardID))
		return fmt.Errorf("steward %s not found in registry", stewardID)
	}
	if dna == nil {
		// The in-memory DNA is nil when the steward registered via the direct-approval
		// path with no initial attributes. A minimal placeholder is used here: it records
		// the status transition without clobbering any earlier DNA. checkDNAIntegrity is
		// intentionally skipped — the placeholder carries only the steward ID and status,
		// which is sufficient for warm-load; the steward's real DNA arrives on first sync.
		dna = &common.DNA{Id: stewardID}
	}
	s.storeDNA(context.Background(), stewardID, tenantID, dna, status)
	return nil
}

// SetStewardHidden sets the operator-controlled visibility flag for the given steward
// in the in-memory registry. Returns an error if the steward is not found.
func (s *ControllerService) SetStewardHidden(stewardID string, hidden bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	steward, exists := s.stewards[stewardID]
	if !exists {
		return fmt.Errorf("steward %s not found", stewardID)
	}
	steward.Hidden = hidden
	return nil
}

// UpdateStewardTenant reassigns a steward to a different tenant in the live registry
// and persists the new mapping to the durable device_tenant store. Both writes are
// required: skipping the durable write causes tenant-reversion, because EnsureSteward
// and RecordHeartbeat let the durable tenant win unconditionally, so the next reconnect
// or controller restart would restore the pre-move tenant (Issue #3324).
//
// The durable write happens first and is independent of registry presence — a steward
// that is offline during the move is exactly the case that reverts. Callers that treat
// an absent registry entry as benign must match on ErrStewardNotInRegistry rather than
// on "error != nil"; any other error means the move was NOT persisted.
//
// The durable write uses a background context deliberately: an aborted request must not
// leave the mapping pointing at the old tenant after the move has been recorded elsewhere.
func (s *ControllerService) UpdateStewardTenant(stewardID, newTenantID string) error {
	if err := s.persistDeviceTenant(context.Background(), stewardID, newTenantID); err != nil {
		s.logger.Error("Failed to persist device tenant mapping on tenant move",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(err.Error()))
		return fmt.Errorf("failed to persist tenant mapping for steward %s: %w", stewardID, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	steward, exists := s.stewards[stewardID]
	if !exists {
		return fmt.Errorf("steward %s not found: %w", stewardID, ErrStewardNotInRegistry)
	}
	steward.TenantID = newTenantID
	return nil
}

// SetPostDNASyncHook registers a hook invoked at the end of each SyncDNA call,
// after the full DNA snapshot has been written to durable storage.  Follows the
// same late-wiring pattern as heartbeat.Service.SetOnDNAHashMismatch — the hook
// receiver (heartbeat.Service) is constructed after ControllerService, so the
// hook cannot be supplied at construction time without creating an init cycle.
func (s *ControllerService) SetPostDNASyncHook(fn func(stewardID string, dna *common.DNA)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.postDNASyncHook = fn
}

// SetStewardStore wires the durable fleet registry store into the service
// (Issue #3403). The store is used by LoadFromStorage to warm-load enrolled
// stewards that have never connected, and by EnsureSteward to update the
// persistent lifecycle status on reconnect. Nil until wired.
//
// Callers must call this before any goroutines that read s.stewardStore are
// started; the field is not protected for concurrent access after the initial
// wiring (server.go calls it once at startup before serving begins).
func (s *ControllerService) SetStewardStore(store business.StewardStore) {
	s.stewardStore = store
}

// SetTagStore wires the durable controller-side tag store into the service.
// Follows the same late-wiring idiom as SetPostDNASyncHook — the store is
// constructed during server startup and injected here so that the selector
// engine (S1b) and role adapter (S4) can reach it via TagStore().
func (s *ControllerService) SetTagStore(store *tagstore.Store) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tagStore = store
}

// TagStore returns the controller-side tag store, or nil when not yet wired.
// Later stories (S1b selector merge, S4 role adapter) access tags via this accessor.
func (s *ControllerService) TagStore() *tagstore.Store {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tagStore
}

// GetAllStewards returns a list of all registered stewards. Each entry is a
// copy-on-read: DNA is deep-cloned and Metrics is shallow-copied under the
// read lock, so callers can safely read the results concurrently with SyncDNA
// writes without holding a reference into the live registry.
func (s *ControllerService) GetAllStewards() []*StewardInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stewards := make([]*StewardInfo, 0, len(s.stewards))
	for _, info := range s.stewards {
		copied := *info
		copied.DNA = cloneDNA(info.DNA)
		copied.Metrics = copyMetrics(info.Metrics)
		stewards = append(stewards, &copied)
	}
	return stewards
}

// findStewardByDNAId finds an existing steward by DNA ID and returns a
// copy-on-read. The caller (verifySyncStatus) reads DNA fields — e.g.
// SyncFingerprint, AttributeCount — after the lock is released, so returning
// the live pointer would race with a concurrent SyncDNA write.
func (s *ControllerService) findStewardByDNAId(dnaId string) *StewardInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, steward := range s.stewards {
		if steward.DNA != nil && steward.DNA.Id == dnaId {
			copied := *steward
			copied.DNA = cloneDNA(steward.DNA)
			copied.Metrics = copyMetrics(steward.Metrics)
			return &copied
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
