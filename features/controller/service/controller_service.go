// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	common "github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	controllerconfig "github.com/cfgis/cfgms/features/controller/config"
	fleetStorage "github.com/cfgis/cfgms/features/controller/fleet/storage"
	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"google.golang.org/protobuf/proto"
)

// ControllerService implements the Controller service
type ControllerService struct {
	logger     logging.Logger
	mu         sync.RWMutex
	stewards   map[string]*StewardInfo
	dnaStorage *fleetStorage.Manager

	ringMu     sync.RWMutex
	ringConfig controllerconfig.DeploymentRingConfig
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

	// RingResolvedVersion is the desired_version resolved from the steward's
	// deployment_ring DNA attribute and the controller ring config. Empty when
	// the resolved ring has no version set. Applied as an override over any
	// tenant-path desired_version when delivering config to the steward.
	RingResolvedVersion string
	// ResolvedRing is the ring name that was matched (or fell back to).
	ResolvedRing string
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
		// Read via the SQL-backed path: a freshly started controller has an
		// empty in-memory index, so GetLatest (index-based) would miss every
		// device persisted by the previous run.
		record, err := s.dnaStorage.GetLatestByDeviceID(ctx, deviceID)
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
	// authoritatively from durable storage. The tenant drives exec cross-tenant
	// scoping (api/handlers_runs.go enforceExecTenantScope) and the config storage
	// location, so fabricating an entry with a wrong or empty tenant is worse than
	// leaving it absent. When no durable tenant is available we decline here and
	// let the connect hook (which has the same authoritative lookup) handle it,
	// preserving the no-fabrication contract.
	//
	// The durable lookup is blocking storage I/O, so it runs OUTSIDE s.mu to keep
	// the whole registry from serializing behind storage at fleet scale (50k+
	// stewards, amplified under heartbeat flapping).
	tenantID, dna, ok := s.lookupDurableTenant(stewardID)
	if !ok {
		return false
	}

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

	// Resolve the authoritative tenant from durable storage. The storage-derived
	// tenant always wins over the caller-supplied value, which (for the connect
	// hook) is empty anyway — the hook only knows the mTLS CN, never a tenant.
	durableTenant, durableDNA, haveDurable := s.lookupDurableTenant(stewardID)
	if haveDurable {
		tenantID = durableTenant
	}

	s.mu.Lock()
	if existing, ok := s.stewards[stewardID]; ok {
		existing.LastHeartbeat = now
		if existing.Status == "" || existing.Status == "registered" {
			existing.Status = "active"
		}
		s.mu.Unlock()
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

	// Persist so the entry survives a later restart's warm-load, mirroring
	// RegisterSteward's durable write.
	s.storeDNA(context.Background(), stewardID, tenantID, dna, status)

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

// ResolveRingVersion resolves the effective desired_version and ring name for a steward
// given its DNA attributes and the current ring configuration.
// Returns (version, resolvedRing, didFallback, originalRingValue).
func (s *ControllerService) ResolveRingVersion(dnaAttrs map[string]string) (version, ring string, didFallback bool, originalValue string) {
	s.ringMu.RLock()
	rings := s.ringConfig
	s.ringMu.RUnlock()
	return pkgconfig.ResolveRingVersion(dnaAttrs, rings)
}

// ApplyRingResolution resolves the deployment ring for a steward, stores the result in
// the StewardInfo, and logs a WARN when ring fallback occurs (absent or invalid ring).
// steward must be the live registry entry; caller must hold s.mu (at least read lock
// for reading DNA, write lock if updating RingResolvedVersion).
func (s *ControllerService) ApplyRingResolution(stewardID string, steward *StewardInfo) {
	if steward.DNA == nil {
		return
	}
	version, ring, didFallback, original := s.ResolveRingVersion(steward.DNA.Attributes)
	steward.RingResolvedVersion = version
	steward.ResolvedRing = ring
	if didFallback {
		s.logger.Warn("deployment_ring_fallback",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"ring_value", logging.SanitizeLogValue(original),
			"fallback_ring", logging.SanitizeLogValue(ring),
		)
	}
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

// lookupDurableTenant resolves a steward's authoritative tenant (and last DNA
// snapshot) from durable storage by stewardID. The tenant comes from the
// registration-minted DNA record, never from a steward-supplied value, so that
// cross-tenant exec scoping and config storage paths stay correct (Issue #2008).
//
// Returns ok=false when there is no durable backend or no record for the
// steward; callers must treat that as "tenant unknown" and decline to fabricate
// a tenant-scoped registry entry.
func (s *ControllerService) lookupDurableTenant(stewardID string) (tenantID string, dna *common.DNA, ok bool) {
	if s.dnaStorage == nil {
		return "", nil, false
	}
	record, err := s.dnaStorage.GetLatestByDeviceID(context.Background(), stewardID)
	if err != nil || record == nil {
		return "", nil, false
	}
	return record.TenantID, record.DNA, true
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
	dna := &common.DNA{Id: stewardID}

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

// UpdateStewardStatus updates the status of a registered steward.
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

// UpdateStewardTenant reassigns a steward to a different tenant in the live registry.
// The steward need not be currently connected — the update is applied to the in-memory
// entry so the next config resolution uses the new tenant path. Returns an error if
// the steward is not in the registry (it may have been loaded from durable storage but
// not yet reconnected; callers must ensure the durable store is also updated).
func (s *ControllerService) UpdateStewardTenant(stewardID, newTenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	steward, exists := s.stewards[stewardID]
	if !exists {
		return fmt.Errorf("steward %s not found", stewardID)
	}
	steward.TenantID = newTenantID
	return nil
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
