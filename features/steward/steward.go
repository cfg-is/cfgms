// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package steward provides standalone configuration management capabilities.
//
// The steward package implements a complete standalone system that operates
// using local hostname.cfg files. It includes module discovery, configuration
// management, and execution orchestration.
//
// Basic usage:
//
//	logger := logging.NewLogger("info")
//	steward, err := steward.NewStandalone("", logger)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	ctx := context.Background()
//	err = steward.Start(ctx)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// For controller-connected operation, use client.NewTransportClient from the
// features/steward/client package (see cmd/steward/main.go for the production pattern).
package steward

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/features/steward/dna/drift"
	"github.com/cfgis/cfgms/features/steward/driftdiff"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/features/steward/factory"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// ErrDNAIDMismatch is returned by detectUnmanagedDNADrift when the DNA identity
// (derived from MAC + hostname) changes between convergence cycles, indicating a
// VM/container migration or hardware change that requires manual reconciliation.
var ErrDNAIDMismatch = errors.New("DNA-ID mismatch: manual reconciliation required")

// Steward manages configuration for a single endpoint in standalone mode.
//
// The Steward uses local hostname.cfg files and discovered modules to
// converge the system to the desired configuration state. All operations
// are thread-safe and support graceful shutdown via context cancellation.
type Steward struct {

	// Standalone configuration loaded from hostname.cfg
	standaloneConfig config.StewardConfig

	// Logger for structured logging
	logger logging.Logger

	// Health monitoring
	healthCheck *HealthMonitor

	// Standalone components
	moduleRegistry discovery.ModuleRegistry
	moduleFactory  *factory.ModuleFactory
	comparator     *stewardtesting.StateComparator
	executor       *execution.Executor

	// DNA collection and drift detection for unmanaged attribute reporting
	dnaCollector  *dna.Collector
	driftDetector drift.Detector

	// previousDNA is the DNA snapshot from the last convergence cycle.
	// Comparing it against a fresh snapshot detects unmanaged attribute changes.
	previousDNA   *commonpb.DNA
	previousDNAMu sync.Mutex

	// driftDiffs buffers the DriftDiffRecord that onManagedResourceDrift builds for
	// every managed-resource drift event (Issue #3373). Bounded and drop-oldest; see
	// driftdiff.Accumulator. Drained at the end of each convergence pass by
	// drainDriftDiffs. Held by value so a zero Steward still has a bounded buffer.
	driftDiffs driftdiff.Accumulator

	// configRevision identifies the desired-state revision the standalone engine is
	// converging against, and is stamped on every drift-diff record so a record can be
	// attributed to the cfg that produced it. Standalone mode receives no
	// controller-assigned config version, so it is the content hash of the loaded cfg.
	configRevision string

	// Secret store for steward-side secret management
	secretStore secretsif.SecretStore

	// monitorDNARefreshes counts DNA snapshot refreshes triggered by a
	// monitor-driven targeted reconcile that applied changes (standalone only).
	// Read via export_test.go.
	monitorDNARefreshes atomic.Int64

	// wg tracks the convergence loop goroutine and the health monitor goroutine
	// for clean shutdown.
	wg sync.WaitGroup

	// Shutdown coordination
	shutdown chan struct{}

	// healthCancel cancels the health monitor goroutine's context. Called in Stop()
	// to guarantee the goroutine exits even if Stop() is called before
	// HealthMonitor.Start() sets running=true (TOCTOU race on running.Load()).
	healthCancel context.CancelFunc
}

// NewStandalone creates a new Steward instance for standalone operation.
//
// The steward will load configuration from hostname.cfg files and discover
// available modules from the filesystem. If configPath is empty, the steward
// searches platform-specific locations for hostname.cfg.
//
// Configuration search order:
//  1. Provided configPath (if not empty)
//  2. Current working directory
//  3. User configuration directories
//  4. System configuration directories
//
// Module discovery searches:
//  1. Custom paths from configuration
//  2. Directory relative to binary
//  3. Platform-specific system paths
//
// Returns an error if configuration loading, module discovery, or component
// initialization fails.
func NewStandalone(configPath string, logger logging.Logger) (*Steward, error) {
	// Load standalone configuration with validation and defaults
	cfg, err := config.LoadConfiguration(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// Discover available modules from filesystem
	registry, err := discovery.DiscoverModules(cfg.Steward.ModulePaths)
	if err != nil {
		return nil, fmt.Errorf("failed to discover modules: %w", err)
	}

	// Create module factory for dynamic loading with steward ID for central logging
	stewardID := cfg.Steward.ID
	if stewardID == "" {
		stewardID = "steward-standalone" // Default ID for standalone mode
	}
	moduleFactory := factory.NewWithStewardID(registry, cfg.Steward.ErrorHandling, stewardID, logger)

	// Initialize steward secret store if provider is available
	var secretStore secretsif.SecretStore
	secretsProvider := cfg.Steward.Secrets.Provider
	if secretsProvider == "" {
		secretsProvider = "steward"
	}
	secretsConfig := map[string]interface{}{
		"secrets_dir": cfg.Steward.Secrets.SecretsDir,
	}
	secretStore, err = secretsif.CreateSecretStoreFromConfig(secretsProvider, secretsConfig)
	if err != nil {
		// Secret store is best-effort in standalone mode — log warning but continue
		if logger != nil {
			logger.Warn("Failed to initialize secret store, modules requiring secrets will not function",
				"provider", secretsProvider,
				"error", err)
		}
	} else {
		// Inject secret store into factory for module injection
		moduleFactory.SetSecretStore(secretStore)
		if logger != nil {
			logger.Info("Steward secret store initialized", "provider", secretsProvider)
		}
	}

	// Create state comparator for configuration drift detection
	comparator := stewardtesting.NewStateComparator()

	// Create executor for resource orchestration
	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:        logger,
		Factory:       moduleFactory,
		Comparator:    comparator,
		ErrorHandling: cfg.Steward.ErrorHandling,
		// Explicit rather than relying on executor.go's 120s fallback (Issue
		// #3801) — see the matching comment at client_transport.go's ExecutorConfig
		// literal for the reasoning (covers observed cloud-image VM provisioning,
		// 25-27s, with comfortable headroom while still bounding a wedged module).
		ModuleCallTimeoutSec: 120,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create executor: %w", err)
	}

	// Create health monitor for metrics collection
	healthMonitor := NewHealthMonitor(logger)

	// Create DNA collector for system fingerprinting and unmanaged drift detection
	dnaCollector := dna.NewCollector(logger)

	// Create drift detector for unmanaged DNA attribute change detection
	driftDetector, err := drift.NewDetector(drift.DefaultDetectorConfig(), logger)
	if err != nil {
		// Drift detector is best-effort — log warning but continue
		if logger != nil {
			logger.Warn("Failed to initialize drift detector, DNA drift reporting will be disabled",
				"error", err)
		}
		driftDetector = nil
	}

	// Wire script module signing config from steward config (Story #1671).
	// This ensures the signing policy is live before any convergence run executes scripts.
	if scriptMod, loadErr := moduleFactory.LoadModule("script"); loadErr == nil {
		if sm, ok := scriptMod.(*script.Module); ok {
			sm.SetSigningConfig(config.BuildModuleSigningConfig(cfg.Steward.ScriptSigning))
		}
	} else if logger != nil {
		logger.Warn("Failed to load script module for signing config wiring", "error", loadErr)
	}

	s := &Steward{
		standaloneConfig: cfg,
		logger:           logger,
		healthCheck:      healthMonitor,
		moduleRegistry:   registry,
		moduleFactory:    moduleFactory,
		secretStore:      secretStore,
		comparator:       comparator,
		executor:         executor,
		dnaCollector:     dnaCollector,
		driftDetector:    driftDetector,
		configRevision:   configContentRevision(cfg),
		shutdown:         make(chan struct{}),
	}

	// Register the managed-resource drift handler at construction, not at Start, so
	// every path that drives the executor records drift-diff records: the convergence
	// loop, monitor-driven targeted reconciles, and a direct ExecuteConfiguration call.
	s.executor.SetDriftEventHandler(s.onManagedResourceDrift)

	return s, nil
}

// configContentRevision derives the revision identifier stamped on every drift-diff
// record produced in standalone mode.
//
// A standalone steward is driven by a local cfg file and receives no
// controller-assigned config version, but a drift record still has to say which
// desired state it was measured against — otherwise a record read later cannot be
// attributed to the cfg that produced it. The revision is therefore the SHA-256 of
// the effective (post-defaults, post-validation) configuration. encoding/json emits
// map keys in sorted order, so the same cfg always produces the same revision, and
// any edit to the cfg produces a different one.
func configContentRevision(cfg config.StewardConfig) string {
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Start initializes and starts the steward's convergence loop.
//
// This method:
//  1. Starts health monitoring in a background goroutine
//  2. Converges immediately on startup
//  3. Starts the scheduled convergence loop at the interval defined in the cfg
//
// The method is non-blocking and starts background goroutines for ongoing operations.
// Use Stop() to gracefully shut down the steward.
//
// Returns an error if startup fails, but not for configuration execution errors
// (those are logged and included in execution reports).
func (s *Steward) Start(ctx context.Context) error {
	return s.startStandalone(ctx)
}

// startStandalone starts the steward's cfg-driven convergence loop.
//
// This method:
//  1. Starts health monitoring in a background goroutine
//  2. Converges immediately on startup
//  3. Starts the scheduled convergence loop at the interval defined in the cfg
//
// The convergence loop runs until the context is cancelled or Stop() is called.
// Convergence errors are logged but do not stop the loop — the steward retries
// at the next scheduled interval.
func (s *Steward) startStandalone(ctx context.Context) error {
	interval := config.GetConvergeInterval(s.standaloneConfig)

	s.logger.Info("Starting steward in standalone mode",
		"id", s.standaloneConfig.Steward.ID,
		"resources", len(s.standaloneConfig.Resources),
		"converge_interval", interval)

	// Start health monitoring in background. Tracked by s.wg so Stop() →
	// s.wg.Wait() ensures the goroutine exits before cleanup proceeds.
	// healthCtx is derived so Stop() can cancel it directly, covering the TOCTOU
	// window where Stop() is called before HealthMonitor.Start() sets running=true.
	healthCtx, healthCancel := context.WithCancel(ctx)
	s.healthCancel = healthCancel
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.healthCheck.Start(healthCtx)
	}()

	// The managed-resource drift handler is registered in NewStandalone, before any
	// executor path can run.

	// Start monitors for modules that implement the Monitor interface.
	// Monitor events feed a targeted reconcile of the changed resource.
	s.startMonitors(ctx)

	// Converge immediately on startup
	s.runConvergence(ctx)

	// Start scheduled convergence loop
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.convergenceLoop(ctx, interval)
	}()

	s.logger.Info("Steward started successfully in standalone mode")
	return nil
}

// runConvergence executes a single convergence pass against the current cfg.
//
// Applies the Get→Compare→Set→Verify cycle for every resource. Errors are
// logged individually but do not abort the overall run — error handling
// policy is controlled by the cfg's error_handling settings.
//
// After convergence, a DNA snapshot is collected and compared against the previous
// snapshot to detect changes to unmanaged attributes (hardware, installed software,
// network config). These are attributes not controlled by cfg resources — the
// convergence loop handles managed resources, so changes here represent out-of-band
// system modifications.
func (s *Steward) runConvergence(ctx context.Context) {
	s.logger.Info("Starting convergence run",
		"id", s.standaloneConfig.Steward.ID,
		"resources", len(s.standaloneConfig.Resources))

	report := s.executor.ExecuteConfiguration(ctx, s.standaloneConfig)

	s.logger.Info("Convergence run completed",
		"total", report.TotalResources,
		"successful", report.SuccessfulCount,
		"failed", report.FailedCount,
		"skipped", report.SkippedCount)

	for _, err := range report.Errors {
		s.logger.Error("Convergence error", "error", err)
	}

	// Empty the drift-diff accumulator this pass filled. Standalone mode has no
	// controller to sync the records to, so this is their terminus (Issue #3373).
	s.drainDriftDiffs()

	// Collect a fresh DNA snapshot and compare against the previous one to detect
	// changes to unmanaged attributes. This is a natural post-convergence activity:
	// the convergence loop already handled managed resources above.
	events, err := s.detectUnmanagedDNADrift(ctx)
	if err != nil {
		s.logger.Error("Unmanaged DNA drift detection returned an error",
			"error", err,
			"event_count", len(events))
		for _, evt := range events {
			s.logger.Error("Critical DNA drift event",
				"event_id", evt.ID,
				"severity", evt.Severity,
				"category", evt.Category,
				"description", evt.Description)
		}
	}
}

// detectUnmanagedDNADrift collects a fresh DNA snapshot and compares it against
// the previous snapshot. Changes to unmanaged attributes (hardware, OS, network)
// are logged and reported to the controller for visibility.
//
// On DNA-ID mismatch (MAC or hostname change), a SeverityCritical drift event is
// returned along with ErrDNAIDMismatch so callers know not to proceed with stale
// comparison logic. This signals the operator that manual reconciliation is required.
//
// This is NOT a separate monitoring loop — it runs as part of the convergence cycle.
func (s *Steward) detectUnmanagedDNADrift(ctx context.Context) ([]*drift.DriftEvent, error) {
	if s.dnaCollector == nil {
		return nil, nil
	}

	currentDNA, err := s.dnaCollector.Collect(ctx)
	if err != nil {
		s.logger.Warn("Failed to collect DNA for drift detection", "error", err)
		return nil, nil
	}

	s.previousDNAMu.Lock()
	prevDNA := s.previousDNA
	s.previousDNA = currentDNA
	s.previousDNAMu.Unlock()

	// On the first run there is no previous snapshot — just record and return.
	if prevDNA == nil {
		s.logger.Debug("DNA snapshot captured (first convergence run)")
		return nil, nil
	}

	// DNA IDs are derived from stable hardware identifiers (MAC + hostname).
	// A mismatch indicates VM/container migration or hardware change — emit a critical
	// drift event so the operator is aware, and return ErrDNAIDMismatch so the caller
	// knows not to proceed with stale comparison results.
	if prevDNA.Id != currentDNA.Id {
		s.logger.Error("DNA identity changed between convergence cycles — manual reconciliation required",
			"previous_id", logging.RedactedID(prevDNA.Id),
			"current_id", logging.RedactedID(currentDNA.Id))
		evt := &drift.DriftEvent{
			Severity:    drift.SeverityCritical,
			Category:    drift.CategoryConfiguration,
			Title:       "DNA identity mismatch",
			Description: "DNA-ID mismatch (MAC or hostname change) — manual reconciliation required",
			ChangeCount: 1,
			Changes: []*drift.AttributeChange{
				{
					Attribute:     "id",
					PreviousValue: prevDNA.Id,
					CurrentValue:  currentDNA.Id,
					ChangeType:    drift.ChangeTypeModified,
					Severity:      drift.SeverityCritical,
				},
			},
		}
		return []*drift.DriftEvent{evt}, ErrDNAIDMismatch
	}

	if s.driftDetector == nil {
		return nil, nil
	}

	events, err := s.driftDetector.DetectDrift(ctx, prevDNA, currentDNA)
	if err != nil {
		s.logger.Warn("DNA drift detection failed", "error", err)
		return nil, nil
	}

	if len(events) == 0 {
		s.logger.Debug("No unmanaged DNA attribute changes detected")
		return nil, nil
	}

	// Log detected unmanaged drift events.
	// When connected to a controller these would also be reported via the data plane.
	for _, event := range events {
		s.logger.Info("Unmanaged DNA attribute change detected",
			"event_id", event.ID,
			"severity", event.Severity,
			"category", event.Category,
			"change_count", event.ChangeCount,
			"title", event.Title)
	}
	return events, nil
}

// onManagedResourceDrift is the DriftEventHandler registered on the execution engine.
// It is called by the convergence Compare step when a managed resource has drifted,
// before Set corrects it.
//
// It does two things (Issue #3373, ADR-022 §6). It logs the event, as it always has,
// and it builds a DriftDiffRecord from the StateDiff and records it in the steward's
// drift-diff accumulator instead of discarding the diff. The record carries the full
// compared field set — matching fields included — so a consumer can render how much of
// the resource was in compliance, not only what drifted.
//
// Where the accumulated record goes depends on the engine that produced it, and the
// two engines are separate by construction:
//
//   - Standalone (this type): there is no controller and therefore no DNA sync, so
//     drainDriftDiffs() empties the accumulator at the end of every convergence pass
//     and reports each record locally. Nothing is left to grow unbounded.
//   - Controller-connected (features/steward/client.TransportClient): its own
//     executor carries an equivalent handler wired in InitializeConfigExecutor, and
//     its accumulator is drained onto DNATransfer.DriftDiffBytes on each SYNC_DNA
//     cycle — that is the path that carries the record to the entity graph.
//
// Both engines build the record through driftdiff.BuildRecord and buffer it in a
// driftdiff.Accumulator, so the two paths cannot diverge on record shape or on the
// memory bound.
func (s *Steward) onManagedResourceDrift(resourceName string, moduleName string, diff *stewardtesting.StateDiff) {
	changedCount := len(diff.ChangedFields)
	addedCount := len(diff.AddedFields)
	removedCount := len(diff.RemovedFields)

	s.logger.Info("Managed resource drift detected (will be corrected by convergence)",
		"resource", resourceName,
		"module", moduleName,
		"changed_fields", changedCount,
		"added_fields", addedCount,
		"removed_fields", removedCount,
		"summary", diff.GetDriftSummary())

	rec := driftdiff.BuildRecord(diff, s.configRevision)
	if rec == nil {
		// No resource identifier on the diff: the record could not be addressed to an
		// entity-graph EID, so buffering it would only waste the bounded buffer.
		s.logger.Warn("Managed resource drift carried no resource identifier; drift-diff record not produced",
			"resource", logging.SanitizeLogValue(resourceName),
			"module", logging.SanitizeLogValue(moduleName))
		return
	}
	s.driftDiffs.Append(rec)
}

// drainDriftDiffs empties the drift-diff accumulator and reports each record.
//
// Standalone mode has no controller to sync to, so this is where the accumulated
// records terminate: each is reported to the local log with its full compared field
// counts, and the buffer returns to empty every convergence pass. Records dropped
// because the buffer filled between drains are reported as a count, never silently.
func (s *Steward) drainDriftDiffs() {
	records, dropped := s.driftDiffs.Drain()
	if dropped > 0 {
		s.logger.Warn("Drift-diff records were dropped: accumulator reached capacity between drains",
			"dropped", dropped,
			"capacity", s.driftDiffs.Capacity())
	}
	for _, rec := range records {
		matching := 0
		for _, f := range rec.Fields {
			if f.Matching {
				matching++
			}
		}
		s.logger.Info("Managed resource drift-diff record",
			"fragment_id", logging.SanitizeLogValue(rec.FragmentID),
			"config_revision", logging.SanitizeLogValue(rec.ConfigRevision),
			"detected_at", rec.DetectedAt.Format(time.RFC3339),
			"total_fields", len(rec.Fields),
			"matching_fields", matching)
	}
}

// convergenceLoop runs scheduled convergence at the given interval until the
// context is cancelled or shutdown is signalled.
func (s *Steward) convergenceLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.shutdown:
			return
		case <-ticker.C:
			s.logger.Info("Scheduled convergence triggered", "interval", interval)
			s.runConvergence(ctx)
		}
	}
}

// startMonitors delegates to the executor's monitor engine, registering a
// standalone-mode reconcile observer that refreshes DNA snapshots and increments
// monitorDNARefreshes when a targeted reconcile applies changes.
func (s *Steward) startMonitors(ctx context.Context) {
	// Register the standalone-specific post-reconcile observer before starting
	// the engine so the first reconcile already has it wired.
	s.executor.SetMonitorReconcileObserver(func(rCtx context.Context, resourceID string) {
		s.monitorDNARefreshes.Add(1)
		if _, err := s.detectUnmanagedDNADrift(rCtx); err != nil {
			s.logger.Warn("DNA refresh after targeted reconcile returned error",
				"resource_id", logging.SanitizeLogValue(resourceID),
				"error", err)
		}
	})
	if err := s.executor.StartMonitors(ctx, s.standaloneConfig.Resources); err != nil {
		s.logger.Warn("Failed to start module monitors", "error", err)
	}
}

// CollectModuleDNAAttributes delegates to the executor's monitor engine.
// See execution.Executor.CollectModuleDNAAttributes for the key convention.
func (s *Steward) CollectModuleDNAAttributes(ctx context.Context) map[string]string {
	return s.executor.CollectModuleDNAAttributes(ctx)
}

// CollectModuleFragments delegates to the executor's monitor engine.
// See execution.Executor.CollectModuleFragments for the fragment convention.
func (s *Steward) CollectModuleFragments(ctx context.Context) []*commonpb.Fragment {
	return s.executor.CollectModuleFragments(ctx)
}

// Stop gracefully shuts down the steward and cleans up resources.
//
// This method:
//  1. Signals shutdown to all background goroutines
//  2. Stops health monitoring
//  3. Closes drift detector and secret store
//  4. Unloads all modules
//
// The context can be used to set a timeout for shutdown operations.
// Returns an error only if cleanup operations fail.
func (s *Steward) Stop(ctx context.Context) error {
	s.logger.Info("Stopping steward", "id", s.standaloneConfig.Steward.ID)

	// Signal shutdown to all background goroutines.
	select {
	case <-s.shutdown:
		// Already closed
	default:
		close(s.shutdown)
	}

	// Cancel the health monitor's context so its goroutine exits via ctx.Done()
	// even if Stop() races with HealthMonitor.Start() before running is set.
	if s.healthCancel != nil {
		s.healthCancel()
	}

	// Stop health monitoring (blocks until goroutine exits).
	s.healthCheck.Stop()

	// Wait for the convergence loop goroutine to exit.
	s.wg.Wait()

	// Stop the monitor engine: waits for all fan-in + event-loop goroutines to
	// exit, then closes all monitor instances. Must happen before UnloadAllModules
	// so no further ChangeEvents are produced after module Close().
	s.executor.StopMonitors()

	// Close drift detector
	if s.driftDetector != nil {
		if err := s.driftDetector.Close(); err != nil {
			s.logger.Warn("Failed to close drift detector", "error", err)
		}
	}

	// Close secret store if initialized
	if s.secretStore != nil {
		if err := s.secretStore.Close(); err != nil {
			s.logger.Warn("Failed to close secret store", "error", err)
		}
	}

	// Unload modules
	if s.moduleFactory != nil {
		s.moduleFactory.UnloadAllModules()
	}

	s.logger.Info("Steward stopped successfully")
	return nil
}

// ExecuteConfiguration manually executes the current configuration.
//
// This method allows manual triggering of configuration execution outside of
// the automatic startup execution and scheduled convergence loop.
//
// Returns a detailed execution report including resource results, timing,
// and any errors encountered during execution.
func (s *Steward) ExecuteConfiguration(ctx context.Context) (execution.ExecutionReport, error) {
	report := s.executor.ExecuteConfiguration(ctx, s.standaloneConfig)
	return report, nil
}

// GetModuleRegistry returns the discovered module registry.
//
// The registry contains information about all modules discovered during
// steward initialization, including their paths, versions, and capabilities.
func (s *Steward) GetModuleRegistry() discovery.ModuleRegistry {
	return s.moduleRegistry
}

// GetLoadedModules returns a list of currently loaded module names.
//
// This includes only modules that have been successfully instantiated by the
// module factory, not all discovered modules. Modules are loaded on-demand
// when needed for resource execution.
//
// Returns an empty slice if no modules have been loaded yet.
func (s *Steward) GetLoadedModules() []string {
	if s.moduleFactory == nil {
		return []string{}
	}
	return s.moduleFactory.GetLoadedModules()
}

// GetStewardID returns the steward ID from configuration.
func (s *Steward) GetStewardID() string {
	return s.standaloneConfig.Steward.ID
}

// GetConvergeInterval returns the convergence interval string from configuration.
// Useful for CLI status output and operator observability.
func (s *Steward) GetConvergeInterval() string {
	return s.standaloneConfig.Steward.ConvergeInterval
}
