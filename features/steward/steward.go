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
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/script"
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/features/steward/dna/drift"
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

// monitorQueueCapacity is the maximum number of ChangeEvents the fan-in channel
// can buffer. When full, events are shed to the next scheduled convergence pass.
const monitorQueueCapacity = 64

// monitorEntry pairs a module's Monitor with its resource configuration.
// Used to fan-in ChangeEvents and dispatch targeted reconciles.
type monitorEntry struct {
	resourceID string
	resource   config.ResourceConfig
	monitor    modules.Monitor
}

// bundleNameFromModuleRef extracts the module bundle name from a module reference.
// "hyperv.vm" → "hyperv"; "file" → "file".
func bundleNameFromModuleRef(moduleRef string) string {
	if idx := strings.IndexByte(moduleRef, '.'); idx >= 0 {
		return moduleRef[:idx]
	}
	return moduleRef
}

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

	// Secret store for steward-side secret management
	secretStore secretsif.SecretStore

	// monitors holds active monitor entries started on cfg load.
	// Each entry has had Monitor(ctx, resourceID, desired) called on it.
	monitors []monitorEntry

	// debounceWindow is the per-resource debounce interval for monitor events.
	// Events for the same resourceID within this window are coalesced into one
	// targeted reconcile. Defaults to 1500ms; override via export_test.go in tests.
	debounceWindow time.Duration

	// monitorFanInCap overrides the fan-in channel capacity when non-zero.
	// Tests set a small value (e.g. 2) to guarantee queue overflow without
	// relying on scheduler timing. Production code always uses monitorQueueCapacity.
	monitorFanInCap int

	// wg tracks the convergence loop goroutine and the health monitor goroutine
	// for clean shutdown.
	wg sync.WaitGroup
	// monitorWg tracks fan-in and event-loop goroutines started by startMonitors.
	monitorWg sync.WaitGroup

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

	return &Steward{
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
		debounceWindow:   1500 * time.Millisecond,
		shutdown:         make(chan struct{}),
	}, nil
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

	// Register managed resource drift handler on the execution engine.
	// When the Compare step detects drift, this logs the event before Set corrects it.
	s.executor.SetDriftEventHandler(s.onManagedResourceDrift)

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
// before Set corrects it. This gives visibility into what was out of compliance.
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

// startMonitors iterates the cfg resources, loads each module from the factory,
// type-asserts modules.Monitor, and calls Monitor(ctx, resourceID, desired) for
// each module that implements the interface. A fan-in goroutine forwards all
// ChangeEvents to a single dispatch loop that calls runTargetedReconcile.
//
// Modules that do not implement Monitor are silently skipped — they fall back
// to the scheduled convergence interval. This is always the case today; the
// first Monitor implementation (Hyper-V) lands in S2.
func (s *Steward) startMonitors(ctx context.Context) {
	var entries []monitorEntry

	for _, resource := range s.standaloneConfig.Resources {
		bundle := bundleNameFromModuleRef(resource.Module)

		mod, err := s.moduleFactory.LoadModule(bundle)
		if err != nil || mod == nil {
			continue
		}

		mon, ok := mod.(modules.Monitor)
		if !ok {
			continue
		}

		resourceID := s.executor.GetResourceID(resource)
		desired := execution.NewConfigState(resource.Config)

		if err := mon.Monitor(ctx, resourceID, desired); err != nil {
			s.logger.Warn("Failed to start module monitor",
				"resource", resource.Name,
				"resource_id", logging.SanitizeLogValue(resourceID),
				"error", err)
			continue
		}

		entries = append(entries, monitorEntry{
			resourceID: resourceID,
			resource:   resource,
			monitor:    mon,
		})
	}

	if len(entries) == 0 {
		return
	}

	s.monitors = entries

	// Fan-in: one forwarding goroutine per monitor channel; all send to fanIn.
	// fanIn is bounded at monitorQueueCapacity; excess events are shed to the
	// next scheduled convergence pass (non-blocking drop with Warn log).
	fanInCap := monitorQueueCapacity
	if s.monitorFanInCap > 0 {
		fanInCap = s.monitorFanInCap
	}
	fanIn := make(chan modules.ChangeEvent, fanInCap)
	for _, entry := range entries {
		ch := entry.monitor.Changes()
		s.monitorWg.Add(1)
		go func(ch <-chan modules.ChangeEvent) {
			defer s.monitorWg.Done()
			for {
				select {
				case evt, ok := <-ch:
					if !ok {
						return
					}
					// Non-blocking send: if the queue is full, shed this event to
					// the next scheduled convergence pass and log at Warn.
					select {
					case fanIn <- evt:
					default:
						s.logger.Warn("Monitor event queue full, event shed to scheduled poll",
							"resource_id", logging.SanitizeLogValue(evt.ResourceID))
					}
				case <-ctx.Done():
					return
				case <-s.shutdown:
					return
				}
			}
		}(ch)
	}

	s.monitorWg.Add(1)
	go func() {
		defer s.monitorWg.Done()
		s.monitorEventLoop(ctx, fanIn)
	}()
}

// monitorEventLoop reads ChangeEvents from the fan-in channel and dispatches
// debounced targeted reconciles. Multiple events for the same resourceID within
// the debounce window are coalesced into a single runTargetedReconcile call.
// Exits when the context is cancelled or the shutdown channel is closed.
func (s *Steward) monitorEventLoop(ctx context.Context, events <-chan modules.ChangeEvent) {
	// fireCh receives debounced resourceIDs after their timer window elapses.
	// Buffered to avoid blocking the timer goroutines under load.
	fireCh := make(chan string, 16)
	// debounce maps resourceID → pending AfterFunc timer.
	debounce := make(map[string]*time.Timer)
	// afterFuncWg tracks in-flight AfterFunc goroutines so monitorEventLoop
	// does not return (and monitorWg.Done() is not called) until every timer
	// callback has exited. Without this, a timer that fires concurrently with
	// Stop() outlives monitorWg.Wait() and is caught by goleak as a leak.
	var afterFuncWg sync.WaitGroup

	defer func() {
		// Stop pending timers. t.Stop() returns true only if the timer has not
		// yet fired — in that case the goroutine will never run, so we call
		// Done() ourselves to balance the Add(1) from below. If t.Stop()
		// returns false the goroutine is already running; it will call Done().
		for _, t := range debounce {
			if t.Stop() {
				afterFuncWg.Done()
			}
		}
		// Wait for any in-flight AfterFunc goroutines to exit. They observe
		// s.shutdown (already closed) via their select and return promptly.
		afterFuncWg.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.shutdown:
			return
		case evt, ok := <-events:
			if !ok {
				return
			}
			s.logger.Info("Monitor change event received",
				"resource_id", logging.SanitizeLogValue(evt.ResourceID),
				"change_type", evt.ChangeType)
			resourceID := evt.ResourceID
			if _, exists := debounce[resourceID]; !exists {
				// First event for this resourceID in the window — start the timer.
				afterFuncWg.Add(1)
				debounce[resourceID] = time.AfterFunc(s.debounceWindow, func() {
					defer afterFuncWg.Done()
					select {
					case fireCh <- resourceID:
					case <-ctx.Done():
					case <-s.shutdown:
					}
				})
			}
			// Duplicate events within the window are coalesced — the existing
			// timer will fire once after the debounce window elapses.
		case resourceID := <-fireCh:
			delete(debounce, resourceID)
			s.runTargetedReconcile(ctx, resourceID)
		}
	}
}

// runTargetedReconcile finds the ResourceConfig whose module-internal ID matches
// resourceID and calls ExecuteResource for it. The ChangeEvent that triggered
// this call is treated as a hint only — current state is read via module.Get()
// and desired state comes from the cfg ResourceConfig, never from the event.
//
// If resourceID is not present in cfg (unmanaged resource), the call is a no-op.
// Both ctx.Done() and s.shutdown are checked before the reconcile so a shutdown
// mid-dispatch exits cleanly without calling Set after Close().
//
// When the reconcile changes state (ChangesApplied), a fresh DNA snapshot is
// collected so the next heartbeat reflects the corrected state before the
// scheduled convergence tick fires.
func (s *Steward) runTargetedReconcile(ctx context.Context, resourceID string) {
	select {
	case <-ctx.Done():
		return
	case <-s.shutdown:
		return
	default:
	}

	for _, resource := range s.standaloneConfig.Resources {
		if s.executor.GetResourceID(resource) == resourceID {
			s.logger.Info("Running targeted reconcile for monitored resource",
				"resource", resource.Name,
				"resource_id", logging.SanitizeLogValue(resourceID))
			result := s.executor.ExecuteResource(ctx, resource)
			if result.ChangesApplied {
				s.logger.Info("Targeted reconcile changed state, refreshing DNA snapshot",
					"resource", resource.Name,
					"resource_id", logging.SanitizeLogValue(resourceID))
				if _, err := s.detectUnmanagedDNADrift(ctx); err != nil {
					s.logger.Warn("DNA refresh after targeted reconcile returned error",
						"resource", resource.Name,
						"error", err)
				}
			}
			return
		}
	}

	s.logger.Info("Monitor event for unmanaged resource (not in cfg, skipping)",
		"resource_id", logging.SanitizeLogValue(resourceID))
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

	// Wait for all monitor goroutines (fan-in + event loop) to exit.
	// This guarantees no further ExecuteResource calls after Close() is called
	// on the monitors below.
	s.monitorWg.Wait()

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

	// Close all active monitors before unloading modules.
	// Closing the monitor releases any OS-level watchers and signals to the
	// module that no further ChangeEvents will be produced.
	for _, entry := range s.monitors {
		if err := entry.monitor.Close(); err != nil {
			s.logger.Warn("Failed to close monitor",
				"resource_id", logging.SanitizeLogValue(entry.resourceID),
				"error", err)
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
