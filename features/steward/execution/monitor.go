// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package execution

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/steward/config"
	sdna "github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/pkg/logging"
)

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

// monitorFields holds the monitor-engine state added to Executor (Issue #2435).
// Separated into a struct purely for readability; Executor embeds these fields inline.
type monitorFields struct {
	// monitorMu guards monitorEntries and monitorStop so StartMonitors and
	// StopMonitors can coordinate without holding the executor's main RWMutex.
	monitorMu      sync.Mutex
	monitorEntries []monitorEntry
	monitorStop    chan struct{} // closed by StopMonitors; recreated by StartMonitors
	monitorWg      sync.WaitGroup

	// monitorStateMu guards monitorState.
	monitorStateMu sync.Mutex
	monitorState   map[string]map[string]interface{}

	// monitorDebounceWindow is the per-resource debounce interval (default 1500ms).
	// Overridden by SetMonitorDebounceWindow for tests.
	monitorDebounceWindow time.Duration

	// monitorFanInCap overrides the fan-in channel capacity when non-zero.
	// Tests set a small value to guarantee queue overflow without relying on timing.
	monitorFanInCap int

	// monitorReconcileObserver is called after a targeted reconcile applies changes.
	// Standalone mode wires in DNA refresh + counter increment; controller mode leaves nil.
	monitorReconcileObserver func(ctx context.Context, resourceID string)
}

// SetMonitorReconcileObserver registers a callback invoked by the monitor engine
// after a targeted reconcile applies changes (ChangesApplied is true). Standalone
// mode wires this to detectUnmanagedDNADrift + counter increment; controller mode
// leaves it nil. Pass nil to clear the observer.
func (e *Executor) SetMonitorReconcileObserver(fn func(ctx context.Context, resourceID string)) {
	e.monitorMu.Lock()
	e.monitorReconcileObserver = fn
	e.monitorMu.Unlock()
}

// SetMonitorDebounceWindow overrides the debounce window for tests.
// Call before StartMonitors; has no effect on a running engine.
func (e *Executor) SetMonitorDebounceWindow(d time.Duration) {
	e.monitorMu.Lock()
	e.monitorDebounceWindow = d
	e.monitorMu.Unlock()
}

// SetMonitorFanInCap overrides the fan-in channel capacity for tests.
// Call before StartMonitors; has no effect on a running engine.
func (e *Executor) SetMonitorFanInCap(cap int) {
	e.monitorMu.Lock()
	e.monitorFanInCap = cap
	e.monitorMu.Unlock()
}

// StartMonitors iterates the provided resources, loads each module from the
// factory, type-asserts modules.Monitor, and calls Monitor(ctx, resourceID,
// desired) for each module that implements the interface. A fan-in goroutine
// forwards all ChangeEvents to a single dispatch loop that calls
// runTargetedReconcile on the affected resource.
//
// Any previously-running monitor engine is stopped (all goroutines and module
// instances closed) before the new one starts — a full stop+restart, no
// incremental diffing. This is safe because factory.ModuleFactory caches
// instances: calling Monitor() on an already-monitoring instance without an
// intervening Close() is undefined/leaky.
//
// Modules that do not implement Monitor are silently skipped — they fall back
// to the scheduled convergence interval.
func (e *Executor) StartMonitors(ctx context.Context, resources []config.ResourceConfig) error {
	// Stop any previously-running engine first. Full stop+restart — no diff.
	e.stopMonitorEngine()

	var entries []monitorEntry

	for _, resource := range resources {
		bundle := bundleNameFromModuleRef(resource.Module)

		mod, err := e.factory.LoadModule(bundle)
		if err != nil || mod == nil {
			continue
		}

		mon, ok := mod.(modules.Monitor)
		if !ok {
			continue
		}

		resourceID := e.GetResourceID(resource)
		desired := NewConfigState(resource.Config)

		if err := mon.Monitor(ctx, resourceID, desired); err != nil {
			e.logger.Warn("Failed to start module monitor",
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
		return nil
	}

	e.monitorMu.Lock()
	e.monitorEntries = entries
	stopCh := make(chan struct{})
	e.monitorStop = stopCh
	debounce := e.monitorDebounceWindow
	fanInCap := e.monitorFanInCap
	e.monitorMu.Unlock()

	if debounce <= 0 {
		debounce = 1500 * time.Millisecond
	}

	// Fan-in: one forwarding goroutine per monitor; all send to fanIn.
	// fanIn is bounded; excess events are shed to the next scheduled convergence
	// pass (non-blocking drop with Warn log).
	cap := monitorQueueCapacity
	if fanInCap > 0 {
		cap = fanInCap
	}
	fanIn := make(chan modules.ChangeEvent, cap)

	for _, entry := range entries {
		ch := entry.monitor.Changes()
		e.monitorWg.Add(1)
		go func(ch <-chan modules.ChangeEvent) {
			defer e.monitorWg.Done()
			// seen tracks every resourceID this goroutine cached state for,
			// so all of them are evicted when monitoring stops.
			seen := make(map[string]struct{})
			defer func() { e.evictMonitorState(seen) }()
			for {
				select {
				case evt, ok := <-ch:
					if !ok {
						return
					}
					// Cache the latest observed state BEFORE the non-blocking
					// send, so even a shed event still refreshes the module
					// DNA snapshot (Issue #2423).
					if e.cacheMonitorState(evt) {
						seen[evt.ResourceID] = struct{}{}
					}
					// Non-blocking send: if the queue is full, shed this event.
					select {
					case fanIn <- evt:
					default:
						e.logger.Warn("Monitor event queue full, event shed to scheduled poll",
							"resource_id", logging.SanitizeLogValue(evt.ResourceID))
					}
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				}
			}
		}(ch)
	}

	e.monitorWg.Add(1)
	go func() {
		defer e.monitorWg.Done()
		e.monitorEventLoop(ctx, fanIn, stopCh, debounce)
	}()

	return nil
}

// StopMonitors stops the running monitor engine: closes all goroutines, waits
// for them to exit, closes all monitor instances, and clears state. Idempotent
// — safe to call when no engine is running.
func (e *Executor) StopMonitors() {
	e.stopMonitorEngine()
}

// stopMonitorEngine is the internal implementation shared by StartMonitors
// (before re-starting) and StopMonitors (public teardown).
func (e *Executor) stopMonitorEngine() {
	e.monitorMu.Lock()
	stopCh := e.monitorStop
	entries := e.monitorEntries
	e.monitorStop = nil
	e.monitorEntries = nil
	e.monitorMu.Unlock()

	if stopCh != nil {
		close(stopCh)
	}

	// Wait for all fan-in and event-loop goroutines to exit before closing
	// monitor instances — no further ChangeEvents will be produced after Close().
	e.monitorWg.Wait()

	// Close all monitor instances (releases OS-level watchers).
	for _, entry := range entries {
		if err := entry.monitor.Close(); err != nil {
			e.logger.Warn("Failed to close monitor",
				"resource_id", logging.SanitizeLogValue(entry.resourceID),
				"error", err)
		}
	}

	// Clear cached state so CollectModuleDNAAttributes returns empty after stop.
	e.monitorStateMu.Lock()
	e.monitorState = nil
	e.monitorStateMu.Unlock()
}

// monitorEventLoop reads ChangeEvents from the fan-in channel and dispatches
// debounced targeted reconciles. Multiple events for the same resourceID within
// the debounce window are coalesced into a single runTargetedReconcile call.
// Exits when ctx is cancelled or stopCh is closed.
func (e *Executor) monitorEventLoop(ctx context.Context, events <-chan modules.ChangeEvent, stopCh <-chan struct{}, debounce time.Duration) {
	// fireCh receives debounced resourceIDs after their timer window elapses.
	fireCh := make(chan string, 16)
	pending := make(map[string]*time.Timer)
	// afterFuncWg tracks in-flight AfterFunc goroutines so monitorEventLoop
	// does not return until every timer callback has exited (goroutine-leak guard).
	var afterFuncWg sync.WaitGroup

	defer func() {
		// Stop pending timers; if t.Stop() returns true the goroutine never ran,
		// so call Done() ourselves to balance the Add(1).
		for _, t := range pending {
			if t.Stop() {
				afterFuncWg.Done()
			}
		}
		afterFuncWg.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-stopCh:
			return
		case evt, ok := <-events:
			if !ok {
				return
			}
			e.logger.Info("Monitor change event received",
				"resource_id", logging.SanitizeLogValue(evt.ResourceID),
				"change_type", fmt.Sprintf("%d", evt.ChangeType))
			resourceID := evt.ResourceID
			if _, exists := pending[resourceID]; !exists {
				afterFuncWg.Add(1)
				pending[resourceID] = time.AfterFunc(debounce, func() {
					defer afterFuncWg.Done()
					select {
					case fireCh <- resourceID:
					case <-ctx.Done():
					case <-stopCh:
					}
				})
			}
			// Duplicate events within the window are coalesced — the existing
			// timer fires once after the debounce window elapses.
		case resourceID := <-fireCh:
			delete(pending, resourceID)
			e.runTargetedReconcile(ctx, stopCh, resourceID)
		}
	}
}

// cacheMonitorState stores the latest ChangeEvent Details snapshot for a
// resourceID (Issue #2423). Returns true when a snapshot was cached.
// Nil Details or an empty ResourceID cache nothing.
func (e *Executor) cacheMonitorState(evt modules.ChangeEvent) bool {
	if evt.ResourceID == "" || evt.Details == nil {
		return false
	}
	snap := evt.Details.AsMap()
	if snap == nil {
		return false
	}
	// Shallow-copy so a module mutating the map it returned cannot race the flattener.
	copied := make(map[string]interface{}, len(snap))
	for k, v := range snap {
		copied[k] = v
	}
	e.monitorStateMu.Lock()
	if e.monitorState == nil {
		e.monitorState = make(map[string]map[string]interface{})
	}
	e.monitorState[evt.ResourceID] = copied
	e.monitorStateMu.Unlock()
	return true
}

// evictMonitorState removes the given resourceIDs from the module-DNA cache.
// Called when a fan-in goroutine exits so a resource that leaves monitoring
// disappears from CollectModuleDNAAttributes — the missing key becomes the
// "this is gone" signal on the next PublishDNAUpdate delta.
func (e *Executor) evictMonitorState(resourceIDs map[string]struct{}) {
	if len(resourceIDs) == 0 {
		return
	}
	e.monitorStateMu.Lock()
	for id := range resourceIDs {
		delete(e.monitorState, id)
	}
	e.monitorStateMu.Unlock()
}

// ModuleDNASnapshot is a process-stable store of each managed resource's last
// observed state (AsMap), keyed by resourceID. It is shared across Executor
// instances so module DNA survives executor re-initialization on reconnect
// (#2520): InitializeConfigExecutor replaces the Executor on every connect, and a
// per-Executor snapshot would be lost each time — the client owns ONE snapshot and
// passes it into every Executor it builds. Safe for concurrent use.
type ModuleDNASnapshot struct {
	mu   sync.Mutex
	snap map[string]map[string]interface{}
}

// NewModuleDNASnapshot returns an empty shared module-DNA store.
func NewModuleDNASnapshot() *ModuleDNASnapshot {
	return &ModuleDNASnapshot{snap: make(map[string]map[string]interface{})}
}

func (s *ModuleDNASnapshot) set(resourceID string, attrs map[string]interface{}) {
	s.mu.Lock()
	s.snap[resourceID] = attrs
	s.mu.Unlock()
}

func (s *ModuleDNASnapshot) prune(keep map[string]struct{}) {
	s.mu.Lock()
	for id := range s.snap {
		if _, ok := keep[id]; !ok {
			delete(s.snap, id)
		}
	}
	s.mu.Unlock()
}

// collect flattens every stored resource's fields into out under the DNA key
// convention "<resourceID>.<field>".
func (s *ModuleDNASnapshot) collect(out map[string]string) {
	s.mu.Lock()
	for resourceID, fields := range s.snap {
		for field, v := range fields {
			flattenDNAValue(resourceID+"."+field, v, out)
		}
	}
	s.mu.Unlock()
}

// cacheModuleDNAState records a managed resource's observed state (AsMap) into the
// shared module-DNA snapshot, keyed by resourceID. Called after each successful
// convergence / targeted-reconcile Get (executor.ExecuteResource) so a STABLE
// resource still contributes module DNA between change-events — the steady-state
// source for #2520 mechanism 1. No extra module call: it reuses the Get the
// Get→Compare→Set→Verify cycle already performs.
func (e *Executor) cacheModuleDNAState(resourceID string, state modules.ConfigState) {
	if resourceID == "" || state == nil || e.moduleDNA == nil {
		return
	}
	snap := state.AsMap()
	if snap == nil {
		return
	}
	// Shallow-copy so a module mutating the map it returned cannot race the reader.
	copied := make(map[string]interface{}, len(snap))
	for k, v := range snap {
		copied[k] = v
	}
	e.moduleDNA.set(resourceID, copied)
}

// pruneModuleDNAState drops shared-snapshot entries whose resourceID is not in
// keep, so a resource removed from the config disappears from module DNA on the
// next full convergence pass (ExecuteConfiguration). Targeted single-resource
// reconciles never call this — only the full pass knows the complete resource set.
func (e *Executor) pruneModuleDNAState(keep map[string]struct{}) {
	if e.moduleDNA == nil {
		return
	}
	e.moduleDNA.prune(keep)
}

// CollectModuleDNAAttributes returns a flattened, namespaced snapshot of every
// managed module resource's latest observed state (Issue #2423, #2520).
//
// Two sources are unioned:
//   - the shared moduleDNA snapshot: the convergence/targeted-reconcile Get result
//     for every managed resource — the STEADY-STATE source, present even when
//     nothing has changed and surviving executor re-init on reconnect.
//   - monitorState: the monitor change-event cache — a fresher per-change overlay
//     (e.g. cluster status carried on the event before the triggered reconcile's
//     Get lands). On key collision the monitor value wins as the more recent.
//
// Key convention:
//   - every key is "<resourceID>.<field>" with the resourceID verbatim
//   - nested map keys join with "." → "cluster:cfg-lab.resource_owner.web-01"
//   - slice values join with ","   → "CFG-70-02,CFG-AB-02"
//   - any other value stringifies via fmt.Sprintf("%v", v)
func (e *Executor) CollectModuleDNAAttributes(_ context.Context) map[string]string {
	out := make(map[string]string)
	// Steady-state snapshot first (covers all managed resources)...
	if e.moduleDNA != nil {
		e.moduleDNA.collect(out)
	}
	// ...then overlay fresher monitor change-event deltas.
	e.monitorStateMu.Lock()
	for resourceID, snap := range e.monitorState {
		for field, v := range snap {
			flattenDNAValue(resourceID+"."+field, v, out)
		}
	}
	e.monitorStateMu.Unlock()
	return out
}

// RunTargetedReconcile is the exported entry point for targeted reconcile
// dispatch, called by tests that need to exercise the reconcile path directly
// without going through the async event loop (e.g. to test the "unmanaged
// resource" early-exit without starting monitors). A never-closed stop channel
// is used so the function never exits early via the shutdown path.
func (e *Executor) RunTargetedReconcile(ctx context.Context, resourceID string) {
	neverStop := make(chan struct{})
	e.runTargetedReconcile(ctx, neverStop, resourceID)
}

// runTargetedReconcile finds the monitorEntry whose resourceID matches and calls
// ExecuteResource for it. The ChangeEvent that triggered this call is a hint only
// — current state is read via module.Get() and desired state comes from the
// retained monitorEntry's ResourceConfig, never from the event.
//
// If resourceID is not in the retained entries (unmanaged resource), the call is
// a no-op. Both ctx.Done() and stopCh are checked before the reconcile so a
// shutdown mid-dispatch exits cleanly without calling Set after Close().
//
// An optional monitorReconcileObserver is called when ChangesApplied is true;
// standalone mode registers DNA refresh logic there (Issue #2435).
func (e *Executor) runTargetedReconcile(ctx context.Context, stopCh <-chan struct{}, resourceID string) {
	select {
	case <-ctx.Done():
		return
	case <-stopCh:
		return
	default:
	}

	// Resolve resourceID → resource from the retained monitorEntry slice.
	e.monitorMu.Lock()
	entries := e.monitorEntries
	observer := e.monitorReconcileObserver
	e.monitorMu.Unlock()

	for _, entry := range entries {
		if entry.resourceID == resourceID {
			e.logger.Info("Running targeted reconcile for monitored resource",
				"resource", entry.resource.Name,
				"resource_id", logging.SanitizeLogValue(resourceID))
			result := e.ExecuteResource(ctx, entry.resource)
			if result.ChangesApplied && observer != nil {
				observer(ctx, resourceID)
			}
			return
		}
	}

	e.logger.Info("Monitor event for unmanaged resource (not in cfg, skipping)",
		"resource_id", logging.SanitizeLogValue(resourceID))
}

// CollectModuleFragments returns ADR-017 fragments for cluster:* resourceIDs
// observed in the monitor change-event cache (Issue #2908).
//
// Only cluster:* resourceIDs are emitted as fragments; all other resourceIDs
// continue to publish via the flat CollectModuleDNAAttributes path.
// The authority for each fragment is resolved from the active monitorEntries by
// resourceID; entries that left monitoring between the event and this call
// receive an empty authority (negligible: the fragment is still well-formed).
//
// Fragment construction goes through sdna.NewFragment so canonical bytes and
// fragment hash are produced by the same code path the controller-side registry
// parses (FragmentId is the resourceID verbatim, e.g. "cluster:cfg-lab";
// Authority is the module bundle name, e.g. "hyperv").
func (e *Executor) CollectModuleFragments(_ context.Context) []*commonpb.Fragment {
	const clusterPrefix = "cluster:"

	// Resolve resourceID → authority from current monitor entries (best-effort).
	e.monitorMu.Lock()
	authority := make(map[string]string, len(e.monitorEntries))
	for _, entry := range e.monitorEntries {
		authority[entry.resourceID] = bundleNameFromModuleRef(entry.resource.Module)
	}
	e.monitorMu.Unlock()

	e.monitorStateMu.Lock()
	defer e.monitorStateMu.Unlock()

	var frags []*commonpb.Fragment
	for resourceID, snap := range e.monitorState {
		if !strings.HasPrefix(resourceID, clusterPrefix) {
			continue
		}
		frag, err := sdna.NewFragment(resourceID, authority[resourceID], sdna.MapState(snap))
		if err != nil {
			e.logger.Warn("CollectModuleFragments: canonicalize failed",
				"resource_id", logging.SanitizeLogValue(resourceID), "error", err)
			continue
		}
		frags = append(frags, frag)
	}
	return frags
}

// flattenDNAValue flattens one value into out under key, per the convention
// documented on CollectModuleDNAAttributes. Handles the ConfigState.AsMap
// shapes that occur in practice and falls back to fmt.Sprintf("%v") for
// anything else — never panics on an unexpected type.
func flattenDNAValue(key string, v interface{}, out map[string]string) {
	switch val := v.(type) {
	case map[string]interface{}:
		for k, sub := range val {
			flattenDNAValue(key+"."+k, sub, out)
		}
	case map[string]string:
		for k, sub := range val {
			out[key+"."+k] = sub
		}
	case []string:
		out[key] = strings.Join(val, ",")
	case []interface{}:
		parts := make([]string, 0, len(val))
		for _, elem := range val {
			parts = append(parts, fmt.Sprintf("%v", elem))
		}
		out[key] = strings.Join(parts, ",")
	case string:
		out[key] = val
	default:
		out[key] = fmt.Sprintf("%v", val)
	}
}
