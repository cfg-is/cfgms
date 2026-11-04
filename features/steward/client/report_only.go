// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"google.golang.org/grpc"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/steward/modules/install"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// Report-only link.
//
// A report-only client tells the controller about a security refusal without
// enforcing anything. It connects with the stored mTLS identity, sends
// heartbeats (status "error" plus the reasons), DNA inventory and logs out, and
// acts on nothing the controller sends. The receive switch accepts exactly two
// fixed-shape signals (TamperState, RepairRequest) and, when a locked-trust
// handler is installed, operator commands; every other inbound payload is
// dropped and counted.
//
// Trust anchor: the link trusts the controller only through the anchor the
// caller supplies as CACertPEM: the install-pinned CA, or the CA pin recorded in
// the identity. Both are data-folder material, so neither ranks above the
// other. The baked publisher fingerprint plays no part in connecting or
// reporting, so a controller root rotation never strands a locked host; it
// gates only operator actions and the repair signature check, which belong to
// the locked-command and repair handlers.
//
// Residual, stated plainly: an attacker who can impersonate the controller to
// this steward must have rewritten the anchor in the data folder, and so could
// already delete local logs directly. The repair handler checks the request's
// signature chain against the baked list and refuses a CA-class repair that
// does not verify to a baked fingerprint.

// ErrReportOnly is returned by operations a report-only client refuses.
var ErrReportOnly = errors.New("report-only link: operation not permitted")

// Health reason component and codes recorded when a client enters report-only.
const (
	// ReportOnlyReasonComponent is the health-reason component of the link.
	ReportOnlyReasonComponent = "report_only"

	// ReasonControllerLockedDown is recorded when a pull returned the typed
	// lockdown refusal.
	ReasonControllerLockedDown = controlplaneInterfaces.LockedDownReason

	// ReasonTamperLocked is recorded when the controller sent TamperState{locked}.
	ReasonTamperLocked = "tamper.locked"
)

// Names of the components a report-only link may start.
const (
	ReportOnlyComponentHeartbeat    = "heartbeat"
	ReportOnlyComponentDNAInventory = "dna_inventory"
	ReportOnlyComponentEventEmitter = "event_emitter"
)

// LockedCommandHandler receives a command on a report-only link once a
// locked-trust handler is installed. peerChain returns the certificate chain of
// the session the command arrived on, for the handler's own signer checks.
type LockedCommandHandler func(ctx context.Context, cmd *cpTypes.SignedCommand, peerChain controlplaneInterfaces.PeerChain) error

// hostFactsOnlyCollector is implemented by a DNACollector that can narrow
// itself to host facts: no module DNA source, no osquery source, nothing loaded
// from the module cache.
type hostFactsOnlyCollector interface {
	HostFactsOnly() DNACollector
}

// hostFactsOnly narrows c to host facts when it knows how. A collector that
// does not implement hostFactsOnlyCollector is used as is: it is the caller's
// contract that a report-only collector reads host facts only.
func hostFactsOnly(c DNACollector) DNACollector {
	if h, ok := c.(hostFactsOnlyCollector); ok {
		return h.HostFactsOnly()
	}
	return c
}

// offlineQueueStorage returns the directory and secret store the offline queue
// persists with. A report-only link writes nothing to disk: its queue is in
// memory whatever the configuration says.
func offlineQueueStorage(cfg *TransportConfig) (string, secretsif.SecretStore) {
	if cfg.ReportOnly {
		return "", nil
	}
	return cfg.QueueDir, cfg.SecretStore
}

// applyReportOnlyConfig switches a freshly built client to report-only when the
// configuration asks for it, narrowing its DNA collector to host facts.
func (c *TransportClient) applyReportOnlyConfig(cfg *TransportConfig) {
	if !cfg.ReportOnly {
		return
	}
	c.reportOnly.Store(true)
	c.dnaCollector = hostFactsOnly(cfg.DNACollector)
}

// IsReportOnly reports whether the client is a report-only link.
func (c *TransportClient) IsReportOnly() bool { return c.reportOnly.Load() }

// SetTamperStateHandler installs the callback for TamperState signals that
// passed the signal rules (locked always; unlocked only on a session whose
// server certificate verified against the anchor). The callback decides what an
// unlock means; the link itself never releases anything.
func (c *TransportClient) SetTamperStateHandler(fn func(locked bool)) {
	c.reportOnlyMu.Lock()
	c.tamperHandler = fn
	c.reportOnlyMu.Unlock()
}

// SetRepairHandler installs the callback for RepairRequest signals received on a
// session that passed the anchor check. The handler verifies the signature.
func (c *TransportClient) SetRepairHandler(fn func(req cpTypes.RepairRequest)) {
	c.reportOnlyMu.Lock()
	c.repairHandler = fn
	c.reportOnlyMu.Unlock()
}

// SetLockedCommandHandler installs the locked-trust command handler. Without
// one a report-only link drops every command.
func (c *TransportClient) SetLockedCommandHandler(fn LockedCommandHandler) {
	c.reportOnlyMu.Lock()
	c.lockedCmdHandler = fn
	c.reportOnlyMu.Unlock()
}

// InboundDropped returns how many inbound payloads the receive switch dropped.
func (c *TransportClient) InboundDropped() int64 {
	c.reportOnlyMu.Lock()
	defer c.reportOnlyMu.Unlock()
	var total int64
	for _, n := range c.droppedInbound {
		total += n
	}
	return total
}

// InboundDroppedKind returns the drop count for one payload kind ("command",
// "event", "heartbeat", "response", "unknown", "tamper_state",
// "repair_request").
func (c *TransportClient) InboundDroppedKind(kind string) int64 {
	c.reportOnlyMu.Lock()
	defer c.reportOnlyMu.Unlock()
	return c.droppedInbound[kind]
}

// ReportOnlyComponents lists the components the report-only link started, sorted.
func (c *TransportClient) ReportOnlyComponents() []string {
	c.reportOnlyMu.Lock()
	defer c.reportOnlyMu.Unlock()
	out := append([]string(nil), c.reportOnlyParts...)
	sort.Strings(out)
	return out
}

func (c *TransportClient) noteReportOnlyComponent(name string) {
	c.reportOnlyMu.Lock()
	c.reportOnlyParts = append(c.reportOnlyParts, name)
	c.reportOnlyMu.Unlock()
}

func (c *TransportClient) countDropped(kind string) {
	c.reportOnlyMu.Lock()
	if c.droppedInbound == nil {
		c.droppedInbound = make(map[string]int64)
	}
	c.droppedInbound[kind]++
	c.reportOnlyMu.Unlock()
}

// installInboundHooks wires the narrow inbound callbacks into a control plane
// that supports them and tells it whether this client is report-only.
func (c *TransportClient) installInboundHooks(cp controlplaneInterfaces.ControlPlaneProvider) {
	ic, ok := cp.(controlplaneInterfaces.InboundController)
	if !ok {
		return
	}
	ic.SetInboundHooks(controlplaneInterfaces.InboundHooks{
		OnTamperState: c.onTamperState,
		OnRepair:      c.onRepair,
		OnCommand:     c.onLockedCommand,
		OnDropped:     c.countDropped,
	})
	ic.SetReportOnly(c.reportOnly.Load())
}

func (c *TransportClient) onTamperState(locked bool) {
	if locked {
		c.EnterReportOnly(ReasonTamperLocked, "controller reports this host locked")
	}
	c.reportOnlyMu.Lock()
	fn := c.tamperHandler
	c.reportOnlyMu.Unlock()
	if fn != nil {
		fn(locked)
	}
}

func (c *TransportClient) onRepair(req cpTypes.RepairRequest) {
	c.reportOnlyMu.Lock()
	fn := c.repairHandler
	c.reportOnlyMu.Unlock()
	if fn == nil {
		c.countDropped("repair_request")
		return
	}
	fn(req)
}

func (c *TransportClient) onLockedCommand(ctx context.Context, cmd *cpTypes.SignedCommand, chain controlplaneInterfaces.PeerChain) error {
	c.reportOnlyMu.Lock()
	fn := c.lockedCmdHandler
	c.reportOnlyMu.Unlock()
	if fn == nil {
		c.countDropped("command")
		return nil
	}
	return fn(ctx, cmd, chain)
}

// EnterReportOnly switches a running client to report-only: commands are
// dropped from now on, no pull runs, module DNA stops leaving the host and the
// offline queue becomes memory-only. code is the health reason reported on
// every heartbeat. It is idempotent and one-way: leaving report-only takes a
// restart.
func (c *TransportClient) EnterReportOnly(code, message string) {
	if !c.reportOnly.CompareAndSwap(false, true) {
		return
	}
	c.SetHealthReason(ReportOnlyReasonComponent, code, message)

	c.mu.Lock()
	cp := c.controlPlane
	c.dnaCollector = hostFactsOnly(c.dnaCollector)
	exec := c.configExecutor
	session := c.dataPlaneSession
	c.dataPlaneSession = nil
	c.mu.Unlock()

	// Stop persisting reports: swap in a memory-only queue.
	if q, err := NewOfflineQueue(OfflineQueueConfig{Logger: c.logger}); err == nil {
		c.mu.Lock()
		c.offlineQueue = q
		c.mu.Unlock()
	}
	if ic, ok := cp.(controlplaneInterfaces.InboundController); ok {
		ic.SetReportOnly(true)
	}
	if exec != nil {
		exec.StopMonitors()
	}
	if session != nil {
		if err := session.Close(context.Background()); err != nil {
			c.logger.Warn("Failed to close data plane session", "error", logging.SanitizeLogValue(err.Error()))
		}
	}
	c.logger.Warn("Entered report-only mode", "reason", logging.SanitizeLogValue(code))
}

// HandleLockedDown enters report-only when err is the typed lockdown refusal
// from a pull (SyncConfig, FetchModuleBundle, BulkTransfer) and reports whether
// it was. Entering stops further pulls, so a locked-down controller is not
// retried in a tight loop.
func (c *TransportClient) HandleLockedDown(err error) bool {
	if !controlplaneInterfaces.IsLockedDown(err) {
		return false
	}
	c.EnterReportOnly(ReasonControllerLockedDown, "controller refused a pull: this host is locked down")
	return true
}

// EnqueueLog hands a log entry to the event emitter so it leaves the host. It
// reports false when the link has no emitter.
func (c *TransportClient) EnqueueLog(entry *transportpb.LogEntry) bool {
	c.mu.RLock()
	e := c.eventEmitter
	stewardID := c.stewardID
	c.mu.RUnlock()
	if e == nil || entry == nil {
		return false
	}
	if entry.StewardId == "" {
		entry.StewardId = stewardID
	}
	e.Enqueue(entry)
	return true
}

// connectReportOnly is Connect for a report-only client. It starts only the
// heartbeat, the out-only DNA inventory loop and the event emitter: no data
// plane, no command subscription, no config executor, no on-connect sync, no
// offline-queue drain and no convergence loop.
func (c *TransportClient) connectReportOnly(ctx context.Context) error {
	c.logger.Info("Connecting report-only link to controller")

	c.mu.RLock()
	stewardID := c.stewardID
	controlPlane := c.controlPlane
	transportAddress := c.transportAddress
	tenantID := c.tenantID
	c.mu.RUnlock()

	tlsConfig, err := c.createTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to create TLS config: %w", err)
	}
	if tlsConfig == nil {
		return fmt.Errorf("refusing to connect without mutual TLS")
	}
	if controlPlane == nil {
		controlPlane, err = c.newControlPlaneProvider(ctx, stewardID, transportAddress, tenantID, tlsConfig)
		if err != nil {
			return err
		}
		c.mu.Lock()
		c.controlPlane = controlPlane
		c.mu.Unlock()
	}
	// Hooks and the report-only switch are set before Start so nothing the
	// controller sends on connect reaches the normal command queue.
	c.installInboundHooks(controlPlane)

	if !controlPlane.IsConnected() {
		if err := controlPlane.Start(ctx); err != nil {
			return fmt.Errorf("failed to start report-only control plane: %w", err)
		}
	}

	c.startReportOnlyEmitter(controlPlane, stewardID)

	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()

	// #nosec G118 -- heartbeat is client-owned, each send has a five-second
	// timeout, and Disconnect closes heartbeatStop to end the goroutine.
	go c.startHeartbeat()
	c.noteReportOnlyComponent(ReportOnlyComponentHeartbeat)
	c.announceReportOnlyLink(ctx)

	c.mu.RLock()
	hasCollector := c.dnaCollector != nil
	c.mu.RUnlock()
	if hasCollector {
		c.StartDNAInventoryLoop(ctx)
		c.noteReportOnlyComponent(ReportOnlyComponentDNAInventory)
	}

	c.logger.Info("Report-only link connected")
	return nil
}

// startReportOnlyEmitter starts the event emitter that carries logs and events
// off the host over LogStream. Its queue is a channel: memory only.
func (c *TransportClient) startReportOnlyEmitter(cp controlplaneInterfaces.ControlPlaneProvider, stewardID string) {
	grpcProv, ok := cp.(*grpcCP.Provider)
	if !ok || grpcProv.TransportClient() == nil {
		return
	}
	emitter := NewEventEmitter(EventEmitterConfig{
		ClientSource: grpcProv.TransportClient,
		StewardID:    stewardID,
		Logger:       c.logger,
		OnPanic:      c.recordComponentPanic,
	})
	emitter.Start(context.Background())
	c.mu.Lock()
	c.eventEmitter = emitter
	c.mu.Unlock()
	c.noteReportOnlyComponent(ReportOnlyComponentEventEmitter)
}

// announceReportOnlyLink sends the first heartbeat now, with its reasons, rather
// than after the first tick.
func (c *TransportClient) announceReportOnlyLink(ctx context.Context) {
	go c.guard(componentHeartbeat, func() {
		hbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := c.SendHeartbeat(hbCtx, c.heartbeatStatus(), nil); err != nil {
			c.logger.Warn("Failed to send initial report-only heartbeat", "error", logging.SanitizeLogValue(err.Error()))
		}
	})
}

// StartDNAInventoryLoop is the out-only DNA loop: it publishes the host-fact
// inventory now and on every refresh interval, and applies nothing it receives.
// It returns a channel closed when the periodic loop has exited.
func (c *TransportClient) StartDNAInventoryLoop(ctx context.Context) <-chan struct{} {
	go c.guard(componentDNARefresh, func() {
		if err := c.PublishCurrentDNA(ctx); err != nil {
			c.logger.Warn("DNA inventory publish failed", "error", logging.SanitizeLogValue(err.Error()))
		}
	})
	return c.StartDNARefreshLoop(ctx)
}

// lockdownWatchingClient reports every error from FetchModuleBundle, including
// one that arrives on the stream, so the typed lockdown refusal is noticed
// whichever side of the call it surfaces on.
type lockdownWatchingClient struct {
	inner install.Client
	onErr func(error) bool
}

func (w lockdownWatchingClient) FetchModuleBundle(ctx context.Context, in *transportpb.FetchModuleBundleRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[transportpb.ModuleBundleChunk], error) {
	stream, err := w.inner.FetchModuleBundle(ctx, in, opts...)
	if err != nil {
		w.onErr(err)
		return nil, err
	}
	return lockdownWatchingStream{ServerStreamingClient: stream, onErr: w.onErr}, nil
}

type lockdownWatchingStream struct {
	grpc.ServerStreamingClient[transportpb.ModuleBundleChunk]
	onErr func(error) bool
}

func (s lockdownWatchingStream) Recv() (*transportpb.ModuleBundleChunk, error) {
	m, err := s.ServerStreamingClient.Recv()
	if err != nil && !errors.Is(err, io.EOF) {
		s.onErr(err)
	}
	return m, err
}
