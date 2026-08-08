// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package memory provides an in-process ControlPlaneProvider implementation.
//
// The provider is a complete implementation of
// interfaces.ControlPlaneProvider: it routes commands, events and heartbeats
// between a server-mode provider (controller) and client-mode providers
// (stewards) attached to a shared Bus, enforces per-steward addressing,
// applies event filters, tracks connection lifecycle and reports real
// statistics. Only the transport differs from the gRPC-over-QUIC provider —
// messages are handed between providers in-process instead of being serialised
// onto a QUIC stream.
//
// It exists so that consumers of the control plane (controller API wiring,
// dispatchers, heartbeat services) can be tested against a real provider
// instead of each package hand-rolling its own partial fake. The same
// behavioural contract suite that validates the gRPC provider
// (interfaces.RunCPContractTests) runs against this provider.
//
// Usage:
//
//	bus := memory.NewBus()
//
//	server := memory.New(memory.ModeServer)
//	_ = server.Initialize(ctx, map[string]interface{}{"bus": bus})
//	_ = server.Start(ctx)
//
//	client := memory.New(memory.ModeClient)
//	_ = client.Initialize(ctx, map[string]interface{}{"bus": bus, "steward_id": "steward-1"})
//	_ = client.Start(ctx)
package memory

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Mode defines the provider operating mode. It mirrors the gRPC provider's
// modes so that wiring code can switch transports without other changes.
type Mode string

const (
	// ModeServer indicates controller (server) mode.
	ModeServer Mode = "server"

	// ModeClient indicates steward (client) mode.
	ModeClient Mode = "client"
)

// providerName is reported by Name().
const providerName = "memory"

// Bus is the in-process message fabric shared by one server-mode provider and
// the client-mode providers connected to it. It plays the role the network
// plays for the gRPC provider: a client is only reachable while it is attached,
// and a client can only attach while a server is listening.
//
// A Bus is safe for concurrent use.
type Bus struct {
	mu      sync.RWMutex
	server  *Provider
	clients map[string]*Provider
}

// NewBus returns an empty Bus with no server and no connected clients.
func NewBus() *Bus {
	return &Bus{clients: make(map[string]*Provider)}
}

// attachServer registers p as the bus's server. Only one server may listen on
// a bus at a time, matching the single-listener semantics of a real address.
func (b *Bus) attachServer(p *Provider) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.server != nil && b.server != p {
		return fmt.Errorf("bus already has a server-mode provider attached")
	}
	b.server = p
	return nil
}

// detachServer removes p as the bus's server and disconnects every client,
// mirroring a listener close tearing down all live streams.
func (b *Bus) detachServer(p *Provider) {
	b.mu.Lock()
	if b.server != p {
		b.mu.Unlock()
		return
	}
	b.server = nil
	clients := make([]*Provider, 0, len(b.clients))
	for id, c := range b.clients {
		clients = append(clients, c)
		delete(b.clients, id)
	}
	b.mu.Unlock()

	for _, c := range clients {
		c.markDisconnected()
	}
}

// attachClient connects the client provider for stewardID. It fails when no
// server is listening, or when a different provider already holds that ID.
func (b *Bus) attachClient(stewardID string, p *Provider) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.server == nil {
		return fmt.Errorf("no server-mode provider is listening on the bus")
	}
	if existing, ok := b.clients[stewardID]; ok && existing != p {
		return fmt.Errorf("steward %q is already connected", stewardID)
	}
	b.clients[stewardID] = p
	return nil
}

// detachClient disconnects the client provider registered for stewardID.
func (b *Bus) detachClient(stewardID string, p *Provider) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if existing, ok := b.clients[stewardID]; ok && existing == p {
		delete(b.clients, stewardID)
	}
}

// lookupClient returns the connected client provider for stewardID.
func (b *Bus) lookupClient(stewardID string) (*Provider, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	c, ok := b.clients[stewardID]
	return c, ok
}

// lookupServer returns the attached server provider.
func (b *Bus) lookupServer() (*Provider, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.server, b.server != nil
}

// ClientCount returns the number of currently connected client providers.
func (b *Bus) ClientCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.clients)
}

// eventSubscription pairs an event filter with its handler.
type eventSubscription struct {
	filter  *types.EventFilter
	handler interfaces.EventHandler
}

// Provider implements interfaces.ControlPlaneProvider over an in-process Bus.
//
// A Provider is safe for concurrent use. Handlers are invoked on their own
// goroutines, as they are in the gRPC provider, so a slow handler never blocks
// the sender; Stop waits for in-flight handler goroutines to finish.
type Provider struct {
	mu sync.RWMutex

	mode      Mode
	bus       *Bus
	stewardID string
	tenantID  string
	logger    logging.Logger

	started   bool
	connected bool
	startTime time.Time

	// Subscriptions (client mode)
	commandHandler interfaces.CommandHandler

	// Subscriptions (server mode)
	eventHandlers     []eventSubscription
	heartbeatHandlers []interfaces.HeartbeatHandler

	// Lifecycle
	ctx      context.Context
	cancel   context.CancelFunc
	dispatch sync.WaitGroup

	// Statistics
	commandsSent       atomic.Int64
	commandsReceived   atomic.Int64
	eventsPublished    atomic.Int64
	eventsReceived     atomic.Int64
	heartbeatsSent     atomic.Int64
	heartbeatsReceived atomic.Int64
	deliveryFailures   atomic.Int64
}

// Compile-time proof that Provider satisfies the central provider interface.
var _ interfaces.ControlPlaneProvider = (*Provider)(nil)

// New creates an in-process control plane provider in the given mode.
// The provider must be initialised with a Bus before it is started.
func New(mode Mode) *Provider {
	return &Provider{
		mode:              mode,
		logger:            logging.NewNoopLogger(),
		eventHandlers:     []eventSubscription{},
		heartbeatHandlers: []interfaces.HeartbeatHandler{},
	}
}

// Name returns the provider name.
func (p *Provider) Name() string { return providerName }

// Initialize configures the provider.
//
// Config keys:
//   - "bus": *Bus - the shared in-process fabric (required)
//   - "mode": string - "server" or "client" (optional; overrides the constructor)
//   - "logger": logging.Logger - logger (optional)
//
// Client mode additional keys:
//   - "steward_id": string - this steward's ID (required)
//   - "tenant_id": string - tenant ID (optional)
func (p *Provider) Initialize(_ context.Context, config map[string]interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if modeStr, ok := config["mode"].(string); ok {
		p.mode = Mode(modeStr)
	}
	if logger, ok := config["logger"].(logging.Logger); ok {
		p.logger = logger
	}

	bus, ok := config["bus"].(*Bus)
	if !ok || bus == nil {
		return fmt.Errorf("memory control plane requires 'bus' (*memory.Bus) in config")
	}
	p.bus = bus

	switch p.mode {
	case ModeServer:
		return nil
	case ModeClient:
		stewardID, ok := config["steward_id"].(string)
		if !ok || stewardID == "" {
			return fmt.Errorf("client mode requires 'steward_id' in config")
		}
		p.stewardID = stewardID
		if tenantID, ok := config["tenant_id"].(string); ok {
			p.tenantID = tenantID
		}
		return nil
	default:
		return fmt.Errorf("invalid mode: %s (must be 'server' or 'client')", p.mode)
	}
}

// Start attaches the provider to its bus. In server mode the provider begins
// accepting client attachments; in client mode it connects, which fails when
// no server is listening.
func (p *Provider) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.bus == nil {
		p.mu.Unlock()
		return fmt.Errorf("provider not initialized")
	}
	if p.started {
		p.mu.Unlock()
		return fmt.Errorf("provider already started")
	}
	mode, bus, stewardID := p.mode, p.bus, p.stewardID
	p.mu.Unlock()

	switch mode {
	case ModeServer:
		if err := bus.attachServer(p); err != nil {
			return err
		}
	case ModeClient:
		if err := bus.attachClient(stewardID, p); err != nil {
			return fmt.Errorf("failed to connect steward %s: %w", stewardID, err)
		}
	default:
		return fmt.Errorf("provider not initialized")
	}

	p.mu.Lock()
	p.ctx, p.cancel = context.WithCancel(ctx)
	p.startTime = time.Now()
	p.started = true
	p.connected = true
	p.mu.Unlock()

	return nil
}

// Stop detaches the provider from its bus and waits for in-flight handler
// goroutines to finish. Stop is idempotent and safe to call on a provider that
// was never started.
func (p *Provider) Stop(ctx context.Context) error {
	p.mu.Lock()
	if !p.started {
		p.mu.Unlock()
		return nil
	}
	p.started = false
	p.connected = false
	if p.cancel != nil {
		p.cancel()
	}
	mode, bus, stewardID := p.mode, p.bus, p.stewardID
	p.commandHandler = nil
	p.eventHandlers = nil
	p.heartbeatHandlers = nil
	p.mu.Unlock()

	if bus != nil {
		switch mode {
		case ModeServer:
			bus.detachServer(p)
		case ModeClient:
			bus.detachClient(stewardID, p)
		}
	}

	return p.waitForDispatch(ctx)
}

// waitForDispatch blocks until every in-flight handler goroutine returns, or
// until ctx is done.
func (p *Provider) waitForDispatch(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		p.dispatch.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("timed out waiting for in-flight handlers: %w", ctx.Err())
	}
}

// Reconnect re-attaches a client-mode provider to its bus without discarding
// its statistics. It returns an error in server mode, matching the gRPC
// provider.
func (p *Provider) Reconnect(ctx context.Context) error {
	p.mu.RLock()
	mode, bus, stewardID := p.mode, p.bus, p.stewardID
	p.mu.RUnlock()

	if mode != ModeClient {
		return fmt.Errorf("Reconnect called on server-mode provider")
	}
	if bus == nil {
		return fmt.Errorf("provider not initialized")
	}

	bus.detachClient(stewardID, p)
	if err := bus.attachClient(stewardID, p); err != nil {
		return fmt.Errorf("failed to reconnect steward %s: %w", stewardID, err)
	}

	p.mu.Lock()
	if p.ctx == nil || p.ctx.Err() != nil {
		p.ctx, p.cancel = context.WithCancel(context.WithoutCancel(ctx))
	}
	if p.startTime.IsZero() {
		p.startTime = time.Now()
	}
	p.started = true
	p.connected = true
	p.mu.Unlock()

	return nil
}

// markDisconnected flips the provider to disconnected without detaching it
// from the bus. Used when the server tears down and drops all clients.
func (p *Provider) markDisconnected() {
	p.mu.Lock()
	p.connected = false
	p.mu.Unlock()
}

// --- Commands (Controller → Steward) ---

// SendCommand delivers a signed command to the addressed steward. It returns
// an error when the steward is not connected.
func (p *Provider) SendCommand(_ context.Context, cmd *types.SignedCommand) error {
	if p.mode != ModeServer {
		return fmt.Errorf("SendCommand is only available in server mode")
	}
	if cmd == nil {
		return fmt.Errorf("SendCommand: command must not be nil")
	}
	if err := p.checkStarted(); err != nil {
		return err
	}

	if err := p.deliverCommand(cmd, cmd.Command.StewardID); err != nil {
		p.deliveryFailures.Add(1)
		return err
	}
	p.commandsSent.Add(1)
	return nil
}

// FanOutCommand delivers a signed command to each listed steward, reporting
// per-steward delivery status. Stewards that are not connected appear in
// FanOutResult.Failed; the error return is reserved for systemic failures.
func (p *Provider) FanOutCommand(_ context.Context, cmd *types.SignedCommand, stewardIDs []string) (*types.FanOutResult, error) {
	if p.mode != ModeServer {
		return nil, fmt.Errorf("FanOutCommand is only available in server mode")
	}
	if cmd == nil {
		return nil, fmt.Errorf("FanOutCommand: command must not be nil")
	}
	if len(stewardIDs) == 0 {
		return nil, fmt.Errorf("stewardIDs must not be empty")
	}
	if err := p.checkStarted(); err != nil {
		return nil, err
	}

	result := &types.FanOutResult{Failed: make(map[string]error)}
	for _, id := range stewardIDs {
		if err := p.deliverCommand(cmd, id); err != nil {
			result.Failed[id] = err
			p.deliveryFailures.Add(1)
			continue
		}
		result.Succeeded = append(result.Succeeded, id)
		p.commandsSent.Add(1)
	}
	return result, nil
}

// deliverCommand routes one command to one steward. Each steward receives its
// own copy, so a handler cannot mutate the sender's command or another
// steward's copy — the isolation a serialising transport provides for free.
func (p *Provider) deliverCommand(cmd *types.SignedCommand, stewardID string) error {
	if stewardID == "" {
		return fmt.Errorf("command has no target steward ID")
	}
	p.mu.RLock()
	bus := p.bus
	p.mu.RUnlock()

	client, ok := bus.lookupClient(stewardID)
	if !ok {
		return fmt.Errorf("steward %s not connected", stewardID)
	}
	client.receiveCommand(cloneSignedCommand(cmd))
	return nil
}

// receiveCommand is the client-side ingress for a command.
func (p *Provider) receiveCommand(cmd *types.SignedCommand) {
	p.commandsReceived.Add(1)

	p.mu.RLock()
	handler := p.commandHandler
	ctx := p.ctx
	p.mu.RUnlock()

	if handler == nil {
		return
	}
	p.dispatchAsync(func() {
		if err := handler(ctx, cmd); err != nil {
			p.logger.Error("command handler error",
				"command_id", logging.SanitizeLogValue(cmd.Command.ID),
				"error", logging.SanitizeLogValue(err.Error()))
		}
	})
}

// SubscribeCommands registers the client-side command handler. The stewardID
// must match the ID this provider was initialised with (or be empty), since
// routing is by the provider's own identity, as it is by mTLS CN on the wire.
func (p *Provider) SubscribeCommands(_ context.Context, stewardID string, handler interfaces.CommandHandler) error {
	if p.mode != ModeClient {
		return fmt.Errorf("SubscribeCommands is only available in client mode")
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if stewardID != "" && stewardID != p.stewardID {
		return fmt.Errorf("cannot subscribe to commands for steward %s: provider identity is %s", stewardID, p.stewardID)
	}
	p.commandHandler = handler
	return nil
}

// --- Events (Steward → Controller) ---

// PublishEvent sends an event to the controller. It returns an error when the
// client is not connected.
func (p *Provider) PublishEvent(_ context.Context, event *types.Event) error {
	if p.mode != ModeClient {
		return fmt.Errorf("PublishEvent is only available in client mode")
	}
	if event == nil {
		return fmt.Errorf("PublishEvent: event must not be nil")
	}

	server, err := p.serverForSend()
	if err != nil {
		p.deliveryFailures.Add(1)
		return fmt.Errorf("failed to publish event: %w", err)
	}

	server.receiveEvent(cloneEvent(event))
	p.eventsPublished.Add(1)
	return nil
}

// receiveEvent is the server-side ingress for an event.
func (p *Provider) receiveEvent(event *types.Event) {
	p.eventsReceived.Add(1)

	p.mu.RLock()
	subs := make([]eventSubscription, len(p.eventHandlers))
	copy(subs, p.eventHandlers)
	ctx := p.ctx
	p.mu.RUnlock()

	for _, sub := range subs {
		if sub.filter != nil && !sub.filter.Match(event) {
			continue
		}
		handler := sub.handler
		p.dispatchAsync(func() {
			if err := handler(ctx, event); err != nil {
				p.logger.Error("event handler error",
					"event_id", logging.SanitizeLogValue(event.ID),
					"error", logging.SanitizeLogValue(err.Error()))
			}
		})
	}
}

// SubscribeEvents registers a server-side event handler with an optional filter.
func (p *Provider) SubscribeEvents(_ context.Context, filter *types.EventFilter, handler interfaces.EventHandler) error {
	if p.mode != ModeServer {
		return fmt.Errorf("SubscribeEvents is only available in server mode")
	}

	p.mu.Lock()
	p.eventHandlers = append(p.eventHandlers, eventSubscription{filter: filter, handler: handler})
	p.mu.Unlock()
	return nil
}

// --- Heartbeats ---

// SendHeartbeat sends a heartbeat to the controller. It returns an error when
// the client is not connected.
func (p *Provider) SendHeartbeat(_ context.Context, heartbeat *types.Heartbeat) error {
	if p.mode != ModeClient {
		return fmt.Errorf("SendHeartbeat is only available in client mode")
	}
	if heartbeat == nil {
		return fmt.Errorf("SendHeartbeat: heartbeat must not be nil")
	}

	server, err := p.serverForSend()
	if err != nil {
		p.deliveryFailures.Add(1)
		return fmt.Errorf("failed to send heartbeat: %w", err)
	}

	server.receiveHeartbeat(cloneHeartbeat(heartbeat))
	p.heartbeatsSent.Add(1)
	return nil
}

// receiveHeartbeat is the server-side ingress for a heartbeat.
func (p *Provider) receiveHeartbeat(hb *types.Heartbeat) {
	p.heartbeatsReceived.Add(1)

	p.mu.RLock()
	handlers := make([]interfaces.HeartbeatHandler, len(p.heartbeatHandlers))
	copy(handlers, p.heartbeatHandlers)
	ctx := p.ctx
	p.mu.RUnlock()

	for _, handler := range handlers {
		handler := handler
		p.dispatchAsync(func() {
			if err := handler(ctx, hb); err != nil {
				p.logger.Error("heartbeat handler error",
					"steward_id", logging.SanitizeLogValue(hb.StewardID),
					"error", logging.SanitizeLogValue(err.Error()))
			}
		})
	}
}

// SubscribeHeartbeats registers a server-side heartbeat handler.
func (p *Provider) SubscribeHeartbeats(_ context.Context, handler interfaces.HeartbeatHandler) error {
	if p.mode != ModeServer {
		return fmt.Errorf("SubscribeHeartbeats is only available in server mode")
	}

	p.mu.Lock()
	p.heartbeatHandlers = append(p.heartbeatHandlers, handler)
	p.mu.Unlock()
	return nil
}

// --- Status & Monitoring ---

// GetStats returns the provider's operational counters.
func (p *Provider) GetStats(_ context.Context) (*types.ControlPlaneStats, error) {
	stats := &types.ControlPlaneStats{
		CommandsSent:       p.commandsSent.Load(),
		CommandsReceived:   p.commandsReceived.Load(),
		EventsPublished:    p.eventsPublished.Load(),
		EventsReceived:     p.eventsReceived.Load(),
		HeartbeatsSent:     p.heartbeatsSent.Load(),
		HeartbeatsReceived: p.heartbeatsReceived.Load(),
		DeliveryFailures:   p.deliveryFailures.Load(),
		ProviderMetrics:    make(map[string]interface{}),
	}

	p.mu.RLock()
	if !p.startTime.IsZero() {
		stats.Uptime = time.Since(p.startTime)
	}
	stats.ActiveSubscriptions = int64(len(p.eventHandlers) + len(p.heartbeatHandlers))
	mode, bus, connected := p.mode, p.bus, p.connected
	p.mu.RUnlock()

	if mode == ModeServer && bus != nil {
		stats.ConnectedStewards = int64(bus.ClientCount())
	}
	if mode == ModeClient {
		state := "disconnected"
		if connected {
			state = "connected"
		}
		stats.ProviderMetrics["connection_state"] = state
	}

	return stats, nil
}

// IsConnected reports whether the provider is attached to its bus: accepting
// clients in server mode, connected to the server in client mode.
func (p *Provider) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.started && p.connected
}

// StewardID returns the steward identity a client-mode provider was
// initialised with. Empty in server mode.
func (p *Provider) StewardID() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.stewardID
}

// checkStarted returns an error when the provider is not attached to its bus.
func (p *Provider) checkStarted() error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.started {
		return fmt.Errorf("provider is not started")
	}
	return nil
}

// serverForSend returns the bus server for a client-side send, erroring when
// the client is disconnected or no server is listening.
func (p *Provider) serverForSend() (*Provider, error) {
	p.mu.RLock()
	started, connected, bus := p.started, p.connected, p.bus
	p.mu.RUnlock()

	if !started || !connected {
		return nil, fmt.Errorf("provider is disconnected")
	}
	server, ok := bus.lookupServer()
	if !ok {
		return nil, fmt.Errorf("no server-mode provider is listening on the bus")
	}
	return server, nil
}

// dispatchAsync runs fn on its own goroutine, tracked so Stop can wait for it.
func (p *Provider) dispatchAsync(fn func()) {
	p.dispatch.Add(1)
	go func() {
		defer p.dispatch.Done()
		fn()
	}()
}

// --- Message copying ---

// cloneSignedCommand returns a deep-enough copy of cmd that the receiver and
// the sender share no mutable state. The signature is treated as immutable.
func cloneSignedCommand(cmd *types.SignedCommand) *types.SignedCommand {
	out := &types.SignedCommand{
		Command:   cmd.Command,
		Signature: cmd.Signature,
	}
	if cmd.Command.Params != nil {
		params := make(map[string]interface{}, len(cmd.Command.Params))
		for k, v := range cmd.Command.Params {
			params[k] = v
		}
		out.Command.Params = params
	}
	if cmd.RawParams != nil {
		raw := make(map[string]string, len(cmd.RawParams))
		for k, v := range cmd.RawParams {
			raw[k] = v
		}
		out.RawParams = raw
	}
	return out
}

// cloneEvent returns a copy of event with an independent Details map.
func cloneEvent(event *types.Event) *types.Event {
	out := *event
	if event.Details != nil {
		details := make(map[string]interface{}, len(event.Details))
		for k, v := range event.Details {
			details[k] = v
		}
		out.Details = details
	}
	return &out
}

// cloneHeartbeat returns a copy of hb with an independent Metrics map.
func cloneHeartbeat(hb *types.Heartbeat) *types.Heartbeat {
	out := *hb
	if hb.Metrics != nil {
		metrics := make(map[string]interface{}, len(hb.Metrics))
		for k, v := range hb.Metrics {
			metrics[k] = v
		}
		out.Metrics = metrics
	}
	return &out
}
