// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package grpc provides a gRPC-over-QUIC control plane provider implementation.
//
// This provider implements the ControlPlaneProvider interface using a persistent
// bidirectional gRPC ControlChannel stream per steward, enabling direct
// controller-steward communication over QUIC.
package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
	quicgo "github.com/quic-go/quic-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Mode defines the provider operating mode.
type Mode string

const (
	// ModeServer indicates controller (server) mode.
	ModeServer Mode = "server"

	// ModeClient indicates steward (client) mode.
	ModeClient Mode = "client"
)

// option is an unexported functional option for New.
type option func(*Provider)

// withBackoff injects a custom backoff configuration into the provider.
// Intended for testing only; production code uses the defaults.
func withBackoff(b *backoff) option {
	return func(p *Provider) {
		p.backoffOverride = b
	}
}

// withQUICConfig injects a custom QUIC configuration into the provider.
// Intended for testing only; production code uses the defaults.
func withQUICConfig(cfg *quicgo.Config) option {
	return func(p *Provider) {
		p.quicConfigOverride = cfg
	}
}

// Provider implements the ControlPlaneProvider interface using gRPC-over-QUIC.
type Provider struct {
	mu sync.RWMutex

	name string
	mode Mode

	// Server-side components
	grpcServer    *grpc.Server
	ownGRPCServer bool // true when this provider created the gRPC server
	listener      *quictransport.Listener
	registry      registry.Registry
	serverImpl    *transportServer

	// Client-side components
	grpcConn      *grpc.ClientConn
	grpcClient    transportpb.StewardTransportClient
	controlStream grpc.BidiStreamingClient[transportpb.ControlMessage, transportpb.ControlMessage]
	sendMu        sync.Mutex // serializes writes to controlStream
	reconnectMu   sync.Mutex // ensures only one reconnectLoop runs at a time
	connState     atomic.Int32
	onStateChange func(ConnectionState)

	// Shared configuration
	config          map[string]interface{}
	addr            string
	tlsConfig       *tls.Config
	keepalivePeriod time.Duration // 0 = use QUIC default (25s)
	idleTimeout     time.Duration // 0 = use QUIC default (90s)
	maxConnections  int
	stewardID       string
	tenantID        string
	logger          logging.Logger
	startTime       time.Time

	// Per-instance overrides injected via constructor options (test-only)
	backoffOverride *backoff
	// reconnectBackoff persists across reconnectLoop invocations so successive
	// refused cycles keep escalating. It must NOT be rebuilt per call: a stream
	// that opens and is then rejected on its first Recv re-enters reconnectLoop,
	// so a per-call backoff restarts at the initial interval every cycle and
	// never grows (Issue #3481).
	//
	// Guarded by its own backoffMu rather than reconnectMu, because reconnectMu
	// is TryLock-ed to mean "a reconnect is already running": briefly holding it
	// to reset the backoff would make a concurrent reconnectLoop see a false
	// positive and skip reconnecting altogether.
	backoffMu          sync.Mutex
	reconnectBackoff   *backoff
	quicConfigOverride *quicgo.Config

	// approvalChecker gates reconnecting stewards on the ControlChannel path.
	// Nil means "always admit" (default). Injected by WithApprovalChecker for
	// the approval-gate epic (#1690–#1698).
	approvalChecker StewardApprovalChecker

	// onConnectHook is called after a steward successfully registers, before the
	// receive loop begins. Nil means no-op (default). Injected via WithOnConnectHook
	// for refresh-on-connect cert delivery (Issue #1817).
	onConnectHook StewardOnConnectHook

	// tenantAdmission gates the Register (connect) and ControlChannel heartbeat
	// paths with a per-tenant concurrency limit. Nil means no admission control
	// (default). Injected via WithTenantAdmission (Issue #3759, ADR-031 Decision 6).
	tenantAdmission TenantAdmission

	// stewardTenantResolver maps an mTLS-verified steward identity to its tenant
	// using server-side fleet records, so admission buckets are never keyed on a
	// caller-supplied tenant field. Nil falls back to per-steward buckets.
	// Injected via WithStewardTenantResolver.
	stewardTenantResolver StewardTenantResolver

	// Subscription handlers (client mode)
	commandHandler interfaces.CommandHandler

	// Server-side tenant binding store. When non-nil, Register() enforces that
	// the registration token (creds.ClientId) maps to a tenant matching creds.TenantId.
	// Injected via Initialize config key "registration_token_store".
	registrationTokenStore business.RegistrationTokenStore
	requireSecurityStores  bool

	// Subscription handlers (server mode)
	eventHandlers     []eventSubscription
	heartbeatHandlers []interfaces.HeartbeatHandler

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc

	// Statistics (atomic for lock-free updates)
	commandsSent       atomic.Int64
	commandsReceived   atomic.Int64
	eventsPublished    atomic.Int64
	eventsReceived     atomic.Int64
	heartbeatsSent     atomic.Int64
	heartbeatsReceived atomic.Int64
	responsesSent      atomic.Int64
	responsesReceived  atomic.Int64
	deliveryFailures   atomic.Int64
	reconnectAttempts  atomic.Int64
	identityMismatches atomic.Int64

	// Connection timestamps (protected by mu)
	lastConnectedAt    time.Time
	lastDisconnectedAt time.Time
}

// eventSubscription represents an event subscription with filter.
type eventSubscription struct {
	filter  *types.EventFilter
	handler interfaces.EventHandler
}

// New creates a new gRPC control plane provider.
func New(mode Mode, opts ...option) *Provider {
	p := &Provider{
		name:              "grpc",
		mode:              mode,
		eventHandlers:     []eventSubscription{},
		heartbeatHandlers: []interfaces.HeartbeatHandler{},
		logger:            logging.NewNoopLogger(),
		maxConnections:    50000,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *Provider) Name() string { return p.name }

// Registry returns the steward connection registry used by this provider in
// server mode. It is the registry passed via the "registry" Initialize config
// key, or the one auto-created when none was supplied. Controller wiring uses
// this to share a single registry instance with the HTTP API server so
// connection_state stays accurate (Issue #1572).
func (p *Provider) Registry() registry.Registry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.registry
}

// Initialize configures the provider.
//
// Common config keys:
//   - "mode": string - "server" or "client"
//   - "addr": string - Listen address (server) or controller address (client)
//   - "tls_config": *tls.Config - TLS configuration for mTLS
//   - "logger": logging.Logger - Logger (optional)
//   - "keepalive_period": time.Duration - QUIC keepalive interval (optional, default 25s)
//   - "idle_timeout": time.Duration - QUIC idle timeout (optional, default 90s)
//   - "on_state_change": func(ConnectionState) - Connection state change callback (optional, client mode only)
//
// Server mode additional keys:
//   - "grpc_server": *grpc.Server - Externally-created gRPC server (optional; when provided,
//     the provider will not create its own QUIC listener or gRPC server)
//   - "registry": registry.Registry - Connection registry (optional, creates one if nil)
//
// Client mode additional keys:
//   - "steward_id": string - This steward's ID
//   - "tenant_id": string - Tenant ID (optional)
func (p *Provider) Initialize(ctx context.Context, config map[string]interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.config = config

	if modeStr, ok := config["mode"].(string); ok {
		p.mode = Mode(modeStr)
	}

	if logger, ok := config["logger"].(logging.Logger); ok {
		p.logger = logger
	}

	if addr, ok := config["addr"].(string); ok {
		p.addr = addr
	}

	if tlsCfg, ok := config["tls_config"].(*tls.Config); ok {
		p.tlsConfig = tlsCfg
	}

	if kp, ok := config["keepalive_period"].(time.Duration); ok {
		p.keepalivePeriod = kp
	}
	if it, ok := config["idle_timeout"].(time.Duration); ok {
		p.idleTimeout = it
	}
	if max, ok := config["max_connections"].(int); ok {
		if max < 1 {
			return fmt.Errorf("max_connections must be at least 1")
		}
		p.maxConnections = max
	}
	if cb, ok := config["on_state_change"].(func(ConnectionState)); ok {
		p.onStateChange = cb
	}

	switch p.mode {
	case ModeServer:
		return p.initializeServer(config)
	case ModeClient:
		return p.initializeClient(config)
	default:
		return fmt.Errorf("invalid mode: %s (must be 'server' or 'client')", p.mode)
	}
}

func (p *Provider) initializeServer(config map[string]interface{}) error {
	// Accept an externally-created gRPC server (Story #515: shared CP+DP server).
	// When provided, the provider will not create its own QUIC listener or gRPC server.
	if srv, ok := config["grpc_server"].(*grpc.Server); ok && srv != nil {
		p.grpcServer = srv
		p.ownGRPCServer = false
		p.logger.Info("CP provider using external gRPC server (ownGRPCServer=false)")
	} else {
		p.ownGRPCServer = true
		p.logger.Info("CP provider will create own gRPC server (ownGRPCServer=true)")
		if p.addr == "" {
			return fmt.Errorf("server mode requires 'addr' or 'grpc_server' in config")
		}
		if p.tlsConfig == nil {
			return fmt.Errorf("server mode requires 'tls_config' when creating own gRPC server")
		}
	}

	if reg, ok := config["registry"].(registry.Registry); ok {
		p.registry = reg
	} else {
		p.registry = registry.NewRegistry()
	}

	if ts, ok := config["registration_token_store"].(business.RegistrationTokenStore); ok {
		p.registrationTokenStore = ts
	}
	if required, _ := config["require_security_stores"].(bool); required {
		p.requireSecurityStores = true
		if p.approvalChecker == nil {
			return fmt.Errorf("server mode requires an approval checker")
		}
		if p.registrationTokenStore == nil {
			return fmt.Errorf("server mode requires a registration token store")
		}
		if _, ok := p.registrationTokenStore.(business.RegistrationTokenClaimer); !ok {
			return fmt.Errorf("server mode requires atomic registration token claiming")
		}
	}

	return nil
}

func (p *Provider) initializeClient(config map[string]interface{}) error {
	if p.addr == "" {
		return fmt.Errorf("client mode requires 'addr' in config")
	}
	if p.tlsConfig == nil {
		return fmt.Errorf("client mode requires 'tls_config' in config")
	}

	stewardID, ok := config["steward_id"].(string)
	if !ok || stewardID == "" {
		return fmt.Errorf("client mode requires 'steward_id' in config")
	}
	p.stewardID = stewardID

	if tenantID, ok := config["tenant_id"].(string); ok {
		p.tenantID = tenantID
	}

	return nil
}

// Start begins control plane operation.
func (p *Provider) Start(ctx context.Context) error {
	p.mu.Lock()
	p.ctx, p.cancel = context.WithCancel(ctx)
	p.startTime = time.Now()
	mode := p.mode

	switch mode {
	case ModeServer:
		defer p.mu.Unlock()
		return p.startServer()
	case ModeClient:
		// startClient manages its own locking rather than holding mu for the
		// duration of this call -- see its doc comment.
		p.mu.Unlock()
		return p.startClient()
	default:
		p.mu.Unlock()
		return fmt.Errorf("provider not initialized")
	}
}

// quicConfig returns a *quicgo.Config with any user overrides, or nil for defaults.
func (p *Provider) quicConfig() *quicgo.Config {
	if p.quicConfigOverride != nil {
		return p.quicConfigOverride
	}
	if p.keepalivePeriod == 0 && p.idleTimeout == 0 {
		return nil // use QUIC transport defaults
	}
	cfg := &quicgo.Config{}
	if p.keepalivePeriod > 0 {
		cfg.KeepAlivePeriod = p.keepalivePeriod
	}
	if p.idleTimeout > 0 {
		cfg.MaxIdleTimeout = p.idleTimeout
	}
	return cfg
}

func (p *Provider) startServer() error {
	p.serverImpl = &transportServer{provider: p}

	if p.ownGRPCServer {
		ql, err := quictransport.ListenWithLimits(
			p.addr,
			p.tlsConfig,
			p.quicConfig(),
			quictransport.LimitsForMaxConnections(p.maxConnections),
		)
		if err != nil {
			return fmt.Errorf("failed to start QUIC listener: %w", err)
		}
		p.listener = ql

		p.grpcServer = grpc.NewServer(
			grpc.Creds(quictransport.TransportCredentials()),
		)
		transportpb.RegisterStewardTransportServer(p.grpcServer, p.serverImpl)

		// Capture local references: ForceStop/stopServer may nil the shared
		// fields before this goroutine runs, and reading p.grpcServer inside
		// the goroutine would then panic.
		grpcSrv := p.grpcServer
		go func() {
			if err := grpcSrv.Serve(ql); err != nil {
				p.logger.Error("gRPC server stopped", "error", err)
			}
		}()

		p.logger.Info("gRPC control plane server started", "addr", logging.SanitizeLogValue(p.addr))
	} else {
		// External gRPC server (Story #515): the caller is responsible for
		// registering a composite handler and starting the server. We only
		// create serverImpl so ServerHandler() returns a usable handler.
		p.logger.Info("gRPC control plane handler attached to existing gRPC server")
	}

	return nil
}

// startClient performs the initial ControlChannel dial. Unlike startServer,
// it is NOT called with p.mu held: dialInitial retries the dial until p.ctx
// is done, and a concurrent Stop() needs p.mu.Lock() to reach p.cancel() and
// unblock that retry. Holding mu here would make Stop() wait on the very
// thing only Stop() can end -- the same reason reconnectLoop never holds mu
// across dialAndOpenStream or its own backoff wait.
func (p *Provider) startClient() error {
	p.setState(StateConnecting)

	if err := p.dialInitial(); err != nil {
		p.setState(StateDisconnected)
		return err
	}

	p.mu.Lock()
	p.lastConnectedAt = time.Now()
	p.mu.Unlock()
	p.setState(StateConnected)

	go p.clientReceiveLoop()

	p.logger.Info("gRPC control plane client connected", "addr", logging.SanitizeLogValue(p.addr), "steward_id", logging.SanitizeLogValue(p.stewardID))
	return nil
}

// dialInitial repeats dialAndOpenStream, using the same escalating backoff as
// reconnectLoop, until it succeeds or p.ctx is done.
//
// A single dialAndOpenStream attempt can hit gRPC-go's own per-attempt
// connect ceiling (MinConnectTimeout, 20s by default) before a QUIC+TLS
// handshake completes under CPU contention -- even though the peer is
// already listening -- and because ControlChannel is a fail-fast call (no
// WaitForReady), that one failed attempt surfaces immediately as Unavailable.
// Bumping the per-attempt ceiling would only move the same race to a bigger
// number. Retrying against the caller's own context instead makes the
// initial connect deterministic under load: as long as the caller does not
// impose its own deadline, the dial keeps trying until the peer is reachable
// (Issue #3849).
func (p *Provider) dialInitial() error {
	b := defaultBackoff()
	for {
		err := p.dialAndOpenStream()
		if err == nil {
			return nil
		}

		select {
		case <-p.ctx.Done():
			return err
		default:
		}

		timer := time.NewTimer(b.next())
		select {
		case <-p.ctx.Done():
			timer.Stop()
			return err
		case <-timer.C:
		}
	}
}

// dialAndOpenStream creates a new gRPC client connection over QUIC and opens the
// ControlChannel bidi stream. On failure, any partially created connection is closed.
func (p *Provider) dialAndOpenStream() error {
	// Check context before attempting to dial
	select {
	case <-p.ctx.Done():
		return p.ctx.Err()
	default:
	}

	// Read addr under sendMu (not mu) because this function is called from
	// startClient which already holds mu. sendMu serializes with the test
	// helper restartServerAndRepoint which updates addr under sendMu.
	p.sendMu.Lock()
	addr := p.addr
	p.sendMu.Unlock()

	dialer := quictransport.NewDialer(p.tlsConfig, p.quicConfig())

	conn, err := grpc.NewClient(
		quictransport.DialTarget(addr),
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(quictransport.TransportCredentials()),
	)
	if err != nil {
		return fmt.Errorf("failed to create gRPC client: %w", err)
	}

	stream, err := transportpb.NewStewardTransportClient(conn).ControlChannel(p.ctx)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("failed to open ControlChannel: %w", err)
	}

	p.sendMu.Lock()
	p.grpcConn = conn
	p.grpcClient = transportpb.NewStewardTransportClient(conn)
	p.controlStream = stream
	p.sendMu.Unlock()

	return nil
}

// clientReceiveLoop reads messages from the ControlChannel and dispatches them.
// When the stream breaks, it triggers the reconnection loop unless the provider
// is shutting down.
func (p *Provider) clientReceiveLoop() {
	// Capture the stream reference at goroutine start to avoid reading the
	// field concurrently with closeClientConn/dialAndOpenStream writes.
	p.sendMu.Lock()
	stream := p.controlStream
	p.sendMu.Unlock()

	if stream == nil {
		p.logger.Error("clientReceiveLoop started with nil stream")
		return
	}

	for {
		msg, err := stream.Recv()
		if err == nil {
			// The stream has proven it can carry traffic, so this connection
			// counts as a genuine success and the escalating backoff is cleared.
			// Doing it here rather than at stream-open is what keeps a
			// persistently-refused steward escalating while leaving an ordinary
			// transport drop reconnecting promptly (Issue #3481).
			p.resetReconnectBackoff()
		}
		if err != nil {
			select {
			case <-p.ctx.Done():
				p.setState(StateDisconnected)
				return
			default:
			}
			p.logger.Error("ControlChannel receive error", "error", err)
			p.setState(StateDisconnected)
			p.mu.Lock()
			p.lastDisconnectedAt = time.Now()
			p.mu.Unlock()

			p.closeClientConn()
			p.reconnectLoop()
			return
		}

		switch payload := msg.GetPayload().(type) {
		case *transportpb.ControlMessage_Command:
			sc := signedCommandFromProto(payload.Command)
			p.commandsReceived.Add(1)

			p.mu.RLock()
			handler := p.commandHandler
			p.mu.RUnlock()

			if handler != nil {
				go func() {
					if err := handler(p.ctx, sc); err != nil {
						p.logger.Error("command handler error", "command_id", sc.Command.ID, "error", err)
					}
				}()
			}
		}
	}
}

// nextReconnectBackoff returns the next reconnect delay and the attempt number
// it corresponds to, lazily creating the provider-scoped backoff on first use.
//
// The backoff deliberately lives on the Provider: an admission refusal does not
// fail dialAndOpenStream (the stream opens; the rejection surfaces on the first
// Recv), so clientReceiveLoop re-enters reconnectLoop on every refusal. A backoff
// built per reconnectLoop call therefore restarted at its initial interval every
// cycle and never grew — measured live at "attempt 1, backoff 1s" indefinitely,
// 78 MB of controller log in a day from three refused stewards (Issue #3481).
func (p *Provider) nextReconnectBackoff() (time.Duration, int) {
	p.backoffMu.Lock()
	defer p.backoffMu.Unlock()
	if p.reconnectBackoff == nil {
		p.reconnectBackoff = defaultBackoff()
		if p.backoffOverride != nil {
			p.reconnectBackoff = &backoff{
				initial:    p.backoffOverride.initial,
				max:        p.backoffOverride.max,
				multiplier: p.backoffOverride.multiplier,
				jitter:     p.backoffOverride.jitter,
			}
		}
	}
	return p.reconnectBackoff.next(), p.reconnectBackoff.attempt
}

// resetReconnectBackoff clears the escalating reconnect backoff after a stream
// has demonstrably carried a message.
func (p *Provider) resetReconnectBackoff() {
	p.backoffMu.Lock()
	defer p.backoffMu.Unlock()
	if p.reconnectBackoff != nil {
		p.reconnectBackoff.reset()
	}
}

// reconnectLoop attempts to re-establish the ControlChannel with exponential backoff.
// It runs until either a connection is established or the provider context is cancelled.
// TryLock ensures only one reconnectLoop is active at a time: when Reconnect() closes
// the connection, both the new goroutine and the existing clientReceiveLoop race to call
// reconnectLoop; the loser returns immediately, letting the winner own reconnection.
func (p *Provider) reconnectLoop() {
	if !p.reconnectMu.TryLock() {
		return
	}
	defer p.reconnectMu.Unlock()

	for {
		select {
		case <-p.ctx.Done():
			p.setState(StateDisconnected)
			return
		default:
		}

		p.setState(StateReconnecting)
		p.reconnectAttempts.Add(1)

		wait, attempt := p.nextReconnectBackoff()

		// Read addr under sendMu — restartServerAndRepoint writes p.addr under sendMu,
		// so reads outside sendMu are a data race (same pattern as dialAndOpenStream).
		p.sendMu.Lock()
		addr := p.addr
		p.sendMu.Unlock()

		p.logger.Info("reconnecting to controller",
			"attempt", attempt,
			"backoff", wait,
			"addr", logging.SanitizeLogValue(addr),
		)

		// Wait for backoff duration or cancellation
		timer := time.NewTimer(wait)
		select {
		case <-p.ctx.Done():
			timer.Stop()
			p.setState(StateDisconnected)
			return
		case <-timer.C:
		}

		// Attempt to reconnect
		if err := p.dialAndOpenStream(); err != nil {
			p.logger.Warn("reconnection failed", "error", err, "attempt", attempt)
			continue
		}

		// The stream is OPEN, which is not the same as usable: a server-side
		// admission refusal is delivered on the first Recv, not by
		// dialAndOpenStream. Resetting the backoff here therefore rewarded a
		// connection that was about to be rejected. The reset now happens in
		// clientReceiveLoop once a message has actually been received, so a
		// stream that never carries one keeps escalating (Issue #3481).
		p.setState(StateConnected)
		p.mu.Lock()
		p.lastConnectedAt = time.Now()
		p.mu.Unlock()

		// Re-read addr under sendMu for the success log — addr may have changed
		// if restartServerAndRepoint updated it during the backoff window.
		p.sendMu.Lock()
		addr = p.addr
		p.sendMu.Unlock()

		p.logger.Info("reconnected to controller", "addr", logging.SanitizeLogValue(addr), "steward_id", logging.SanitizeLogValue(p.stewardID))

		// Restart the receive loop (which will call reconnectLoop again if it breaks)
		go p.clientReceiveLoop()
		return
	}
}

// Reconnect tears down the current connection and re-establishes it without
// cancelling p.ctx. Only valid in client mode; returns an error in server mode.
// Closes the gRPC connection (via closeClientConn) then launches reconnectLoop
// so the provider re-dials and restarts clientReceiveLoop on success.
func (p *Provider) Reconnect(_ context.Context) error {
	if p.mode != ModeClient {
		return fmt.Errorf("Reconnect called on server-mode provider")
	}
	p.closeClientConn()
	go p.reconnectLoop()
	return nil
}

// closeClientConn closes the current gRPC connection and clears the stream reference.
func (p *Provider) closeClientConn() {
	p.sendMu.Lock()
	// Nil the stream reference first to prevent new sends. Don't call
	// CloseSend — it races with concurrent Recv in clientReceiveLoop.
	// Closing the gRPC conn below will terminate the stream.
	p.controlStream = nil
	conn := p.grpcConn
	p.grpcConn = nil
	p.sendMu.Unlock()

	if conn != nil {
		_ = conn.Close()
	}
}

// setState updates the connection state and fires the on_state_change callback.
func (p *Provider) setState(state ConnectionState) {
	// #nosec G115 -- ConnectionState is a closed enum whose constants are all
	// within int32; callers cannot construct an out-of-range enum value here.
	old := ConnectionState(p.connState.Swap(int32(state)))
	if old == state {
		return
	}
	if p.onStateChange != nil {
		p.onStateChange(state)
	}
}

// getState returns the current connection state.
func (p *Provider) getState() ConnectionState {
	return ConnectionState(p.connState.Load())
}

// sendControlMessage sends a ControlMessage on the client stream under sendMu.
// It handles the TOCTOU race where closeClientConn may nil the stream between
// the checkClientConnected call and the actual send.
func (p *Provider) sendControlMessage(msg *transportpb.ControlMessage) error {
	p.sendMu.Lock()
	stream := p.controlStream
	p.sendMu.Unlock()

	if stream == nil {
		return fmt.Errorf("provider is %s", p.getState())
	}
	return stream.Send(msg)
}

// checkClientConnected returns an error if the client is not in the Connected state.
func (p *Provider) checkClientConnected() error {
	state := p.getState()
	if state != StateConnected {
		return fmt.Errorf("provider is %s", state)
	}
	return nil
}

// Stop gracefully shuts down the control plane.
func (p *Provider) Stop(ctx context.Context) error {
	p.mu.Lock()
	if p.cancel != nil {
		p.cancel()
	}
	mode := p.mode
	p.mu.Unlock()
	// mu is released before the blocking teardown so that ControlChannel
	// handlers (which acquire mu.RLock in dispatchEvent/dispatchHeartbeat)
	// can exit without deadlocking against GracefulStop.

	switch mode {
	case ModeServer:
		return p.stopServer()
	case ModeClient:
		return p.stopClient()
	default:
		return nil
	}
}

func (p *Provider) stopServer() error {
	// Snapshot and clear fields under mu so concurrent calls and
	// ForceStop() see nil fields and skip double-teardown.
	p.mu.Lock()
	ownGRPC := p.ownGRPCServer
	listener := p.listener
	grpcServer := p.grpcServer
	p.listener = nil
	p.grpcServer = nil
	p.serverImpl = nil
	p.eventHandlers = nil
	p.heartbeatHandlers = nil
	p.mu.Unlock()

	if ownGRPC {
		// Close the QUIC listener first so that all active ControlChannel
		// streams receive an error from stream.Recv(). This unblocks
		// GracefulStop, which would otherwise wait forever for persistent
		// bidirectional streams to close on their own.
		if listener != nil {
			_ = listener.Close()
		}
		if grpcServer != nil {
			grpcServer.GracefulStop()
		}
	}
	return nil
}

func (p *Provider) stopClient() error {
	// cancel() was already called in Stop(), which will cause reconnectLoop
	// and clientReceiveLoop to exit. Clean up the connection.
	p.closeClientConn()
	p.setState(StateDisconnected)
	return nil
}

// --- Commands (Controller → Steward) ---

func (p *Provider) SendCommand(ctx context.Context, cmd *types.SignedCommand) error {
	if p.mode != ModeServer {
		return fmt.Errorf("SendCommand is only available in server mode")
	}
	if cmd == nil {
		return fmt.Errorf("SendCommand: command must not be nil")
	}

	conn, ok := p.registry.Get(cmd.Command.StewardID)
	if !ok {
		p.deliveryFailures.Add(1)
		return fmt.Errorf("steward %s not connected: %w", cmd.Command.StewardID, interfaces.ErrStewardNotConnected)
	}

	msg := &transportpb.ControlMessage{
		Payload: &transportpb.ControlMessage_Command{Command: signedCommandToProto(cmd)},
	}

	if err := conn.Send(msg); err != nil {
		p.deliveryFailures.Add(1)
		return fmt.Errorf("failed to send command to steward %s: %w", cmd.Command.StewardID, err)
	}

	p.commandsSent.Add(1)
	return nil
}

func (p *Provider) FanOutCommand(ctx context.Context, cmd *types.SignedCommand, stewardIDs []string) (*types.FanOutResult, error) {
	if p.mode != ModeServer {
		return nil, fmt.Errorf("FanOutCommand is only available in server mode")
	}
	if len(stewardIDs) == 0 {
		return nil, fmt.Errorf("stewardIDs must not be empty")
	}

	result := &types.FanOutResult{
		Failed: make(map[string]error),
	}

	msg := &transportpb.ControlMessage{
		Payload: &transportpb.ControlMessage_Command{Command: signedCommandToProto(cmd)},
	}

	conns := p.registry.GetMany(stewardIDs)

	for _, id := range stewardIDs {
		conn, ok := conns[id]
		if !ok {
			result.Failed[id] = fmt.Errorf("steward %s not connected: %w", id, interfaces.ErrStewardNotConnected)
			p.deliveryFailures.Add(1)
			continue
		}

		if err := conn.Send(msg); err != nil {
			result.Failed[id] = err
			p.deliveryFailures.Add(1)
			continue
		}

		result.Succeeded = append(result.Succeeded, id)
		p.commandsSent.Add(1)
	}

	return result, nil
}

func (p *Provider) SubscribeCommands(ctx context.Context, stewardID string, handler interfaces.CommandHandler) error {
	if p.mode != ModeClient {
		return fmt.Errorf("SubscribeCommands is only available in client mode")
	}

	p.mu.Lock()
	p.commandHandler = handler
	p.mu.Unlock()

	return nil
}

// --- Events (Steward → Controller) ---

func (p *Provider) PublishEvent(ctx context.Context, event *types.Event) error {
	if p.mode != ModeClient {
		return fmt.Errorf("PublishEvent is only available in client mode")
	}
	if event == nil {
		return fmt.Errorf("PublishEvent: event must not be nil")
	}
	if err := p.checkClientConnected(); err != nil {
		p.deliveryFailures.Add(1)
		return fmt.Errorf("failed to publish event: %w", err)
	}

	msg := &transportpb.ControlMessage{
		Payload: &transportpb.ControlMessage_Event{Event: eventToProto(event)},
	}

	if err := p.sendControlMessage(msg); err != nil {
		p.deliveryFailures.Add(1)
		return fmt.Errorf("failed to publish event: %w", err)
	}

	p.eventsPublished.Add(1)
	return nil
}

func (p *Provider) SubscribeEvents(ctx context.Context, filter *types.EventFilter, handler interfaces.EventHandler) error {
	if p.mode != ModeServer {
		return fmt.Errorf("SubscribeEvents is only available in server mode")
	}

	p.mu.Lock()
	p.eventHandlers = append(p.eventHandlers, eventSubscription{
		filter:  filter,
		handler: handler,
	})
	p.mu.Unlock()

	return nil
}

// --- Heartbeats ---

func (p *Provider) SendHeartbeat(ctx context.Context, heartbeat *types.Heartbeat) error {
	if p.mode != ModeClient {
		return fmt.Errorf("SendHeartbeat is only available in client mode")
	}
	if heartbeat == nil {
		return fmt.Errorf("SendHeartbeat: heartbeat must not be nil")
	}
	if err := p.checkClientConnected(); err != nil {
		p.deliveryFailures.Add(1)
		return fmt.Errorf("failed to send heartbeat: %w", err)
	}

	msg := &transportpb.ControlMessage{
		Payload: &transportpb.ControlMessage_Heartbeat{Heartbeat: heartbeatToProto(heartbeat)},
	}

	if err := p.sendControlMessage(msg); err != nil {
		p.deliveryFailures.Add(1)
		return fmt.Errorf("failed to send heartbeat: %w", err)
	}

	p.heartbeatsSent.Add(1)
	return nil
}

func (p *Provider) SubscribeHeartbeats(ctx context.Context, handler interfaces.HeartbeatHandler) error {
	if p.mode != ModeServer {
		return fmt.Errorf("SubscribeHeartbeats is only available in server mode")
	}

	p.mu.Lock()
	p.heartbeatHandlers = append(p.heartbeatHandlers, handler)
	p.mu.Unlock()

	return nil
}

func (p *Provider) SendResponse(ctx context.Context, response *types.Response) error {
	if p.mode != ModeClient {
		return fmt.Errorf("SendResponse is only available in client mode")
	}
	if response == nil {
		return fmt.Errorf("SendResponse: response must not be nil")
	}
	if err := p.checkClientConnected(); err != nil {
		p.deliveryFailures.Add(1)
		return fmt.Errorf("failed to send response: %w", err)
	}

	msg := &transportpb.ControlMessage{
		Payload: &transportpb.ControlMessage_Response{Response: responseToProto(response)},
	}

	if err := p.sendControlMessage(msg); err != nil {
		p.deliveryFailures.Add(1)
		return fmt.Errorf("failed to send response: %w", err)
	}

	p.responsesSent.Add(1)
	return nil
}

// dispatchEvent routes an incoming event to matching event handlers.
func (p *Provider) dispatchEvent(event *types.Event) {
	p.eventsReceived.Add(1)

	p.mu.RLock()
	handlers := make([]eventSubscription, len(p.eventHandlers))
	copy(handlers, p.eventHandlers)
	p.mu.RUnlock()

	for _, sub := range handlers {
		if sub.filter != nil && !sub.filter.Match(event) {
			continue
		}
		handler := sub.handler
		go func() {
			if err := handler(p.ctx, event); err != nil {
				p.logger.Error("event handler error", "event_id", event.ID, "error", err)
			}
		}()
	}
}

// dispatchHeartbeat routes an incoming heartbeat to all heartbeat handlers.
func (p *Provider) dispatchHeartbeat(hb *types.Heartbeat) {
	p.heartbeatsReceived.Add(1)

	p.mu.RLock()
	handlers := make([]interfaces.HeartbeatHandler, len(p.heartbeatHandlers))
	copy(handlers, p.heartbeatHandlers)
	p.mu.RUnlock()

	for _, handler := range handlers {
		handler := handler
		go func() {
			if err := handler(p.ctx, hb); err != nil {
				p.logger.Error("heartbeat handler error", "steward_id", logging.SanitizeLogValue(hb.StewardID), "error", err)
			}
		}()
	}
}

// --- Status & Monitoring ---

func (p *Provider) GetStats(ctx context.Context) (*types.ControlPlaneStats, error) {
	stats := &types.ControlPlaneStats{
		CommandsSent:       p.commandsSent.Load(),
		CommandsReceived:   p.commandsReceived.Load(),
		EventsPublished:    p.eventsPublished.Load(),
		EventsReceived:     p.eventsReceived.Load(),
		HeartbeatsSent:     p.heartbeatsSent.Load(),
		HeartbeatsReceived: p.heartbeatsReceived.Load(),
		ResponsesSent:      p.responsesSent.Load(),
		ResponsesReceived:  p.responsesReceived.Load(),
		DeliveryFailures:   p.deliveryFailures.Load(),
		IdentityMismatches: p.identityMismatches.Load(),
		ProviderMetrics:    make(map[string]interface{}),
	}

	p.mu.RLock()
	if !p.startTime.IsZero() {
		stats.Uptime = time.Since(p.startTime)
	}
	numEventHandlers := int64(len(p.eventHandlers))
	numHeartbeatHandlers := int64(len(p.heartbeatHandlers))
	lastConnected := p.lastConnectedAt
	lastDisconnected := p.lastDisconnectedAt
	p.mu.RUnlock()

	stats.ActiveSubscriptions = numEventHandlers + numHeartbeatHandlers

	if p.mode == ModeServer && p.registry != nil {
		stats.ConnectedStewards = int64(p.registry.Count())
	}

	// Client-mode reconnection metrics
	if p.mode == ModeClient {
		stats.ProviderMetrics["reconnect_attempts"] = p.reconnectAttempts.Load()
		stats.ProviderMetrics["connection_state"] = p.getState().String()
		if !lastConnected.IsZero() {
			stats.ProviderMetrics["last_connected_at"] = lastConnected
		}
		if !lastDisconnected.IsZero() {
			stats.ProviderMetrics["last_disconnected_at"] = lastDisconnected
		}
	}

	return stats, nil
}

func (p *Provider) IsConnected() bool {
	switch p.mode {
	case ModeServer:
		p.mu.RLock()
		defer p.mu.RUnlock()
		if p.ownGRPCServer {
			return p.grpcServer != nil && p.listener != nil
		}
		return p.grpcServer != nil && p.serverImpl != nil
	case ModeClient:
		return p.getState() == StateConnected
	default:
		return false
	}
}

// ListenAddr returns the actual listen address after Start() in server mode.
// Returns empty string if not started or in client mode.
func (p *Provider) ListenAddr() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.listener != nil {
		return p.listener.Addr().String()
	}
	return ""
}

// ForceStop immediately closes all connections and stops the server without
// waiting for in-progress RPCs to complete. Use in tests when GracefulStop
// would hang on long-lived ControlChannel streams.
func (p *Provider) ForceStop() {
	// Cancel the provider context and snapshot+clear shared fields under mu
	// so that concurrent Stop() calls and multiple ForceStop() invocations
	// are safe (mu also guards p.listener and p.grpcServer against races).
	p.mu.Lock()
	if p.cancel != nil {
		p.cancel()
	}
	ownGRPC := p.ownGRPCServer
	listener := p.listener
	grpcServer := p.grpcServer
	p.listener = nil
	p.grpcServer = nil
	p.serverImpl = nil
	p.mu.Unlock()

	if ownGRPC {
		if listener != nil {
			_ = listener.Close()
		}
		if grpcServer != nil {
			grpcServer.Stop()
		}
	}
}

// ServerHandler returns the CP handler that implements StewardTransportServer
// for control plane RPCs (Register, Ping, ControlChannel). Used by the controller
// to build a composite handler that delegates CP and DP RPCs appropriately.
// Returns nil if Start() has not been called.
func (p *Provider) ServerHandler() transportpb.StewardTransportServer {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.serverImpl
}

// TransportClient returns the gRPC StewardTransportClient used by this provider.
// This client shares the same gRPC-over-QUIC connection as the ControlChannel.
// Returns nil when the provider is running in server mode or before Start().
func (p *Provider) TransportClient() transportpb.StewardTransportClient {
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
	return p.grpcClient
}

// --- gRPC StewardTransportServer implementation ---

// transportServer implements the gRPC StewardTransportServer interface,
// delegating to the Provider for handler dispatch and registry management.
type transportServer struct {
	transportpb.UnimplementedStewardTransportServer
	provider *Provider
}

func (s *transportServer) Register(ctx context.Context, req *controllerpb.RegisterRequest) (*controllerpb.RegisterResponse, error) {
	// Derive steward identity from the mTLS-verified peer certificate CN.
	// req.GetCredentials().GetClientId() is caller-supplied and forgeable;
	// it must never be used as the authoritative identity source.
	stewardID, err := extractStewardIDFromPeer(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "failed to extract steward identity from mTLS certificate: %v", err)
	}

	// Tenant binding: enforced when a registration token store is wired in.
	// The authoritative tenant comes from the server-side RegistrationTokenStore lookup
	// using the token string the steward supplies in creds.ClientId. creds.TenantId is only
	// a post-derivation consistency check and must never be the source of truth.
	//
	// This block runs BEFORE the admission gate below (Issue #3759 security
	// review): the gate's bucket key must be a tenant the caller has proven, so
	// the proof has to come first.
	var verifiedTenantID string
	if ts := s.provider.registrationTokenStore; ts != nil {
		creds := req.GetCredentials()

		claimedTenantID := creds.GetTenantId()
		if claimedTenantID == "" {
			return nil, status.Error(codes.PermissionDenied, "registration rejected: creds.tenant_id must not be empty")
		}

		// creds.ClientId carries the registration token issued at HTTP registration time.
		// The identity (stewardID) is authoritative from the mTLS cert CN above; ClientId
		// is reused here as the token-string key into the server-side RegistrationTokenStore.
		tokenStr := creds.GetClientId()
		if tokenStr == "" {
			return nil, status.Error(codes.PermissionDenied, "registration rejected: no registration token provided in creds.client_id")
		}

		tokenData, lookupErr := ts.GetToken(ctx, tokenStr)
		if lookupErr != nil || tokenData == nil || !tokenData.IsValid() {
			return nil, status.Error(codes.PermissionDenied, "registration rejected: invalid or expired registration token")
		}

		if claimedTenantID != tokenData.TenantID {
			s.provider.logger.Warn("registration tenant mismatch",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"claimed_tenant", logging.SanitizeLogValue(claimedTenantID))
			return nil, status.Error(codes.PermissionDenied, "registration rejected: creds.tenant_id does not match registration token")
		}

		// The token is not spent here. Registration tokens are perennial
		// (Issue #1690) — one enrolment token is what an RMM or GPO deployment
		// bakes into a script for a whole fleet, so revoking it on first use
		// would lock out every remaining endpoint. At this point the caller has
		// already presented an mTLS client certificate that only the REST
		// issuance boundary can mint, and that boundary holds the per-device
		// single-issuance guard (RegistrationTokenClaimer). The token's role
		// here is tenant binding, which the checks above enforce.
		verifiedTenantID = tokenData.TenantID
	}

	// Per-tenant admission control (Issue #3759, ADR-031 Decision 6): the same
	// mechanism the DNA ingest path uses (TenantQueue, same per-tenant limit),
	// on its own instance, so a single tenant cannot exhaust connect capacity on
	// a shared cell.
	//
	// The bucket is keyed on server-verified state only — the tenant the
	// registration token is bound to, else the tenant on this steward's fleet
	// record, else the mTLS-verified certificate CN. creds.tenant_id is never an
	// input: it is caller-supplied, so keying on it would let any steward with a
	// valid certificate pin all of a victim tenant's connect and heartbeat slots.
	if s.provider.tenantAdmission != nil {
		bucket := s.provider.admissionBucket(ctx, stewardID, verifiedTenantID)
		if aErr := s.provider.tenantAdmission.Acquire(bucket); aErr != nil {
			return nil, status.Error(codes.ResourceExhausted, "tenant connect queue full")
		}
		defer s.provider.tenantAdmission.Release(bucket)
	}

	s.provider.logger.Info("steward registered", "steward_id", logging.SanitizeLogValue(stewardID), "version", logging.SanitizeLogValue(req.GetVersion()))

	return &controllerpb.RegisterResponse{
		StewardId: stewardID,
		Status: &commonpb.Status{
			Code:    commonpb.Status_OK,
			Message: "registered",
		},
	}, nil
}

func (s *transportServer) Ping(ctx context.Context, req *transportpb.PingRequest) (*transportpb.PingResponse, error) {
	return &transportpb.PingResponse{
		RequestTimestampNs:  req.GetTimestampNs(),
		ResponseTimestampNs: timestamppb.Now().AsTime().UnixNano(),
	}, nil
}

func (s *transportServer) ControlChannel(stream grpc.BidiStreamingServer[transportpb.ControlMessage, transportpb.ControlMessage]) error {
	// Extract steward identity from mTLS peer certificate
	p, ok := peer.FromContext(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "no peer info")
	}

	stewardID, err := extractStewardIDFromPeer(stream.Context())
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "failed to extract steward identity: %v", err)
	}

	// Approval gate hook (Issue #1719): checked before admitting the stream.
	// Store and service failures deny admission; an unavailable authorization
	// dependency must not turn into fleet-wide implicit approval.
	if s.provider.approvalChecker != nil {
		admitted, checkErr := s.provider.approvalChecker.IsApproved(stream.Context(), stewardID)
		if checkErr != nil {
			s.provider.logger.Error("steward approval check error, rejecting (fail-closed)",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", logging.SanitizeLogValue(checkErr.Error()))
			return status.Error(codes.Unavailable, "steward approval service unavailable")
		}
		if !admitted {
			s.provider.logger.Warn("steward ControlChannel rejected by approval checker",
				"steward_id", logging.SanitizeLogValue(stewardID))
			return status.Error(codes.PermissionDenied, "steward reconnect not approved")
		}
	}

	// Per-tenant admission bucket for every heartbeat on this stream (Issue
	// #3759). Resolved ONCE here, at connect, from the server-side fleet record
	// for the mTLS-verified CN — never from heartbeat.tenant_id, which is
	// caller-supplied and unverified, and which a saturated bucket would let a
	// steward use to silently drop an entire victim tenant's liveness traffic.
	// Resolving once also keeps the per-heartbeat path free of store lookups.
	var heartbeatBucket string
	if s.provider.tenantAdmission != nil {
		heartbeatBucket = s.provider.admissionBucket(stream.Context(), stewardID, "")
	}

	// Create a stream sender adapter for the registry
	sender := &streamSender{stream: stream}

	conn := &registry.StewardConnection{
		StewardID:   stewardID,
		Sender:      sender,
		ConnectedAt: time.Now(),
		RemoteAddr:  p.Addr.String(),
	}

	if err := s.provider.registry.Register(conn); err != nil {
		return status.Errorf(codes.Internal, "failed to register steward: %v", err)
	}
	// Reconnect-safe cleanup: if the steward restarts, its new ControlChannel
	// registers a fresh connection before this stale handler's stream.Recv
	// finally errors. Unregistering by ID would evict the live new connection;
	// UnregisterConn only removes this exact connection if it is still current.
	defer s.provider.registry.UnregisterConn(conn)

	// Issue #1817: fire the on-connect hook after successful registration, before
	// the receive loop, so the refresh push reaches the steward before any
	// controller-originated commands begin flowing. Fail-open: a missed refresh is
	// recoverable via the overlap window; refusing the stream is not.
	if s.provider.onConnectHook != nil {
		if hookErr := s.provider.onConnectHook.OnConnect(stream.Context(), stewardID); hookErr != nil {
			s.provider.logger.Warn("on-connect hook error, steward continues (fail-open)",
				"steward_id", logging.SanitizeLogValue(stewardID), "error", hookErr)
		}
	}

	s.provider.logger.Info("steward connected to ControlChannel", "steward_id", logging.SanitizeLogValue(stewardID), "remote_addr", logging.SanitizeLogValue(p.Addr.String()))

	// Receive loop: authenticated-CN-wins contract — the mTLS peer CN is the
	// authoritative steward identity. Empty payload StewardIDs are stamped with
	// the CN; mismatched payload StewardIDs are rejected and counted without
	// tearing down the stream (misconfiguration tolerance per Issue #828).
	for {
		msg, err := stream.Recv()
		if err != nil {
			s.provider.logger.Info("steward ControlChannel closed", "steward_id", logging.SanitizeLogValue(stewardID), "error", err)
			return nil
		}

		conn.UpdateActivity()

		switch payload := msg.GetPayload().(type) {
		case *transportpb.ControlMessage_Event:
			event := eventFromProto(payload.Event)
			if event.StewardID == "" {
				event.StewardID = stewardID
			} else if event.StewardID != stewardID {
				s.provider.logger.Warn("controlchannel event stewardID mismatch",
					"authenticated_cn", logging.SanitizeLogValue(stewardID),
					"payload_steward_id", logging.SanitizeLogValue(event.StewardID))
				s.provider.identityMismatches.Add(1)
				continue
			}
			s.provider.dispatchEvent(event)

		case *transportpb.ControlMessage_Heartbeat:
			hb := heartbeatFromProto(payload.Heartbeat)
			if hb.StewardID == "" {
				hb.StewardID = stewardID
			} else if hb.StewardID != stewardID {
				s.provider.logger.Warn("controlchannel heartbeat stewardID mismatch",
					"authenticated_cn", logging.SanitizeLogValue(stewardID),
					"payload_steward_id", logging.SanitizeLogValue(hb.StewardID))
				s.provider.identityMismatches.Add(1)
				continue
			}

			// Per-tenant admission control (Issue #3759, ADR-031 Decision 6): the
			// same queue instance as the connect gate above — and the same
			// mechanism the DNA path runs on its own instance, since that path's
			// key is wire data. Acquire/Release bracket only this one heartbeat's
			// dispatch — never deferred to stream teardown — so a saturated
			// tenant sheds its own excess heartbeats without blocking the
			// receive loop or other tenants' concurrently-connected streams.
			// The bucket is heartbeatBucket, resolved server-side at connect;
			// hb.TenantID is payload data and never selects a bucket.
			if s.provider.tenantAdmission != nil {
				if aErr := s.provider.tenantAdmission.Acquire(heartbeatBucket); aErr != nil {
					s.provider.logger.Warn("controlchannel heartbeat dropped — tenant admission queue full",
						"steward_id", logging.SanitizeLogValue(stewardID),
						"admission_bucket", logging.SanitizeLogValue(heartbeatBucket))
					continue
				}
				s.provider.dispatchHeartbeat(hb)
				s.provider.tenantAdmission.Release(heartbeatBucket)
				continue
			}
			s.provider.dispatchHeartbeat(hb)

		case *transportpb.ControlMessage_Response:
			resp := responseFromProto(payload.Response)
			if resp.StewardID == "" {
				resp.StewardID = stewardID
			} else if resp.StewardID != stewardID {
				s.provider.logger.Warn("controlchannel response stewardID mismatch",
					"authenticated_cn", logging.SanitizeLogValue(stewardID),
					"payload_steward_id", logging.SanitizeLogValue(resp.StewardID))
				s.provider.identityMismatches.Add(1)
				continue
			}
			// Response handling is currently receive-only — no controller logic
			// awaits responses. See epic #747 for the rationale (WaitForResponse
			// had zero callers). If sync-ack becomes a product need, reinstate a
			// per-(CN, CommandID)-scoped waiter with a ceiling at that time.
			s.provider.responsesReceived.Add(1)
			s.provider.logger.Debug("controlchannel response received",
				"command_id", logging.SanitizeLogValue(resp.CommandID),
				"steward_id", logging.SanitizeLogValue(resp.StewardID))
		}
	}
}

// extractStewardIDFromPeer extracts the steward ID from the peer's TLS certificate CN.
//
// The QUIC transport credentials (quictransport.TransportCredentials) bridge the
// QUIC-layer TLS state into gRPC's peer AuthInfo as credentials.TLSInfo. This
// function reads the peer certificates from that TLS state and extracts the CN.
func extractStewardIDFromPeer(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", fmt.Errorf("no peer info in context")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", fmt.Errorf("no TLS auth info in peer (got %T)", p.AuthInfo)
	}

	return quictransport.PeerStewardID(tlsInfo.State)
}

// streamSender adapts a gRPC server stream to the registry.MessageSender interface.
type streamSender struct {
	stream grpc.BidiStreamingServer[transportpb.ControlMessage, transportpb.ControlMessage]
}

func (s *streamSender) SendMsg(msg interface{}) error {
	cm, ok := msg.(*transportpb.ControlMessage)
	if !ok {
		return fmt.Errorf("expected *ControlMessage, got %T", msg)
	}
	return s.stream.Send(cm)
}
