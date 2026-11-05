// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package interfaces defines the pluggable control plane abstraction for CFGMS.
//
// The control plane handles commands, events, and heartbeats between controller
// and stewards, abstracting away transport-specific details (gRPC, WebSocket, etc.).
package interfaces

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cfgis/cfgms/pkg/controlplane/types"
)

// ErrStewardNotConnected is wrapped into the error SendCommand returns when
// the target steward has no live connection in the provider's local registry.
// A caller checks this with errors.Is rather than matching the error string,
// so that pkg/controlplane/internaldelivery (Issue #3764, ADR-031 Decision 3)
// can distinguish "not connected to this node — consult the routing table and
// try a peer" from a genuine transport failure worth surfacing as-is.
var ErrStewardNotConnected = errors.New("steward not connected")

// ErrIdentityRejected reports that the controller definitively refused the
// steward's identity: the control channel was refused as unauthenticated or not
// approved (unknown, deregistered or revoked steward). It is never returned for an
// unreachable or timed-out controller, nor for a TLS handshake failure, which can
// be transient (clock skew, an intercepting proxy) (Issue #4532).
var ErrIdentityRejected = errors.New("controller rejected steward identity")

// ErrIdentityInUse reports that the controller refused the steward's identity
// because it is, or appears to be, in use by another device: the connection is a
// copy of an approved identity (ADR-034 §2). It wraps ErrIdentityRejected so a
// caller that only cares about refusal keeps working, but it is distinct: the
// stored device key must NOT be re-presented for re-admission, because the key
// itself was copied. The steward re-keys and registers as a new device instead.
var ErrIdentityInUse = fmt.Errorf("steward identity in use by another device: %w", ErrIdentityRejected)

// LockedDownReason and LockedDownDomain identify the typed lockdown refusal: a
// FailedPrecondition status carrying an ErrorInfo detail with this reason. The
// controller returns it from a pull (SyncConfig, FetchModuleBundle,
// BulkTransfer) to a steward it has locked; the steward then enters report-only
// and stops pulling.
const (
	LockedDownReason = "controller.locked_down"
	LockedDownDomain = "cfgms.io"
)

// NewLockedDownError builds the typed lockdown refusal. The text is fixed.
func NewLockedDownError() error {
	st := status.New(codes.FailedPrecondition, "steward is locked down by the controller")
	withDetail, err := st.WithDetails(&errdetails.ErrorInfo{Reason: LockedDownReason, Domain: LockedDownDomain})
	if err != nil {
		return st.Err()
	}
	return withDetail.Err()
}

// IsLockedDown reports whether err is, or wraps, the typed lockdown refusal.
func IsLockedDown(err error) bool {
	if err == nil {
		return false
	}
	s, ok := status.FromError(err)
	if !ok || s.Code() != codes.FailedPrecondition {
		return false
	}
	for _, d := range s.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok &&
			info.GetReason() == LockedDownReason && info.GetDomain() == LockedDownDomain {
			return true
		}
	}
	return false
}

// ControlPlaneProvider defines the interface for control plane implementations.
//
// The control plane is responsible for command/event/heartbeat communication
// between controllers and stewards. It provides semantic methods that hide
// transport-specific details like topics, QoS levels, and subscriptions.
// SendResponse is not part of this interface — it lives on the concrete
// *grpc.Provider to prevent cross-steward response injection (epic #747).
//
// Implementations must be thread-safe and support concurrent operations.
type ControlPlaneProvider interface {
	// Name returns the provider name (e.g., "grpc", "websocket")
	Name() string

	// Initialize configures the provider with implementation-specific settings
	//
	// The config map contains provider-specific configuration. Common keys:
	//   - "broker_addr": string - Broker/server address
	//   - "client_id": string - Client identifier
	//   - "tls_config": *tls.Config - TLS configuration
	//   - "steward_id": string - Steward ID (for client mode)
	Initialize(ctx context.Context, config map[string]interface{}) error

	// Start begins control plane operation
	//
	// For server-side (controller): Starts listening for connections
	// For client-side (steward): Connects to the controller
	Start(ctx context.Context) error

	// Stop gracefully shuts down the control plane
	//
	// Disconnects all connections and stops accepting new ones.
	// The context can be used to force shutdown if graceful shutdown times out.
	Stop(ctx context.Context) error

	// Reconnect tears down the current connection and re-establishes it without
	// cancelling the provider's internal context (client mode only).
	// Returns an error if called on a server-mode provider.
	Reconnect(ctx context.Context) error

	// =================================================================
	// Commands (Controller → Steward)
	// =================================================================

	// SendCommand sends a signed command to a specific steward.
	//
	// The cmd envelope must already be signed by the controller before calling
	// this method. The transport layer carries the signature intact; verification
	// is performed by the steward handler on receipt.
	//
	// Returns an error if the command cannot be delivered. Does not wait
	// for command execution — use SubscribeEvents to receive completion events.
	SendCommand(ctx context.Context, cmd *types.SignedCommand) error

	// FanOutCommand sends a signed command to a specific list of stewards.
	//
	// The caller is responsible for resolving target steward IDs (by tenant,
	// search results, online status, etc.). The transport layer delivers to
	// each steward without knowledge of organizational hierarchy.
	//
	// Returns FanOutResult with per-steward delivery status. The error return
	// is for systemic failures (provider not started, etc.), not per-steward
	// delivery failures which are reported in FanOutResult.Failed.
	FanOutCommand(ctx context.Context, cmd *types.SignedCommand, stewardIDs []string) (*types.FanOutResult, error)

	// SubscribeCommands subscribes to commands (steward-side)
	//
	// The handler is called for each command received by this steward.
	// Returns an error if subscription fails.
	SubscribeCommands(ctx context.Context, stewardID string, handler CommandHandler) error

	// SendTamperState tells a connected steward whether the controller considers
	// its host locked (controller-side). The message carries only the flag; the
	// steward honors locked=true always and locked=false only on a session whose
	// server certificate verified against its trust anchor.
	SendTamperState(ctx context.Context, stewardID string, locked bool) error

	// SendRepair delivers a repair request to a connected steward
	// (controller-side). The steward link only receives it and hands it to the
	// repair handler, which checks the signature and the approved-loss list.
	SendRepair(ctx context.Context, stewardID string, req types.RepairRequest) error

	// =================================================================
	// Events (Steward → Controller)
	// =================================================================

	// PublishEvent publishes an event from steward to controller
	//
	// Events notify the controller of significant occurrences (command
	// completion, errors, state changes, etc.).
	PublishEvent(ctx context.Context, event *types.Event) error

	// SubscribeEvents subscribes to events matching a filter (controller-side)
	//
	// The handler is called for each matching event. Use EventFilter to
	// subscribe to specific stewards, tenants, or event types.
	SubscribeEvents(ctx context.Context, filter *types.EventFilter, handler EventHandler) error

	// =================================================================
	// Heartbeats (Bidirectional)
	// =================================================================

	// SendHeartbeat sends a heartbeat from steward to controller
	//
	// Heartbeats allow the controller to monitor steward connectivity
	// and health. Typically sent on a periodic interval (e.g., every 30s).
	SendHeartbeat(ctx context.Context, heartbeat *types.Heartbeat) error

	// SubscribeHeartbeats subscribes to heartbeats (controller-side)
	//
	// The handler is called for each heartbeat received. Use this to
	// detect steward connectivity and health status changes.
	SubscribeHeartbeats(ctx context.Context, handler HeartbeatHandler) error

	// =================================================================
	// Status & Monitoring
	// =================================================================

	// GetStats returns provider operational statistics
	GetStats(ctx context.Context) (*types.ControlPlaneStats, error)

	// IsConnected reports connection status
	//
	// For server-side: true if accepting connections
	// For client-side: true if connected to server
	IsConnected() bool
}

// CommandHandler is called when a signed command is received (steward-side).
//
// The handler receives the full SignedCommand envelope so that it can verify
// the signature and metadata (StewardID, replay window) before dispatching.
// The handler should publish events/responses to notify the controller of
// progress and completion.
type CommandHandler func(ctx context.Context, cmd *types.SignedCommand) error

// EventHandler is called when an event is received (controller-side).
//
// Events provide asynchronous notifications from stewards about state
// changes, command progress, and significant occurrences.
type EventHandler func(ctx context.Context, event *types.Event) error

// HeartbeatHandler is called when a heartbeat is received (controller-side).
//
// Heartbeats allow monitoring of steward connectivity and health status.
type HeartbeatHandler func(ctx context.Context, heartbeat *types.Heartbeat) error

// ResponseHandler is called when a steward response is received (controller-side).
//
// The provider guarantees resp.StewardID is the authenticated identity of the
// sending steward before the handler runs (Issue #4569).
type ResponseHandler func(ctx context.Context, resp *types.Response) error

// ResponseSender is an optional capability of a client-mode provider: it sends a
// steward-originated Response (for example a receive-path rejection) to the
// controller. It is deliberately not part of ControlPlaneProvider (epic #747);
// callers type-assert for it. Only client-mode providers may send.
type ResponseSender interface {
	SendResponse(ctx context.Context, response *types.Response) error
}

// ResponseSubscriber is an optional capability of a server-mode provider: it
// delivers every response received from a connected steward to the handler.
// Only server-mode providers may subscribe.
type ResponseSubscriber interface {
	SubscribeResponses(ctx context.Context, handler ResponseHandler) error
}

// PeerChain returns the certificate chain the server presented on the stream a
// message arrived on, leaf first. After a reconnect to a different server it is
// that server's chain. It is nil when the transport carries no certificates.
type PeerChain func() []*x509.Certificate

// InboundHooks are the narrow callbacks a client-mode provider calls for the
// few inbound message kinds a report-only steward accepts. Every other inbound
// payload is dropped and counted through OnDropped.
//
// anchorVerified reports whether the session's server certificate verified
// against the steward's trust anchor: the install-pinned CA, or the CA pin
// recorded in the identity. Both are data-folder material, so neither ranks
// above the other, and the baked fingerprint plays no part in this check.
type InboundHooks struct {
	// OnTamperState receives a well-formed TamperState. locked=true is always
	// delivered; locked=false is delivered only when anchorVerified is true.
	OnTamperState func(locked bool)

	// OnRepair receives a RepairRequest that carries a repair ID, on a session
	// that passed the anchor check. It is not called on any other session.
	OnRepair func(req types.RepairRequest)

	// OnCommand receives commands while report-only (a locked-trust handler).
	// When nil, report-only drops commands and counts them.
	OnCommand func(ctx context.Context, cmd *types.SignedCommand, peerChain PeerChain) error

	// OnDropped is told the kind of each inbound payload the receive switch
	// dropped: "command", "event", "heartbeat", "response", "unknown",
	// "tamper_state" and "repair_request" for ignored or malformed signals.
	OnDropped func(kind string)
}

// InboundController is an optional capability of a client-mode provider: it
// accepts the inbound callbacks and the report-only switch. Callers
// type-assert for it.
type InboundController interface {
	// SetInboundHooks replaces the provider's inbound callbacks.
	SetInboundHooks(hooks InboundHooks)

	// SetReportOnly switches the receive switch between normal operation and
	// report-only. In report-only the provider hands commands only to
	// InboundHooks.OnCommand and drops every other payload.
	SetReportOnly(on bool)
}

// ErrStewardLockedDown is returned to a controller caller when the command gate
// refuses a command to a locked-down (tampered) steward. It is distinct from
// ErrStewardNotConnected so a refusal is never mistaken for "try a peer node" or
// "retry later". The steward never sees it; the steward-side handling of a
// refused pull is the typed gRPC error above.
var ErrStewardLockedDown = errors.New("steward is locked down: command refused")

// LockdownChecker is the one-method view of the lockdown predicate the command
// gate consumes. A non-nil error means the status could not be established; the
// gate then refuses the command (fail closed).
type LockdownChecker interface {
	IsLockedDown(ctx context.Context, stewardID string) (bool, error)
}

// LockdownObserver receives the gate's audit events. Nil disables auditing.
type LockdownObserver interface {
	// CommandRefused is told once per refused command. reason is a short fixed
	// token, never caller text.
	CommandRefused(ctx context.Context, stewardID string, cmdType types.CommandType, reason string)

	// OperatorCommandAllowed is told of every operator-origin command the gate
	// lets through to a locked-down steward.
	OperatorCommandAllowed(ctx context.Context, operator, stewardID string, cmdType types.CommandType)
}

// LockdownPolicy classifies one command type for a locked-down steward.
type LockdownPolicy int

const (
	// LockdownDenied is refused for a locked-down steward even when
	// operator-originated, until an operator restore. It is the zero value, so a
	// command type missing from CommandLockdownPolicy is denied by default.
	LockdownDenied LockdownPolicy = iota

	// LockdownOperatorOnly is delivered to a locked-down steward only when the
	// context carries the operator-origin marker.
	LockdownOperatorOnly
)

// CommandLockdownPolicy is the one allow-list of command types that may reach a
// locked-down steward. Anything not listed is denied, so a new command type must
// opt in here. Every automated or controller-originated command is denied
// regardless of this table, because it carries no operator-origin marker.
var CommandLockdownPolicy = map[types.CommandType]LockdownPolicy{
	types.CommandExecuteScript:  LockdownOperatorOnly,
	types.CommandOpenTerminal:   LockdownOperatorOnly,
	types.CommandStewardAction:  LockdownOperatorOnly,
	types.CommandObserveModules: LockdownOperatorOnly,
	// sync_dna is a request with no data to the endpoint; reconnect carries no information.
	types.CommandSyncDNA:   LockdownOperatorOnly,
	types.CommandReconnect: LockdownOperatorOnly,
	// relay_response is stamped only for a relay request that belongs to an open
	// execution an operator started on that steward.
	types.CommandRelayResponse: LockdownOperatorOnly,

	types.CommandSyncConfig:        LockdownDenied,
	types.CommandPushSigningCert:   LockdownDenied,
	types.CommandPushStewardBinary: LockdownDenied,
}

type operatorOriginKey struct{}

// WithOperatorOrigin returns ctx carrying the operator-origin marker. It is the
// storage primitive behind features/controller/commands.NewOperatorOrigin, the
// only constructor controller code may use, and behind the peer-authenticated
// restore in internaldelivery. An empty principal yields no marker. A test
// pins the set of non-test callers.
func WithOperatorOrigin(ctx context.Context, principal string) context.Context {
	if principal == "" {
		return ctx
	}
	return context.WithValue(ctx, operatorOriginKey{}, principal)
}

// OperatorOriginFrom reports the operator principal carried on ctx.
func OperatorOriginFrom(ctx context.Context) (string, bool) {
	principal, ok := ctx.Value(operatorOriginKey{}).(string)
	return principal, ok && principal != ""
}

// LockdownGate is the server-side, default-deny gate on controller-pushed
// commands. A provider calls Check before it looks the steward up in its
// registry, so a locked steward attached to another node is refused here and
// never forwarded.
type LockdownGate struct {
	checker  LockdownChecker
	observer LockdownObserver
}

// NewLockdownGate builds a gate over the predicate. observer may be nil.
func NewLockdownGate(checker LockdownChecker, observer LockdownObserver) *LockdownGate {
	return &LockdownGate{checker: checker, observer: observer}
}

// Check returns nil when cmdType may be delivered to stewardID, and
// ErrStewardLockedDown when it must be refused. A lookup error refuses.
func (g *LockdownGate) Check(ctx context.Context, stewardID string, cmdType types.CommandType) error {
	_, err := g.CheckLocked(ctx, stewardID, cmdType)
	return err
}

// CheckLocked is Check that also reports whether the steward is locked down, so
// a caller that attaches the signer chain to a locked steward's commands needs
// one predicate lookup, not two. locked is false when err is non-nil.
func (g *LockdownGate) CheckLocked(ctx context.Context, stewardID string, cmdType types.CommandType) (locked bool, err error) {
	if g == nil || g.checker == nil {
		return false, nil
	}
	locked, err = g.checker.IsLockedDown(ctx, stewardID)
	if err != nil {
		g.refuse(ctx, stewardID, cmdType, "lookup_failed")
		return false, ErrStewardLockedDown
	}
	if !locked {
		return false, nil
	}
	if CommandLockdownPolicy[cmdType] != LockdownOperatorOnly {
		g.refuse(ctx, stewardID, cmdType, "command_type_denied")
		return false, ErrStewardLockedDown
	}
	operator, ok := OperatorOriginFrom(ctx)
	if !ok {
		g.refuse(ctx, stewardID, cmdType, "no_operator_origin")
		return false, ErrStewardLockedDown
	}
	if g.observer != nil {
		g.observer.OperatorCommandAllowed(ctx, operator, stewardID, cmdType)
	}
	return true, nil
}

func (g *LockdownGate) refuse(ctx context.Context, stewardID string, cmdType types.CommandType, reason string) {
	if g.observer != nil {
		g.observer.CommandRefused(ctx, stewardID, cmdType, reason)
	}
}
