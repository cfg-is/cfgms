// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/transport/registry"
	"google.golang.org/grpc"
)

// StewardOnConnectHook is called after a steward successfully registers on the
// ControlChannel. The controller uses it to push state that must be current on
// every (re)connect — e.g. the latest signing cert set (Issue #1817).
//
// The hook runs on its own goroutine beside the stream's receive loop, so it may
// wait on a reply from the steward. Its context ends when the stream does:
// implementations must return when it is cancelled.
//
// Errors are logged at Warn and do not tear down the stream (fail-open). A missed
// refresh push is recoverable via the overlap window; refusing the stream is not.
//
// The default behaviour (no hook injected) is a no-op: the hook is only called
// when a non-nil implementation is injected via WithOnConnectHook.
type StewardOnConnectHook interface {
	// OnConnect is called once per successful ControlChannel registration.
	// stewardID is the mTLS-authenticated CN of the connecting steward.
	OnConnect(ctx context.Context, stewardID string) error
}

// WithOnConnectHook injects a StewardOnConnectHook into the Provider.
// The hook fires after registry.Register succeeds, as the receive loop starts, so
// the refresh push is the first thing the hook sends on the stream.
// Following the WithApprovalChecker pattern (approval.go).
func WithOnConnectHook(hook StewardOnConnectHook) option {
	return func(p *Provider) {
		p.onConnectHook = hook
	}
}

// --- Capability declaration (control channel) ---

// DefaultCapabilityGrace is how long a new connection may stay pending before it
// is settled at the floor profile. A steward declares as the first message on its
// stream, so the grace only has to cover one round trip on a slow link; a steward
// build that predates declarations never sends one and runs on the floor.
const DefaultCapabilityGrace = 5 * time.Second

// capabilityResetTimeout bounds the synchronous durable reset in the
// registration path, so a stalled store cannot hold a stream's admission open.
const capabilityResetTimeout = 5 * time.Second

// capabilityWriteTimeout bounds one durable capability write.
const capabilityWriteTimeout = 10 * time.Second

// CapabilityRecorder keeps a connection's durable capability record. The
// controller service implements it; the provider cannot import it, so it is
// injected with WithCapabilityRecorder (the seam WithOnConnectHook uses).
//
// A connection is identified by conn.StewardID and conn.ConnectionID. Every
// write is keyed to the connection ID, so a late write from an old stream cannot
// overwrite a newer connection's record.
type CapabilityRecorder interface {
	// ResetCapabilities starts the connection's record in the pending state,
	// replacing whatever an earlier connection stored. It is called
	// synchronously in the registration path, before the receive loop starts and
	// before any on-connect hook runs, so a declaration sent right after the
	// stream opens is never overwritten by the reset. An error leaves the stored
	// record belonging to an older connection: the provider then treats the
	// connection as pending and writes nothing durable for it.
	ResetCapabilities(ctx context.Context, conn *registry.StewardConnection) error

	// DeclareCapabilities stores profile (state declared or floor) for the
	// connection as a compare-and-set on the connection ID. applied=false means a
	// newer connection owns the record. It is called off the receive loop and may
	// block on the store.
	DeclareCapabilities(ctx context.Context, conn *registry.StewardConnection, profile types.CapabilityProfile) (applied bool, err error)

	// CapabilityConnectionClosed is called once when the connection's stream
	// ends, so the recorder can drop what it holds for the connection.
	CapabilityConnectionClosed(conn *registry.StewardConnection)
}

// WithCapabilityRecorder injects the recorder of the connections' durable
// capability records (server mode). Without one the connection state lives in
// memory only.
func WithCapabilityRecorder(r CapabilityRecorder) option {
	return func(p *Provider) {
		p.capabilityRecorder = r
	}
}

// WithCapabilityGrace sets how long a connection may stay pending before it is
// settled at the floor profile. A non-positive value restores
// DefaultCapabilityGrace.
func WithCapabilityGrace(d time.Duration) option {
	return func(p *Provider) {
		p.capabilityGrace = d
	}
}

// WithOnLateCapabilities sets a callback run once when a steward's declaration
// arrives after the grace period already settled its connection at the floor
// profile, so work done on the floor assumption can be redone. It runs on its own
// goroutine, never on the receive loop; its context ends with the stream. A
// second declaration on the same connection does not call it again.
func WithOnLateCapabilities(cb func(ctx context.Context, stewardID string)) option {
	return func(p *Provider) {
		p.onLateCapabilities = cb
	}
}

// WithStewardCapabilities sets the declaration a client-mode provider sends as
// the first message of every stream it opens, including each reconnect. It
// replaces nothing the controller sends: the controller never replies, and the
// provider never waits for a reply, so it works against a controller that
// predates declarations.
func WithStewardCapabilities(caps types.StewardCapabilities) option {
	return func(p *Provider) {
		cp := caps
		cp.CommandTypes = append([]int32(nil), caps.CommandTypes...)
		cp.SigningPayloadVersions = append([]uint32(nil), caps.SigningPayloadVersions...)
		p.declaredCaps = &cp
	}
}

func (p *Provider) capabilityGracePeriod() time.Duration {
	if p.capabilityGrace > 0 {
		return p.capabilityGrace
	}
	return DefaultCapabilityGrace
}

// declareCapabilitiesOnStream sends the remembered declaration as the first
// message of a stream that was just opened. A failed send is only logged: a
// stream the server refused reports its status on the first receive, and the
// controller settles a silent steward at the floor profile.
func (p *Provider) declareCapabilitiesOnStream(stream grpc.BidiStreamingClient[transportpb.ControlMessage, transportpb.ControlMessage]) {
	p.declaredCapsMu.Lock()
	caps := p.declaredCaps
	p.declaredCapsMu.Unlock()
	if caps == nil {
		return
	}
	msg := &transportpb.ControlMessage{
		Payload: &transportpb.ControlMessage_Capabilities{Capabilities: capabilitiesToProto(caps)},
	}
	if err := stream.Send(msg); err != nil {
		p.logger.Debug("capability declaration not sent on new stream",
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// newConnectionID returns a random identifier for one connection. crypto/rand.Read
// does not return an error: it ends the process if the system source fails.
func newConnectionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// resetConnectionCapabilities puts a newly admitted connection in the pending
// state durably. It returns before the receive loop starts. A failure marks the
// connection so its profile is never taken from the stored record, which then
// belongs to an older connection. The returned function tells the recorder the
// connection ended; the caller defers it.
func (s *transportServer) resetConnectionCapabilities(ctx context.Context, conn *registry.StewardConnection) (closed func()) {
	rec := s.provider.capabilityRecorder
	if rec == nil {
		return func() {}
	}
	rctx, cancel := context.WithTimeout(ctx, capabilityResetTimeout)
	defer cancel()
	if err := rec.ResetCapabilities(rctx, conn); err != nil {
		conn.MarkCapabilityDurableLost()
		s.provider.logger.Warn("capability record reset failed; connection stays pending",
			"steward_id", logging.SanitizeLogValue(conn.StewardID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
	return func() { rec.CapabilityConnectionClosed(conn) }
}

// beginCapabilityWrite registers one capability writer goroutine with the
// provider and returns the context its writes run under: the provider's lifetime
// context, which Stop and ForceStop cancel. It refuses (ok=false) once shutdown
// has begun, so no writer starts after Stop or ForceStop and Add never races the
// Wait in drainCapabilityWrites. The caller must call endCapabilityWrite when the
// goroutine exits.
func (p *Provider) beginCapabilityWrite() (ctx context.Context, ok bool) {
	p.mu.RLock()
	ctx = p.ctx
	p.mu.RUnlock()
	if ctx == nil {
		// Never started: nothing can cancel the write, but nothing waits on it either.
		ctx = context.Background()
	}

	p.capWriteMu.Lock()
	defer p.capWriteMu.Unlock()
	if p.capWriteStopping {
		return nil, false
	}
	p.capWriteWG.Add(1)
	return ctx, true
}

func (p *Provider) endCapabilityWrite() {
	p.capWriteWG.Done()
}

// stopCapabilityWrites makes the provider refuse new capability writers. Stop and
// ForceStop call it together with cancelling the provider context.
func (p *Provider) stopCapabilityWrites() {
	p.capWriteMu.Lock()
	p.capWriteStopping = true
	p.capWriteMu.Unlock()
}

// resumeCapabilityWrites lets a restarted provider accept capability writers
// again; Start re-creates the provider context they run under.
func (p *Provider) resumeCapabilityWrites() {
	p.capWriteMu.Lock()
	p.capWriteStopping = false
	p.capWriteMu.Unlock()
}

// drainCapabilityWrites waits until every tracked capability writer goroutine has
// exited, or ctx ends. Shutdown cancels the writers' context first, so the wait is
// short unless a recorder ignores its context.
func (p *Provider) drainCapabilityWrites(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		p.capWriteWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("capability writes still running at shutdown: %w", ctx.Err())
	}
}

// capabilityWriter serialises one connection's durable capability writes off the
// receive loop. It keeps only the latest request while a write is running, so a
// slow store neither blocks the loop nor lets an earlier state overwrite a later
// one for the connection.
type capabilityWriter struct {
	mu      sync.Mutex
	next    *types.CapabilityProfile
	running bool
}

// submit queues profile and starts the writer goroutine when none is running. The
// goroutine is tracked by p and runs write under the provider's lifetime context.
// It reports false, and drops profile, when shutdown has begun.
func (w *capabilityWriter) submit(p *Provider, profile types.CapabilityProfile, write func(context.Context, types.CapabilityProfile)) bool {
	w.mu.Lock()
	if w.running {
		w.next = &profile
		w.mu.Unlock()
		return true
	}
	ctx, ok := p.beginCapabilityWrite()
	if !ok {
		w.mu.Unlock()
		return false
	}
	w.next = &profile
	w.running = true
	w.mu.Unlock()

	go func() {
		defer p.endCapabilityWrite()
		for {
			w.mu.Lock()
			job := w.next
			w.next = nil
			if job == nil {
				w.running = false
				w.mu.Unlock()
				return
			}
			w.mu.Unlock()
			write(ctx, *job)
		}
	}()
	return true
}

// persistConnectionCapabilities queues the connection's new profile for the
// durable record. It never blocks; the write runs on the connection's writer. The
// write outlives its stream (the compare-and-set on the connection ID keeps a late
// write harmless) but not the provider: Stop and ForceStop cancel it and wait for
// it.
func (s *transportServer) persistConnectionCapabilities(conn *registry.StewardConnection, w *capabilityWriter, profile types.CapabilityProfile) {
	rec := s.provider.capabilityRecorder
	if rec == nil {
		return
	}
	if conn.CapabilityDurableLost() {
		s.provider.logger.Debug("capability write skipped: durable reset failed for this connection",
			"steward_id", logging.SanitizeLogValue(conn.StewardID))
		return
	}
	queued := w.submit(s.provider, profile, func(providerCtx context.Context, profile types.CapabilityProfile) {
		wctx, cancel := context.WithTimeout(providerCtx, capabilityWriteTimeout)
		defer cancel()
		applied, err := rec.DeclareCapabilities(wctx, conn, profile)
		switch {
		case err != nil:
			s.provider.logger.Warn("capability record write failed",
				"steward_id", logging.SanitizeLogValue(conn.StewardID),
				"state", profile.State,
				"error", logging.SanitizeLogValue(err.Error()))
		case !applied:
			s.provider.logger.Debug("capability record write superseded by a newer connection",
				"steward_id", logging.SanitizeLogValue(conn.StewardID), "state", profile.State)
		}
	})
	if !queued {
		s.provider.logger.Debug("capability write dropped: provider is shutting down",
			"steward_id", logging.SanitizeLogValue(conn.StewardID), "state", profile.State)
	}
}

// runCapabilityGrace settles the connection at the floor profile when its grace
// period ends with no declaration. It ends with the stream, or as soon as the
// connection settles.
func (s *transportServer) runCapabilityGrace(ctx context.Context, conn *registry.StewardConnection, w *capabilityWriter) {
	timer := time.NewTimer(s.provider.capabilityGracePeriod())
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-conn.CapabilitiesSettled():
		return
	case <-timer.C:
	}
	floor := types.FloorProfile()
	if changed, _ := conn.SettleCapabilities(registry.CapabilityFloor, floor.CommandTypes, floor.SigningPayloadVersions); !changed {
		return
	}
	s.provider.logger.Info("steward declared no capabilities within the grace period; using the floor profile",
		"steward_id", logging.SanitizeLogValue(conn.StewardID))
	s.persistConnectionCapabilities(conn, w, floor)
}

// receiveCapabilities handles a steward's declaration on the receive loop. It
// updates the connection's in-memory state inline and queues the durable write;
// it never waits on the store. The authenticated identity wins: a declaration
// naming another steward is rejected. The lists are untrusted, so unknown command
// type numbers are ignored and the lists are capped.
func (s *transportServer) receiveCapabilities(ctx context.Context, pb *transportpb.StewardCapabilities, stewardID string, conn *registry.StewardConnection, w *capabilityWriter) {
	caps := capabilitiesFromProto(pb)
	if caps == nil {
		return
	}
	if caps.StewardID != "" && caps.StewardID != stewardID {
		s.provider.logger.Warn("controlchannel capabilities stewardID mismatch",
			"authenticated_cn", logging.SanitizeLogValue(stewardID),
			"payload_steward_id", logging.SanitizeLogValue(caps.StewardID))
		s.provider.identityMismatches.Add(1)
		return
	}
	cmds, vers := types.NormalizeCapabilityLists(caps.CommandTypes, caps.SigningPayloadVersions, isKnownCommandTypeNumber)
	if len(cmds) == 0 || len(vers) == 0 {
		s.provider.logger.Warn("steward capability declaration carries nothing usable; ignored",
			"steward_id", logging.SanitizeLogValue(stewardID))
		return
	}

	changed, late := conn.SettleCapabilities(registry.CapabilityDeclared, cmds, vers)
	if !changed {
		return
	}
	s.persistConnectionCapabilities(conn, w, types.CapabilityProfile{
		State:                  types.CapabilityDeclared,
		CommandTypes:           cmds,
		SigningPayloadVersions: vers,
	})
	if late {
		s.provider.logger.Info("steward declared capabilities after the grace period",
			"steward_id", logging.SanitizeLogValue(stewardID))
		if cb := s.provider.onLateCapabilities; cb != nil {
			go s.runLateCapabilities(ctx, cb, stewardID)
		}
	}
}

// runLateCapabilities runs the late-declaration callback. A panic is logged and
// never ends the stream.
func (s *transportServer) runLateCapabilities(ctx context.Context, cb func(context.Context, string), stewardID string) {
	defer func() {
		if r := recover(); r != nil {
			s.provider.logger.Error("late-capabilities callback panicked",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"panic", logging.SanitizeLogValue(fmt.Sprint(r)))
		}
	}()
	cb(ctx, stewardID)
}
