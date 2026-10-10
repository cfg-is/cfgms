// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/pkg/cert"
	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

const (
	// stewardMigrationStepTimeout bounds one candidate attempt. A steward rejects a
	// command signed by a key it does not trust silently, so the timeout is the
	// only signal that a candidate key was the wrong one.
	stewardMigrationStepTimeout = 10 * time.Second

	// stewardMigrationRetryBackoff is the least time between two migration
	// attempts for one steward. With N legacy signers an attempt can cost N
	// timeouts, so a steward that cannot be migrated is not retried more often.
	stewardMigrationRetryBackoff = 5 * time.Minute

	// stewardMigrationReconcileInterval is how often the stewards connected to
	// this node are re-checked, so stewards connected before the shared
	// certificate became active are migrated without reconnecting.
	stewardMigrationReconcileInterval = 30 * time.Second

	// stewardMigrationMaxWorkers is the per-node cap on stewards migrated at once.
	stewardMigrationMaxWorkers = 8

	// stewardMigrationQueueSize bounds the pending-steward queue. A steward that
	// does not fit is picked up by the next reconcile pass.
	stewardMigrationQueueSize = 4096

	// stewardMigrationPlanTTL bounds how long the shared and legacy signers are
	// reused, so a worker does not read the key store for every steward.
	stewardMigrationPlanTTL = 5 * time.Second

	// MaxMigrationUnconfirmedListed bounds the unconfirmed steward IDs the
	// progress report names.
	MaxMigrationUnconfirmedListed = 100
)

// ErrStewardMigrationNotShared is returned by Progress when this node is not in
// Shared signing identity mode, so there is no shared certificate to report on.
var ErrStewardMigrationNotShared = errors.New("signing identity is not in shared mode")

// ErrStewardMigrationUnavailable is returned by Progress when the service lacks
// the controller service it counts stewards through.
var ErrStewardMigrationUnavailable = errors.New("steward signing migration is not fully wired")

// connectedStewards lists the stewards connected to this node.
type connectedStewards interface {
	GetAll() map[string]*registry.StewardConnection
}

// StewardSigningMigrationProgress is the fleet-wide state of the migration.
type StewardSigningMigrationProgress struct {
	SharedSerial string
	Stewards     int
	Confirmed    int
	// Unconfirmed names at most MaxMigrationUnconfirmedListed stewards, sorted.
	Unconfirmed []string
	// UnconfirmedTruncated is true when more stewards are unconfirmed than listed.
	UnconfirmedTruncated bool
}

type legacySigner struct {
	serial string
	signer signature.Signer
}

// migrationPlan is the key material one migration pass works from. It holds
// signers, never the key bytes, and is never logged.
type migrationPlan struct {
	sharedSerial   string
	sharedSigner   signature.Signer
	legacy         []legacySigner
	certParam      string
	overlapExpires string
	retireSerials  []string
	resolvedAt     time.Time
}

// StewardSigningMigrationService moves the stewards connected to this node onto
// the shared signing certificate (Issue #4797) and then retires the legacy
// node-local signing certificates from them. It runs on every node: only the node
// holding a steward's stream receives that steward's completion events, so each
// node migrates its own connected stewards and records the confirmation in the
// cluster-visible acknowledgement store.
//
// Per steward, with every step waiting for the steward's completion event:
//  1. push the shared certificate signed by the shared key; completing proves the
//     steward already trusts the shared key;
//  2. otherwise push it signed by each legacy migration signer in turn; the first
//     to complete proves the key the steward trusts;
//  3. a confirmation push signed by the shared key; completing proves the steward
//     trusts the shared key;
//  4. record the confirmation, and only then push, signed by the shared key,
//     retire_serials naming every legacy migration serial.
//
// Nothing here runs on the connect path: OnConnect only queues the steward for a
// bounded worker pool.
type StewardSigningMigrationService struct {
	certManager *cert.Manager
	acks        certinterfaces.SigningTrustAckStore
	logger      logging.Logger

	stepTimeout       time.Duration
	retryBackoff      time.Duration
	reconcileInterval time.Duration
	maxWorkers        int
	planTTL           time.Duration
	now               func() time.Time

	mu                sync.Mutex
	publisher         *commands.Publisher
	connected         connectedStewards
	controllerService *ControllerService
	queue             chan string
	queued            map[string]struct{}  // queued or being worked
	nextAttempt       map[string]time.Time // earliest next attempt per steward
	retirePending     map[string]string    // steward -> shared serial whose retire push failed
	plan              *migrationPlan

	runMu  sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// NewStewardSigningMigrationService creates the service. The publisher, the
// connected-steward source and the controller service are injected afterwards
// (the publisher does not exist until the control plane does).
func NewStewardSigningMigrationService(certManager *cert.Manager, acks certinterfaces.SigningTrustAckStore, logger logging.Logger) *StewardSigningMigrationService {
	return &StewardSigningMigrationService{
		certManager:       certManager,
		acks:              acks,
		logger:            logger,
		stepTimeout:       stewardMigrationStepTimeout,
		retryBackoff:      stewardMigrationRetryBackoff,
		reconcileInterval: stewardMigrationReconcileInterval,
		maxWorkers:        stewardMigrationMaxWorkers,
		planTTL:           stewardMigrationPlanTTL,
		now:               time.Now,
		queue:             make(chan string, stewardMigrationQueueSize),
		queued:            make(map[string]struct{}),
		nextAttempt:       make(map[string]time.Time),
		retirePending:     make(map[string]string),
	}
}

// SetPublisher injects the command publisher.
func (s *StewardSigningMigrationService) SetPublisher(p *commands.Publisher) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publisher = p
}

// SetConnectedStewards injects the registry listing this node's stewards.
func (s *StewardSigningMigrationService) SetConnectedStewards(c connectedStewards) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connected = c
}

// SetControllerService injects the service Progress counts stewards through.
func (s *StewardSigningMigrationService) SetControllerService(cs *ControllerService) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.controllerService = cs
}

// SetTimings overrides the step timeout, retry backoff and reconcile interval.
// Non-positive values are ignored. Call before Start.
func (s *StewardSigningMigrationService) SetTimings(stepTimeout, retryBackoff, reconcileInterval time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if stepTimeout > 0 {
		s.stepTimeout = stepTimeout
	}
	if retryBackoff > 0 {
		s.retryBackoff = retryBackoff
	}
	if reconcileInterval > 0 {
		s.reconcileInterval = reconcileInterval
	}
}

// SetMaxWorkers overrides the worker-pool size. Call before Start.
func (s *StewardSigningMigrationService) SetMaxWorkers(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > 0 {
		s.maxWorkers = n
	}
}

// OnConnect implements the StewardOnConnectHook interface. It only queues the
// steward and returns at once; the migration never delays admission.
func (s *StewardSigningMigrationService) OnConnect(_ context.Context, stewardID string) error {
	s.enqueue(stewardID)
	return nil
}

// Start launches the worker pool and the reconciler. A second Start is a no-op.
func (s *StewardSigningMigrationService) Start(ctx context.Context) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if s.cancel != nil {
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	done := make(chan struct{})
	s.done = done

	s.mu.Lock()
	workers, interval := s.maxWorkers, s.reconcileInterval
	s.mu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(runCtx)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		s.reconcile(runCtx)
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				s.reconcile(runCtx)
			}
		}
	}()
	go func() {
		wg.Wait()
		close(done)
	}()
}

// Stop ends the workers and the reconciler and waits for them. Idempotent.
func (s *StewardSigningMigrationService) Stop() {
	s.runMu.Lock()
	cancel, done := s.cancel, s.done
	s.cancel, s.done = nil, nil
	s.runMu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

// enqueue queues a steward unless it is already queued or in flight, or its
// retry backoff has not elapsed. It never blocks: a full queue drops the
// steward, which the next reconcile pass queues again.
func (s *StewardSigningMigrationService) enqueue(stewardID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, busy := s.queued[stewardID]; busy {
		return
	}
	if at, ok := s.nextAttempt[stewardID]; ok && s.now().Before(at) {
		return
	}
	s.queued[stewardID] = struct{}{}
	select {
	case s.queue <- stewardID:
	default:
		delete(s.queued, stewardID)
	}
}

func (s *StewardSigningMigrationService) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-s.queue:
			s.process(ctx, id)
			s.mu.Lock()
			delete(s.queued, id)
			s.mu.Unlock()
		}
	}
}

// reconcile queues every steward connected to this node that has no recorded
// confirmation for the shared serial (and every steward whose retire push is
// still owed), and forgets expired backoff entries.
func (s *StewardSigningMigrationService) reconcile(ctx context.Context) {
	if s.acks == nil {
		return
	}
	s.mu.Lock()
	connected := s.connected
	now := s.now()
	for id, at := range s.nextAttempt {
		if !now.Before(at) {
			delete(s.nextAttempt, id)
		}
	}
	s.mu.Unlock()
	if connected == nil {
		return
	}
	plan, err := s.currentPlan(ctx)
	if err != nil {
		s.logger.Warn("steward signing migration: could not resolve the shared signing identity",
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	if plan == nil {
		return
	}
	acked, err := s.acks.ListAcked(ctx, plan.sharedSerial)
	if err != nil {
		s.logger.Warn("steward signing migration: could not list confirmations",
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	confirmed := make(map[string]struct{}, len(acked))
	for _, a := range acked {
		confirmed[a.StewardID] = struct{}{}
	}
	for id := range connected.GetAll() {
		if _, ok := confirmed[id]; ok {
			s.mu.Lock()
			owed := s.retirePending[id] == plan.sharedSerial
			s.mu.Unlock()
			if !owed {
				continue
			}
		}
		s.enqueue(id)
	}
}

// currentPlan returns the signers the migration works from, or nil when this
// node is not in Shared identity mode.
func (s *StewardSigningMigrationService) currentPlan(ctx context.Context) (*migrationPlan, error) {
	s.mu.Lock()
	if p := s.plan; p != nil && s.now().Sub(p.resolvedAt) < s.planTTL {
		s.mu.Unlock()
		return p, nil
	}
	s.mu.Unlock()

	set, err := s.certManager.SigningMigrationSet(ctx)
	if err != nil {
		if errors.Is(err, cert.ErrNoSigningKeyStore) {
			return nil, nil
		}
		return nil, err
	}
	if set.Shared == nil {
		s.mu.Lock()
		s.plan = nil
		s.mu.Unlock()
		return nil, nil
	}
	plan, err := s.buildPlan(set)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.plan = plan
	s.mu.Unlock()
	return plan, nil
}

func (s *StewardSigningMigrationService) buildPlan(set *cert.SigningMigrationSet) (*migrationPlan, error) {
	shared, err := signature.NewSigner(&signature.SignerConfig{
		CertificatePEM: set.Shared.CertificatePEM,
		PrivateKeyPEM:  set.Shared.PrivateKeyPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("build shared signer: %w", err)
	}
	plan := &migrationPlan{
		sharedSerial: set.Shared.Serial,
		sharedSigner: shared,
		resolvedAt:   s.now(),
	}
	// The shared certificate travels with its issuer chain, so a certificate from
	// an imported intermediate verifies against the steward's pinned root.
	pushPEM := append(append([]byte{}, set.Shared.CertificatePEM...), set.Shared.IssuerChainPEM...)
	plan.certParam = base64.StdEncoding.EncodeToString(pushPEM)

	// A rotating serial is still inside its overlap window: its deadline is sent
	// on every push (omitting it would clear the steward's) and it is not retired.
	rotating := ""
	if cursor, cerr := s.certManager.GetSigningCursorState(); cerr == nil && cursor != nil && cursor.RotatingSerial != "" {
		rotating = cursor.RotatingSerial
		deadline := cursor.RotatedAt.Add(time.Duration(cursor.OverlapWindowDays) * 24 * time.Hour)
		plan.overlapExpires = deadline.UTC().Format(time.RFC3339)
	}
	for _, serial := range set.LegacySerials {
		if serial != rotating {
			plan.retireSerials = append(plan.retireSerials, serial)
		}
	}
	for _, mat := range set.Legacy {
		signer, serr := signature.NewSigner(&signature.SignerConfig{
			CertificatePEM: mat.CertificatePEM,
			PrivateKeyPEM:  mat.PrivateKeyPEM,
		})
		if serr != nil {
			s.logger.Warn("steward signing migration: skipping a legacy signer that cannot sign",
				"serial", logging.SanitizeLogValue(mat.Serial),
				"error", logging.SanitizeLogValue(serr.Error()))
			continue
		}
		plan.legacy = append(plan.legacy, legacySigner{serial: mat.Serial, signer: signer})
	}
	return plan, nil
}

func (p *migrationPlan) pushParams(retire bool) map[string]interface{} {
	params := map[string]interface{}{
		"cert_pem":           p.certParam,
		"serial":             p.sharedSerial,
		"overlap_expires_at": p.overlapExpires,
	}
	if retire {
		params["retire_serials"] = append([]string{}, p.retireSerials...)
	}
	return params
}

// process runs the state machine for one steward.
func (s *StewardSigningMigrationService) process(ctx context.Context, stewardID string) {
	if s.acks == nil {
		return
	}
	plan, err := s.currentPlan(ctx)
	if err != nil {
		s.logger.Warn("steward signing migration: could not resolve the shared signing identity",
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	if plan == nil {
		return
	}
	ack, err := s.acks.GetAck(ctx, stewardID, plan.sharedSerial)
	if err != nil {
		s.logger.Warn("steward signing migration: could not read confirmation",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}

	s.mu.Lock()
	publisher := s.publisher
	owed := s.retirePending[stewardID] == plan.sharedSerial
	s.nextAttempt[stewardID] = s.now().Add(s.retryBackoff)
	s.mu.Unlock()
	if publisher == nil {
		return
	}

	if ack != nil {
		if owed {
			s.retire(ctx, publisher, plan, stewardID)
		}
		return
	}

	if !s.deliver(ctx, publisher, stewardID, plan.pushParams(false), plan.sharedSigner) {
		// The steward does not (yet) trust the shared key: find the legacy key it does.
		proven := false
		for _, l := range plan.legacy {
			if s.deliver(ctx, publisher, stewardID, plan.pushParams(false), l.signer) {
				proven = true
				break
			}
		}
		if !proven {
			s.logger.Warn("steward signing migration: no candidate key delivered the shared certificate; steward left unconfirmed",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"shared_serial", logging.SanitizeLogValue(plan.sharedSerial),
				"legacy_candidates", len(plan.legacy))
			return
		}
		// Completion of this push proves the steward trusts the shared key.
		if !s.deliver(ctx, publisher, stewardID, plan.pushParams(false), plan.sharedSigner) {
			s.logger.Warn("steward signing migration: shared-key confirmation push did not complete; steward left unconfirmed",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"shared_serial", logging.SanitizeLogValue(plan.sharedSerial))
			return
		}
	}

	if err := s.acks.RecordAck(ctx, stewardID, plan.sharedSerial); err != nil {
		s.logger.Error("steward signing migration: could not record confirmation; legacy certificates are not retired",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	s.retire(ctx, publisher, plan, stewardID)
}

// retire pushes, signed by the shared key, the retirement of every legacy
// migration serial. It runs only after the confirmation is recorded. A failure is
// remembered so this process retries it after the backoff.
func (s *StewardSigningMigrationService) retire(ctx context.Context, publisher *commands.Publisher, plan *migrationPlan, stewardID string) {
	if len(plan.retireSerials) == 0 {
		return
	}
	if s.deliver(ctx, publisher, stewardID, plan.pushParams(true), plan.sharedSigner) {
		s.mu.Lock()
		delete(s.retirePending, stewardID)
		s.mu.Unlock()
		s.logger.Info("steward signing migration: legacy signing certificates retired",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"shared_serial", logging.SanitizeLogValue(plan.sharedSerial),
			"retired", len(plan.retireSerials))
		return
	}
	s.mu.Lock()
	s.retirePending[stewardID] = plan.sharedSerial
	s.mu.Unlock()
	s.logger.Warn("steward signing migration: retire push did not complete; it will be retried",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"shared_serial", logging.SanitizeLogValue(plan.sharedSerial))
}

// deliver sends one push_signing_cert signed by signer and waits for the
// steward's completion event. It reports true only on completion; a failure
// event, a send error and the step timeout (the signature of a rejected
// command) all report false.
func (s *StewardSigningMigrationService) deliver(ctx context.Context, publisher *commands.Publisher, stewardID string, params map[string]interface{}, signer signature.Signer) bool {
	s.mu.Lock()
	timeout := s.stepTimeout
	s.mu.Unlock()

	result := make(chan bool, 1)
	report := func(ok bool) {
		select {
		case result <- ok:
		default:
		}
	}
	_, err := publisher.PublishCommandWithSignerAndCallback(ctx, stewardID, types.CommandPushSigningCert, params, signer, timeout,
		func(ev *types.Event) {
			// The publisher calls back for every event naming the command. A
			// completion counts as proof of trust only from the steward the
			// command was sent to.
			if ev.StewardID != stewardID {
				return
			}
			switch ev.Type {
			case types.EventCommandCompleted:
				report(true)
			case types.EventCommandFailed:
				report(false)
			}
		},
		func() { report(false) })
	if err != nil {
		s.logger.Warn("steward signing migration: could not send push",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(err.Error()))
		return false
	}
	// The publisher stops its timer on any event naming the command, so a steward
	// that acknowledged receipt and then stalled is bounded here instead.
	timer := time.NewTimer(timeout + time.Second)
	defer timer.Stop()
	select {
	case ok := <-result:
		return ok
	case <-timer.C:
		return false
	case <-ctx.Done():
		return false
	}
}

// Progress reports how many of the fleet's stewards have confirmed the shared
// certificate. The count is fleet-wide and tenant-independent, so it reads the
// stewards with a system-internal context.
func (s *StewardSigningMigrationService) Progress(ctx context.Context) (*StewardSigningMigrationProgress, error) {
	s.mu.Lock()
	controllerSvc := s.controllerService
	s.mu.Unlock()
	if controllerSvc == nil || s.acks == nil {
		return nil, ErrStewardMigrationUnavailable
	}
	plan, err := s.currentPlan(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve shared signing identity: %w", err)
	}
	if plan == nil {
		return nil, ErrStewardMigrationNotShared
	}
	acked, err := s.acks.ListAcked(ctx, plan.sharedSerial)
	if err != nil {
		return nil, fmt.Errorf("list confirmations: %w", err)
	}
	confirmed := make(map[string]struct{}, len(acked))
	for _, a := range acked {
		confirmed[a.StewardID] = struct{}{}
	}

	stewards := controllerSvc.ListFleetStewards(ctxkeys.WithSystem(ctx))
	progress := &StewardSigningMigrationProgress{SharedSerial: plan.sharedSerial, Stewards: len(stewards)}
	var unconfirmed []string
	for _, st := range stewards {
		if _, ok := confirmed[st.ID]; ok {
			progress.Confirmed++
			continue
		}
		unconfirmed = append(unconfirmed, st.ID)
	}
	sort.Strings(unconfirmed)
	if len(unconfirmed) > MaxMigrationUnconfirmedListed {
		unconfirmed = unconfirmed[:MaxMigrationUnconfirmedListed]
		progress.UnconfirmedTruncated = true
	}
	progress.Unconfirmed = unconfirmed
	return progress, nil
}
