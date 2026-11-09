// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	notifif "github.com/cfgis/cfgms/pkg/notification/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// The two guards of a finished repair (Issue #5727).
//
// After a repair completes, two parties may hold the same pre-repair keys. A
// thief who wins the race must never be trusted automatically, so:
//
//   - any use of a retired credential inside the 24-hour watch window marks the
//     steward tampered again with repair.contested, audits it with its source and
//     notifies admins (markRepairContested); and
//   - the steward returns to trusted only on a clean heartbeat on the NEW
//     certificate after a 10-minute quiet window with no contested signal
//     (HandleRepairHeartbeat).
//
// Accepted residual (founder decision 2026-11-01): the steward returns to trusted
// automatically after the quiet window, counting only new-serial heartbeats; any
// use of retired credentials inside the 24-hour watch window gives
// repair.contested plus an admin notice. A thief who wins the race and whose
// victim host stays offline for the whole window is therefore treated as
// trusted. When both parties hold identical keys no protocol can tell them
// apart; the compensating controls are the completion audit event with its
// source address, the immediate admin notice on any retired-credential use, and
// the always-available ban.
//
// All state is derived from audit events and the retired-device tombstone, so
// every node reaches the same decision and a restart loses nothing.

// Audit actions of the guards. steward_tamper_repair_contested is declared with
// the other repair actions.
const (
	// auditActionTamperRepairNewSerialSeen is written once, by the admission path,
	// on the first connection on the serial a repair issued.
	auditActionTamperRepairNewSerialSeen = "steward_tamper_repair_new_serial_seen"

	// auditActionTamperRepaired is written when the quiet window passed and the
	// steward returned to trusted.
	auditActionTamperRepaired = "steward_tamper_repaired"
)

const (
	// repairWatchWindow is how long after steward_tamper_repair_completed any use
	// of a retired credential contests the repair.
	repairWatchWindow = 24 * time.Hour

	// repairQuietWindow is how long after the completion the steward must have
	// stayed free of contested signals before it returns to trusted. It is more
	// than defaultStreamRevocationRecheckInterval (30 s, the time a stream open
	// on the old serial survives its revocation) plus the steward's maximum
	// re-admission backoff.
	repairQuietWindow = 10 * time.Minute

	// repairContestedAuditInterval is the minimum gap between two contested audit
	// events for a steward that is already tampered, so a looping holder of the
	// retired credentials cannot flood the audit log. The first signal after a
	// restore is always recorded.
	repairContestedAuditInterval = 10 * time.Minute

	// repairGuardAuditLimit bounds the audit events read for one decision.
	repairGuardAuditLimit = 500
)

// Sources of a contested signal, recorded on steward_tamper_repair_contested.
const (
	repairContestRevokedSerial     = "revoked_serial"
	repairContestRetiredKeyRefresh = "retired_key_refresh"
	repairContestCloneOf           = "clone_of"
	repairContestIdentityConflict  = "identity_conflict"
)

// repairGuardActions are the audit actions read to decide the guards: the repair
// state machine plus the two guard events.
var repairGuardActions = append(append([]string(nil), repairAuditActions...),
	auditActionTamperRepairNewSerialSeen, auditActionTamperRepaired)

// repairGuard is what the audit log says about a steward's repair, oldest first.
type repairGuard struct {
	record *business.StewardRecord
	// view is the latest repair request folded with its outcome; nil when the
	// steward has no repair request left in the log.
	view *repairView
	// completed is the latest completion event; nil when none is left (never
	// completed, or pruned).
	completed *business.AuditEntry
	// newSerial is the serial the latest completion issued.
	newSerial string
	// newSerialSeen is true once the first connection on newSerial was recorded
	// after the completion.
	newSerialSeen bool
	// lastContested is the time of the latest contested event after the completion
	// (or of any, when the completion is gone); zero when there is none.
	lastContested time.Time
	// evidence is true when something other than the completion event shows a
	// repair completed: the steward's own repair.completed report, a recorded
	// first connection on a new serial, a recorded return to trusted or a
	// contested record.
	evidence bool
}

// sortRepairEventsOldestFirst orders entries by write order: ascending Timestamp,
// with the per-tenant SequenceNumber breaking a tie. A coarse wall clock (about
// 15.6 ms on Windows) gives two events written moments apart the same Timestamp,
// and the store's timestamp-only sort leaves their relative order undefined; the
// guard derives its state from event order, so it must not depend on that. The
// sort is stable, so entries that tie on both keep the order they were read in.
func sortRepairEventsOldestFirst(entries []*business.AuditEntry) {
	sort.SliceStable(entries, func(i, j int) bool {
		if !entries[i].Timestamp.Equal(entries[j].Timestamp) {
			return entries[i].Timestamp.Before(entries[j].Timestamp)
		}
		return entries[i].SequenceNumber < entries[j].SequenceNumber
	})
}

// loadRepairGuard reads the steward's repair events. The events are read newest
// first up to a bound (so the bound keeps the newest events), then folded oldest
// first.
func (s *Server) loadRepairGuard(ctx context.Context, record *business.StewardRecord) (*repairGuard, error) {
	if s.auditManager == nil {
		return nil, fmt.Errorf("audit manager unavailable")
	}
	if err := s.auditManager.Flush(ctx); err != nil {
		s.logger.Debug("repair guard: audit flush failed before reading state",
			"error", logging.SanitizeLogValue(err.Error()))
	}
	entries, err := s.auditManager.QueryEntries(ctx, &business.AuditFilter{
		TenantID:      record.TenantID,
		Actions:       repairGuardActions,
		ResourceTypes: []string{"steward"},
		ResourceIDs:   []string{record.ID},
		Limit:         repairGuardAuditLimit,
		SortBy:        "timestamp",
		Order:         "desc",
	})
	if err != nil {
		return nil, fmt.Errorf("read repair events: %w", err)
	}
	sortRepairEventsOldestFirst(entries)
	g := &repairGuard{record: record}
	g.fold(entries)
	return g, nil
}

func (g *repairGuard) fold(entries []*business.AuditEntry) {
	if idx := latestRequestIndex(entries, g.record); idx >= 0 {
		g.view = newRepairView(entries[idx])
		g.view.fold(entries[idx+1:], g.record)
	}
	for _, hr := range g.record.HealthReasons {
		if hr.Code == controlplaneTypes.ReasonCodeRepairCompleted {
			g.evidence = true
		}
	}
	for _, e := range entries {
		if !belongsTo(e, g.record) {
			continue
		}
		if e.Action == auditActionTamperRepairCompleted {
			g.completed = e
			g.newSerial = auditString(e.Details, "new_serial")
			g.newSerialSeen = false
			g.lastContested = time.Time{}
			continue
		}
		g.foldAfterCompletion(e)
	}
}

// foldAfterCompletion applies one guard event that is not a completion.
func (g *repairGuard) foldAfterCompletion(e *business.AuditEntry) {
	switch e.Action {
	case auditActionTamperRepairNewSerialSeen:
		g.evidence = true
		if g.newSerial != "" && auditString(e.Details, "serial") == g.newSerial {
			g.newSerialSeen = true
		}
	case auditActionTamperRepaired:
		g.evidence = true
	case auditActionTamperRepairContested:
		g.evidence = true
		g.lastContested = e.Timestamp
	}
}

// armed reports whether a contested signal from source counts now.
//
// With the completion event: inside its 24-hour watch window. Without it (pruned
// or never written) the steward is treated as inside the window, but only when
// something shows a repair completed, so a steward that was never repaired is not
// contested by an unrelated revoked serial. A pending request makes the other
// sources count (a conflict while a repair is pending cancels it).
//
// The revoked-serial source is armed only after the controller saw the first
// connection on the new serial, so the steward's own late dial on the old serial
// during the completion cannot contest its own repair. If the completion is older
// than the quiet window and that event is absent, it is armed anyway (fail
// closed). A retired-key refresh source is itself proof of a completion: the
// caller found the retired-device tombstone.
func (g *repairGuard) armed(source string, now time.Time) bool {
	switch {
	case g.completed != nil:
		age := now.Sub(g.completed.Timestamp)
		if age >= repairWatchWindow {
			return false
		}
		return source != repairContestRevokedSerial || g.newSerialSeen || age >= repairQuietWindow
	case g.evidence || source == repairContestRetiredKeyRefresh:
		return true
	default:
		return g.view != nil && g.view.Unresolved && source != repairContestRevokedSerial
	}
}

// repairNow is the clock of the repair guard windows.
func (s *Server) repairNow() time.Time {
	if s.repairClock != nil {
		return s.repairClock()
	}
	return time.Now()
}

// markRepairContested records a use of retired credentials of stewardID: the
// steward becomes tampered with repair.contested, any pending repair nonce is
// cancelled, the contested event is audited with source and admins are told. It
// does nothing, and returns false, when the guard is not armed for source (no
// repair, outside the watch window, a revoked-serial attempt before the first
// connection on the new serial) or the steward is banned.
func (s *Server) markRepairContested(ctx context.Context, stewardID, source string) bool {
	record, g, ok := s.armedRepairGuard(ctx, stewardID, source)
	if !ok {
		return false
	}
	if record.Status == business.StewardStatusTampered && g.contestedWithin(repairContestedAuditInterval, s.repairNow()) {
		return true // already contested and recorded a moment ago
	}
	return s.recordRepairContested(ctx, record, g, source)
}

// armedRepairGuard loads the steward and its repair state and reports whether a
// contested signal from source counts now.
func (s *Server) armedRepairGuard(ctx context.Context, stewardID, source string) (*business.StewardRecord, *repairGuard, bool) {
	if s.stewardStore == nil || s.auditManager == nil {
		return nil, nil, false
	}
	record, err := s.stewardStore.GetSteward(ctx, stewardID)
	if err != nil || record == nil || record.Status == business.StewardStatusRevoked {
		return nil, nil, false
	}
	g, err := s.loadRepairGuard(ctx, record)
	if err != nil {
		s.logger.Error("repair guard: reading repair state failed",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
		return nil, nil, false
	}
	return record, g, g.armed(source, s.repairNow())
}

// contestedWithin reports whether a contested event was recorded within d of now.
func (g *repairGuard) contestedWithin(d time.Duration, now time.Time) bool {
	return !g.lastContested.IsZero() && now.Sub(g.lastContested) < d
}

// recordRepairContested cancels a pending repair, makes sure the steward is
// tampered, audits the signal with its source and tells admins.
func (s *Server) recordRepairContested(ctx context.Context, record *business.StewardRecord, g *repairGuard, source string) bool {
	repairID := ""
	if g.view != nil {
		repairID = g.view.RepairID
		if g.view.Unresolved {
			s.cancelRepairNonce(ctx, record.ID, repairID)
		}
	}
	if !s.tamperForContestedRepair(ctx, record) {
		return false
	}
	s.recordRepairAudit(ctx, record, auditActionTamperRepairContested, business.AuditResultFailure, map[string]interface{}{
		"repair_id": repairID,
		"source":    logging.SanitizeLogValue(source),
		"codes":     []string{controlplaneTypes.ReasonCodeRepairContested},
	})
	s.logger.Warn("Repaired steward contested: a retired credential was used",
		"steward_id", logging.SanitizeLogValue(record.ID), "source", logging.SanitizeLogValue(source))
	s.announceRepairContested(ctx, record, source)
	return true
}

// cancelRepairNonce consumes the single-use right to complete a pending repair.
func (s *Server) cancelRepairNonce(ctx context.Context, stewardID, repairID string) {
	if s.nonceStore == nil || repairID == "" {
		return
	}
	if _, _, err := s.nonceStore.GetAndConsumeNonce(ctx, repairRequestKey(stewardID, repairID)); err != nil {
		s.logger.Warn("repair guard: cancelling the pending repair failed",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
	}
}

// tamperForContestedRepair makes sure the steward is tampered: a steward in a
// trusted or idle state moves to tampered, mirrors that onto the node-local
// registry and is told to lock. A steward that is already tampered is left as it
// is. It reports false when the steward is in a state that must not become
// tampered (banned, deregistered, quarantined) or the write failed.
func (s *Server) tamperForContestedRepair(ctx context.Context, record *business.StewardRecord) bool {
	if record.Status == business.StewardStatusTampered {
		return true
	}
	transitioned, err := s.stewardStore.TransitionStewardStatus(ctx, record.ID, business.StewardStatusTampered,
		business.StewardStatusRegistered, business.StewardStatusActive,
		business.StewardStatusLost, business.StewardStatusArchived)
	if err != nil {
		s.logger.Error("repair guard: status transition failed",
			"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		return false
	}
	if !transitioned {
		return s.stewardIsTampered(ctx, record.ID)
	}
	s.mirrorStewardStatus(record, business.StewardStatusTampered)
	s.notifyTamperState(ctx, record.ID)
	return true
}

// mirrorStewardStatus mirrors a durable status change onto the node-local list
// entry that GET /stewards reads for attached stewards.
func (s *Server) mirrorStewardStatus(record *business.StewardRecord, status business.StewardStatus) {
	if s.controllerService == nil {
		return
	}
	if err := s.controllerService.UpdateStewardStatusDurable(record.ID, record.TenantID, string(status)); err != nil {
		s.logger.Debug("repair guard: in-memory status update skipped",
			"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
	}
}

// announceRepairContested tells the tenant's administrators in a tracked
// goroutine on a context detached from the caller, so a slow mail server never
// delays an admission or a refresh. Close() waits on crossingNotifyWG.
func (s *Server) announceRepairContested(parent context.Context, record *business.StewardRecord, source string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), stewardTamperNotifyTimeout)
	s.crossingNotifyWG.Add(1)
	go func() {
		defer s.crossingNotifyWG.Done()
		defer cancel()
		outcome := s.notifyTenantAdmins(ctx, record.TenantID,
			func() bool { return s.tamperNotify.claim("repair-contested/"+record.ID, time.Now()) },
			func(contacts []string) notifif.Message {
				return s.composeRepairContestedEmail(ctx, record, source, contacts)
			})
		s.logger.Info("Repair contested notification",
			"steward_id", logging.SanitizeLogValue(record.ID), "outcome", outcome)
	}()
}

// composeRepairContestedEmail builds the notice. It names the steward, the
// tenant and the source of the signal only: no host details or free text.
func (s *Server) composeRepairContestedEmail(ctx context.Context, record *business.StewardRecord, source string, contacts []string) notifif.Message {
	tenantName := record.TenantID
	if s.tenantManager != nil {
		if t, err := s.tenantManager.GetTenant(ctx, record.TenantID); err == nil && t != nil && t.Name != "" {
			tenantName = t.Name
		}
	}
	tenantName = headerSafe(tenantName)
	body := fmt.Sprintf(`The retired credentials of a repaired steward were used after its repair. Two parties may hold the same pre-repair keys, so the steward is marked tampered again (repair.contested).

Tenant: %s
Steward: %s
Source: %s
Reported: %s

The steward stays tampered until an operator restores or bans it. Ban it if the other party is not yours. A later healthy heartbeat does not clear it.
`, tenantName, headerSafe(record.ID), headerSafe(source), time.Now().UTC().Format(time.RFC3339))
	return notifif.Message{
		To:      contacts,
		Subject: "Steward repair contested in tenant " + tenantName,
		Body:    body,
	}
}

// ---- Detection hooks --------------------------------------------------------

// ObserveRevokedPeer is the admission hook for a connection on a revoked serial
// (the control channel and the other steward streams). It contests the repair of
// stewardID when the guard is armed for it.
func (s *Server) ObserveRevokedPeer(ctx context.Context, stewardID, serial string) {
	s.markRepairContested(ctx, stewardID, repairContestRevokedSerial)
}

// ObserveAdmittedPeer records, once, the first connection on the serial a repair
// issued: audit event steward_tamper_repair_new_serial_seen. It is durable and
// visible to every node, and it arms the revoked-serial hook.
func (s *Server) ObserveAdmittedPeer(ctx context.Context, stewardID, serial string) {
	if s.stewardStore == nil || s.auditManager == nil || serial == "" {
		return
	}
	record, err := s.stewardStore.GetSteward(ctx, stewardID)
	if err != nil || record == nil {
		return
	}
	g, err := s.loadRepairGuard(ctx, record)
	if err != nil {
		s.logger.Warn("repair guard: reading repair state failed",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
		return
	}
	if g.completed == nil || g.newSerial != serial || g.newSerialSeen {
		return
	}
	s.recordRepairAudit(ctx, record, auditActionTamperRepairNewSerialSeen, business.AuditResultSuccess, map[string]interface{}{
		"repair_id": auditString(g.completed.Details, "repair_id"),
		"serial":    serial,
	})
}

// ObserveIdentityConflict handles a steward identity seen on two endpoints at
// once: a conflict while a repair is pending cancels the repair, and one inside
// the watch window contests it.
func (s *Server) ObserveIdentityConflict(ctx context.Context, stewardID string) {
	s.markRepairContested(ctx, stewardID, repairContestIdentityConflict)
}

// contestOnRetiredDevice contests the repair that retired deviceID, if a
// retired-device tombstone for it is still held AND proven reports that the
// request proved possession of the retired key recorded in it. It is called when
// a refresh is addressed to a device ID that no longer resolves. The device ID is
// the hash of a public key and is not secret, so a request without a valid proof
// never changes state; the caller's refusal audit is its only record. A tombstone
// without a recorded key cannot be proven against and never contests.
func (s *Server) contestOnRetiredDevice(ctx context.Context, deviceID string, proven func(*repairRetiredEntry) bool) {
	tomb, ok := s.retiredDevice(ctx, deviceID)
	if !ok || tomb.StewardID == "" || len(tomb.OldKeyPub) == 0 || !proven(tomb) {
		return
	}
	s.markRepairContested(ctx, tomb.StewardID, repairContestRetiredKeyRefresh)
}

// retiredDevice reads the retired-device tombstone the completion writes without
// consuming it. It reports false when there is none.
func (s *Server) retiredDevice(ctx context.Context, deviceID string) (*repairRetiredEntry, bool) {
	if s.nonceStore == nil || deviceID == "" {
		return nil, false
	}
	key := repairRetiredKeyPrefix + deviceID
	raw, found, err := s.nonceStore.GetAndConsumeNonce(ctx, key)
	if err != nil || !found {
		return nil, false
	}
	var tomb repairRetiredEntry
	if jsonErr := json.Unmarshal(raw, &tomb); jsonErr != nil {
		return nil, false
	}
	remaining := time.Until(tomb.CompletedAt.Add(repairRetiredTTL))
	if remaining <= 0 {
		return nil, false
	}
	if err := s.nonceStore.PutNonce(ctx, key, raw, remaining); err != nil {
		s.logger.Error("repair guard: restoring the retired-device tombstone failed",
			"error", logging.SanitizeLogValue(err.Error()))
	}
	return &tomb, true
}

// contestOnCloneOf contests the repair of the steward a registration names as
// clone_of. Like validatedCloneOf it only matches a steward in the token's
// tenant, and the registration response does not change.
func (s *Server) contestOnCloneOf(ctx context.Context, cloneOf, tenantID string) {
	if id := s.validatedCloneOf(ctx, cloneOf, tenantID); id != "" {
		s.markRepairContested(ctx, id, repairContestCloneOf)
	}
}

// ---- Return to trusted ------------------------------------------------------

// HandleRepairHeartbeat returns a repaired steward to trusted. The heartbeat must
// report repair.completed for the latest repair, carry no tamper code, and have
// arrived on a stream authenticated by the NEW serial the repair issued (a clean
// heartbeat from an old-serial stream still open in the revocation window never
// counts). The quiet window must have passed since the completion with no
// contested signal; until then the state stays tampered and GET reports
// completed. The status moves from tampered to active, the node-local status
// follows, steward_tamper_repaired is audited and the steward is sent
// TamperState{locked: false}.
//
// The caller must pass the steward ID bound to the authenticated mTLS identity,
// and peerSerial from the same stream.
func (s *Server) HandleRepairHeartbeat(ctx context.Context, stewardID, peerSerial string, reasons []controlplaneTypes.HealthReason) {
	record, repairID, ok := s.repairedStewardToRelease(ctx, stewardID, peerSerial, reasons)
	if !ok {
		return
	}
	transitioned, err := s.stewardStore.TransitionStewardStatus(ctx, record.ID, business.StewardStatusActive, business.StewardStatusTampered)
	if err != nil {
		s.logger.Error("repair guard: return to trusted failed",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
		return
	}
	if !transitioned {
		return
	}
	s.mirrorStewardStatus(record, business.StewardStatusActive)
	s.recordRepairAudit(ctx, record, auditActionTamperRepaired, business.AuditResultSuccess, map[string]interface{}{
		"repair_id":       repairID,
		"new_serial":      peerSerial,
		"previous_status": string(business.StewardStatusTampered),
		"new_status":      string(business.StewardStatusActive),
	})
	s.logger.Info("Repaired steward returned to trusted", "steward_id", logging.SanitizeLogValue(stewardID))
	s.notifyTamperState(ctx, record.ID)
}

// repairedStewardToRelease applies every condition of the return to trusted that
// is read-only: a clean heartbeat for a repair on the new serial, a tampered
// steward whose repair is completed and not contested, and the quiet window
// passed.
func (s *Server) repairedStewardToRelease(ctx context.Context, stewardID, peerSerial string, reasons []controlplaneTypes.HealthReason) (*business.StewardRecord, string, bool) {
	repairID := repairCompletedID(reasons)
	if repairID == "" || peerSerial == "" || len(tamperCodesIn(reasons)) > 0 ||
		s.stewardStore == nil || s.auditManager == nil {
		return nil, "", false
	}
	record, err := s.stewardStore.GetSteward(ctx, stewardID)
	if err != nil || record == nil || record.Status != business.StewardStatusTampered {
		return nil, "", false
	}
	g, err := s.loadRepairGuard(ctx, record)
	if err != nil {
		s.logger.Error("repair guard: reading repair state failed",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
		return nil, "", false
	}
	return record, repairID, g.mayReturnToTrusted(repairID, peerSerial, s.repairNow())
}

// repairCompletedID returns the repair_id (the reason message) of the
// repair.completed reason, or "".
func repairCompletedID(reasons []controlplaneTypes.HealthReason) string {
	for _, r := range reasons {
		if r.Code == controlplaneTypes.ReasonCodeRepairCompleted {
			return strings.TrimSpace(logging.SanitizeLogValue(r.Message))
		}
	}
	return ""
}

// mayReturnToTrusted reports whether a clean heartbeat for repairID on peerSerial
// returns the steward to trusted now: the latest repair is this one and is
// completed (not contested, cancelled, restored or superseded), the completion
// event is known (a pruned one cannot show the quiet window passed), the serial
// is the one the completion issued, and the quiet window has passed.
func (g *repairGuard) mayReturnToTrusted(repairID, peerSerial string, now time.Time) bool {
	if g.view == nil || g.view.State != repairStateCompleted || g.view.RepairID != repairID {
		return false
	}
	if g.completed == nil || auditString(g.completed.Details, "repair_id") != repairID {
		return false
	}
	if g.newSerial == "" || g.newSerial != peerSerial {
		return false
	}
	return now.Sub(g.completed.Timestamp) >= repairQuietWindow
}
