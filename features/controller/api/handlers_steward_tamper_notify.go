// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/audit"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	notifif "github.com/cfgis/cfgms/pkg/notification/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// auditActionStewardTamperAlarm is written once per transition to tampered. It
// carries the steward ID, tenant, tamper codes and the notification outcome; the
// REST payload reads the codes of the latest one back (no storage field holds them).
const auditActionStewardTamperAlarm = "steward_tamper_alarm"

const (
	// stewardTamperNotifyTimeout bounds one announcement: the contact lookup, the
	// SMTP send and the audit entry.
	stewardTamperNotifyTimeout = 20 * time.Second

	// stewardTamperNotifyCooldown is the per-steward minimum gap between two
	// notifications, so an alarm-restore-alarm cycle cannot flood admins. Every
	// transition is still audited. The last-notified time is kept in memory per
	// node: a restart or another node may notify once more, which is accepted.
	stewardTamperNotifyCooldown = time.Hour

	// stewardTamperAuditLimit bounds the alarm events read for one REST response.
	stewardTamperAuditLimit = 5000
)

// Outcomes of the tamper notification, recorded on the alarm audit event. The
// channel outcomes are the break-glass strings; cooldown is the only extra.
const (
	tamperNotifySent          = breakGlassNotifySent
	tamperNotifyPartial       = breakGlassNotifyPartial
	tamperNotifyFailed        = breakGlassNotifyFailed
	tamperNotifyNotConfigured = breakGlassNotifyNotConfigured
	tamperNotifyNoContacts    = breakGlassNotifyNoContacts
	tamperNotifyCooldown      = "cooldown"
)

// tamperNotifyState holds the node-local last-notified time per steward.
type tamperNotifyState struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// inCooldown reports whether stewardID was notified within the cooldown.
func (t *tamperNotifyState) inCooldown(stewardID string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	at, ok := t.last[stewardID]
	return ok && now.Sub(at) < stewardTamperNotifyCooldown
}

// markNotified records a notification attempt and drops expired entries so the
// map stays bounded by the stewards alarmed within one cooldown.
func (t *tamperNotifyState) markNotified(stewardID string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.last == nil {
		t.last = make(map[string]time.Time)
	}
	for id, at := range t.last {
		if now.Sub(at) >= stewardTamperNotifyCooldown {
			delete(t.last, id)
		}
	}
	t.last[stewardID] = now
}

// tamperCodesIn returns the distinct, sorted tamper codes in reasons. It is an
// exact-set check: an unknown "tamper.*" code is not a tamper code.
func tamperCodesIn(reasons []controlplaneTypes.HealthReason) []string {
	seen := make(map[string]struct{})
	for _, r := range reasons {
		if controlplaneTypes.IsTamperCode(r.Code) {
			seen[r.Code] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	codes := make([]string, 0, len(seen))
	for c := range seen {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	return codes
}

// HandleStewardTamperAlarm acts on one heartbeat's health reasons. When they hold
// a tamper code it moves the steward to tampered, mirrors that onto the node-local
// registry, and audits and announces the transition.
//
// The caller must pass the steward ID bound to the authenticated mTLS identity (the
// control-plane provider rejects a heartbeat whose StewardID differs from the peer
// certificate CN), so a steward can raise an alarm only about itself.
//
// An alarm can only lower trust. The source states are exactly registered, active,
// lost and archived: revoked, deregistered, dormant, quarantined and tampered
// records are left unchanged (a quarantined steward is hidden by design and is not
// promoted to a visible state; a tampered one has already alarmed). The status
// write comes first; an audit or notification failure never undoes it.
func (s *Server) HandleStewardTamperAlarm(ctx context.Context, stewardID string, reasons []controlplaneTypes.HealthReason) {
	codes := tamperCodesIn(reasons)
	if len(codes) == 0 || s.stewardStore == nil {
		return
	}
	transitioned, err := s.stewardStore.TransitionStewardStatus(ctx, stewardID, business.StewardStatusTampered,
		business.StewardStatusRegistered, business.StewardStatusActive,
		business.StewardStatusLost, business.StewardStatusArchived)
	if err != nil {
		s.logger.Error("Tamper alarm: status transition failed",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	if !transitioned {
		return
	}

	tenantID := ""
	if rec, getErr := s.stewardStore.GetSteward(ctx, stewardID); getErr == nil && rec != nil {
		tenantID = rec.TenantID
	}
	// The node-local list entry is what GET /stewards reads for attached stewards.
	if s.controllerService != nil {
		if updErr := s.controllerService.UpdateStewardStatusDurable(stewardID, tenantID, string(business.StewardStatusTampered)); updErr != nil {
			s.logger.Debug("Tamper alarm: in-memory status update skipped",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", logging.SanitizeLogValue(updErr.Error()))
		}
	}
	s.logger.Warn("Steward raised a tamper alarm and is now tampered",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"tenant_id", logging.SanitizeLogValue(tenantID),
		"codes", logging.SanitizeLogValue(strings.Join(codes, ",")))

	s.announceStewardTamper(ctx, stewardID, tenantID, codes)
}

// announceStewardTamper notifies admins and writes the alarm audit event in a
// tracked goroutine on a context detached from the heartbeat, so a slow mail server
// never delays the heartbeat path. Close() waits on crossingNotifyWG.
func (s *Server) announceStewardTamper(parent context.Context, stewardID, tenantID string, codes []string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), stewardTamperNotifyTimeout)
	s.crossingNotifyWG.Add(1)
	go func() {
		defer s.crossingNotifyWG.Done()
		defer cancel()
		outcome := s.notifyStewardTamper(ctx, stewardID, tenantID, codes)
		s.recordStewardTamperAudit(ctx, stewardID, tenantID, codes, outcome)
	}()
}

// notifyStewardTamper emails the tenant's administrator contacts and returns the
// outcome. Addresses are never logged.
func (s *Server) notifyStewardTamper(ctx context.Context, stewardID, tenantID string, codes []string) string {
	if s.tamperNotify.inCooldown(stewardID, time.Now()) {
		return tamperNotifyCooldown
	}
	notifier := s.EmailNotifier()
	if notifier == nil {
		return tamperNotifyNotConfigured
	}
	if s.tenantManager == nil {
		return tamperNotifyNoContacts
	}
	contacts, err := s.tenantManager.GetAdminContacts(ctx, tenantID)
	if err != nil {
		s.logger.Error("Tamper notification: reading administrator contacts failed",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()))
		return tamperNotifyFailed
	}
	if len(contacts) == 0 {
		return tamperNotifyNoContacts
	}

	s.tamperNotify.markNotified(stewardID, time.Now())
	result, err := notifier.Send(ctx, s.composeStewardTamperEmail(ctx, stewardID, tenantID, codes, contacts))
	var accepted, rejected int
	if result != nil {
		accepted, rejected = len(result.Accepted()), len(result.Failed())
	}
	if err != nil {
		s.logger.Warn("Tamper notification email failed",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
	switch {
	case accepted == 0:
		return tamperNotifyFailed
	case rejected > 0 || err != nil:
		return tamperNotifyPartial
	default:
		return tamperNotifySent
	}
}

// composeStewardTamperEmail builds the notice. It names the steward and the
// exact-set codes only: no host details, paths or free text from the steward.
func (s *Server) composeStewardTamperEmail(ctx context.Context, stewardID, tenantID string, codes []string, contacts []string) notifif.Message {
	tenantName := tenantID
	if s.tenantManager != nil {
		if t, err := s.tenantManager.GetTenant(ctx, tenantID); err == nil && t != nil && t.Name != "" {
			tenantName = t.Name
		}
	}
	tenantName = headerSafe(tenantName)
	stewardID = headerSafe(stewardID)

	body := fmt.Sprintf(`A steward has reported tampering on its own host and is now marked tampered.

Tenant: %s
Steward: %s
Tamper codes: %s
Reported: %s

The steward stays visible in the fleet with status "tampered" until an operator restores or bans it. A later healthy heartbeat does not clear it.
`, tenantName, stewardID, strings.Join(codes, ", "), time.Now().UTC().Format(time.RFC3339))

	return notifif.Message{
		To:      contacts,
		Subject: "Steward tamper alarm in tenant " + tenantName,
		Body:    body,
	}
}

// recordStewardTamperAudit writes the alarm event. A failure is logged and goes no
// further: the status transition has already happened.
func (s *Server) recordStewardTamperAudit(ctx context.Context, stewardID, tenantID string, codes []string, outcome string) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSecurityEvent).
		Action(auditActionStewardTamperAlarm).
		User(stewardID, business.AuditUserTypeSystem).
		Resource("steward", stewardID, "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityCritical).
		Detail("steward_id", stewardID).
		Detail("tenant_id", tenantID).
		Detail("codes", codes).
		Detail("notification", outcome)
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to record steward tamper alarm audit event",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// tamperCodesFromAudit returns, per steward ID, the codes of its latest
// steward_tamper_alarm audit event, for the stewards in ids whose event tenant
// matches the tenant the caller was already allowed to read. Codes are untrusted
// once read back: the S1 caps are applied again and control characters removed.
// An absent audit manager, a failed read or pruned events yield no codes.
func (s *Server) tamperCodesFromAudit(ctx context.Context, tenantByID map[string]string) map[string][]string {
	if s.auditManager == nil || len(tenantByID) == 0 {
		return nil
	}
	ids := make([]string, 0, len(tenantByID))
	for id := range tenantByID {
		ids = append(ids, id)
	}
	entries, err := s.auditManager.QueryEntries(ctx, &business.AuditFilter{
		Actions:       []string{auditActionStewardTamperAlarm},
		ResourceTypes: []string{"steward"},
		ResourceIDs:   ids,
		Limit:         stewardTamperAuditLimit,
		SortBy:        "timestamp",
		Order:         "desc",
	})
	if err != nil {
		s.logger.Warn("Failed to read steward tamper alarm events",
			"error", logging.SanitizeLogValue(err.Error()))
		return nil
	}
	out := make(map[string][]string, len(ids))
	for _, e := range entries {
		wantTenant, ok := tenantByID[e.ResourceID]
		if !ok || e.TenantID != wantTenant {
			continue
		}
		if _, done := out[e.ResourceID]; done {
			continue // entries are newest first: the first one seen is the latest
		}
		out[e.ResourceID] = sanitizeTamperCodes(auditStringSlice(e.Details["codes"]))
	}
	return out
}

// sanitizeTamperCodes re-applies the S1 reason caps (count and per-code length) and
// drops control characters from codes read back from the audit log.
func sanitizeTamperCodes(codes []string) []string {
	in := make([]controlplaneTypes.HealthReason, 0, len(codes))
	for _, c := range codes {
		in = append(in, controlplaneTypes.HealthReason{Code: c})
	}
	capped := controlplaneTypes.TruncateHealthReasons(in)
	out := make([]string, 0, len(capped))
	for _, r := range capped {
		if code := logging.SanitizeLogValue(r.Code); code != "" {
			out = append(out, code)
		}
	}
	return out
}

// attachTamperCodesTo fills TamperCodes on one already-authorized response.
func (s *Server) attachTamperCodesTo(ctx context.Context, info *StewardInfo) {
	list := []StewardInfo{*info}
	s.attachTamperCodes(ctx, list)
	info.TamperCodes = list[0].TamperCodes
}

// attachTamperCodes fills TamperCodes on each already-tenant-scoped row whose
// status is tampered. Rows outside the caller's read scope are never in list, so
// the codes are returned only to callers with scope on the steward's tenant.
func (s *Server) attachTamperCodes(ctx context.Context, list []StewardInfo) {
	tenantByID := make(map[string]string)
	for i := range list {
		if list[i].Status == string(business.StewardStatusTampered) {
			tenantByID[list[i].ID] = list[i].TenantID
		}
	}
	if len(tenantByID) == 0 {
		return
	}
	codes := s.tamperCodesFromAudit(ctx, tenantByID)
	for i := range list {
		if c, ok := codes[list[i].ID]; ok && len(c) > 0 {
			list[i].TamperCodes = c
		}
	}
}
