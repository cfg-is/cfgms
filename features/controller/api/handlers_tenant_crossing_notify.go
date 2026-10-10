// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	notifif "github.com/cfgis/cfgms/pkg/notification/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// tenantCrossingNotifyTimeout bounds one break-glass announcement: the contact
// lookup, the SMTP send and the follow-up audit entry.
const tenantCrossingNotifyTimeout = 20 * time.Second

// Outcomes of the break-glass email channel, recorded on the
// tenant.crossing_break_glass_notified audit entry.
const (
	breakGlassNotifySent          = "sent"
	breakGlassNotifyPartial       = "partial"
	breakGlassNotifyFailed        = "failed"
	breakGlassNotifyNotConfigured = "not_configured"
	breakGlassNotifyNoContacts    = "no_contacts"
)

// announceBreakGlassActive announces a break-glass crossing that has just become
// active (created approved, or approved from pending). The crossing is already
// persisted: the announcement runs in a tracked goroutine on a context detached
// from the request, so no channel failure can fail, delay or undo it, and a client
// disconnect does not cancel the email. Close() waits on crossingNotifyWG.
func (s *Server) announceBreakGlassActive(reqCtx context.Context, crossing *business.TenantCrossing, actorID string) {
	if crossing == nil || crossing.Kind != business.TenantCrossingKindBreakGlass {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), tenantCrossingNotifyTimeout)
	snapshot := *crossing
	s.crossingNotifyWG.Add(1)
	go func() {
		defer s.crossingNotifyWG.Done()
		defer cancel()
		outcome := s.sendBreakGlassEmail(ctx, &snapshot)
		s.recordTenantCrossingAuditCtx(ctx, snapshot.TenantID, actorID, &snapshot, business.AuditSeverityCritical,
			"tenant.crossing_break_glass_notified", "", map[string]string{"outcome": outcome})
	}()
}

// sendBreakGlassEmail sends the break-glass email to the tenant's administrator
// contacts and returns the outcome. Addresses are never logged.
func (s *Server) sendBreakGlassEmail(ctx context.Context, crossing *business.TenantCrossing) string {
	notifier := s.EmailNotifier()
	if notifier == nil {
		return breakGlassNotifyNotConfigured
	}
	if s.tenantManager == nil {
		return breakGlassNotifyNoContacts
	}
	contacts, err := s.tenantManager.GetAdminContacts(ctx, crossing.TenantID)
	if err != nil {
		s.logger.Error("Break-glass notification: reading administrator contacts failed",
			"tenant_id", logging.SanitizeLogValue(crossing.TenantID),
			"error", logging.SanitizeLogValue(err.Error()))
		return breakGlassNotifyFailed
	}
	if len(contacts) == 0 {
		return breakGlassNotifyNoContacts
	}

	result, err := notifier.Send(ctx, s.composeBreakGlassEmail(ctx, crossing, contacts))
	var accepted, rejected int
	if result != nil {
		accepted, rejected = len(result.Accepted()), len(result.Failed())
	}
	if err != nil {
		s.logger.Warn("Break-glass notification email failed",
			"tenant_id", logging.SanitizeLogValue(crossing.TenantID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
	switch {
	case accepted == 0:
		return breakGlassNotifyFailed
	case rejected > 0 || err != nil:
		return breakGlassNotifyPartial
	default:
		return breakGlassNotifySent
	}
}

// composeBreakGlassEmail builds the notice. The justification is deliberately
// absent: free text may be sensitive, and MSP admins read it in the console and the
// audit view.
func (s *Server) composeBreakGlassEmail(ctx context.Context, crossing *business.TenantCrossing, contacts []string) notifif.Message {
	tenantName := crossing.TenantID
	if s.tenantManager != nil {
		if t, err := s.tenantManager.GetTenant(ctx, crossing.TenantID); err == nil && t != nil && t.Name != "" {
			tenantName = t.Name
		}
	}
	operator := crossing.PrincipalID
	if acct, err := s.getAccountByID(ctx, crossing.PrincipalID); err == nil && acct != nil && acct.Username != "" {
		operator = acct.Username
	}
	start := crossing.CreatedAt
	if crossing.ApprovedAt != nil {
		start = *crossing.ApprovedAt
	}
	tenantName = headerSafe(tenantName)

	body := fmt.Sprintf(`Platform support has started a break-glass elevation into your tenant.

Tenant: %s
Reason category: %s
Invoked by: %s
Started: %s
Expires: %s

The elevation ends automatically at the expiry time. To end it earlier, open the tenant's access view in the console and end the break-glass crossing, or call:

  DELETE /api/v1/tenants/%s/access-grants/%s

The justification given for this elevation is visible to your administrators in the console and in the audit view.
`,
		tenantName, crossing.ReasonCategory, headerSafe(operator),
		start.UTC().Format(time.RFC3339), crossing.ExpiresAt.UTC().Format(time.RFC3339),
		crossing.TenantID, crossing.ID)

	return notifif.Message{
		To:      contacts,
		Subject: "Break-glass access started on tenant " + tenantName,
		Body:    body,
	}
}

// headerSafe removes line breaks so a value cannot inject headers or lines.
func headerSafe(v string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(v)
}
