// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/cfgis/cfgms/pkg/logging"
	notifif "github.com/cfgis/cfgms/pkg/notification/interfaces"
)

// pendingNotifyTimeout bounds one announcement: the contact lookup and the send.
const pendingNotifyTimeout = 20 * time.Second

// noticeFieldMax caps one identifier placed in a notice, so a long script id
// cannot bloat the subject or a header line.
const noticeFieldMax = 128

// noticeSafe makes an identifier safe for a subject, a header and a body line:
// every control character, CR and LF included, becomes a space, and the result
// is capped. Identifiers are library data an author chose, so they are untrusted.
func noticeSafe(v string) string {
	var sb strings.Builder
	n := 0
	for _, r := range v {
		if n == noticeFieldMax {
			sb.WriteString("...")
			break
		}
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			r = ' '
		}
		sb.WriteRune(r)
		n++
	}
	return strings.TrimSpace(sb.String())
}

// consoleLink returns the authenticated console address of the approvals view,
// optionally narrowed to one script version, or "" when the controller has no
// external URL. It carries identifiers only, escaped as query values; the diff
// itself is behind the sign-in.
func (s *Server) consoleLink(scriptID, version string) string {
	if s.cfg == nil || s.cfg.ExternalURL == "" {
		return ""
	}
	link := strings.TrimRight(s.cfg.ExternalURL, "/") + "/automation/approvals"
	if scriptID == "" {
		return link
	}
	q := url.Values{"script_id": {scriptID}, "version": {version}}
	return link + "?" + q.Encode()
}

// announcePendingChange emails the owner tenant's administrators that one script
// changed after its approval and awaits a new one.
func (s *Server) announcePendingChange(parent context.Context, pc *PendingChange) {
	s.sendPendingNotice(parent, pc.TenantID, "change", func(contacts []string) notifif.Message {
		return s.composePendingChangeEmail(pc, contacts)
	})
}

// announcePendingSummary sends the one notice that stands for every change past
// the window's cap.
func (s *Server) announcePendingSummary(parent context.Context, ownerTenant string) {
	s.sendPendingNotice(parent, ownerTenant, "summary", s.composePendingSummaryEmail)
}

// sendPendingNotice sends a notice to the OWNER tenant's administrator contacts
// on a tracked goroutine and a context detached from the caller, so a slow mail
// server never delays a refusal. The caller has already won the durable claim, so
// nothing here claims again. Addresses are never logged. Close() waits on
// crossingNotifyWG.
func (s *Server) sendPendingNotice(parent context.Context, ownerTenant, kind string, compose func(contacts []string) notifif.Message) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), pendingNotifyTimeout)
	s.crossingNotifyWG.Add(1)
	go func() {
		defer s.crossingNotifyWG.Done()
		defer cancel()
		outcome := s.notifyTenantAdmins(ctx, ownerTenant, func() bool { return true }, compose)
		s.logger.Info("Content change notice handled",
			"tenant_id", logging.SanitizeLogValue(ownerTenant),
			"kind", kind,
			"outcome", outcome)
	}()
}

// composePendingChangeEmail builds the notice of one changed script. It carries
// the script id, versions, the two approval hashes and a link, and nothing else:
// never script text or a diff, because script text routinely holds inline
// credentials and an email leaves the tenant boundary. Every identifier is
// flattened to one line.
func (s *Server) composePendingChangeEmail(pc *PendingChange, contacts []string) notifif.Message {
	id, version := noticeSafe(pc.ScriptID), noticeSafe(pc.Version)
	body := fmt.Sprintf(`A script in your automation library changed after it was approved. Automation runs of it are refused until an administrator approves the new content. The previously approved version is unchanged and can still be pinned.

Script: %s
Version: %s
New approval hash: %s
Previous approved version: %s
Previous approval hash: %s
First seen: %s

`, id, version, noticeSafe(pc.ApprovalHash), noticeSafe(pc.PreviousVersion), noticeSafe(pc.PreviousApprovalHash),
		pc.FirstSeen.UTC().Format(time.RFC3339))
	if link := s.consoleLink(pc.ScriptID, pc.Version); link != "" {
		body += "Review the change and approve it (sign-in required): " + link + "\n"
	} else {
		body += "Review the change and approve it in the console under Automation, Approvals (sign-in required).\n"
	}
	body += "\nThis notice carries no script text. The change is shown in the console to administrators of the owning tenant only.\n"

	return notifif.Message{
		To:      contacts,
		Subject: "Script change awaiting approval: " + id + " " + version,
		Body:    body,
	}
}

// composePendingSummaryEmail builds the one notice that replaces the individual
// ones once the window's cap is reached. It names no script.
func (s *Server) composePendingSummaryEmail(contacts []string) notifif.Message {
	body := fmt.Sprintf(`More than %d approved scripts in your automation library changed within one hour. Further changes in this window are refused without an individual notice. Automation runs of every changed script are refused until an administrator approves its new content.
`, pendingChangeCap)
	if link := s.consoleLink("", ""); link != "" {
		body += "\nReview the pending changes (sign-in required): " + link + "\n"
	} else {
		body += "\nReview the pending changes in the console under Automation, Approvals (sign-in required).\n"
	}
	return notifif.Message{
		To:      contacts,
		Subject: "Script changes awaiting approval (summary)",
		Body:    body,
	}
}
