// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"

	"github.com/cfgis/cfgms/pkg/logging"
	notifif "github.com/cfgis/cfgms/pkg/notification/interfaces"
)

// emailSenderRule says which sender a send path may use. Every send path names
// one explicitly; the choice is a policy decision per notice, not a default.
type emailSenderRule int

const (
	// emailRuleOwningMSPWithPlatformFallback is for notices that tell an MSP's
	// administrators about the MSP's own tenants: the owning MSP's sender when it
	// is complete, otherwise the controller-wide sender.
	emailRuleOwningMSPWithPlatformFallback emailSenderRule = iota + 1
	// emailRulePlatformOnly is for notices the platform owes the tenant (a
	// break-glass elevation by platform support) and for the controller-wide
	// test route: only the controller-wide sender, never a tenant-supplied one.
	emailRulePlatformOnly
)

// emailSenderSource names the sender a send used. It is recorded on audit entries.
type emailSenderSource string

const (
	emailSourceMSP      emailSenderSource = "msp"
	emailSourcePlatform emailSenderSource = "platform"
	emailSourceNone     emailSenderSource = "none"
)

// platformEmailNotifier returns the controller-wide email sender, or nil when
// email delivery is not configured or the SMTP credential has not been stored.
// Only resolveEmailSender calls it: send paths go through the resolver so the
// rule they use is explicit (enforced by email_sender_architecture_test.go).
func (s *Server) platformEmailNotifier() notifif.Notifier {
	s.emailMu.RLock()
	defer s.emailMu.RUnlock()
	return s.emailNotifier
}

// resolveEmailSender returns the notifier a send path must use under rule for
// tenantID, and which sender that is. A nil notifier comes with
// emailSourceNone: callers treat it as "skip this channel", never as an error.
//
// The owning MSP's notifier is built per call from its stored sender and
// password, with no cache, so a change made on another controller node is seen
// at once. A missing record or password, or a store error, falls back to the
// controller-wide sender; an unknown rule is treated as platform-only.
func (s *Server) resolveEmailSender(ctx context.Context, rule emailSenderRule, tenantID string) (notifif.Notifier, emailSenderSource) {
	if rule == emailRuleOwningMSPWithPlatformFallback && s.tenantManager != nil {
		if mspID := s.tenantManager.ResolveOwningMSPID(ctx, tenantID); mspID != "" {
			n, err := s.buildMSPEmailNotifier(ctx, mspID)
			if err != nil {
				s.logger.Warn("MSP email sender could not be built; using the controller-wide sender",
					"msp_tenant_id", logging.SanitizeLogValue(mspID),
					"error", logging.SanitizeLogValue(err.Error()))
			} else if n != nil {
				return n, emailSourceMSP
			}
		}
	}
	if n := s.platformEmailNotifier(); n != nil {
		return n, emailSourcePlatform
	}
	return nil, emailSourceNone
}
