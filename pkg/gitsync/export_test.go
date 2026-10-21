// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package gitsync

// WithWebhookCoalescedHook registers fn to be called whenever a webhook
// trigger is coalesced into an already-waiting sync. Test-only.
func WithWebhookCoalescedHook(fn func()) Option {
	return func(s *Syncer) {
		s.webhookCoalesced = fn
	}
}
