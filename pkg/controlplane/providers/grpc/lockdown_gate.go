// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import "github.com/cfgis/cfgms/pkg/controlplane/interfaces"

// WithLockdown installs the default-deny gate on SendCommand and FanOutCommand
// (Issue #5665). checker is the lockdown predicate; observer, which may be nil,
// receives the audit events. A nil checker installs no gate; the controller
// always passes the predicate.
func WithLockdown(checker interfaces.LockdownChecker, observer interfaces.LockdownObserver) option {
	return func(p *Provider) {
		if checker == nil {
			p.lockdownGate = nil
			return
		}
		p.lockdownGate = interfaces.NewLockdownGate(checker, observer)
	}
}
