// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import "context"

// StewardOnConnectHook is called after a steward successfully registers on the
// ControlChannel, before the receive loop begins. The controller uses it to push
// state that must be current on every (re)connect — e.g. the latest signing cert
// set (Issue #1817).
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
// The hook fires after registry.Register succeeds and before the receive loop,
// ensuring the refresh push reaches the steward before any commands begin flowing.
// Following the WithApprovalChecker pattern (approval.go).
func WithOnConnectHook(hook StewardOnConnectHook) option {
	return func(p *Provider) {
		p.onConnectHook = hook
	}
}
