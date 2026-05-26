// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

// GetState exposes the private getState method for test-only connection state inspection.
var GetState = (*Provider).getState

// SetAddrUnderSendMu atomically updates the provider's dial address under sendMu,
// preserving the invariant that the reconnect loop reads addr under sendMu.
var SetAddrUnderSendMu = func(p *Provider, addr string) {
	p.sendMu.Lock()
	p.addr = addr
	p.sendMu.Unlock()
}
