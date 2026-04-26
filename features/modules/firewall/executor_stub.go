// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build !linux

package firewall

import "github.com/cfgis/cfgms/features/modules"

// stubFirewallExecutor is used on platforms where iptables firewall management
// is not supported. Windows and macOS implementations are deferred.
type stubFirewallExecutor struct{}

func newExecutor() firewallExecutor {
	return &stubFirewallExecutor{}
}

func (e *stubFirewallExecutor) applyRule(_ firewallConfig) error {
	return modules.ErrUnsupportedPlatform
}

func (e *stubFirewallExecutor) deleteRule(_ firewallConfig) error {
	return modules.ErrUnsupportedPlatform
}

func (e *stubFirewallExecutor) ruleExists(_ string) (bool, error) {
	return false, modules.ErrUnsupportedPlatform
}
