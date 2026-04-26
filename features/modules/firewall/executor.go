// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package firewall

// firewallExecutor is the platform-specific backend for OS firewall operations.
// Each platform provides its own implementation via build tags. Unsupported
// platforms use the stub implementation that returns ErrUnsupportedPlatform.
//
// Chain selection (INPUT/OUTPUT/FORWARD) is determined by rule.Direction —
// not by source/destination address patterns. Callers must set Direction
// explicitly; the executor never infers chain from address heuristics.
type firewallExecutor interface {
	// applyRule installs the firewall rule on the OS. The chain is derived
	// from rule.Direction. The rule is tagged with "cfgms:<rule.Name>" so
	// ruleExists can locate it without line-number parsing.
	applyRule(rule firewallConfig) error

	// deleteRule removes the firewall rule from the OS. The full rule spec
	// is reconstructed from rule fields — no line-number parsing required.
	deleteRule(rule firewallConfig) error

	// ruleExists reports whether a rule tagged "cfgms:<name>" is currently
	// installed in the chain that corresponds to the rule's Direction.
	ruleExists(name string) (bool, error)
}
