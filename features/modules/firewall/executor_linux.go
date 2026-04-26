// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build linux

package firewall

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// linuxFirewallExecutor manages OS firewall rules via iptables on Linux.
type linuxFirewallExecutor struct{}

func newExecutor() firewallExecutor {
	return &linuxFirewallExecutor{}
}

// directionToChain maps the rule's Direction value to an iptables chain name.
// Chain selection is always explicit — never inferred from address patterns.
func directionToChain(direction string) (string, error) {
	switch direction {
	case "input":
		return "INPUT", nil
	case "output":
		return "OUTPUT", nil
	case "forward":
		return "FORWARD", nil
	default:
		return "", fmt.Errorf("unknown direction %q", direction)
	}
}

// buildRuleSpec constructs the iptables rule arguments (excluding the chain and
// action flags) from the rule fields. The spec is shared between applyRule and
// deleteRule so both operate on an identical argument list.
func buildRuleSpec(rule firewallConfig) []string {
	var args []string

	if rule.Protocol != "" {
		args = append(args, "-p", rule.Protocol)
	}
	if rule.Service != "" {
		args = append(args, "-m", "service", "--dport", rule.Service)
	}
	if rule.Port != 0 {
		args = append(args, "--dport", fmt.Sprintf("%d", rule.Port))
	}
	if len(rule.Ports) > 0 {
		ports := make([]string, len(rule.Ports))
		for i, p := range rule.Ports {
			ports[i] = fmt.Sprintf("%d", p)
		}
		args = append(args, "-m", "multiport", "--dports", strings.Join(ports, ","))
	}
	if rule.Source != "" {
		args = append(args, "-s", rule.Source)
	}
	if rule.Destination != "" {
		args = append(args, "-d", rule.Destination)
	}

	// Translate action to iptables target
	target := "ACCEPT"
	if rule.Action == "deny" {
		target = "DROP"
	}
	args = append(args, "-j", target)
	args = append(args, "-m", "comment", "--comment", fmt.Sprintf("cfgms:%s", rule.Name))

	return args
}

// applyRule installs the rule in the iptables chain derived from rule.Direction.
func (e *linuxFirewallExecutor) applyRule(rule firewallConfig) error {
	chain, err := directionToChain(rule.Direction)
	if err != nil {
		return err
	}

	spec := buildRuleSpec(rule)
	args := append([]string{"-A", chain}, spec...)
	out, err := exec.Command("iptables", args...).CombinedOutput() // #nosec G204 — rule fields validated by firewallConfig.validate() before reaching executor
	if err != nil {
		return fmt.Errorf("iptables -A %s: %w (output: %s)", chain, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// deleteRule removes the rule from the iptables chain by reconstructing the
// full rule spec from rule fields — no line-number parsing required.
func (e *linuxFirewallExecutor) deleteRule(rule firewallConfig) error {
	chain, err := directionToChain(rule.Direction)
	if err != nil {
		return err
	}

	spec := buildRuleSpec(rule)
	args := append([]string{"-D", chain}, spec...)
	out, err := exec.Command("iptables", args...).CombinedOutput() // #nosec G204 — rule fields validated by firewallConfig.validate() before reaching executor
	if err != nil {
		return fmt.Errorf("iptables -D %s: %w (output: %s)", chain, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ruleExists scans all iptables chains for a rule tagged with "cfgms:<name>".
// It uses iptables -L -n -v rather than iptables -C to avoid false negatives
// from spec reconstruction differences.
func (e *linuxFirewallExecutor) ruleExists(name string) (bool, error) {
	out, err := exec.Command("iptables", "-L", "-n", "-v").CombinedOutput() // #nosec G204 — rule fields validated by firewallConfig.validate() before reaching executor
	if err != nil {
		return false, fmt.Errorf("iptables -L: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	target := fmt.Sprintf("cfgms:%s", name)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), target) {
			return true, nil
		}
	}
	return false, nil
}
