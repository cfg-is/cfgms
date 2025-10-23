// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package firewall

import "errors"

var (
	// ErrInvalidName is returned when the rule name is invalid
	ErrInvalidName = errors.New("invalid rule name")

	// ErrInvalidAction is returned when the action is invalid
	ErrInvalidAction = errors.New("invalid action (must be 'allow' or 'deny')")

	// ErrInvalidProtocol is returned when the protocol is invalid
	ErrInvalidProtocol = errors.New("invalid protocol (must be 'tcp', 'udp', or 'icmp')")

	// ErrInvalidPort is returned when the port is invalid
	ErrInvalidPort = errors.New("invalid port (must be between 0 and 65535)")

	// ErrInvalidSource is returned when the source address is invalid
	ErrInvalidSource = errors.New("invalid source address")

	// ErrInvalidDestination is returned when the destination address is invalid
	ErrInvalidDestination = errors.New("invalid destination address")

	// ErrRuleNotFound is returned when a rule cannot be found
	ErrRuleNotFound = errors.New("rule not found")

	// ErrPermissionDenied is returned when the operation is not permitted
	ErrPermissionDenied = errors.New("permission denied")

	// ErrInvalidService is returned when the service name is invalid
	ErrInvalidService = errors.New("invalid service name")
)
