// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import (
	"strings"
)

// stewardACLHandler enforces topic-level access control for MQTT broker.
//
// Story #313: Multi-Tenant Isolation via MQTT ACLs
//
// Security Model:
//   - Each steward connects with a unique client ID (typically their steward ID)
//   - Stewards can only publish/subscribe to topics under their own namespace:
//     cfgms/steward/{clientID}/#
//   - Controllers and test observers can subscribe to any steward topics (for monitoring)
//   - This prevents cross-tenant message eavesdropping and unauthorized access
//
// Parameters:
// - clientID: The authenticated MQTT client identifier (steward ID from certificate CN)
// - topic: The MQTT topic being accessed
// - operation: "publish" or "subscribe"
//
// Returns:
// - true if access is allowed
// - false if access is denied
//
// Examples:
// - stewardACLHandler("steward-123", "cfgms/steward/steward-123/config", "publish") → true
// - stewardACLHandler("steward-123", "cfgms/steward/steward-456/config", "publish") → false
// - stewardACLHandler("controller-primary", "cfgms/steward/steward-123/status", "subscribe") → true
func stewardACLHandler(clientID, topic, operation string) bool {
	// Deny empty client IDs (security: prevent anonymous access)
	if clientID == "" {
		return false
	}

	// Allow controller clients full access to control plane topics
	// Controllers can: send commands, read events/heartbeats/responses
	// Controllers identified by client ID prefix: controller-, test-observer-, test-controller-
	if strings.HasPrefix(clientID, "controller-") ||
		strings.HasPrefix(clientID, "test-observer-") ||
		strings.HasPrefix(clientID, "test-controller-") {
		// Controllers can subscribe to any steward topic (legacy)
		if operation == "subscribe" && strings.HasPrefix(topic, "cfgms/steward/") {
			return true
		}
		// Controllers can publish to any steward topic (legacy commands)
		if operation == "publish" && strings.HasPrefix(topic, "cfgms/steward/") {
			return true
		}
		// Story #363: Controllers can publish commands to stewards (new topics)
		if operation == "publish" && strings.HasPrefix(topic, "cfgms/commands/") {
			return true
		}
		// Story #363: Controllers can subscribe to events, heartbeats, responses (new topics)
		if operation == "subscribe" && (strings.HasPrefix(topic, "cfgms/events/") ||
			strings.HasPrefix(topic, "cfgms/heartbeats/") ||
			strings.HasPrefix(topic, "cfgms/responses/")) {
			return true
		}
	}

	// Story #363: Allow stewards access to new control plane topics
	// Stewards can subscribe to their own commands: cfgms/commands/{clientID}
	if strings.HasPrefix(topic, "cfgms/commands/"+clientID) {
		return true
	}
	// Stewards can publish events: cfgms/events/{clientID}
	if operation == "publish" && topic == "cfgms/events/"+clientID {
		return true
	}
	// Stewards can publish heartbeats: cfgms/heartbeats/{clientID}
	if operation == "publish" && topic == "cfgms/heartbeats/"+clientID {
		return true
	}
	// Stewards can publish responses: cfgms/responses/{commandID}
	if operation == "publish" && strings.HasPrefix(topic, "cfgms/responses/") {
		return true
	}

	// Allow registration topics (bootstrap phase, pre-control-plane)
	if topic == "cfgms/register" || strings.HasPrefix(topic, "cfgms/register/") {
		return true
	}

	// Legacy: Define the allowed topic prefix for this client
	// Pattern: cfgms/steward/{clientID}/
	allowedPrefix := "cfgms/steward/" + clientID + "/"

	// Check for exact wildcard match (subscription pattern)
	// Pattern: cfgms/steward/{clientID}/#
	allowedWildcard := "cfgms/steward/" + clientID + "/#"
	if topic == allowedWildcard {
		return true
	}

	// Check if topic starts with allowed prefix
	// This covers: cfgms/steward/{clientID}/config, cfgms/steward/{clientID}/dna, etc.
	if strings.HasPrefix(topic, allowedPrefix) {
		return true
	}

	// Deny all other topic patterns
	return false
}
