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

	// Allow controller clients full read access to steward topics for monitoring
	// Controllers can: read heartbeats, LWT status, DNA updates, etc.
	// Controllers identified by client ID prefix: controller-, test-observer-, test-controller-
	if strings.HasPrefix(clientID, "controller-") ||
		strings.HasPrefix(clientID, "test-observer-") ||
		strings.HasPrefix(clientID, "test-controller-") {
		// Controllers can subscribe to any steward topic
		if operation == "subscribe" && strings.HasPrefix(topic, "cfgms/steward/") {
			return true
		}
		// Controllers can publish to any steward topic (for commands, config delivery)
		if operation == "publish" && strings.HasPrefix(topic, "cfgms/steward/") {
			return true
		}
	}

	// Define the allowed topic prefix for this client
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
