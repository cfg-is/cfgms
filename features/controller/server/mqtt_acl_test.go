// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestStewardACLHandler validates the ACL handler enforces topic-level access control
// Story #313: MQTT Broker ACLs for Multi-Tenant Isolation
func TestStewardACLHandler(t *testing.T) {
	tests := []struct {
		name      string
		clientID  string
		topic     string
		operation string
		expected  bool
		reason    string
	}{
		// ALLOW cases - client accessing own topics
		{
			name:      "allow_subscribe_own_wildcard",
			clientID:  "steward-123",
			topic:     "cfgms/steward/steward-123/#",
			operation: "subscribe",
			expected:  true,
			reason:    "steward should subscribe to own wildcard topic",
		},
		{
			name:      "allow_publish_own_config",
			clientID:  "steward-456",
			topic:     "cfgms/steward/steward-456/config",
			operation: "publish",
			expected:  true,
			reason:    "steward should publish to own config topic",
		},
		{
			name:      "allow_subscribe_own_heartbeat",
			clientID:  "steward-789",
			topic:     "cfgms/steward/steward-789/heartbeat",
			operation: "subscribe",
			expected:  true,
			reason:    "steward should subscribe to own heartbeat topic",
		},
		{
			name:      "allow_publish_own_dna",
			clientID:  "tenant1-steward-abc",
			topic:     "cfgms/steward/tenant1-steward-abc/dna",
			operation: "publish",
			expected:  true,
			reason:    "steward should publish to own DNA topic",
		},

		// DENY cases - client accessing other steward's topics
		{
			name:      "deny_subscribe_other_steward_wildcard",
			clientID:  "steward-123",
			topic:     "cfgms/steward/steward-456/#",
			operation: "subscribe",
			expected:  false,
			reason:    "steward should NOT subscribe to another steward's wildcard",
		},
		{
			name:      "deny_publish_other_steward_config",
			clientID:  "steward-123",
			topic:     "cfgms/steward/steward-999/config",
			operation: "publish",
			expected:  false,
			reason:    "steward should NOT publish to another steward's config",
		},
		{
			name:      "deny_subscribe_cross_tenant",
			clientID:  "tenant1-steward-abc",
			topic:     "cfgms/steward/tenant2-steward-xyz/#",
			operation: "subscribe",
			expected:  false,
			reason:    "steward should NOT subscribe to another tenant's steward topics",
		},
		{
			name:      "deny_publish_cross_tenant",
			clientID:  "tenant1-steward-abc",
			topic:     "cfgms/steward/tenant2-steward-xyz/secret",
			operation: "publish",
			expected:  false,
			reason:    "steward should NOT publish to another tenant's steward topics",
		},

		// DENY cases - non-steward topics
		{
			name:      "deny_subscribe_controller_topic",
			clientID:  "steward-123",
			topic:     "cfgms/controller/status",
			operation: "subscribe",
			expected:  false,
			reason:    "steward should NOT subscribe to controller topics",
		},
		{
			name:      "deny_publish_admin_topic",
			clientID:  "steward-123",
			topic:     "cfgms/admin/commands",
			operation: "publish",
			expected:  false,
			reason:    "steward should NOT publish to admin topics",
		},

		// Edge cases
		{
			name:      "deny_empty_client_id",
			clientID:  "",
			topic:     "cfgms/steward/steward-123/config",
			operation: "subscribe",
			expected:  false,
			reason:    "empty client ID should be denied",
		},
		{
			name:      "deny_partial_match",
			clientID:  "steward-123",
			topic:     "cfgms/steward/steward-1234/config",
			operation: "subscribe",
			expected:  false,
			reason:    "partial client ID match should be denied (steward-123 vs steward-1234)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call the ACL handler function (TDD - function doesn't exist yet)
			result := stewardACLHandler(tt.clientID, tt.topic, tt.operation)

			assert.Equal(t, tt.expected, result,
				"Test: %s\nReason: %s\nClientID: %s\nTopic: %s\nOperation: %s",
				tt.name, tt.reason, tt.clientID, tt.topic, tt.operation)
		})
	}
}

// TestStewardACLHandler_TopicPatterns tests specific topic pattern matching edge cases
func TestStewardACLHandler_TopicPatterns(t *testing.T) {
	clientID := "test-steward-123"

	tests := []struct {
		name     string
		topic    string
		expected bool
	}{
		// Valid patterns
		{"exact_match", "cfgms/steward/test-steward-123/config", true},
		{"subtopic_match", "cfgms/steward/test-steward-123/dna/network", true},
		{"deep_subtopic", "cfgms/steward/test-steward-123/a/b/c/d", true},
		{"wildcard_all", "cfgms/steward/test-steward-123/#", true},

		// Invalid patterns
		{"prefix_mismatch", "cfgms/steward/test-steward-12/config", false},
		{"suffix_mismatch", "cfgms/steward/test-steward-1234/config", false},
		{"different_prefix", "cfgms/steward/other-steward-123/config", false},
		{"missing_steward_segment", "cfgms/test-steward-123/config", false},
		{"extra_prefix", "prefix/cfgms/steward/test-steward-123/config", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stewardACLHandler(clientID, tt.topic, "subscribe")
			assert.Equal(t, tt.expected, result,
				"Topic pattern test failed: %s for topic: %s", tt.name, tt.topic)
		})
	}
}
