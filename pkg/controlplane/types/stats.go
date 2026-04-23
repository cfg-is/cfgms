// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package types

import "time"

// ControlPlaneStats contains operational metrics for the control plane provider.
//
// These statistics help monitor control plane health and performance.
type ControlPlaneStats struct {
	// Total commands sent (controller perspective)
	CommandsSent int64 `json:"commands_sent"`

	// Total commands received (steward perspective)
	CommandsReceived int64 `json:"commands_received"`

	// Total events published (steward perspective)
	EventsPublished int64 `json:"events_published"`

	// Total events received (controller perspective)
	EventsReceived int64 `json:"events_received"`

	// Total heartbeats sent
	HeartbeatsSent int64 `json:"heartbeats_sent"`

	// Total heartbeats received
	HeartbeatsReceived int64 `json:"heartbeats_received"`

	// Total responses sent
	ResponsesSent int64 `json:"responses_sent"`

	// Total responses received
	ResponsesReceived int64 `json:"responses_received"`

	// Number of active subscriptions
	ActiveSubscriptions int64 `json:"active_subscriptions"`

	// Number of connected stewards (controller perspective)
	ConnectedStewards int64 `json:"connected_stewards"`

	// Uptime since provider started
	Uptime time.Duration `json:"uptime"`

	// Message delivery failures
	DeliveryFailures int64 `json:"delivery_failures"`

	// IdentityMismatches counts ControlChannel messages whose payload StewardID
	// disagreed with the mTLS-authenticated CN and were rejected without dispatch.
	IdentityMismatches int64 `json:"identity_mismatches"`

	// Average message latency (if measurable)
	AvgLatency time.Duration `json:"avg_latency,omitempty"`

	// Provider-specific metrics
	ProviderMetrics map[string]interface{} `json:"provider_metrics,omitempty"`
}
