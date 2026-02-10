// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package mqtt

import (
	"context"
	"fmt"

	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
)

// SendHeartbeat sends a heartbeat from steward to controller (steward-side).
func (p *Provider) SendHeartbeat(ctx context.Context, heartbeat *types.Heartbeat) error {
	if p.mode != ModeClient {
		return fmt.Errorf("SendHeartbeat only available in client mode")
	}

	p.mu.Lock()
	p.stats.HeartbeatsSent++
	p.mu.Unlock()

	// Serialize heartbeat to JSON
	payload, err := marshalMessage(heartbeat)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat: %w", err)
	}

	// Publish to steward-specific heartbeat topic
	topic := fmt.Sprintf(topicHeartbeat, heartbeat.StewardID)
	err = p.client.Publish(ctx, topic, payload, 1, false)
	if err != nil {
		p.mu.Lock()
		p.stats.DeliveryFailures++
		p.mu.Unlock()
		return fmt.Errorf("failed to publish heartbeat: %w", err)
	}

	return nil
}

// SubscribeHeartbeats subscribes to all heartbeats (controller-side).
func (p *Provider) SubscribeHeartbeats(ctx context.Context, handler interfaces.HeartbeatHandler) error {
	if p.mode != ModeServer {
		return fmt.Errorf("SubscribeHeartbeats only available in server mode")
	}

	p.mu.Lock()
	p.heartbeatHandlers = append(p.heartbeatHandlers, handler)
	p.stats.ActiveSubscriptions++
	p.mu.Unlock()

	// Subscribe to all heartbeats
	// Only subscribe once even if multiple handlers
	if len(p.heartbeatHandlers) == 1 {
		err := p.broker.Subscribe(ctx, topicHeartbeatAll, 1, p.handleHeartbeatMessage)
		if err != nil {
			return fmt.Errorf("failed to subscribe to heartbeats: %w", err)
		}
	}

	return nil
}

// handleHeartbeatMessage processes incoming heartbeat messages (controller-side).
func (p *Provider) handleHeartbeatMessage(topic string, payload []byte, qos byte, retained bool) error {
	p.mu.Lock()
	p.stats.HeartbeatsReceived++
	p.mu.Unlock()

	// Deserialize heartbeat
	var heartbeat types.Heartbeat
	if err := unmarshalMessage(payload, &heartbeat); err != nil {
		// Log error but don't fail
		return nil
	}

	// Get all heartbeat handlers
	p.mu.RLock()
	handlers := make([]interfaces.HeartbeatHandler, len(p.heartbeatHandlers))
	copy(handlers, p.heartbeatHandlers)
	p.mu.RUnlock()

	// Call all handlers in goroutines
	for _, handler := range handlers {
		go func(h interfaces.HeartbeatHandler) {
			ctx := context.Background()
			_ = h(ctx, &heartbeat)
		}(handler)
	}

	return nil
}
