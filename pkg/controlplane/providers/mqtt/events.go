// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package mqtt

import (
	"context"
	"fmt"

	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
)

// PublishEvent publishes an event from steward to controller (steward-side).
func (p *Provider) PublishEvent(ctx context.Context, event *types.Event) error {
	if p.mode != ModeClient {
		return fmt.Errorf("PublishEvent only available in client mode")
	}

	p.mu.Lock()
	p.stats.EventsPublished++
	p.mu.Unlock()

	// Serialize event to JSON
	payload, err := marshalMessage(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Publish to steward-specific event topic
	topic := fmt.Sprintf(topicEvent, event.StewardID)
	err = p.client.Publish(ctx, topic, payload, 1, false)
	if err != nil {
		p.mu.Lock()
		p.stats.DeliveryFailures++
		p.mu.Unlock()
		return fmt.Errorf("failed to publish event: %w", err)
	}

	return nil
}

// SubscribeEvents subscribes to events matching a filter (controller-side).
func (p *Provider) SubscribeEvents(ctx context.Context, filter *types.EventFilter, handler interfaces.EventHandler) error {
	if p.mode != ModeServer {
		return fmt.Errorf("SubscribeEvents only available in server mode")
	}

	p.mu.Lock()
	p.eventHandlers = append(p.eventHandlers, eventSubscription{
		filter:  filter,
		handler: handler,
	})
	p.stats.ActiveSubscriptions++
	p.mu.Unlock()

	// Subscribe to all events (filtering happens in handler)
	// Only subscribe once even if multiple handlers
	if len(p.eventHandlers) == 1 {
		err := p.broker.Subscribe(ctx, topicEventAll, 1, p.handleEventMessage)
		if err != nil {
			return fmt.Errorf("failed to subscribe to events: %w", err)
		}
	}

	return nil
}

// handleEventMessage processes incoming event messages (controller-side).
func (p *Provider) handleEventMessage(topic string, payload []byte, qos byte, retained bool) error {
	p.mu.Lock()
	p.stats.EventsReceived++
	p.mu.Unlock()

	// Deserialize event
	var event types.Event
	if err := unmarshalMessage(payload, &event); err != nil {
		// Log error but don't fail
		return nil
	}

	// Get all event handlers
	p.mu.RLock()
	handlers := make([]eventSubscription, len(p.eventHandlers))
	copy(handlers, p.eventHandlers)
	p.mu.RUnlock()

	// Call matching handlers in goroutines
	for _, sub := range handlers {
		if sub.filter == nil || sub.filter.Match(&event) {
			go func(h interfaces.EventHandler) {
				ctx := context.Background()
				_ = h(ctx, &event)
			}(sub.handler)
		}
	}

	return nil
}
