// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package mqtt

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/controlplane/types"
)

// SendResponse sends a command response/acknowledgment (steward-side).
func (p *Provider) SendResponse(ctx context.Context, response *types.Response) error {
	if p.mode != ModeClient {
		return fmt.Errorf("SendResponse only available in client mode")
	}

	p.mu.Lock()
	p.stats.ResponsesSent++
	p.mu.Unlock()

	// Serialize response to JSON
	payload, err := marshalMessage(response)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	// Publish to command-specific response topic
	topic := fmt.Sprintf(topicResponse, response.CommandID)
	err = p.client.Publish(ctx, topic, payload, 1, false)
	if err != nil {
		p.mu.Lock()
		p.stats.DeliveryFailures++
		p.mu.Unlock()
		return fmt.Errorf("failed to publish response: %w", err)
	}

	return nil
}

// WaitForResponse waits for a command response with timeout (controller-side).
func (p *Provider) WaitForResponse(ctx context.Context, commandID string, timeout time.Duration) (*types.Response, error) {
	if p.mode != ModeServer {
		return nil, fmt.Errorf("WaitForResponse only available in server mode")
	}

	// Create response channel
	responseChan := make(chan *types.Response, 1)

	p.responseMu.Lock()
	p.pendingResponses[commandID] = responseChan
	p.responseMu.Unlock()

	// Subscribe to this specific response topic
	topic := fmt.Sprintf(topicResponse, commandID)
	err := p.broker.Subscribe(ctx, topic, 1, func(topic string, payload []byte, qos byte, retained bool) error {
		var response types.Response
		if err := unmarshalMessage(payload, &response); err != nil {
			return nil
		}

		// Send response to waiting goroutine
		p.responseMu.RLock()
		if ch, exists := p.pendingResponses[commandID]; exists {
			select {
			case ch <- &response:
			default:
				// Channel full, response already delivered
			}
		}
		p.responseMu.RUnlock()

		return nil
	})
	if err != nil {
		p.responseMu.Lock()
		delete(p.pendingResponses, commandID)
		p.responseMu.Unlock()
		return nil, fmt.Errorf("failed to subscribe to response: %w", err)
	}

	// Wait for response or timeout
	select {
	case response := <-responseChan:
		// Cleanup
		p.responseMu.Lock()
		delete(p.pendingResponses, commandID)
		p.responseMu.Unlock()

		_ = p.broker.Unsubscribe(ctx, topic)

		p.mu.Lock()
		p.stats.ResponsesReceived++
		p.mu.Unlock()

		return response, nil

	case <-time.After(timeout):
		// Timeout - cleanup
		p.responseMu.Lock()
		delete(p.pendingResponses, commandID)
		p.responseMu.Unlock()

		_ = p.broker.Unsubscribe(ctx, topic)

		return nil, fmt.Errorf("timeout waiting for response to command %s", commandID)

	case <-ctx.Done():
		// Context cancelled - cleanup
		p.responseMu.Lock()
		delete(p.pendingResponses, commandID)
		p.responseMu.Unlock()

		_ = p.broker.Unsubscribe(ctx, topic)

		return nil, ctx.Err()
	}
}
