// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package mqtt

import (
	"context"
	"fmt"

	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
)

// SendCommand sends a command to a specific steward (controller-side).
func (p *Provider) SendCommand(ctx context.Context, cmd *types.Command) error {
	if p.mode != ModeServer {
		return fmt.Errorf("SendCommand only available in server mode")
	}

	p.mu.Lock()
	p.stats.CommandsSent++
	p.mu.Unlock()

	// Serialize command to JSON
	payload, err := marshalMessage(cmd)
	if err != nil {
		return fmt.Errorf("failed to marshal command: %w", err)
	}

	// Publish to steward-specific topic
	topic := fmt.Sprintf(topicCommandUnicast, cmd.StewardID)
	err = p.broker.Publish(ctx, topic, payload, 1, false)
	if err != nil {
		p.mu.Lock()
		p.stats.DeliveryFailures++
		p.mu.Unlock()
		return fmt.Errorf("failed to publish command: %w", err)
	}

	return nil
}

// FanOutCommand sends a command to a specific list of stewards (controller-side).
func (p *Provider) FanOutCommand(ctx context.Context, cmd *types.Command, stewardIDs []string) (*types.FanOutResult, error) {
	if p.mode != ModeServer {
		return nil, fmt.Errorf("FanOutCommand only available in server mode")
	}

	if len(stewardIDs) == 0 {
		return nil, fmt.Errorf("stewardIDs must not be empty")
	}

	// Serialize command once; reuse payload for all stewards
	payload, err := marshalMessage(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal command: %w", err)
	}

	result := &types.FanOutResult{
		Succeeded: make([]string, 0, len(stewardIDs)),
		Failed:    make(map[string]error),
	}

	for _, stewardID := range stewardIDs {
		topic := fmt.Sprintf(topicCommandUnicast, stewardID)
		if pubErr := p.broker.Publish(ctx, topic, payload, 1, false); pubErr != nil {
			p.mu.Lock()
			p.stats.DeliveryFailures++
			p.mu.Unlock()
			result.Failed[stewardID] = pubErr
		} else {
			p.mu.Lock()
			p.stats.CommandsSent++
			p.mu.Unlock()
			result.Succeeded = append(result.Succeeded, stewardID)
		}
	}

	return result, nil
}

// SubscribeCommands subscribes to commands for a steward (steward-side).
func (p *Provider) SubscribeCommands(ctx context.Context, stewardID string, handler interfaces.CommandHandler) error {
	if p.mode != ModeClient {
		return fmt.Errorf("SubscribeCommands only available in client mode")
	}

	if p.client == nil {
		return fmt.Errorf("client not initialized")
	}

	p.mu.Lock()
	p.commandHandlers[stewardID] = handler
	p.stats.ActiveSubscriptions++
	p.mu.Unlock()

	// Subscribe to unicast commands
	topic := fmt.Sprintf(topicCommandUnicast, stewardID)
	err := p.client.Subscribe(ctx, topic, 1, p.handleCommandMessage)
	if err != nil {
		return fmt.Errorf("failed to subscribe to commands: %w", err)
	}

	// Subscribe to broadcast commands (if tenant ID is configured)
	if tenantID, ok := p.config["tenant_id"].(string); ok && tenantID != "" {
		broadcastTopic := fmt.Sprintf(topicCommandTenantBcast, tenantID)
		err = p.client.Subscribe(ctx, broadcastTopic, 1, p.handleCommandMessage)
		if err != nil {
			return fmt.Errorf("failed to subscribe to broadcast commands: %w", err)
		}
	}

	return nil
}

// handleCommandMessage processes incoming command messages (steward-side).
// This is the client-side handler matching mqttClient.MessageHandler signature.
func (p *Provider) handleCommandMessage(topic string, payload []byte) {
	p.mu.Lock()
	p.stats.CommandsReceived++
	p.mu.Unlock()

	// Deserialize command
	var cmd types.Command
	if err := unmarshalMessage(payload, &cmd); err != nil {
		// Log error but don't fail - message might be malformed
		return
	}

	// Extract stewardID from topic or use command's StewardID field
	// Topic format: cfgms/commands/{steward_id} or cfgms/commands/{tenant_id}/broadcast
	stewardID := cmd.StewardID
	if stewardID == "" {
		// If command doesn't specify steward (broadcast), use provider's steward ID
		stewardID = p.stewardID
	}

	// Find handler for this steward
	// Story #363 bugfix: Use stewardID from command/topic, not p.stewardID
	// This fixes the mismatch where handlers are stored by parameter but looked up by field
	p.mu.RLock()
	handler, exists := p.commandHandlers[stewardID]
	p.mu.RUnlock()

	if !exists {
		// No handler registered, ignore
		return
	}

	// Call handler in goroutine to avoid blocking MQTT callback
	go func() {
		ctx := context.Background()
		_ = handler(ctx, &cmd)
	}()
}
