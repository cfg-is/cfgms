// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package trigger

import (
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// NewControllerTriggerManager creates a fully-wired TriggerManagerImpl for controller use.
//
// The trigger system has a circular dependency: TriggerManagerImpl holds Scheduler,
// WebhookHandler, and SIEMIntegration, while each component also holds a reference
// back to the TriggerManager for execution tracking. This factory resolves the
// dependency via two-phase initialization within the package boundary.
func NewControllerTriggerManager(
	storage interfaces.StorageProvider,
	workflowTrigger WorkflowTrigger,
) *TriggerManagerImpl {
	// Phase 1: Create the manager with nil components to break the circular dependency.
	// The manager's Start() guards against nil components, so this is safe during wiring.
	manager := NewTriggerManager(storage, nil, nil, nil, workflowTrigger)

	// Phase 2: Create each component with the manager reference.
	scheduler := NewCronScheduler(manager, workflowTrigger)

	// Webhook handler binds to port 0 (disabled) by default.
	// The controller's existing REST API handles inbound webhook delivery.
	webhookHandler := NewHTTPWebhookHandler(manager, workflowTrigger, "localhost", 0)

	siemProcessor := NewSIEMProcessor(manager, workflowTrigger)

	// Phase 3: Wire components back into the manager now that all are constructed.
	manager.scheduler = scheduler
	manager.webhookHandler = webhookHandler
	manager.siemIntegration = siemProcessor

	return manager
}
