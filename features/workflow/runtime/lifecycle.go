// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package runtime

import (
	"context"
	"fmt"
	"os/exec"
	"sync"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	featuremodules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/modules/contract"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v3"
)

// LifecycleState tracks the state of a running workflow module process.
type LifecycleState int

const (
	// StateStarting: binary fork/exec'd, socket not yet connected.
	StateStarting LifecycleState = iota + 1
	// StateReady: gRPC connection established and Handshake completed.
	StateReady
	// StateRunning: module is operating normally, ready to serve RPCs.
	StateRunning
	// StateStopping: Shutdown RPC sent, waiting for process exit.
	StateStopping
	// StateStopped: process has exited and resources are cleaned up.
	StateStopped
)

// ModuleHandle represents a running out-of-process workflow module instance.
// Obtain one via ModuleRuntime.Start; release with ModuleRuntime.Stop.
//
// ModuleHandle implements features/modules.Module so callers can return it
// directly from WorkflowModuleFactory.CreateModuleInstance.
type ModuleHandle struct {
	// Name is the module's name from its manifest.
	Name string

	// Client is the gRPC client for this module session.
	Client contract.WorkflowModuleClient

	conn       *grpc.ClientConn
	cmd        *exec.Cmd
	socketPath string
	state      LifecycleState
	waitCh     chan struct{} // closed when the module process exits
	mu         sync.Mutex
}

// GetState returns the current lifecycle state of the handle.
func (h *ModuleHandle) GetState() LifecycleState {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state
}

// Get implements features/modules.Module by delegating to the WorkflowModuleClient.
// The proto GetResponse.ConfigData is returned as a workflowConfigState whose
// AsMap() exposes the raw string under the "config_data" key for workflow variable bindings.
func (h *ModuleHandle) Get(ctx context.Context, resourceID string) (featuremodules.ConfigState, error) {
	resp, err := h.Client.Get(ctx, &proto.GetRequest{ResourceId: resourceID})
	if err != nil {
		return nil, fmt.Errorf("workflow module %q Get(%q): %w", h.Name, resourceID, err)
	}
	return &workflowConfigState{data: resp.ConfigData}, nil
}

// Set implements features/modules.Module by delegating to the WorkflowModuleClient.
// The config state is serialized to YAML for the proto SetRequest.ConfigData field.
func (h *ModuleHandle) Set(ctx context.Context, resourceID string, config featuremodules.ConfigState) error {
	var configData string
	if config != nil {
		b, err := config.ToYAML()
		if err != nil {
			return fmt.Errorf("workflow module %q Set(%q): serialize config: %w", h.Name, resourceID, err)
		}
		configData = string(b)
	}
	resp, err := h.Client.Set(ctx, &proto.SetRequest{ResourceId: resourceID, ConfigData: configData})
	if err != nil {
		return fmt.Errorf("workflow module %q Set(%q): %w", h.Name, resourceID, err)
	}
	if resp.GetError() != "" {
		return fmt.Errorf("workflow module %q Set(%q): module error: %s", h.Name, resourceID, resp.GetError())
	}
	return nil
}

// workflowConfigState is the minimal ConfigState implementation for workflow
// module Get responses. It carries the raw ConfigData string from the proto
// response and exposes it as a map for use in workflow variable bindings.
type workflowConfigState struct {
	data string
}

func (s *workflowConfigState) AsMap() map[string]interface{} {
	return map[string]interface{}{"config_data": s.data}
}

func (s *workflowConfigState) ToYAML() ([]byte, error) {
	return yaml.Marshal(map[string]string{"config_data": s.data})
}

func (s *workflowConfigState) FromYAML(b []byte) error {
	var m map[string]string
	if err := yaml.Unmarshal(b, &m); err != nil {
		return err
	}
	s.data = m["config_data"]
	return nil
}

func (s *workflowConfigState) Validate() error { return nil }

func (s *workflowConfigState) GetManagedFields() []string { return []string{"config_data"} }
