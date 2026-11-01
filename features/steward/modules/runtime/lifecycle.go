// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package runtime

import (
	"os/exec"
	"sync"

	"github.com/cfgis/cfgms/pkg/modules/contract"
	"google.golang.org/grpc"
)

// LifecycleState tracks the state of a running module process.
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

// ModuleHandle represents a running out-of-process module instance.
// Obtain one via ModuleRuntime.Start; release with ModuleRuntime.Stop.
type ModuleHandle struct {
	// Name is the module's name from its manifest.
	Name string

	// Client is the gRPC client for this module session.
	Client contract.StewardModuleClient

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
