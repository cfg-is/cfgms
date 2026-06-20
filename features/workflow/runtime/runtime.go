// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Package runtime implements the workflow module runtime: fork/exec, gRPC client,
// and lifecycle management for out-of-process controller-kind (workflow) modules.
//
// Only controller-kind ("workflow") modules may be started by this runtime. Steward-
// and outpost-kind modules are handled by their respective runtimes.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	goruntime "runtime"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
)

// ErrWrongModuleKind is returned by Start when the bundle's manifest kind is not
// "workflow". The workflow runtime hosts only controller-kind ("workflow") modules.
var ErrWrongModuleKind = errors.New("wrong module kind: workflow runtime hosts only controller-kind (workflow) modules")

// handleSeq generates unique monotonic IDs for socket path generation.
var handleSeq atomic.Int64

// ModuleRuntime manages the lifecycle of out-of-process controller-kind workflow
// module binaries. Create one per controller instance with NewModuleRuntime.
type ModuleRuntime struct {
	runtimeDir string
}

// NewModuleRuntime returns a ModuleRuntime that creates sockets under runtimeDir.
// runtimeDir must be a writable directory; use t.TempDir() in tests.
func NewModuleRuntime(runtimeDir string) *ModuleRuntime {
	return &ModuleRuntime{runtimeDir: runtimeDir}
}

// Start fork/execs the module binary for the current OS/arch, waits for it to
// start listening, dials gRPC, and returns a ModuleHandle ready for RPC calls.
//
// Error precedence:
//  1. ErrWrongModuleKind — bundle.Manifest.Kind != "workflow"
//  2. binary not found in bundle.Binaries for current os-arch
//  3. fork/exec, socket, or gRPC errors
func (r *ModuleRuntime) Start(b *bundle.Bundle) (*ModuleHandle, error) {
	// 1. Kind gate — must be first; workflow runtime hosts only workflow-kind modules.
	if b.Manifest == nil || b.Manifest.Kind != "workflow" {
		got := ""
		if b.Manifest != nil {
			got = b.Manifest.Kind
		}
		return nil, fmt.Errorf("%w: got %q", ErrWrongModuleKind, got)
	}

	// 2. Locate the binary for the current platform.
	osArch := goruntime.GOOS + "-" + goruntime.GOARCH
	binPath, ok := b.Binaries[osArch]
	if !ok {
		return nil, fmt.Errorf("no binary for %q in bundle %q (available: %v)",
			osArch, b.Manifest.Name, binaryKeys(b.Binaries))
	}

	// 3. Construct a unique socket path for this module instance. makeSocketPath
	// also creates the controller-private socket directory (mode 0700).
	id := handleSeq.Add(1)
	socketPath, err := makeSocketPath(r.runtimeDir, b.Manifest.Name, id)
	if err != nil {
		return nil, fmt.Errorf("socket path for module %q: %w", b.Manifest.Name, err)
	}

	// 4. Fork/exec the module binary with the socket path in its environment.
	// #nosec G204 — binPath comes from the bundle manifest, not user-supplied input.
	cmd := exec.Command(binPath)
	cmd.Env = append(os.Environ(), "CFGMS_MODULE_SOCKET="+socketPath)

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("fork/exec module %q (%s): %w", b.Manifest.Name, binPath, err)
	}

	// 5. Wait for the module to start listening on its socket (up to 30 s).
	startCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := waitForSocket(startCtx, socketPath); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.Remove(socketPath)
		return nil, fmt.Errorf("module %q did not start listening: %w", b.Manifest.Name, err)
	}

	// 6. Dial gRPC over the local socket.
	conn, err := dialGRPCSocket(socketPath)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.Remove(socketPath)
		return nil, fmt.Errorf("dial gRPC for module %q: %w", b.Manifest.Name, err)
	}

	client := proto.NewWorkflowModuleServiceClient(conn)

	// 7. Perform the workflow handshake to confirm the gRPC session.
	hsCtx, hsCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer hsCancel()

	if _, err := client.Handshake(hsCtx, &proto.WorkflowHandshakeRequest{
		ModuleName:    b.Manifest.Name,
		ModuleVersion: b.Manifest.Version,
		Publisher:     b.Manifest.Publisher,
	}); err != nil {
		_ = conn.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.Remove(socketPath)
		return nil, fmt.Errorf("handshake with module %q: %w", b.Manifest.Name, err)
	}

	// 8. Start a goroutine to collect the process exit status.
	waitCh := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(waitCh)
	}()

	h := &ModuleHandle{
		Name:       b.Manifest.Name,
		Client:     client,
		conn:       conn,
		cmd:        cmd,
		socketPath: socketPath,
		state:      StateRunning,
		waitCh:     waitCh,
	}
	return h, nil
}

// Stop sends the Shutdown RPC, waits for the module process to exit, and kills
// the process if it has not exited within 10 seconds. Stop is idempotent.
func (r *ModuleRuntime) Stop(h *ModuleHandle) error {
	h.mu.Lock()
	if h.state >= StateStopping {
		h.mu.Unlock()
		return nil
	}
	h.state = StateStopping
	h.mu.Unlock()

	// Send Shutdown RPC (best-effort: process may already have exited).
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, _ = h.Client.Shutdown(shutCtx, &proto.ShutdownRequest{})
	cancel()

	// Wait for process exit with a 10-second deadline.
	select {
	case <-h.waitCh:
	case <-time.After(10 * time.Second):
		_ = h.cmd.Process.Kill()
		<-h.waitCh
	}

	h.mu.Lock()
	h.state = StateStopped
	h.mu.Unlock()

	_ = h.conn.Close()
	_ = os.Remove(h.socketPath)
	return nil
}

// sanitizeName replaces characters that are unsafe in socket/pipe names with
// hyphens so module names like "publisher/name" produce valid path components.
func sanitizeName(name string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, name)
}

// binaryKeys returns the keys of the binaries map for use in error messages.
func binaryKeys(binaries map[string]string) []string {
	keys := make([]string, 0, len(binaries))
	for k := range binaries {
		keys = append(keys, k)
	}
	return keys
}
