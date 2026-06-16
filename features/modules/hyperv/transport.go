// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/masterzen/winrm"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// winrmTransport abstracts WinRM execution for testability and injection safety.
// Basic auth forbidden — credentials exposed to TLS-terminating proxies
type winrmTransport interface {
	ExecutePS(ctx context.Context, psCommand string, psArgs map[string]string) (string, error)
}

// winrmShell is the minimal interface over a WinRM shell connection.
// realWinRMShellWrapper wraps *winrm.Shell; tests substitute a recording implementation.
type winrmShell interface {
	// RunPS executes a PowerShell command via the shell.
	// scriptBlock is the command text (with param declarations but no user values).
	// args are the -ArgumentList values transmitted as separate WinRM Arguments,
	// never embedded in the scriptBlock text.
	RunPS(ctx context.Context, scriptBlock string, args []string) (string, error)
	Close() error
}

// winrmClient is the concrete WinRM transport. It fetches credentials from
// SecretStore on every ExecutePS call — no credential caching between calls.
type winrmClient struct {
	host          string
	userSecretKey string
	passSecretKey string
	store         secretsif.SecretStore
	// newShell creates a WinRM shell; injectable for tests.
	newShell func(host, username, password string) (winrmShell, error)
}

// newWinRMClientWithStore creates a winrmClient that fetches credentials from store
// on every ExecutePS call. Always connects to TLS port 5986.
func newWinRMClientWithStore(host, userSecretKey, passSecretKey string, store secretsif.SecretStore) *winrmClient {
	return &winrmClient{
		host:          host,
		userSecretKey: userSecretKey,
		passSecretKey: passSecretKey,
		store:         store,
		newShell:      realWinRMShell,
	}
}

// ExecutePS executes a PowerShell command via WinRM using Invoke-Command with
// ArgumentList. User-supplied values are transmitted as separate WinRM Arguments
// entries — never interpolated into the script block text.
func (c *winrmClient) ExecutePS(ctx context.Context, psCommand string, psArgs map[string]string) (string, error) {
	// Fetch credentials fresh on every invocation — no caching
	userSecret, err := c.store.GetSecret(ctx, c.userSecretKey)
	if err != nil {
		return "", fmt.Errorf("hyperv: get WinRM username: %w", err)
	}
	passSecret, err := c.store.GetSecret(ctx, c.passSecretKey)
	if err != nil {
		return "", fmt.Errorf("hyperv: get WinRM password: %w", err)
	}

	scriptBlock, args := buildInvokeCommand(psCommand, psArgs)

	shell, err := c.newShell(c.host, userSecret.Value, passSecret.Value)
	if err != nil {
		return "", fmt.Errorf("hyperv: connect to %s: %w", c.host, err)
	}

	output, execErr := shell.RunPS(ctx, scriptBlock, args)
	if closeErr := shell.Close(); closeErr != nil && execErr == nil {
		return "", fmt.Errorf("hyperv: close shell: %w", closeErr)
	}
	return output, execErr
}

// buildInvokeCommand builds the injection-safe PowerShell Invoke-Command string.
// Returns the script block text (containing param declarations but no user values)
// and the argument values in deterministic key order.
func buildInvokeCommand(psCommand string, psArgs map[string]string) (scriptBlock string, args []string) {
	if len(psArgs) == 0 {
		return psCommand, nil
	}

	// Sort keys for deterministic order
	keys := make([]string, 0, len(psArgs))
	for k := range psArgs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build param declarations: $key0, $key1, ...
	paramDecls := make([]string, len(keys))
	for i, k := range keys {
		paramDecls[i] = "$" + k
	}

	// Argument values in same order as param declarations
	args = make([]string, len(keys))
	for i, k := range keys {
		args[i] = psArgs[k]
	}

	// Script block has param declarations; values are sent via ArgumentList separately.
	scriptBlock = "Invoke-Command -ScriptBlock { param(" + strings.Join(paramDecls, ", ") + ") " + psCommand + " } -ArgumentList"
	return scriptBlock, args
}

// productionWinRMParams returns the WinRM parameters used by all connections.
// NTLM is the only permitted auth method; Basic auth is structurally impossible.
func productionWinRMParams() *winrm.Parameters {
	p := winrm.NewParameters("PT60S", "en-US", 153600)
	// Basic auth forbidden — credentials exposed to TLS-terminating proxies
	p.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
	return p
}

// realWinRMShell creates a WinRM shell connected to host:5986 over TLS with NTLM auth.
// Basic auth forbidden — credentials exposed to TLS-terminating proxies
func realWinRMShell(host, username, password string) (winrmShell, error) {
	// Port 5986 is the standard WinRM over TLS port.
	endpoint := winrm.NewEndpoint(host, 5986, true, false, nil, nil, nil, 0)
	endpoint.Insecure = false // explicitly set false, not left to zero value

	client, err := winrm.NewClientWithParameters(endpoint, username, password, productionWinRMParams())
	if err != nil {
		return nil, fmt.Errorf("winrm: create client: %w", err)
	}

	shell, err := client.CreateShell()
	if err != nil {
		return nil, fmt.Errorf("winrm: create shell: %w", err)
	}

	return &realWinRMShellWrapper{shell: shell}, nil
}

// realWinRMShellWrapper wraps *winrm.Shell to satisfy the winrmShell interface.
type realWinRMShellWrapper struct {
	shell *winrm.Shell
}

// RunPS executes a PowerShell command on the remote host.
// scriptBlock is the command text; args are passed as additional WinRM Arguments
// that PowerShell receives as the -ArgumentList entries.
func (r *realWinRMShellWrapper) RunPS(ctx context.Context, scriptBlock string, args []string) (string, error) {
	// Pass scriptBlock as the -Command value; args follow as separate WinRM Arguments.
	allArgs := append([]string{"-NonInteractive", "-Command", scriptBlock}, args...)

	cmd, err := r.shell.ExecuteWithContext(ctx, "powershell", allArgs...)
	if err != nil {
		return "", fmt.Errorf("winrm: execute: %w", err)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	var stdoutErr, stderrErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, stdoutErr = io.Copy(&stdoutBuf, cmd.Stdout)
	}()
	go func() {
		defer wg.Done()
		_, stderrErr = io.Copy(&stderrBuf, cmd.Stderr)
	}()
	wg.Wait()
	cmd.Wait()

	if stdoutErr != nil {
		return "", fmt.Errorf("winrm: read stdout: %w", stdoutErr)
	}
	if stderrErr != nil {
		return "", fmt.Errorf("winrm: read stderr: %w", stderrErr)
	}

	if closeErr := cmd.Close(); closeErr != nil {
		return "", fmt.Errorf("winrm: close command: %w", closeErr)
	}

	if code := cmd.ExitCode(); code != 0 {
		return "", fmt.Errorf("winrm: PowerShell exited %d: %s", code, stderrBuf.String())
	}

	return stdoutBuf.String(), nil
}

// Close closes the underlying WinRM shell.
func (r *realWinRMShellWrapper) Close() error {
	return r.shell.Close()
}
