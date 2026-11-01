// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

import (
	"context"
	"fmt"
)

// ExecutePS satisfies the psTransport interface. It looks psCommand up in
// psDispatchTable (pstransport_args_windows.go), converts psArgs to typed
// values, and runs the matching Cfgms-* verb on the row's run mode.
//
// No psArgs value is ever composed into script text. The values go to a
// per-call JSON args file; the script text is always the fixed
// `Cfgms-Invoke -Verb '<constant>' -ArgsFile '<generated path>'`, and
// Cfgms-Invoke binds the parsed values to the verb's named parameters.
//
// Unknown psCommand strings return an error rather than silently no-op'ing.
// There is no fallback transport here. If a future verb gets added in vm.go/vswitch.go without a matching
// Cfgms-* function, that's a build-time omission, not a runtime graceful
// degradation candidate.
func (t *psHostTransport) ExecutePS(ctx context.Context, psCommand string, psArgs map[string]string) (string, error) {
	call, err := planPSCall(psCommand, psArgs)
	if err != nil {
		return "", err
	}
	switch call.Mode {
	case psModeHost:
		return t.runCall(ctx, call)
	case psModeFresh:
		return t.runFreshCall(ctx, call)
	case psModeDetached:
		return t.runDetachedCall(call)
	}
	return "", fmt.Errorf("hyperv-ps-host: Cfgms-%s has no run mode", call.Verb)
}

// runCall runs a planned call in the persistent host. The args file is
// removed when the call returns, on success, error or panic.
func (t *psHostTransport) runCall(ctx context.Context, call psCall) (string, error) {
	argsPath, remove, err := writeArgsFile(call)
	if err != nil {
		return "", err
	}
	defer remove()
	expression, err := invokeExpression(call.Verb, argsPath)
	if err != nil {
		return "", err
	}
	return t.run(ctx, expression)
}

// runFreshCall runs a planned call in a fresh powershell.exe process. The
// args file is removed after the process exits, including after a deadline
// kill.
func (t *psHostTransport) runFreshCall(ctx context.Context, call psCall) (string, error) {
	argsPath, remove, err := writeArgsFile(call)
	if err != nil {
		return "", err
	}
	defer remove()
	expression, err := invokeExpression(call.Verb, argsPath)
	if err != nil {
		return "", err
	}
	return t.runFresh(ctx, call.Verb, expression, func() {
		t.dismountAfterKill(call.Verb, call.psArgs)
	})
}

// runDetachedCall starts a planned call in a detached process. The args file
// outlives this function: the goroutine that reaps the process removes it
// once the process exits. On a start failure it is removed here.
func (t *psHostTransport) runDetachedCall(call psCall) (out string, err error) {
	argsPath, remove, err := writeArgsFile(call)
	if err != nil {
		return "", err
	}
	started := false
	defer func() {
		if !started {
			remove()
		}
	}()
	expression, err := invokeExpression(call.Verb, argsPath)
	if err != nil {
		return "", err
	}
	out, err = t.runDetached(expression, remove)
	started = err == nil
	return out, err
}
