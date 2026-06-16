// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

// Windows Service Control Manager integration.
//
// When the SCM invokes the launcher with no console (the StartService
// path), the binary must call svc.Run with a Handler that reports
// SERVICE_RUNNING within ~30s and responds to control codes (Stop,
// Shutdown, Interrogate). Without this the SCM kills the process with
// "Error 1053: the service did not respond in a timely fashion."
//
// tryRunAsService detects the SCM-invoked context via
// svc.IsWindowsService(). When it returns true we never come back —
// the function calls os.Exit after svc.Run completes (success or
// failure). When it returns false (interactive invocation, e.g. an
// operator running `cfgms-steward-launcher status`) main() proceeds
// with normal CLI handling.

package main

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"
)

// tryRunAsService returns true after handing control to svc.Run; the
// caller should treat that as "process is done." Returns false if
// we're NOT running under the SCM (interactive console invocation) so
// the caller falls through to the regular CLI dispatch.
func tryRunAsService() bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		// Defensive: log to stderr (which the console branch will
		// honour) and fall through to interactive.
		fmt.Fprintf(os.Stderr, "launcher: svc.IsWindowsService failed: %v\n", err)
		return false
	}
	if !isService {
		return false
	}
	// We're under the SCM. Hand off to svc.Run, which blocks until the
	// service stops. Any error from Run propagates to the OS as a
	// non-zero process exit.
	if err := svc.Run("cfgms-steward-launcher", &windowsServiceHandler{args: os.Args[1:]}); err != nil {
		fmt.Fprintf(os.Stderr, "launcher: svc.Run failed: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
	return true // unreachable, but the signature needs a return
}

// windowsServiceHandler bridges the SCM control protocol to the
// launcher's regular Supervise loop.
//
// On Start: report StartPending, kick off runSuperviseWithCtx in a
// goroutine, then report Running.
// On Stop/Shutdown: cancel the context, wait for Supervise to return,
// report Stopped.
// On Interrogate: echo back the last known status.
// On supervise-exit-on-its-own: report Stopped with the launcher's
// return code as the service-specific exit code.
type windowsServiceHandler struct {
	// args is os.Args[1:] from the original launcher invocation —
	// typically ["run", "--child-args", "..."]. The handler strips a
	// leading "run" if present, since runSuperviseWithCtx parses the
	// `run` flag set directly.
	args []string
}

func (h *windowsServiceHandler) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Filter the leading subcommand token if present so the supervise
	// helper sees only its own flags.
	superviseArgs := h.args
	if len(superviseArgs) > 0 && superviseArgs[0] == "run" {
		superviseArgs = superviseArgs[1:]
	}

	done := make(chan int, 1)
	go func() {
		done <- runSuperviseWithCtx(ctx, superviseArgs)
	}()

	const accepts = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.Running, Accepts: accepts}

	for {
		select {
		case req := <-r:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				// Wait for the supervise goroutine to finish so the SCM
				// knows we've fully released resources. Bounded by the
				// SCM's own stop timeout (usually 30s).
				code := <-done
				status <- svc.Status{State: svc.Stopped}
				return false, uint32(code)
			}
		case code := <-done:
			// Supervise exited on its own (e.g. broken child, no
			// rollback available). Report Stopped with the actual
			// exit code so the SCM can log + apply recovery actions.
			cancel()
			status <- svc.Status{State: svc.Stopped}
			return false, uint32(code)
		}
	}
}
