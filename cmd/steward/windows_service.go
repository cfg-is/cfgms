// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/pflag"
	"golang.org/x/sys/windows/svc"

	"github.com/cfgis/cfgms/cmd/steward/service"
)

// checkAndRunAsWindowsService detects whether the process was launched by the
// Windows Service Control Manager. If so, it registers the service handler,
// runs until the SCM sends a stop signal, and returns true. Returns false when
// invoked interactively (not as a service) so normal CLI processing continues.
func checkAndRunAsWindowsService() bool {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false
	}

	// Run as a Windows service. svc.Run blocks until the service is stopped.
	if err := svc.Run(winServiceName, &stewardServiceHandler{}); err != nil {
		fmt.Fprintf(os.Stderr, "Windows service run failed: %v\n", err)
	}
	return true
}

// serviceRegToken returns the registration token from the service arguments:
// the --regtoken value, or the content of the --regtoken-file file read with
// service.ReadTokenFile, which refuses a file that SYSTEM and Administrators do
// not exclusively control. Giving both flags is an error.
func serviceRegToken(regToken, regTokenFile string) (string, error) {
	if regToken != "" && regTokenFile != "" {
		return "", errors.New("--regtoken and --regtoken-file cannot be used together")
	}
	if regTokenFile == "" {
		return regToken, nil
	}
	return service.ReadTokenFile(regTokenFile)
}

// winServiceName must match the name registered in service/manager_windows.go.
const winServiceName = "CFGMSSteward"

// stewardServiceHandler implements svc.Handler to manage the steward lifecycle
// as a Windows service. The SCM starts the binary with the full command line
// stored during service registration, e.g.:
//
//	cfgms-steward.exe --regtoken TOKEN
//
// These appear in os.Args so normal flag parsing extracts the token.
type stewardServiceHandler struct{}

// Execute is called by the Windows SCM when the service starts. It parses
// os.Args to extract --regtoken, starts the steward, and handles stop/shutdown
// signals from the SCM.
func (h *stewardServiceHandler) Execute(
	_ []string,
	requests <-chan svc.ChangeRequest,
	status chan<- svc.Status,
) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	// Parse the flags directly from os.Args so the service handler can read
	// --regtoken, --controller-url etc. that were stored in the service definition.
	flags := pflag.NewFlagSet("steward-service", pflag.ContinueOnError)
	regToken := flags.String("regtoken", "", "registration token")
	regTokenFile := flags.String("regtoken-file", "", "path to a file holding the registration token")
	controllerURL := flags.String("controller-url", "", "controller URL")
	configPath := flags.String("config", "", "config path")
	// Ignore unknown flags (e.g. subcommand names) so the service can start even
	// if the arg list changes between versions.
	flags.ParseErrorsAllowlist.UnknownFlags = true
	_ = flags.Parse(os.Args[1:])

	token, err := serviceRegToken(*regToken, *regTokenFile)
	if err != nil {
		// The error names the file, never the token. A non-zero exit lets the
		// SCM apply recovery actions.
		fmt.Fprintf(os.Stderr, "steward service start failed: %v\n", err)
		return true, 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runSteward(ctx, token, *controllerURL, *configPath)
	}()

	status <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	for {
		select {
		case req := <-requests:
			switch req.Cmd {
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				// Wait up to 30 s for graceful shutdown before returning to SCM.
				select {
				case errChErr := <-errCh:
					_ = errChErr
				case <-time.After(30 * time.Second):
				}
				return false, 0
			case svc.Interrogate:
				status <- req.CurrentStatus
			}

		case err := <-errCh:
			if err != nil {
				// Non-zero exit signals the SCM to apply recovery actions.
				return true, 1
			}
			return false, 0
		}
	}
}
