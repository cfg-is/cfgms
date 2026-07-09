// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// Self-repair of a deleted SCM service registration (#2465).
//
// Observed live 2026-07-08 (epic #565 runner scale-out): an AV product
// quarantined the launcher binary and, as "remediation", DELETED the
// CFGMSSteward service registration out from under the still-running launcher.
// The SCM's install-time restart recovery actions cannot help — they only fire
// when a service entry still exists to restart. With the registration gone the
// steward is silently and permanently dead until the next manual reinstall.
//
// This is the missing detect-and-recreate loop: the supervise loop runs a
// dedicated ticker (see runServiceRegistrationRepair in lifecycle.go) that, on
// every tick, verifies CFGMSSteward still exists in the SCM and re-creates it
// with the same binary path, start type, and recovery actions as the original
// Install path if it does not.

const (
	// launcherServiceName MUST stay in sync with windowsServiceName in
	// cmd/steward/service/manager_windows.go — the SCM registration the install
	// path creates and this self-repair path re-creates are the same service.
	launcherServiceName = "CFGMSSteward"
	// launcherServiceExePath MUST stay in sync with windowsLauncherPath in
	// cmd/steward/service/manager_windows.go. The steward's push-upgrade handler
	// execs the launcher at this exact compile-time path, so a repaired service
	// must point HERE — never at os.Args[0], which may be a temp/staged path when
	// the running process was launched from somewhere other than the install dir.
	launcherServiceExePath = `C:\Program Files\CFGMS\cfgms-steward-launcher.exe`
	// launcherServiceDisplayName / launcherServiceDescription MUST stay in sync
	// with windowsDisplayName / windowsDescription in manager_windows.go.
	launcherServiceDisplayName = "CFGMS Steward"
	launcherServiceDescription = "CFGMS endpoint configuration management agent"
)

// serviceRegistrationOK reports whether the named service still exists in the
// SCM. It returns (false, nil) — a definite "missing", the repair trigger —
// only when the SCM answers ERROR_SERVICE_DOES_NOT_EXIST. Any other error
// (cannot connect to the SCM in a non-elevated context, a transient RPC fault)
// is returned as (false, err) so the caller SKIPS this tick rather than
// attempting a recreate it could not complete — recreating on an access error
// would just fail. This is a more precise sentinel match than Uninstall's
// catch-all in manager_windows.go:303, deliberately, because here a false
// "missing" verdict would issue a needless CreateService.
func serviceRegistrationOK(name string) (bool, error) {
	scm, err := mgr.Connect()
	if err != nil {
		return false, fmt.Errorf("connect SCM: %w", err)
	}
	defer scm.Disconnect()

	svc, err := scm.OpenService(name)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return false, nil
		}
		return false, fmt.Errorf("open service %q: %w", name, err)
	}
	svc.Close()
	return true, nil
}

// repairServiceRegistration re-creates a deleted service registration with the
// SAME mgr.Config shape and SetRecoveryActions call the install path uses
// (cmd/steward/service/manager_windows.go:224-261). The literal is duplicated
// here rather than shared via an exported helper: factoring it out would make
// this launcher command import cmd/steward/service (a new cmd→cmd dependency —
// today only cmd/steward/main.go imports that package), which is more invasive
// than the ~10-line duplication for a story this size. The const comments above
// call out the fields that MUST stay in sync.
//
// name is a parameter (not the launcherServiceName const) so tests can exercise
// this against a unique throwaway service without ever touching the host's real
// CFGMSSteward registration.
func repairServiceRegistration(name, exePath string, args []string) error {
	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer scm.Disconnect()

	newSvc, err := scm.CreateService(
		name,
		exePath,
		mgr.Config{
			StartType:   mgr.StartAutomatic,
			DisplayName: launcherServiceDisplayName,
			Description: launcherServiceDescription,
		},
		args...,
	)
	if err != nil {
		return fmt.Errorf("create service %q: %w", name, err)
	}
	defer newSvc.Close()

	// Same recovery policy as install: 3 escalating restart delays, 1-day reset.
	recoveryActions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}
	if err := newSvc.SetRecoveryActions(recoveryActions, 86400); err != nil {
		return fmt.Errorf("set recovery actions for %q: %w", name, err)
	}
	return nil
}

// maybeRepairServiceRegistration is the per-tick action of the supervise loop's
// repair ticker (runServiceRegistrationRepair). It targets the production
// CFGMSSteward registration and the launcher's own known install path, and
// re-creates the service from the currently-running process's own arguments
// (os.Args[1:]) so a repaired service starts with the same
// --root/--child-args/--regtoken the operator originally configured.
func maybeRepairServiceRegistration(w io.Writer) {
	repairServiceIfMissing(w, launcherServiceName, launcherServiceExePath, os.Args[1:])
}

// repairServiceIfMissing is the parameterized core of the per-tick check so it
// can be driven against a unique test service. A repair FAILURE is logged
// loudly-but-non-fatally and the loop continues: the running steward child is
// unaffected by a missing SCM entry until the next reboot, so preserving the
// current (bad but not worse) state beats crashing the supervisor. A repair
// SUCCESS logs a greppable event so it surfaces in C:\ProgramData\cfgms\logs.
func repairServiceIfMissing(w io.Writer, name, exePath string, args []string) {
	ok, err := serviceRegistrationOK(name)
	if err != nil {
		// Cannot determine ownership of the registration this tick (usually a
		// non-elevated/standalone run where mgr.Connect is denied — the service
		// normally runs as LocalSystem where it succeeds). Skip quietly and
		// retry next tick rather than spam a benign, known-transient condition.
		return
	}
	if ok {
		return
	}
	if repairErr := repairServiceRegistration(name, exePath, args); repairErr != nil {
		_, _ = fmt.Fprintf(w, "launcher: WARN service registration repair FAILED "+
			"[event=service_registration_repair_failed service=%s error=%v]\n", name, repairErr)
		return
	}
	_, _ = fmt.Fprintf(w, "launcher: WARN service registration was deleted — re-created SCM entry "+
		"[event=service_registration_repaired service=%s path=%s]\n", name, exePath)
}
