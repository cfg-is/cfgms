// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/cfgis/cfgms/features/steward/client"
	"github.com/cfgis/cfgms/pkg/logging"
)

const (
	// runAccountComponent is the health-reason component for the account the
	// steward runs as.
	runAccountComponent = "run_account"
	// runAccountInsufficientRightsCode is the reason code when the steward runs
	// under an account that lacks rights the default account (SYSTEM / root) has.
	runAccountInsufficientRightsCode = "account.insufficient_rights"
)

// runAccount describes the account the steward process runs as.
type runAccount struct {
	// Name is the account name for display; SID is its Windows SID string
	// (empty on unix).
	Name string
	SID  string
	// Default is true for the default run account (SYSTEM / root, or an
	// elevated administrator on Windows), which holds every right required.
	Default bool
	// Missing lists the rights the account lacks. Empty for the default account.
	Missing []string
}

// accountFromUnixEUID classifies a unix effective uid: only root is the default
// account.
func accountFromUnixEUID(euid int, name string) runAccount {
	if name == "" {
		name = fmt.Sprintf("uid %d", euid)
	}
	if euid == 0 {
		return runAccount{Name: name, Default: true}
	}
	return runAccount{
		Name:    name,
		Missing: []string{"root privileges (euid 0) to change system-wide state and take ownership of data entries"},
	}
}

// probeRunAccount returns the current account with the rights it lacks. For a
// non-default account it adds each of dirs that exists and cannot be written.
func probeRunAccount(dirs []string) runAccount {
	acct := currentRunAccount()
	if acct.Default {
		return acct
	}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			continue
		}
		if !canWriteDir(d) {
			acct.Missing = append(acct.Missing, "write access to "+logging.SanitizeLogValue(d))
		}
	}
	return acct
}

// canWriteDir reports whether a file can be created in dir.
func canWriteDir(dir string) bool {
	f, err := os.CreateTemp(dir, ".cfgms-rights-probe-*") //#nosec G304 -- dir is the steward's own data or cert directory
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

// reason returns the health reason for a non-default account.
func (a runAccount) reason() (code, message string, ok bool) {
	if a.Default {
		return "", "", false
	}
	return runAccountInsufficientRightsCode,
		fmt.Sprintf("%s lacks: %s", logging.SanitizeLogValue(a.Name), strings.Join(a.Missing, ", ")),
		true
}

// reportRunAccount records the run-account reason in reg (and clears it for the
// default account) so the heartbeat reports degraded naming the account and
// the missing rights.
func reportRunAccount(reg *client.HealthReasonRegistry, a runAccount, logger logging.Logger) {
	code, msg, ok := a.reason()
	if !ok {
		reg.Clear(runAccountComponent)
		return
	}
	reg.Set(runAccountComponent, code, msg)
	logger.Warn("Steward is running under a non-default account with insufficient rights",
		"account", logging.SanitizeLogValue(a.Name),
		"missing", logging.SanitizeLogValue(strings.Join(a.Missing, ", ")))
}
