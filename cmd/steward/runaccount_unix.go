// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package main

import (
	"os"
	"os/user"
	"strconv"
)

// currentRunAccount probes the effective uid: root is the default account.
func currentRunAccount() runAccount {
	euid := os.Geteuid()
	name := ""
	if u, err := user.LookupId(strconv.Itoa(euid)); err == nil {
		name = u.Username
	}
	return accountFromUnixEUID(euid, name)
}

// secureOwnAccountDataDir has nothing to do outside Windows, where the data
// directory lockdown does not run.
func secureOwnAccountDataDir(string) (handled bool, err error) { return false, nil }
