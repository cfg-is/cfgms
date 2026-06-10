// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

// Non-Windows stub for the Windows-service entry point. On Linux and
// macOS the launcher is invoked by systemd/launchd as a regular
// process — no special service-handshake dance is required.

package main

func tryRunAsService() bool { return false }
