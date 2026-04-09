// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package script

// This file is compiled only on Windows (Go filename convention: _windows.go suffix).

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32                      = windows.NewLazySystemDLL("kernel32.dll")
	modWtsapi32                      = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSGetActiveConsoleSessionId = modKernel32.NewProc("WTSGetActiveConsoleSessionId")
	procWTSQueryUserToken            = modWtsapi32.NewProc("WTSQueryUserToken")
	procWTSQuerySessionInformationW  = modWtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory                = modWtsapi32.NewProc("WTSFreeMemory")
)

// WTS_INFO_CLASS value for retrieving the session username.
const wtsUserName = 5

// activeConsoleSessionNone is the sentinel value returned by WTSGetActiveConsoleSessionId
// when no interactive session is present (0xFFFFFFFF).
const activeConsoleSessionNone = ^uint32(0)

// windowsGetSessionID is a test hook; override in tests to inject session ID errors
// without calling the real WTS API.
var windowsGetSessionID = getActiveConsoleSessionID

// detectLoggedInUser detects the currently logged-in console user on Windows using the
// WTS API. Returns ErrNoUserLoggedIn when no interactive session is present so the caller
// can queue the execution for retry rather than treating it as a permanent failure.
func detectLoggedInUser() (string, error) {
	sessionID, err := windowsGetSessionID()
	if err != nil {
		return "", err
	}
	return querySessionUsername(sessionID)
}

// parseActiveSessionID converts the raw WTSGetActiveConsoleSessionId return value into
// a session ID, returning ErrNoUserLoggedIn for the sentinel value 0xFFFFFFFF.
// This is a pure function exposed for unit testing.
func parseActiveSessionID(r1 uintptr) (uint32, error) {
	sessionID := uint32(r1)
	if sessionID == activeConsoleSessionNone {
		return 0, ErrNoUserLoggedIn
	}
	return sessionID, nil
}

// getActiveConsoleSessionID returns the active console session ID via
// WTSGetActiveConsoleSessionId. Returns ErrNoUserLoggedIn when the sentinel
// value 0xFFFFFFFF is returned (no active session).
func getActiveConsoleSessionID() (uint32, error) {
	r1, _, _ := procWTSGetActiveConsoleSessionId.Call()
	return parseActiveSessionID(r1)
}

// querySessionUsername retrieves the username for a WTS session ID using
// WTSQuerySessionInformationW with WTSUserName (class 5).
func querySessionUsername(sessionID uint32) (string, error) {
	var pBuffer uintptr
	var bytesReturned uint32

	// WTS_CURRENT_SERVER_HANDLE = 0 (local server)
	r1, _, wErr := procWTSQuerySessionInformationW.Call(
		0,
		uintptr(sessionID),
		uintptr(wtsUserName),
		uintptr(unsafe.Pointer(&pBuffer)),  //nolint:gosec // unsafe required for WTS API
		uintptr(unsafe.Pointer(&bytesReturned)), //nolint:gosec // unsafe required for WTS API
	)
	if r1 == 0 {
		return "", fmt.Errorf("WTSQuerySessionInformation failed: %w", wErr)
	}
	if pBuffer != 0 {
		defer procWTSFreeMemory.Call(pBuffer) //nolint:errcheck // WTSFreeMemory has no useful return
	}

	if pBuffer == 0 || bytesReturned < 2 {
		return "", ErrNoUserLoggedIn
	}

	// bytesReturned includes the UTF-16 null terminator; charCount includes it.
	charCount := int(bytesReturned / 2)
	//nolint:gosec // unsafe.Pointer is required to interpret the WTS-allocated buffer
	utf16 := (*[1 << 14]uint16)(unsafe.Pointer(pBuffer))[:charCount:charCount]
	username := windows.UTF16ToString(utf16)

	if username == "" {
		return "", ErrNoUserLoggedIn
	}

	return username, nil
}

// applyExecutionContext returns a (potentially modified) command configured to run
// under the execution context specified in config, the actual OS user the script will
// run as (empty for system context), a cleanup function to call after cmd.Start() to
// release the WTS user token handle, and any error.
//
// For logged_in_user context on Windows, the active console session token is obtained
// via WTSQueryUserToken and attached to cmd.SysProcAttr.Token. This causes Go's runtime
// to call CreateProcessAsUser internally when cmd.Start() is invoked. The cleanup
// function closes the token handle and must be called after cmd.Start() returns.
//
// Requires SE_TCB_NAME privilege (held by the SYSTEM account). Returns ErrNoUserLoggedIn
// when no interactive session exists; the caller should queue for retry.
func applyExecutionContext(ctx context.Context, config *ScriptConfig, cmd *exec.Cmd) (*exec.Cmd, string, func(), error) {
	noCleanup := func() {}

	if config.ExecutionContext != ExecutionContextLoggedInUser {
		return cmd, "", noCleanup, nil
	}

	sessionID, err := windowsGetSessionID()
	if err != nil {
		return nil, "", noCleanup, err
	}

	username, err := querySessionUsername(sessionID)
	if err != nil {
		return nil, "", noCleanup, err
	}

	// Obtain the primary user token for the active session.
	var hToken windows.Token
	//nolint:gosec // unsafe.Pointer is required for the WTS API output parameter
	r1, _, wErr := procWTSQueryUserToken.Call(
		uintptr(sessionID),
		uintptr(unsafe.Pointer(&hToken)), //nolint:gosec // WTS API output parameter
	)
	if r1 == 0 {
		return nil, "", noCleanup, fmt.Errorf(
			"WTSQueryUserToken failed (requires SE_TCB_NAME privilege): %w", wErr,
		)
	}

	cleanup := func() {
		_ = hToken.Close() // best-effort; process already started
	}

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	// syscall.Token and windows.Token are both uintptr-based handle types; the cast is safe.
	cmd.SysProcAttr.Token = syscall.Token(hToken) //nolint:gosec // intentional token assignment

	return cmd, username, cleanup, nil
}
