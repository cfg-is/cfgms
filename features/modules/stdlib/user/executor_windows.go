// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package user

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// windowsExecutor manages local user accounts on Windows via net.exe.
// All operations require the process to run with Administrator privileges.
type windowsExecutor struct{}

func newExecutor() userExecutor {
	return &windowsExecutor{}
}

// getState queries the local account database via "net user <username>".
// If the user does not exist, net exits non-zero with a recognisable message
// and getState returns a zero userState with Exists=false.
func (e *windowsExecutor) getState(username string) (userState, error) {
	out, err := exec.Command("net", "user", username).CombinedOutput() // #nosec G204 - username validated by caller
	output := strings.TrimSpace(string(out))

	if err != nil {
		// "System error 2" or "user name could not be found" → user absent.
		if strings.Contains(output, "System error 2") ||
			strings.Contains(output, "user name could not be found") ||
			strings.Contains(output, "The user name could not be found") {
			return userState{}, nil
		}
		return userState{}, fmt.Errorf("net user %s: %w (output: %s)", username, err, output)
	}

	return parseNetUserOutput(output), nil
}

// parseNetUserOutput converts the textual output of a successful
// "net user <username>" invocation into a userState. It is a pure function of
// its input so the parsing contract can be exercised with fixtures on any
// platform. Callers are responsible for detecting the "user absent" case before
// invoking this function; it always sets Exists=true.
func parseNetUserOutput(output string) userState {
	state := userState{Exists: true}

	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)

		switch {
		case strings.HasPrefix(line, "Full Name"):
			rest := strings.TrimSpace(strings.TrimPrefix(line, "Full Name"))
			state.FullName = rest

		case strings.HasPrefix(line, "Account active"):
			rest := strings.TrimSpace(strings.TrimPrefix(line, "Account active"))
			// "No" means the account is disabled/locked.
			state.Locked = !strings.EqualFold(rest, "Yes")

		case strings.HasPrefix(line, "Password required"):
			rest := strings.TrimSpace(strings.TrimPrefix(line, "Password required"))
			state.HasCredential = strings.EqualFold(rest, "Yes")

		case strings.HasPrefix(line, "Local Group Memberships"):
			rest := strings.TrimPrefix(line, "Local Group Memberships")
			state.Groups = parseWindowsGroups(rest)
		}
	}

	sort.Strings(state.Groups)
	return state
}

// setState creates, modifies, or deletes the local user account to match desired.
// All write operations require Administrator privileges. HasCredential in desired
// is always ignored — this module never manages password material.
func (e *windowsExecutor) setState(username string, desired userState) error {
	current, err := e.getState(username)
	if err != nil {
		return err
	}

	if !desired.Exists {
		if current.Exists {
			if out, err := exec.Command("net", "user", username, "/delete").CombinedOutput(); err != nil { // #nosec G204 - username validated by caller
				return fmt.Errorf("net user %s /delete: %w (output: %s)", username, err, strings.TrimSpace(string(out)))
			}
		}
		return nil
	}

	if !current.Exists {
		// Create account with no password (password management is out of scope).
		args := []string{"user", username, "/add", "/active:yes"}
		if desired.FullName != "" {
			args = append(args, "/fullname:"+desired.FullName)
		}
		if out, err := exec.Command("net", args...).CombinedOutput(); err != nil { // #nosec G204 - username validated by caller
			return fmt.Errorf("net user %s /add: %w (output: %s)", username, err, strings.TrimSpace(string(out)))
		}
		current.Exists = true
		current.FullName = desired.FullName
		current.Locked = false
	} else if desired.FullName != current.FullName {
		if out, err := exec.Command("net", "user", username, "/fullname:"+desired.FullName).CombinedOutput(); err != nil { // #nosec G204 - username validated by caller
			return fmt.Errorf("net user %s /fullname: %w (output: %s)", username, err, strings.TrimSpace(string(out)))
		}
	}

	// Apply active/locked state.
	if desired.Locked != current.Locked {
		activeVal := "yes"
		if desired.Locked {
			activeVal = "no"
		}
		if out, err := exec.Command("net", "user", username, "/active:"+activeVal).CombinedOutput(); err != nil { // #nosec G204 - username validated by caller
			return fmt.Errorf("net user %s /active:%s: %w (output: %s)", username, activeVal, err, strings.TrimSpace(string(out)))
		}
	}

	// Apply group memberships: add to each desired group.
	// Removal from groups that are no longer desired is not performed in v1 to
	// avoid disrupting groups that may have been assigned outside cfg management.
	for _, g := range desired.Groups {
		if out, err := exec.Command("net", "localgroup", g, username, "/add").CombinedOutput(); err != nil { // #nosec G204 - g and username validated by caller
			output := string(out)
			// Error 1378 = "The specified account name is already a member."
			if strings.Contains(output, "1378") || strings.Contains(output, "already a member") {
				continue
			}
			return fmt.Errorf("net localgroup %s %s /add: %w (output: %s)", g, username, err, strings.TrimSpace(output))
		}
	}

	return nil
}

// parseWindowsGroups extracts group names from the "Local Group Memberships"
// line of "net user" output. Groups are prefixed with "*" in that output.
func parseWindowsGroups(s string) []string {
	var groups []string
	for _, part := range strings.Fields(s) {
		if strings.HasPrefix(part, "*") {
			name := strings.TrimPrefix(part, "*")
			if name != "" {
				groups = append(groups, name)
			}
		}
	}
	return groups
}
