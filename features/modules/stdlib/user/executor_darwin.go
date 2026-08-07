// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build darwin

package user

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// darwinExecutor manages local user accounts on macOS via dscl, dseditgroup,
// and pwpolicy. All write operations require Administrator or root privileges.
type darwinExecutor struct{}

func newExecutor() userExecutor {
	return &darwinExecutor{}
}

// getState reads user account information from the local directory via dscl.
// Group membership is resolved via "id -Gn <username>".
// Lock state is resolved via "pwpolicy -u <username> -getpolicy".
func (e *darwinExecutor) getState(username string) (userState, error) {
	out, err := exec.Command("dscl", ".", "-read", "/Users/"+username).CombinedOutput() // #nosec G204 - username validated by caller
	output := strings.TrimSpace(string(out))

	if err != nil {
		if strings.Contains(output, "eDSRecordNotFound") ||
			strings.Contains(output, "No such key") ||
			strings.Contains(output, "record not found") {
			return userState{}, nil
		}
		return userState{}, fmt.Errorf("dscl -read /Users/%s: %w (output: %s)", username, err, output)
	}

	state := userState{Exists: true}

	state.FullName = parseDsclRealName(output)

	// Resolve group names via id -Gn (all groups, space-separated).
	groupOut, err := exec.Command("id", "-Gn", username).CombinedOutput() // #nosec G204 - username validated by caller
	if err == nil {
		state.Groups = append(state.Groups, strings.Fields(strings.TrimSpace(string(groupOut)))...)
		sort.Strings(state.Groups)
	}

	// Check disabled/locked state via pwpolicy.
	pwOut, err := exec.Command("pwpolicy", "-u", username, "-getpolicy").CombinedOutput() // #nosec G204 - username validated by caller
	if err == nil {
		state.Locked = strings.Contains(string(pwOut), "isDisabled=1")
	}

	// has_credential: conservative false — macOS shadow password inspection
	// requires root and is out of scope for this version.
	state.HasCredential = false

	return state, nil
}

// setState creates, modifies, or deletes the local user account to match desired.
// macOS user creation via dscl requires multiple attributes and a unique UID/GID
// allocation. All write operations require Administrator or root privileges.
func (e *darwinExecutor) setState(username string, desired userState) error {
	current, err := e.getState(username)
	if err != nil {
		return err
	}

	if !desired.Exists {
		if current.Exists {
			if out, err := exec.Command("dscl", ".", "-delete", "/Users/"+username).CombinedOutput(); err != nil { // #nosec G204 - username validated by caller
				return fmt.Errorf("dscl -delete /Users/%s: %w (output: %s)", username, err, strings.TrimSpace(string(out)))
			}
		}
		return nil
	}

	if !current.Exists {
		if err := e.createUser(username, desired.FullName); err != nil {
			return err
		}
		current.Exists = true
		current.FullName = desired.FullName
		current.Locked = false
	} else if desired.FullName != current.FullName {
		if out, err := exec.Command("dscl", ".", "-create", "/Users/"+username, "RealName", desired.FullName).CombinedOutput(); err != nil { // #nosec G204 - username validated by caller
			return fmt.Errorf("dscl -create /Users/%s RealName: %w (output: %s)", username, err, strings.TrimSpace(string(out)))
		}
	}

	// Apply lock state via pwpolicy.
	if desired.Locked != current.Locked {
		action := "-enableuser"
		if desired.Locked {
			action = "-disableuser"
		}
		if out, err := exec.Command("pwpolicy", "-u", username, action).CombinedOutput(); err != nil { // #nosec G204 - username validated by caller
			return fmt.Errorf("pwpolicy %s %s: %w (output: %s)", action, username, err, strings.TrimSpace(string(out)))
		}
	}

	// Apply group membership: add to each desired group via dseditgroup.
	// Removal from unreferenced groups is not performed in v1.
	for _, g := range desired.Groups {
		if out, err := exec.Command("dseditgroup", "-o", "edit", "-a", username, "-t", "user", g).CombinedOutput(); err != nil { // #nosec G204 - g and username validated by caller
			output := string(out)
			if strings.Contains(output, "already a member") || strings.Contains(output, "eDSAttributeNotFound") {
				continue
			}
			return fmt.Errorf("dseditgroup -a %s %s: %w (output: %s)", username, g, err, strings.TrimSpace(output))
		}
	}

	return nil
}

// createUser allocates a UID and creates the user record via a sequence of
// dscl commands, following the macOS local user creation convention.
func (e *darwinExecutor) createUser(username, fullName string) error {
	uid, err := e.nextAvailableUID()
	if err != nil {
		return fmt.Errorf("allocate UID for %s: %w", username, err)
	}
	uidStr := fmt.Sprintf("%d", uid)

	steps := [][]string{
		{".", "-create", "/Users/" + username},
		{".", "-create", "/Users/" + username, "UniqueID", uidStr},
		{".", "-create", "/Users/" + username, "PrimaryGroupID", "20"}, // staff group on macOS
		{".", "-create", "/Users/" + username, "UserShell", "/bin/zsh"},
		{".", "-create", "/Users/" + username, "NFSHomeDirectory", "/Users/" + username},
	}
	if fullName != "" {
		steps = append(steps, []string{".", "-create", "/Users/" + username, "RealName", fullName})
	}

	for _, args := range steps {
		if out, err := exec.Command("dscl", args...).CombinedOutput(); err != nil { // #nosec G204 - args constructed from validated inputs
			return fmt.Errorf("dscl %s: %w (output: %s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// nextAvailableUID finds the lowest unused UID >= 501 (macOS regular user range).
func (e *darwinExecutor) nextAvailableUID() (int, error) {
	out, err := exec.Command("dscl", ".", "-list", "/Users", "UniqueID").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("dscl -list /Users UniqueID: %w", err)
	}
	return firstFreeUID(parseUsedUIDs(string(out)))
}

// parseDsclRealName extracts the RealName value from "dscl . -read /Users/<u>"
// output. dscl emits one of two formats: inline ("RealName: value") or a key
// line followed by an indented value line ("RealName:\n value"). This is a pure
// function of its input so both formats can be exercised with fixtures.
func parseDsclRealName(output string) string {
	var fullName string
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "RealName:" && i+1 < len(lines) {
			fullName = strings.TrimSpace(lines[i+1])
		} else if strings.HasPrefix(line, "RealName:") {
			fullName = strings.TrimSpace(strings.TrimPrefix(line, "RealName:"))
		}
	}
	return fullName
}

// parseUsedUIDs extracts the set of allocated UIDs from the output of
// "dscl . -list /Users UniqueID". Each non-empty line is "<username> <uid>";
// malformed lines are skipped. Pure function of its input for fixture testing.
func parseUsedUIDs(output string) map[int]bool {
	used := make(map[int]bool)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		var uid int
		if _, err := fmt.Sscanf(fields[1], "%d", &uid); err == nil {
			used[uid] = true
		}
	}
	return used
}

// firstFreeUID returns the lowest unused UID in the macOS regular-user range
// [501, 60000). It returns an error if the range is exhausted.
func firstFreeUID(used map[int]bool) (int, error) {
	for uid := 501; uid < 60000; uid++ {
		if !used[uid] {
			return uid, nil
		}
	}
	return 0, fmt.Errorf("no available UID in range 501-59999")
}
