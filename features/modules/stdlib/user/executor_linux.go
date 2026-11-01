// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package user

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// linuxExecutor manages local user accounts on Linux via /etc/passwd, /etc/group,
// /etc/shadow (read-only) and useradd/usermod/userdel (write).
type linuxExecutor struct {
	userDBPath string // default: /etc/passwd
	groupFile  string // default: /etc/group
	shadowFile string // default: /etc/shadow
}

func newExecutor() userExecutor {
	return &linuxExecutor{
		userDBPath: "/etc/passwd",
		groupFile:  "/etc/group",
		shadowFile: "/etc/shadow",
	}
}

// passwdEntry holds a parsed line from /etc/passwd.
type passwdEntry struct {
	UID     int
	GID     int
	Comment string // GECOS field — full name
}

// getState reads /etc/passwd and /etc/group to determine the current account
// state. /etc/shadow is read for lock/password state when accessible (requires
// root); if not readable, both fields default to false.
func (e *linuxExecutor) getState(username string) (userState, error) {
	entry, found, err := e.parsePasswd(username)
	if err != nil {
		return userState{}, fmt.Errorf("read %s: %w", e.userDBPath, err)
	}
	if !found {
		return userState{}, nil
	}

	groups, err := e.groupsForUser(username, entry.GID)
	if err != nil {
		return userState{}, fmt.Errorf("read %s: %w", e.groupFile, err)
	}

	locked, hasCredential := e.shadowState(username)

	return userState{
		Exists:        true,
		FullName:      entry.Comment,
		Groups:        groups,
		Locked:        locked,
		HasCredential: hasCredential,
	}, nil
}

// setState creates, modifies, or deletes the local user account to match desired.
// Creating or modifying users requires root privileges. It does not touch password
// material (HasCredential in desired is always ignored).
func (e *linuxExecutor) setState(username string, desired userState) error {
	current, err := e.getState(username)
	if err != nil {
		return err
	}

	if !desired.Exists {
		if current.Exists {
			if out, err := exec.Command("userdel", "-r", username).CombinedOutput(); err != nil { // #nosec G204 - username validated by caller
				// -r removes home dir; ignore "mail spool" removal errors
				output := strings.TrimSpace(string(out))
				if !strings.Contains(output, "warning") && !strings.Contains(output, "no mail spool") {
					return fmt.Errorf("userdel -r %s: %w (output: %s)", username, err, output)
				}
			}
		}
		return nil
	}

	if !current.Exists {
		args := []string{"-m"} // create home directory
		if desired.FullName != "" {
			args = append(args, "-c", desired.FullName)
		}
		args = append(args, username)
		// #nosec G204 -- executable is fixed, no shell is used, and username,
		// full name, and groups are validated before reaching this executor.
		if out, err := exec.Command("useradd", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("useradd %s: %w (output: %s)", username, err, strings.TrimSpace(string(out)))
		}
		current.Exists = true
		current.FullName = desired.FullName
		current.Locked = false
	} else if desired.FullName != current.FullName {
		// #nosec G204 -- executable is fixed, no shell is used, and username
		// and GECOS input are validated before reaching this executor.
		if out, err := exec.Command("usermod", "-c", desired.FullName, username).CombinedOutput(); err != nil {
			return fmt.Errorf("usermod -c %s: %w (output: %s)", username, err, strings.TrimSpace(string(out)))
		}
	}

	// Apply supplementary group membership. usermod -G replaces the full list.
	desiredGroups := sortedCopy(desired.Groups)
	currentGroups := sortedCopy(current.Groups)
	if !slicesEqual(desiredGroups, currentGroups) {
		groupArg := strings.Join(desiredGroups, ",")
		// #nosec G204 -- executable is fixed, no shell is used, and every
		// username/group token is option-injection-safe by module validation.
		if out, err := exec.Command("usermod", "-G", groupArg, username).CombinedOutput(); err != nil {
			return fmt.Errorf("usermod -G %s %s: %w (output: %s)", groupArg, username, err, strings.TrimSpace(string(out)))
		}
	}

	// Apply lock state.
	if desired.Locked && !current.Locked {
		if out, err := exec.Command("usermod", "-L", username).CombinedOutput(); err != nil { // #nosec G204 - username validated by caller
			return fmt.Errorf("usermod -L %s: %w (output: %s)", username, err, strings.TrimSpace(string(out)))
		}
	} else if !desired.Locked && current.Locked {
		if out, err := exec.Command("usermod", "-U", username).CombinedOutput(); err != nil { // #nosec G204 - username validated by caller
			return fmt.Errorf("usermod -U %s: %w (output: %s)", username, err, strings.TrimSpace(string(out)))
		}
	}

	return nil
}

// parsePasswd returns the passwd entry for username, or (zero, false, nil) if
// the user is not present in the file.
func (e *linuxExecutor) parsePasswd(username string) (passwdEntry, bool, error) {
	f, err := os.Open(e.userDBPath)
	if err != nil {
		return passwdEntry{}, false, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 || fields[0] != username {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			return passwdEntry{}, false, fmt.Errorf("invalid UID for %s: %w", username, err)
		}
		gid, err := strconv.Atoi(fields[3])
		if err != nil {
			return passwdEntry{}, false, fmt.Errorf("invalid GID for %s: %w", username, err)
		}
		return passwdEntry{
			UID:     uid,
			GID:     gid,
			Comment: fields[4],
		}, true, nil
	}
	return passwdEntry{}, false, scanner.Err()
}

// groupsForUser returns all group names (primary and supplementary) the user
// belongs to, sorted alphabetically.
func (e *linuxExecutor) groupsForUser(username string, primaryGID int) ([]string, error) {
	f, err := os.Open(e.groupFile)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var groups []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		gname := fields[0]
		gid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		// Primary group by GID.
		if gid == primaryGID {
			groups = append(groups, gname)
			continue
		}
		// Supplementary groups: username appears in the members field.
		for _, member := range strings.Split(fields[3], ",") {
			if strings.TrimSpace(member) == username {
				groups = append(groups, gname)
				break
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Strings(groups)
	return groups, nil
}

// shadowState reads /etc/shadow to determine lock and password state for the
// named user. If the shadow file is not readable (requires root), both values
// default to false — making the result deterministic regardless of privilege level.
func (e *linuxExecutor) shadowState(username string) (locked bool, hasCredential bool) {
	f, err := os.Open(e.shadowFile)
	if err != nil {
		return false, false
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 2 || fields[0] != username {
			continue
		}
		pw := fields[1]
		// Convention: "!" prefix means locked; "*" or "!" alone means no password.
		locked = strings.HasPrefix(pw, "!")
		// hasCredential: any non-empty hash that is not a bare placeholder.
		switch pw {
		case "", "*", "!", "!!", "x":
			hasCredential = false
		default:
			// Could be "!<hash>" (locked with password) or "<hash>" (active).
			hash := strings.TrimPrefix(pw, "!")
			hasCredential = len(hash) > 0 && hash != "*"
		}
		return locked, hasCredential
	}
	return false, false
}

// sortedCopy returns a sorted copy of s without modifying the original.
func sortedCopy(s []string) []string {
	out := make([]string, len(s))
	copy(out, s)
	sort.Strings(out)
	return out
}

// slicesEqual returns true when two sorted string slices are element-wise equal.
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
