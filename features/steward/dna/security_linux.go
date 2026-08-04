//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dna

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

const linuxSecCmdTimeout = 30 * time.Second
const linuxSUIDTimeout = 10 * time.Second

// CollectUsers gathers user account information on Linux.
// Parses /etc/passwd (getent passwd fallback). Emits: local_user_count,
// root_account_locked, domain_joined, domain_name.
func (l *LinuxSecurityCollector) CollectUsers(ctx context.Context, attributes map[string]string) error {
	userCount, err := linuxParsePasswdCount()
	if err != nil {
		userCount = linuxGetentUserCount(ctx)
	}
	attributes["local_user_count"] = fmt.Sprintf("%d", userCount)

	l.checkRootLocked(ctx, attributes)
	l.collectDomainMembership(ctx, attributes)
	return nil
}

// CollectGroups gathers group and local admin counts on Linux.
// Emits: local_group_count, local_admins_count (members of sudo/wheel — count only).
func (l *LinuxSecurityCollector) CollectGroups(_ context.Context, attributes map[string]string) error {
	groupCount, adminsCount := linuxParseGroupFile()
	attributes["local_group_count"] = fmt.Sprintf("%d", groupCount)
	attributes["local_admins_count"] = fmt.Sprintf("%d", adminsCount)
	return nil
}

// CollectPermissions gathers file permission and system security state on Linux.
// Emits: sudo_installed, suid_binary_count, luks_encrypted_devices, luks_device_names,
// av_products_detected.
func (l *LinuxSecurityCollector) CollectPermissions(ctx context.Context, attributes map[string]string) error {
	l.checkSudoInstalled(attributes)
	l.collectSUIDBinaries(ctx, attributes)
	l.collectLUKSState(ctx, attributes)
	l.collectAVProducts(ctx, attributes)
	return nil
}

// CollectCertificates is not specifically implemented for Linux; delegates to the generic stub.
func (l *LinuxSecurityCollector) CollectCertificates(ctx context.Context, attributes map[string]string) error {
	return (&GenericSecurityCollector{}).CollectCertificates(ctx, attributes)
}

// linuxParsePasswdCount counts user entries in /etc/passwd.
func linuxParsePasswdCount() (int, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return count, scanner.Err()
}

// linuxGetentUserCount uses getent passwd as a fallback user counter.
func linuxGetentUserCount(ctx context.Context) int {
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSecCmdTimeout)
	defer cancel()

	output, err := exec.CommandContext(cmdCtx, "getent", "passwd").Output()
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

// checkRootLocked checks whether the root account is locked using passwd -S root (argv form only).
// Defaults to "false" (unlocked) when the command is unavailable (requires root).
func (l *LinuxSecurityCollector) checkRootLocked(ctx context.Context, attributes map[string]string) {
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSecCmdTimeout)
	defer cancel()

	output, err := exec.CommandContext(cmdCtx, "passwd", "-S", "root").Output()
	if err != nil {
		attributes["root_account_locked"] = "false"
		return
	}

	// Output: "root L|P|NP date min max warn inact"
	// L=locked, P=password set, NP=no password
	fields := strings.Fields(strings.TrimSpace(string(output)))
	if len(fields) >= 2 && fields[1] == "L" {
		attributes["root_account_locked"] = "true"
	} else {
		attributes["root_account_locked"] = "false"
	}
}

// collectDomainMembership checks AD/LDAP domain membership on Linux.
// Priority: realm list → /etc/sssd/sssd.conf → /etc/winbind.conf presence.
func (l *LinuxSecurityCollector) collectDomainMembership(ctx context.Context, attributes map[string]string) {
	// Try realm list (realmd)
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSecCmdTimeout)
	output, err := exec.CommandContext(cmdCtx, "realm", "list").Output()
	cancel()
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
			// First non-indented non-empty line is the realm name
			if line != "" && !strings.HasPrefix(line, " ") {
				attributes["domain_joined"] = "true"
				attributes["domain_name"] = logging.SanitizeLogValue(strings.TrimSpace(line))
				return
			}
		}
	}

	// Fallback: /etc/sssd/sssd.conf
	if domain := linuxSSSDDomain(); domain != "" {
		attributes["domain_joined"] = "true"
		attributes["domain_name"] = logging.SanitizeLogValue(domain)
		return
	}

	// Fallback: /etc/winbind.conf presence (winbind/Samba)
	if _, err := os.Stat("/etc/winbind.conf"); err == nil {
		attributes["domain_joined"] = "true"
		return
	}

	attributes["domain_joined"] = "false"
}

// linuxSSSDDomain extracts the first domain from /etc/sssd/sssd.conf if present.
func linuxSSSDDomain() string {
	f, err := os.Open("/etc/sssd/sssd.conf")
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "domains") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				domains := strings.TrimSpace(parts[1])
				first := strings.SplitN(domains, ",", 2)[0]
				if first = strings.TrimSpace(first); first != "" {
					return first
				}
			}
		}
	}
	return ""
}

// linuxParseGroupFile counts groups and sudo/wheel member counts from /etc/group.
// Returns (total group count, admin member count). Names are never stored.
func linuxParseGroupFile() (int, int) {
	f, err := os.Open("/etc/group")
	if err != nil {
		return 0, 0
	}
	defer func() { _ = f.Close() }()

	groupCount := 0
	adminsCount := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		groupCount++

		// Format: name:password:gid:member1,member2,...
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		name := parts[0]
		if name != "sudo" && name != "wheel" {
			continue
		}
		members := strings.TrimSpace(parts[3])
		if members != "" {
			adminsCount += len(strings.Split(members, ","))
		}
	}
	return groupCount, adminsCount
}

// checkSudoInstalled sets sudo_installed=true/false by checking common binary paths.
func (l *LinuxSecurityCollector) checkSudoInstalled(attributes map[string]string) {
	sudoPaths := []string{"/usr/bin/sudo", "/usr/local/bin/sudo", "/bin/sudo"}
	for _, p := range sudoPaths {
		if _, err := os.Stat(p); err == nil {
			attributes["sudo_installed"] = "true"
			return
		}
	}
	attributes["sudo_installed"] = "false"
}

// collectSUIDBinaries enumerates SUID binaries in standard system bin directories.
// Bounded to /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin with -xdev
// -maxdepth 3 and a hard 10-second exec.CommandContext timeout. Omits the
// attribute silently on permission denied or timeout.
func (l *LinuxSecurityCollector) collectSUIDBinaries(ctx context.Context, attributes map[string]string) {
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSUIDTimeout)
	defer cancel()

	output, err := exec.CommandContext(cmdCtx,
		"find",
		"/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
		"-xdev", "-maxdepth", "3",
		"-perm", "/4000",
		"-type", "f",
	).Output()
	if err != nil {
		// Permission denied or timeout — omit attribute per spec
		return
	}

	count := 0
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	attributes["suid_binary_count"] = fmt.Sprintf("%d", count)
}

// collectLUKSState detects LUKS-encrypted block devices via lsblk.
// Emits luks_encrypted_devices (count) and luks_device_names (comma-separated).
func (l *LinuxSecurityCollector) collectLUKSState(ctx context.Context, attributes map[string]string) {
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSecCmdTimeout)
	defer cancel()

	output, err := exec.CommandContext(cmdCtx, "lsblk", "-o", "NAME,FSTYPE").Output()
	if err != nil {
		attributes["luks_encrypted_devices"] = "0"
		return
	}

	var luksNames []string
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "crypto_LUKS" {
			// Strip lsblk tree-drawing characters from the NAME column
			name := strings.TrimLeft(fields[0], "└├─│ ")
			luksNames = append(luksNames, name)
		}
	}

	attributes["luks_encrypted_devices"] = fmt.Sprintf("%d", len(luksNames))
	if len(luksNames) > 0 {
		attributes["luks_device_names"] = strings.Join(luksNames, ",")
	}
}

// collectAVProducts detects common Linux AV agents by process presence and binary path.
// Best-effort: absence does not imply absence of AV.
func (l *LinuxSecurityCollector) collectAVProducts(ctx context.Context, attributes map[string]string) {
	avChecks := []struct {
		proc    string
		paths   []string
		product string
	}{
		{"clamd", []string{"/usr/sbin/clamd", "/usr/bin/clamd"}, "ClamAV"},
		{"falcond", []string{"/opt/CrowdStrike/falcond"}, "CrowdStrike Falcon"},
		{"ds_agent", []string{"/opt/ds_agent/ds_agent"}, "TrendMicro DSA"},
	}

	var detected []string
	for _, av := range avChecks {
		if linuxIsProcessRunning(ctx, av.proc) || linuxAnyPathExists(av.paths) {
			detected = append(detected, av.product)
		}
	}

	if len(detected) == 0 {
		attributes["av_products_detected"] = "none"
	} else {
		attributes["av_products_detected"] = strings.Join(detected, ",")
	}
}

// linuxIsProcessRunning checks whether a named process is running via pgrep -c.
func linuxIsProcessRunning(ctx context.Context, name string) bool {
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSecCmdTimeout)
	defer cancel()

	// #nosec G204 -- name comes only from the compile-time avChecks table and is
	// passed as a single pgrep argv under a fixed timeout, without a shell.
	output, err := exec.CommandContext(cmdCtx, "pgrep", "-c", name).Output()
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(output)))
	return err == nil && n > 0
}

// linuxAnyPathExists returns true if at least one path in the list exists on disk.
func linuxAnyPathExists(paths []string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}
