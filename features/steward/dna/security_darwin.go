//go:build darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package dna

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const darwinSecCmdTimeout = 30 * time.Second

// CollectUsers gathers user account information on macOS
func (d *DarwinSecurityCollector) CollectUsers(ctx context.Context, attributes map[string]string) error {
	// System users using dscl
	cmdCtx, cancel := context.WithTimeout(ctx, darwinSecCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx, "dscl", ".", "-list", "/Users").Output(); err == nil {
		d.parseSystemUsers(ctx, string(output), attributes)
	}
	cancel()

	// User account details
	d.collectUserDetails(ctx, attributes)

	// Login shell information
	d.collectLoginShells(ctx, attributes)

	return nil
}

// CollectGroups gathers group information on macOS
func (d *DarwinSecurityCollector) CollectGroups(ctx context.Context, attributes map[string]string) error {
	// System groups using dscl
	cmdCtx, cancel := context.WithTimeout(ctx, darwinSecCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx, "dscl", ".", "-list", "/Groups").Output(); err == nil {
		d.parseSystemGroups(ctx, string(output), attributes)
	}
	cancel()

	// Administrative users
	cmdCtx2, cancel2 := context.WithTimeout(ctx, darwinSecCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx2, "dseditgroup", "-o", "checkmember", "-m", "admin").Output(); err == nil {
		d.parseAdminUsers(ctx, string(output), attributes)
	}
	cancel2()

	return nil
}

// CollectPermissions gathers file/directory permission information on macOS
func (d *DarwinSecurityCollector) CollectPermissions(ctx context.Context, attributes map[string]string) error {
	// System directory permissions
	d.collectSystemPermissions(ctx, attributes)

	// SIP (System Integrity Protection) status
	cmdCtx, cancel := context.WithTimeout(ctx, darwinSecCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx, "csrutil", "status").Output(); err == nil {
		sipStatus := strings.TrimSpace(string(output))
		if strings.Contains(sipStatus, "enabled") {
			attributes["sip_status"] = "enabled"
		} else if strings.Contains(sipStatus, "disabled") {
			attributes["sip_status"] = "disabled"
		} else {
			attributes["sip_status"] = "unknown"
		}
	}
	cancel()

	// Gatekeeper status
	cmdCtx2, cancel2 := context.WithTimeout(ctx, darwinSecCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx2, "spctl", "--status").Output(); err == nil {
		attributes["gatekeeper_status"] = strings.TrimSpace(string(output))
	}
	cancel2()

	// File system permissions on key directories
	d.collectKeyDirectoryPermissions(ctx, attributes)

	return nil
}

// CollectCertificates gathers installed certificate information on macOS
func (d *DarwinSecurityCollector) CollectCertificates(ctx context.Context, attributes map[string]string) error {
	// System keychain certificates
	d.collectKeychainCertificates(ctx, attributes, "System")

	// Login keychain certificates
	d.collectKeychainCertificates(ctx, attributes, "login")

	// System roots
	cmdCtx, cancel := context.WithTimeout(ctx, darwinSecCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx, "security", "list-keychains").Output(); err == nil {
		keychains := strings.Split(strings.TrimSpace(string(output)), "\n")
		attributes["keychain_count"] = fmt.Sprintf("%d", len(keychains))
	}
	cancel()

	// Code signing certificates
	d.collectCodeSigningCertificates(ctx, attributes)

	return nil
}

// parseSystemUsers parses dscl user list output
func (d *DarwinSecurityCollector) parseSystemUsers(ctx context.Context, output string, attributes map[string]string) {
	users := strings.Split(strings.TrimSpace(output), "\n")
	var regularUsers []string
	var systemUsers []string

	for _, user := range users {
		user = strings.TrimSpace(user)
		if user == "" {
			continue
		}

		// Get user ID to distinguish system vs regular users
		cmdCtx, cancel := context.WithTimeout(ctx, darwinSecCmdTimeout)
		if uidOutput, err := exec.CommandContext(cmdCtx, "id", "-u", user).Output(); err == nil {
			uidStr := strings.TrimSpace(string(uidOutput))
			if uid, parseErr := strconv.Atoi(uidStr); parseErr == nil {
				if uid >= 500 && uid < 65534 { // Regular user range on macOS
					regularUsers = append(regularUsers, user)
				} else {
					systemUsers = append(systemUsers, user)
				}
			}
		}
		cancel()
	}

	attributes["total_user_count"] = fmt.Sprintf("%d", len(users))
	if len(regularUsers) > 0 {
		attributes["regular_user_count"] = fmt.Sprintf("%d", len(regularUsers))
		// Store first 10 regular users as sample
		sampleSize := len(regularUsers)
		if sampleSize > 10 {
			sampleSize = 10
		}
		attributes["regular_users_sample"] = strings.Join(regularUsers[:sampleSize], ",")
	}

	if len(systemUsers) > 0 {
		attributes["system_user_count"] = fmt.Sprintf("%d", len(systemUsers))
	}
}

// collectUserDetails collects detailed user information
func (d *DarwinSecurityCollector) collectUserDetails(ctx context.Context, attributes map[string]string) {
	// Currently logged in users
	cmdCtx, cancel := context.WithTimeout(ctx, darwinSecCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx, "who").Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		var loggedInUsers []string
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				user := fields[0]
				if user != "" {
					loggedInUsers = append(loggedInUsers, user)
				}
			}
		}
		if len(loggedInUsers) > 0 {
			attributes["logged_in_user_count"] = fmt.Sprintf("%d", len(loggedInUsers))
			attributes["logged_in_users"] = strings.Join(loggedInUsers, ",")
		}
	}
	cancel()

	// Last login information
	cmdCtx2, cancel2 := context.WithTimeout(ctx, darwinSecCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx2, "last", "-10").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		var recentLogins []string
		for i, line := range lines {
			if i >= 5 { // Limit to first 5 recent logins
				break
			}
			line = strings.TrimSpace(line)
			if line != "" && !strings.Contains(line, "wtmp begins") {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					recentLogins = append(recentLogins, fields[0])
				}
			}
		}
		if len(recentLogins) > 0 {
			attributes["recent_login_users"] = strings.Join(recentLogins, ",")
		}
	}
	cancel2()
}

// collectLoginShells collects login shell information
func (d *DarwinSecurityCollector) collectLoginShells(ctx context.Context, attributes map[string]string) {
	// Available shells
	cmdCtx, cancel := context.WithTimeout(ctx, darwinSecCmdTimeout)
	defer cancel()

	if output, err := exec.CommandContext(cmdCtx, "cat", "/etc/shells").Output(); err == nil {
		shells := strings.Split(string(output), "\n")
		var validShells []string
		for _, shell := range shells {
			shell = strings.TrimSpace(shell)
			if shell != "" && !strings.HasPrefix(shell, "#") {
				validShells = append(validShells, shell)
			}
		}
		if len(validShells) > 0 {
			attributes["available_shell_count"] = fmt.Sprintf("%d", len(validShells))
			attributes["available_shells"] = strings.Join(validShells, ",")
		}
	}
}

// parseSystemGroups parses dscl group list output
func (d *DarwinSecurityCollector) parseSystemGroups(ctx context.Context, output string, attributes map[string]string) {
	groups := strings.Split(strings.TrimSpace(output), "\n")
	var regularGroups []string
	var systemGroups []string

	for _, group := range groups {
		group = strings.TrimSpace(group)
		if group == "" {
			continue
		}

		// Get group ID to distinguish system vs regular groups
		cmdCtx, cancel := context.WithTimeout(ctx, darwinSecCmdTimeout)
		if gidOutput, err := exec.CommandContext(cmdCtx, "dscl", ".", "-read", "/Groups/"+group, "PrimaryGroupID").Output(); err == nil {
			gidLine := strings.TrimSpace(string(gidOutput))
			if strings.Contains(gidLine, ":") {
				parts := strings.SplitN(gidLine, ":", 2)
				if len(parts) == 2 {
					gidStr := strings.TrimSpace(parts[1])
					if gid, parseErr := strconv.Atoi(gidStr); parseErr == nil {
						if gid >= 500 && gid < 65534 { // Regular group range on macOS
							regularGroups = append(regularGroups, group)
						} else {
							systemGroups = append(systemGroups, group)
						}
					}
				}
			}
		}
		cancel()
	}

	attributes["total_group_count"] = fmt.Sprintf("%d", len(groups))
	if len(regularGroups) > 0 {
		attributes["regular_group_count"] = fmt.Sprintf("%d", len(regularGroups))
		// Store first 10 regular groups as sample
		sampleSize := len(regularGroups)
		if sampleSize > 10 {
			sampleSize = 10
		}
		attributes["regular_groups_sample"] = strings.Join(regularGroups[:sampleSize], ",")
	}

	if len(systemGroups) > 0 {
		attributes["system_group_count"] = fmt.Sprintf("%d", len(systemGroups))
	}
}

// parseAdminUsers parses administrative users
func (d *DarwinSecurityCollector) parseAdminUsers(ctx context.Context, _ string, attributes map[string]string) {
	// This is a simple approach - in practice, we'd want to list admin group members
	cmdCtx, cancel := context.WithTimeout(ctx, darwinSecCmdTimeout)
	defer cancel()

	if output, err := exec.CommandContext(cmdCtx, "dseditgroup", "-o", "read", "-t", "user", "admin").Output(); err == nil {
		adminOutput := string(output)
		// Count admin users by looking for "Users:" line
		lines := strings.Split(adminOutput, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Users:") {
				usersPart := strings.TrimPrefix(line, "Users:")
				usersPart = strings.TrimSpace(usersPart)
				if usersPart != "" {
					adminUsers := strings.Fields(usersPart)
					attributes["admin_user_count"] = fmt.Sprintf("%d", len(adminUsers))
					attributes["admin_users"] = strings.Join(adminUsers, ",")
				}
				break
			}
		}
	}
}

// collectSystemPermissions collects system directory permissions
func (d *DarwinSecurityCollector) collectSystemPermissions(ctx context.Context, attributes map[string]string) {
	// Check permissions on key system directories
	keyDirs := []string{"/System", "/usr", "/bin", "/sbin", "/Applications"}

	for _, dir := range keyDirs {
		cmdCtx, cancel := context.WithTimeout(ctx, darwinSecCmdTimeout)
		if output, err := exec.CommandContext(cmdCtx, "ls", "-ld", dir).Output(); err == nil {
			permLine := strings.TrimSpace(string(output))
			fields := strings.Fields(permLine)
			if len(fields) > 0 {
				perms := fields[0]
				dirName := strings.TrimPrefix(dir, "/")
				if dirName == "" {
					dirName = "root"
				}
				attributes["permissions_"+dirName] = perms
			}
		}
		cancel()
	}
}

// collectKeyDirectoryPermissions collects permissions on key directories
func (d *DarwinSecurityCollector) collectKeyDirectoryPermissions(ctx context.Context, attributes map[string]string) {
	// Check /etc permissions
	cmdCtx, cancel := context.WithTimeout(ctx, darwinSecCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx, "ls", "-ld", "/etc").Output(); err == nil {
		permLine := strings.TrimSpace(string(output))
		fields := strings.Fields(permLine)
		if len(fields) > 0 {
			attributes["etc_permissions"] = fields[0]
		}
	}
	cancel()

	// Check /tmp permissions
	cmdCtx2, cancel2 := context.WithTimeout(ctx, darwinSecCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx2, "ls", "-ld", "/tmp").Output(); err == nil {
		permLine := strings.TrimSpace(string(output))
		fields := strings.Fields(permLine)
		if len(fields) > 0 {
			attributes["tmp_permissions"] = fields[0]
		}
	}
	cancel2()

	// Check /var permissions
	cmdCtx3, cancel3 := context.WithTimeout(ctx, darwinSecCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx3, "ls", "-ld", "/var").Output(); err == nil {
		permLine := strings.TrimSpace(string(output))
		fields := strings.Fields(permLine)
		if len(fields) > 0 {
			attributes["var_permissions"] = fields[0]
		}
	}
	cancel3()
}

// collectKeychainCertificates collects certificates from keychains
func (d *DarwinSecurityCollector) collectKeychainCertificates(ctx context.Context, attributes map[string]string, keychainName string) {
	// List certificates in keychain
	args := []string{"find-certificate", "-a"}
	if keychainName != "login" {
		args = append(args, "-s", keychainName)
	}

	cmdCtx, cancel := context.WithTimeout(ctx, darwinSecCmdTimeout)
	defer cancel()

	if output, err := exec.CommandContext(cmdCtx, "security", args...).Output(); err == nil {
		certOutput := string(output)
		// Count certificate entries
		certCount := strings.Count(certOutput, "keychain:")
		if certCount > 0 {
			attributes["certificates_"+keychainName+"_count"] = fmt.Sprintf("%d", certCount)
		}

		// Extract some certificate common names
		d.extractCertificateNames(certOutput, attributes, keychainName)
	}
}

// extractCertificateNames extracts certificate common names from security output
func (d *DarwinSecurityCollector) extractCertificateNames(output string, attributes map[string]string, keychainName string) {
	lines := strings.Split(output, "\n")
	var certNames []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "\"labl\"<blob>=") {
			// Extract label from the blob format
			if startIdx := strings.Index(line, "\""); startIdx != -1 {
				if endIdx := strings.LastIndex(line, "\""); endIdx != -1 && endIdx > startIdx {
					certName := line[startIdx+1 : endIdx]
					if certName != "" && len(certNames) < 5 { // Limit to first 5
						certNames = append(certNames, certName)
					}
				}
			}
		}
	}

	if len(certNames) > 0 {
		attributes["certificates_"+keychainName+"_sample"] = strings.Join(certNames, ", ")
	}
}

// collectCodeSigningCertificates collects code signing certificate information
func (d *DarwinSecurityCollector) collectCodeSigningCertificates(ctx context.Context, attributes map[string]string) {
	// List code signing identities
	cmdCtx, cancel := context.WithTimeout(ctx, darwinSecCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx, "security", "find-identity", "-v", "-p", "codesigning").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		var validCerts int

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && strings.Contains(line, ")") && !strings.Contains(line, "0 valid identities found") {
				validCerts++
			}
		}

		attributes["code_signing_certificates"] = fmt.Sprintf("%d", validCerts)
	}
	cancel()

	// Check for Developer ID certificates specifically
	cmdCtx2, cancel2 := context.WithTimeout(ctx, darwinSecCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx2, "security", "find-identity", "-v", "-s", "Developer ID").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		var devIDCerts int

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && strings.Contains(line, "Developer ID") {
				devIDCerts++
			}
		}

		if devIDCerts > 0 {
			attributes["developer_id_certificates"] = fmt.Sprintf("%d", devIDCerts)
		}
	}
	cancel2()
}
