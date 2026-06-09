//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dna

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/cfgis/cfgms/pkg/logging"
)

// Windows crypt32.dll lazy handles for certificate store enumeration.
// Defined at package level to avoid repeated DLL resolution on each call.
var (
	modcrypt32dna            = windows.NewLazySystemDLL("crypt32.dll")
	procCertOpenSysStoreW    = modcrypt32dna.NewProc("CertOpenSystemStoreW")
	procCertEnumCertsInStore = modcrypt32dna.NewProc("CertEnumCertificatesInStore")
	procCertCloseStoreDNA    = modcrypt32dna.NewProc("CertCloseStore")
)

// CollectUsers gathers local user and administrator counts on Windows via wmic/net.
// Emits: local_user_count, local_admins_count, domain_joined, domain_name.
// Counts only — no account names are stored (identity exfil prevention).
func (w *WindowsSecurityCollector) CollectUsers(ctx context.Context, attributes map[string]string) error {
	attributes["local_user_count"] = fmt.Sprintf("%d", winCountLocalUsers(ctx))

	// Count members of the local Administrators group (count only)
	netOut, err := runCommand(ctx, "net", "localgroup", "Administrators")
	if err == nil {
		attributes["local_admins_count"] = fmt.Sprintf("%d", winCountNetLocalgroupMembers(netOut))
	} else {
		attributes["local_admins_count"] = "0"
	}

	w.collectDomainMembership(attributes)
	return nil
}

// CollectGroups gathers local group count on Windows via wmic.
// Emits: local_group_count.
func (w *WindowsSecurityCollector) CollectGroups(ctx context.Context, attributes map[string]string) error {
	attributes["local_group_count"] = fmt.Sprintf("%d", winCountLocalGroups(ctx))
	return nil
}

// CollectPermissions gathers encryption and AV security state on Windows.
// Emits: bitlocker_enabled, bitlocker_volumes, av_products_detected.
func (w *WindowsSecurityCollector) CollectPermissions(ctx context.Context, attributes map[string]string) error {
	w.collectBitLockerState(ctx, attributes)
	w.collectAVProducts(ctx, attributes)
	return nil
}

// CollectCertificates enumerates system certificate stores and emits per-store counts.
// Private-key bytes are never accessed or stored — only public certificate contexts
// are enumerated via CertEnumCertificatesInStore.
// Emits: cert_root_count, cert_intermediate_count, cert_personal_count.
func (w *WindowsSecurityCollector) CollectCertificates(_ context.Context, attributes map[string]string) error {
	stores := []struct {
		name string
		attr string
	}{
		{"Root", "cert_root_count"},
		{"CA", "cert_intermediate_count"},
		{"My", "cert_personal_count"},
	}

	for _, s := range stores {
		count := winCountCertsInStore(s.name)
		if count >= 0 {
			attributes[s.attr] = fmt.Sprintf("%d", count)
		}
	}
	return nil
}

// collectDomainMembership reads the Tcpip Parameters registry key to detect domain membership.
// Emits: domain_joined (true/false), domain_name (sanitised, omitted when not joined).
func (w *WindowsSecurityCollector) collectDomainMembership(attributes map[string]string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		registry.QUERY_VALUE)
	if err != nil {
		attributes["domain_joined"] = "false"
		return
	}
	defer key.Close()

	domain, _, err := key.GetStringValue("Domain")
	if err != nil || strings.TrimSpace(domain) == "" {
		attributes["domain_joined"] = "false"
		return
	}

	attributes["domain_joined"] = "true"
	attributes["domain_name"] = logging.SanitizeLogValue(strings.TrimSpace(domain))
}

// collectBitLockerState detects BitLocker-protected volumes via manage-bde -status.
// Emits: bitlocker_enabled (true/false), bitlocker_volumes (comma-separated drive letters).
func (w *WindowsSecurityCollector) collectBitLockerState(ctx context.Context, attributes map[string]string) {
	output, err := runCommand(ctx, "manage-bde", "-status")
	if err != nil {
		attributes["bitlocker_enabled"] = "false"
		return
	}

	var protectedVols []string
	currentVol := ""

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)

		// "Volume C: [OS Volume]" or "Volume D: [Data]"
		if strings.HasPrefix(line, "Volume ") && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) >= 1 {
				letter := strings.TrimPrefix(strings.TrimSpace(parts[0]), "Volume ")
				if len(letter) == 1 {
					currentVol = letter
				}
			}
		}

		if strings.Contains(line, "Protection Status:") && strings.Contains(line, "Protection On") {
			if currentVol != "" {
				protectedVols = append(protectedVols, currentVol+":")
			}
		}
	}

	if len(protectedVols) > 0 {
		attributes["bitlocker_enabled"] = "true"
		attributes["bitlocker_volumes"] = strings.Join(protectedVols, ",")
	} else {
		attributes["bitlocker_enabled"] = "false"
	}
}

// collectAVProducts detects installed AV products via the SecurityCenter2 WMI namespace.
// A static PS1 script is written to a temp file and executed with -File (never -Command).
// Root/SecurityCenter2 is Windows client SKU only; returns "none" on Server SKU.
// Best-effort — absence does not imply absence of AV.
func (w *WindowsSecurityCollector) collectAVProducts(ctx context.Context, attributes map[string]string) {
	tmpFile, err := os.CreateTemp("", "dna-av-*.ps1")
	if err != nil {
		attributes["av_products_detected"] = "none"
		return
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	// Static script — no user input, no runtime code composition
	const script = `(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object -ExpandProperty displayName) -join ','`
	if _, err := tmpFile.WriteString(script); err != nil {
		tmpFile.Close()
		attributes["av_products_detected"] = "none"
		return
	}
	tmpFile.Close()

	output, err := runCommand(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-File", tmpPath,
	)
	if err != nil {
		attributes["av_products_detected"] = "none"
		return
	}

	result := strings.TrimSpace(output)
	if result == "" {
		attributes["av_products_detected"] = "none"
		return
	}

	var products []string
	for _, p := range strings.Split(result, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			products = append(products, logging.SanitizeLogValue(p))
		}
	}
	if len(products) == 0 {
		attributes["av_products_detected"] = "none"
	} else {
		attributes["av_products_detected"] = strings.Join(products, ",")
	}
}

// winCountLocalUsers returns the count of local user accounts.
// Tries wmic first; falls back to PowerShell Get-LocalUser on systems where wmic
// is unavailable or returns 0 (wmic is deprecated on Windows 11 24H2+ and Server 2025).
// PowerShell output is locale-independent (returns a plain integer).
func winCountLocalUsers(ctx context.Context) int {
	output, err := runCommand(ctx, "wmic", "useraccount",
		"where", "LocalAccount='TRUE'",
		"get", "Name",
	)
	if err == nil {
		if count := winCountWMICRows(output); count > 0 {
			return count
		}
	}
	// Fallback: PowerShell Get-LocalUser (Windows 10+ / Server 2016+).
	// Uses -File with a static temp script per the argv-only invocation rule.
	return winPowerShellCount(ctx, "dna-users-*.ps1",
		`(Get-LocalUser -ErrorAction SilentlyContinue | Measure-Object).Count`)
}

// winCountLocalGroups returns the count of local groups.
// Tries wmic first; falls back to PowerShell Get-LocalGroup on systems where wmic
// is unavailable or returns 0.
func winCountLocalGroups(ctx context.Context) int {
	output, err := runCommand(ctx, "wmic", "group",
		"where", "LocalAccount='TRUE'",
		"get", "Name",
	)
	if err == nil {
		if count := winCountWMICRows(output); count > 0 {
			return count
		}
	}
	// Fallback: PowerShell Get-LocalGroup (Windows 10+ / Server 2016+).
	return winPowerShellCount(ctx, "dna-groups-*.ps1",
		`(Get-LocalGroup -ErrorAction SilentlyContinue | Measure-Object).Count`)
}

// winPowerShellCount runs a static PowerShell one-liner (via a temp -File) that
// emits a single integer and returns that integer. Returns 0 on any error.
func winPowerShellCount(ctx context.Context, tmpPattern, script string) int {
	tmpFile, err := os.CreateTemp("", tmpPattern)
	if err != nil {
		return 0
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	if _, err := tmpFile.WriteString(script); err != nil {
		tmpFile.Close()
		return 0
	}
	tmpFile.Close()
	psOut, err := runCommand(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-File", tmpPath)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(psOut))
	if err != nil {
		return 0
	}
	return n
}

// winCountWMICRows counts non-header, non-blank rows in wmic text output.
func winCountWMICRows(output string) int {
	count := 0
	for i, line := range strings.Split(output, "\n") {
		if i == 0 { // skip column-header row
			continue
		}
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

// winCountNetLocalgroupMembers counts member lines in "net localgroup <name>" output.
// Members appear after the dashed separator line.
// Completion messages in all Windows locales end with a period; Windows account names cannot.
func winCountNetLocalgroupMembers(output string) int {
	count := 0
	pastSep := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "---") {
			pastSep = true
			continue
		}
		if pastSep && line != "" && !strings.HasSuffix(line, ".") {
			count++
		}
	}
	return count
}

// winCountCertsInStore uses the Windows CryptoAPI to count certificates in the
// named system store without accessing any private-key material.
// Returns -1 on error (store unavailable or access denied).
func winCountCertsInStore(storeName string) int {
	storeNamePtr, err := windows.UTF16PtrFromString(storeName)
	if err != nil {
		return -1
	}

	hStore, _, _ := procCertOpenSysStoreW.Call(0, uintptr(unsafe.Pointer(storeNamePtr)))
	if hStore == 0 {
		return -1
	}
	defer procCertCloseStoreDNA.Call(hStore, 0) //nolint:errcheck // CertCloseStore with dwFlags=0 is documented to always succeed; return value is unused

	count := 0
	var prevCtx uintptr
	for {
		// CertEnumCertificatesInStore frees prevCtx on each call.
		// Returns 0 when enumeration is complete.
		certCtx, _, _ := procCertEnumCertsInStore.Call(hStore, prevCtx)
		if certCtx == 0 {
			break
		}
		count++
		prevCtx = certCtx
	}

	return count
}
