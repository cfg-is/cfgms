//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package dna

import (
	"context"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	modnetapi32dna   = windows.NewLazySystemDLL("netapi32.dll")
	procDsGetDcNameW = modnetapi32dna.NewProc("DsGetDcNameW")
)

const (
	dsPDCRequired     uint32 = 0x00000080 // DS_PDC_REQUIRED
	dsReturnDNSName   uint32 = 0x40000000 // DS_RETURN_DNS_NAME
	dsPDCFlag         uint32 = 0x00000001 // DS_PDC_FLAG in DOMAIN_CONTROLLER_INFOW.Flags
	productTypeDCName        = "LanmanNT" // ProductOptions\ProductType on a domain controller
)

// domainControllerInfo mirrors DOMAIN_CONTROLLER_INFOW (dsgetdc.h).
type domainControllerInfo struct {
	DomainControllerName        *uint16
	DomainControllerAddress     *uint16
	DomainControllerAddressType uint32
	DomainGUID                  windows.GUID
	DomainName                  *uint16
	DNSForestName               *uint16
	Flags                       uint32
	DCSiteName                  *uint16
	ClientSiteName              *uint16
}

// windowsPDCEmulatorResolver resolves the PDC-emulator role holder with
// DsGetDcNameW and DS_PDC_REQUIRED. DsRoleGetPrimaryDomainInformation is not used
// for the role: it reports the primary-controller role for every DC of a modern
// domain.
type windowsPDCEmulatorResolver struct{}

func newPlatformPDCEmulatorResolver() PDCEmulatorResolver {
	return windowsPDCEmulatorResolver{}
}

// ResolvePDCEmulator implements PDCEmulatorResolver. It skips the directory
// lookup on hosts that are not domain controllers.
func (windowsPDCEmulatorResolver) ResolvePDCEmulator(_ context.Context) (string, string, bool, error) {
	isDC, err := isDomainController()
	if err != nil {
		return "", "", false, err
	}
	if !isDC {
		return "", "", false, nil
	}

	localHost, err := localDNSHostName()
	if err != nil {
		return "", "", true, err
	}

	pdcHost, err := lookupPDCEmulator()
	if err != nil {
		return localHost, "", true, err
	}
	return localHost, pdcHost, true, nil
}

// isDomainController reads ProductOptions\ProductType, which is "LanmanNT" only
// on a domain controller.
func isDomainController() (bool, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\ProductOptions`, registry.QUERY_VALUE)
	if err != nil {
		return false, fmt.Errorf("open ProductOptions: %w", err)
	}
	defer func() { _ = key.Close() }()

	productType, _, err := key.GetStringValue("ProductType")
	if err != nil {
		return false, fmt.Errorf("read ProductType: %w", err)
	}
	return strings.EqualFold(strings.TrimSpace(productType), productTypeDCName), nil
}

// localDNSHostName returns this host's fully qualified DNS name.
func localDNSHostName() (string, error) {
	size := uint32(256)
	for {
		buf := make([]uint16, size)
		n := size
		err := windows.GetComputerNameEx(windows.ComputerNameDnsFullyQualified, &buf[0], &n)
		if err == nil {
			return windows.UTF16ToString(buf[:n]), nil
		}
		// On ERROR_MORE_DATA, n is the required size; retry only if it grew.
		if err != windows.ERROR_MORE_DATA || n <= size {
			return "", fmt.Errorf("GetComputerNameEx: %w", err)
		}
		size = n
	}
}

// lookupPDCEmulator returns the DNS name of the domain's PDC-emulator role holder.
func lookupPDCEmulator() (string, error) {
	if err := procDsGetDcNameW.Find(); err != nil {
		return "", fmt.Errorf("DsGetDcNameW unavailable: %w", err)
	}

	var info *domainControllerInfo
	r1, _, _ := procDsGetDcNameW.Call(
		0, // ComputerName: this host
		0, // DomainName: this host's domain
		0, // DomainGuid
		0, // SiteName
		uintptr(dsPDCRequired|dsReturnDNSName),
		uintptr(unsafe.Pointer(&info)),
	)
	if r1 != 0 {
		return "", fmt.Errorf("DsGetDcNameW: %w", syscall.Errno(r1))
	}
	if info == nil {
		return "", fmt.Errorf("DsGetDcNameW returned no controller info")
	}
	defer func() { _ = windows.NetApiBufferFree((*byte)(unsafe.Pointer(info))) }()

	if info.Flags&dsPDCFlag == 0 {
		return "", fmt.Errorf("DsGetDcNameW returned a controller without the PDC flag")
	}
	name := windows.UTF16PtrToString(info.DomainControllerName)
	if name == "" {
		return "", fmt.Errorf("DsGetDcNameW returned an empty controller name")
	}
	return name, nil
}
