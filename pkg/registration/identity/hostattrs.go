// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package identity

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	stewardcrypto "github.com/cfgis/cfgms/pkg/secrets/providers/steward"
)

// Host attribute keys reported to the controller (ADR-034 §2). The set is
// closed and stable: the controller compares the stored baseline against these
// keys by name. Volatile device-state (DNA) fields are never reported.
const (
	HostAttrMachineID   = "machine_id"
	HostAttrNICMACs     = "nic_macs"
	HostAttrDiskSerials = "disk_serials"
	HostAttrInstallDate = "install_date"
)

// virtualNICPrefixes name interfaces that are created and destroyed by
// container and hypervisor tooling; their MACs change without the host changing.
var virtualNICPrefixes = []string{"veth", "docker", "br-", "virbr", "cni", "flannel", "cali", "tun", "tap", "utun", "awdl", "llw", "vEthernet"}

// CollectHostAttributes gathers the host provenance attributes of this machine.
// identityDir is the directory holding the device identity file; its creation
// date is the install date. Attributes that cannot be read are omitted, never
// fabricated, so the result may be empty. Repeated calls on an unchanged host
// return equal maps.
func CollectHostAttributes(identityDir string) map[string]string {
	attrs := make(map[string]string, 4)

	if id, err := stewardcrypto.MachineID(); err == nil && len(id) > 0 {
		attrs[HostAttrMachineID] = strings.TrimSpace(string(id))
	}
	if macs := nicMACs(); len(macs) > 0 {
		attrs[HostAttrNICMACs] = strings.Join(macs, ",")
	}
	if serials := normalizeList(readDiskSerials()); len(serials) > 0 {
		attrs[HostAttrDiskSerials] = strings.Join(serials, ",")
	}
	if d := installDate(identityDir); d != "" {
		attrs[HostAttrInstallDate] = d
	}
	return attrs
}

// nicMACs returns the sorted, de-duplicated hardware addresses of physical
// network interfaces.
func nicMACs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var macs []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || len(ifc.HardwareAddr) == 0 || isVirtualNIC(ifc.Name) {
			continue
		}
		macs = append(macs, ifc.HardwareAddr.String())
	}
	return normalizeList(macs)
}

func isVirtualNIC(name string) bool {
	for _, p := range virtualNICPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// normalizeList trims, drops empties and duplicates, and sorts.
func normalizeList(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || strings.Contains(v, ",") {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// installDate returns the calendar date (UTC, RFC3339 full-date) on which the
// device identity file was created. The file is written once by GenerateOrLoad,
// so its modification time is its creation time.
func installDate(identityDir string) string {
	if identityDir == "" {
		return ""
	}
	info, err := os.Stat(filepath.Join(identityDir, keyFileName))
	if err != nil {
		return ""
	}
	return info.ModTime().UTC().Format(time.DateOnly)
}
