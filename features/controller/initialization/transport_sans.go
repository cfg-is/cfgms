// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package initialization

import (
	"net"
	"os"
	"strings"

	"github.com/cfgis/cfgms/features/controller/config"
)

// TransportCertSANs returns the DNS names and IP addresses to embed in the
// internal (PurposeTransport) certificate.
//
// The returned SANs merge:
//   - the transport defaults required by every controller (localhost / loopback /
//     "cfgms-internal" / "controller-standalone")
//   - operator-configured legacy server SANs (certificate.server.dns_names /
//     certificate.server.ip_addresses)
//   - operator-configured internal SANs (certificate.internal.dns_names /
//     certificate.internal.ip_addresses), if set
//   - the CFGMS_EXTERNAL_HOSTNAME env value, classified as IP SAN if it parses
//     as an IP literal and DNS SAN otherwise
//
// Without merging in cfg.Certificate.Server and CFGMS_EXTERNAL_HOSTNAME, a
// steward dialing the controller by its external hostname fails mTLS
// verification because the generated certificate omits that name.
// Duplicates are removed and ordering is deterministic (first-seen).
//
// Both --init (initialization.Run) and controller startup
// (buildGRPCControlPlaneTLSConfig) must use this function so the cert minted
// on first boot already covers every name a steward may use to reach the
// controller. EnsureSeparatedCertificates is idempotent — if --init mints the
// cert with the wrong SAN set, startup will not regenerate it.
func TransportCertSANs(cfg *config.Config) (dnsNames, ipAddresses []string) {
	dnsNames = []string{"localhost", "cfgms-internal", "controller-standalone"}
	ipAddresses = []string{"127.0.0.1", "0.0.0.0"}

	if cfg != nil && cfg.Certificate != nil {
		if cfg.Certificate.Server != nil {
			dnsNames = append(dnsNames, cfg.Certificate.Server.DNSNames...)
			ipAddresses = append(ipAddresses, cfg.Certificate.Server.IPAddresses...)
		}
		if cfg.Certificate.Internal != nil {
			dnsNames = append(dnsNames, cfg.Certificate.Internal.DNSNames...)
			ipAddresses = append(ipAddresses, cfg.Certificate.Internal.IPAddresses...)
		}
	}

	if hostname := strings.TrimSpace(os.Getenv("CFGMS_EXTERNAL_HOSTNAME")); hostname != "" {
		if net.ParseIP(hostname) != nil {
			ipAddresses = append(ipAddresses, hostname)
		} else {
			dnsNames = append(dnsNames, hostname)
		}
	}

	return dedupeSANs(dnsNames), dedupeSANs(ipAddresses)
}

// dedupeSANs returns the input slice with empty strings dropped and duplicates
// removed, preserving first-seen order.
func dedupeSANs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
