// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package dna

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"
)

// pdcEmulatorAttr is the baseline DNA fact that is "true" on exactly one domain
// controller per domain: the holder of the PDC-emulator FSMO role. The controller
// gates the AD module's observe activation on it (observe_when
// {fact: ad_pdc_emulator, equals: "true"}), so one host per domain reports domain
// inventory.
const pdcEmulatorAttr = "ad_pdc_emulator"

// pdcEmulatorLookupTimeout bounds one PDC-emulator lookup. The attribute sits on
// the baseline fast path, so a domain whose role holder is unreachable must not
// stall DNA collection; a lookup that has not answered in time counts as
// unresolved.
const pdcEmulatorLookupTimeout = 15 * time.Second

// errPDCEmulatorLookupTimeout is reported when the resolver does not answer
// within pdcEmulatorLookupTimeout.
var errPDCEmulatorLookupTimeout = errors.New("pdc emulator lookup timed out")

// PDCEmulatorResolver reports this host's domain-controller status and the DNS
// name of its domain's PDC-emulator role holder.
//
// localHost is this host's name (DNS FQDN where available). isDC reports whether
// this host is a domain controller. pdcHost is the role holder's name; a resolver
// may leave it empty and skip the lookup when isDC is false. A non-nil err means
// the role holder could not be resolved.
type PDCEmulatorResolver interface {
	ResolvePDCEmulator(ctx context.Context) (localHost, pdcHost string, isDC bool, err error)
}

// IsPDCEmulator reports whether localHost is the domain's PDC emulator.
//
// It is true only when isDC is set and the two names identify the same host. The
// comparison ignores case, a leading UNC "\\" prefix and a trailing root dot.
// When either name is a bare host label (no DNS suffix), only the first labels
// are compared; two fully qualified names must match in full, so dc01.a.example
// and dc01.b.example are different hosts.
func IsPDCEmulator(localHost, pdcHost string, isDC bool) bool {
	if !isDC {
		return false
	}
	local := normalizeHostName(localHost)
	pdc := normalizeHostName(pdcHost)
	if local == "" || pdc == "" {
		return false
	}
	if local == pdc {
		return true
	}
	if strings.Contains(local, ".") && strings.Contains(pdc, ".") {
		return false
	}
	return firstLabel(local) == firstLabel(pdc)
}

func normalizeHostName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimPrefix(name, `\\`)
	name = strings.TrimSuffix(name, ".")
	return strings.ToLower(name)
}

func firstLabel(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return name[:i]
	}
	return name
}

// collectPDCEmulator sets ad_pdc_emulator from resolver. A nil resolver (every
// platform but Windows) emits nothing. A resolver error or timeout emits "false":
// with the role holder unresolvable, no host reports this cycle.
func collectPDCEmulator(ctx context.Context, resolver PDCEmulatorResolver, attributes map[string]string) error {
	if resolver == nil {
		return nil
	}

	type result struct {
		localHost, pdcHost string
		isDC               bool
		err                error
	}

	lookupCtx, cancel := context.WithTimeout(ctx, pdcEmulatorLookupTimeout)
	defer cancel()

	done := make(chan result, 1)
	go func() {
		local, pdc, isDC, err := resolver.ResolvePDCEmulator(lookupCtx)
		done <- result{local, pdc, isDC, err}
	}()

	var r result
	select {
	case r = <-done:
	case <-lookupCtx.Done():
		r.err = errPDCEmulatorLookupTimeout
	}

	if r.err != nil {
		attributes[pdcEmulatorAttr] = "false"
		return r.err
	}
	attributes[pdcEmulatorAttr] = strconv.FormatBool(IsPDCEmulator(r.localHost, r.pdcHost, r.isDC))
	return nil
}
