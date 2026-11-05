// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cfgis/cfgms/features/steward/client"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

// reportOnlyConnectBudget bounds how long connectReportOnly keeps dialing. A
// link that cannot be established inside it hands control back to the caller
// instead of retrying a possibly swapped address forever.
var reportOnlyConnectBudget = 2 * time.Minute

// Errors returned by connectReportOnly. Each is checked with errors.Is so the
// caller can fall to the right recovery: a missing identity or an unusable
// anchor is S19/S20's, not a reason to dial.
var (
	// errReportOnlyNoIdentity: no stored identity could be loaded.
	errReportOnlyNoIdentity = errors.New("report-only link: no stored identity")

	// errReportOnlyAnchor: the CA the link would trust does not verify against
	// its anchor. Nothing is dialed.
	errReportOnlyAnchor = errors.New("report-only link: trust anchor does not verify")

	// errReportOnlyNoClientCert: the cert store holds no valid client
	// certificate, so there is no identity to present.
	errReportOnlyNoClientCert = errors.New("report-only link: no valid client certificate")
)

// reportOnlyAnchor returns the CA the report-only link trusts the controller
// through: the install-pinned CA when the steward was installed that way, else
// the CA recorded in the identity, which must re-derive to the pin recorded
// with it. Both are data-folder material, so neither ranks above the other, and
// an attacker who can rewrite one can rewrite the other. The baked publisher
// fingerprint is deliberately absent: it gates operator actions and repair
// signatures, never connecting or reporting, so a controller root rotation
// cannot strand a locked host.
//
// It reads, and never writes, the installer CA file.
func reportOnlyAnchor(id *StewardIdentity, trustSrc TrustSource, logger logging.Logger) (string, error) {
	identityCA, err := verifyPersistedCA(id.CACertPEM, id.CAPinFingerprint)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errReportOnlyAnchor, err)
	}
	if trustSrc != trustSourceInstallPinned {
		return identityCA, nil
	}

	path := resolveRegistrationCACertPath(logger)
	if path == "" {
		return "", fmt.Errorf("%w: install-pinned steward has no installer CA", errReportOnlyAnchor)
	}
	// #nosec G304 -- path comes from resolveRegistrationCACertPath: the explicit
	// installer CA option or the fixed service CA path.
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%w: installer CA unreadable", errReportOnlyAnchor)
	}
	installCA, err := verifyPersistedCA(string(raw), id.CAPinFingerprint)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errReportOnlyAnchor, err)
	}
	if installCA != identityCA {
		return "", fmt.Errorf("%w: identity CA differs from the installer CA", errReportOnlyAnchor)
	}
	return installCA, nil
}

// connectReportOnly opens a report-only link to the controller with the stored
// mTLS identity (see client.TransportConfig.ReportOnly). It dials the stored
// identity's transport address, which is delivered only in registration and
// refresh responses and is not the controller URL, and trusts the server only
// through the anchor reportOnlyAnchor names: a swapped address fails the
// handshake unless the attacker holds a certificate chained to that anchor. The
// controller URL is never read from the identity file and no registration token
// is needed.
//
// A CA that does not verify against its anchor returns errReportOnlyAnchor and
// dials nothing. A stored identity that cannot be loaded at all is S19/S20's
// case and returns errReportOnlyNoIdentity.
func connectReportOnly(ctx context.Context, certStoreDir string, trustSrc TrustSource, logger logging.Logger) (*client.TransportClient, error) {
	return connectReportOnlyLink(ctx, certStoreDir, trustSrc, reportOnlyLinkOptions{}, logger)
}

// reportOnlyLinkOptions tunes connectReportOnlyLink for the tamper alarm.
type reportOnlyLinkOptions struct {
	// anchorPEM, when set, is the CA the link trusts instead of the one
	// reportOnlyAnchor derives. The caller has already verified it against the
	// identity's pin (reconstructPinnedCA).
	anchorPEM string
	// prepare runs on the client before it connects, so a handler it installs
	// sees everything the controller sends on connect.
	prepare func(tc *client.TransportClient)
}

// connectReportOnlyLink is connectReportOnly with options.
func connectReportOnlyLink(ctx context.Context, certStoreDir string, trustSrc TrustSource, opts reportOnlyLinkOptions, logger logging.Logger) (*client.TransportClient, error) {
	id, err := loadIdentity(certStoreDir)
	if err != nil || id == nil {
		return nil, errReportOnlyNoIdentity
	}
	anchorPEM := opts.anchorPEM
	if anchorPEM == "" {
		anchorPEM, err = reportOnlyAnchor(id, trustSrc, logger)
	}
	if err != nil {
		return nil, err
	}
	certMgr, err := loadReportOnlyCertManager(certStoreDir)
	if err != nil {
		return nil, err
	}

	tc, err := client.NewTransportClient(&client.TransportConfig{
		ReportOnly:            true,
		ControllerURL:         id.TransportAddress,
		CACertPEM:             anchorPEM,
		CertManager:           certMgr,
		CertStoreDir:          certStoreDir,
		HostAttributes:        hostAttributes,
		InitialConnectTimeout: reportOnlyConnectBudget,
		// Host facts only: no module DNA source, no osquery source.
		DNACollector: newDNACollectorAdapter(logger, nil),
		Logger:       logger,
	})
	if err != nil {
		return nil, fmt.Errorf("report-only link: failed to create client: %w", err)
	}
	tc.SetStewardID(id.StewardID)
	tc.SetTenantID(id.TenantID)
	applyStartupReasons(tc)
	if opts.prepare != nil {
		opts.prepare(tc)
	}

	if err := tc.Connect(ctx); err != nil {
		_ = tc.Disconnect(context.Background())
		return nil, fmt.Errorf("report-only link: connect failed: %w", err)
	}
	return tc, nil
}

// loadReportOnlyCertManager opens the cert store and requires a valid client
// certificate in it: the report-only link authenticates with the stored
// identity and never enrolls.
func loadReportOnlyCertManager(certStoreDir string) (*cert.Manager, error) {
	certMgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath:    certStoreDir,
		LoadExistingCA: true,
	})
	if err != nil {
		return nil, fmt.Errorf("report-only link: cert store not loadable: %w", err)
	}
	certs, err := certMgr.ListCertificates()
	if err != nil {
		return nil, fmt.Errorf("report-only link: cert list unavailable: %w", err)
	}
	if !hasValidClientCert(certs) {
		return nil, errReportOnlyNoClientCert
	}
	return certMgr, nil
}
