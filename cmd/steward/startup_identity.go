// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"errors"

	"github.com/cfgis/cfgms/cmd/steward/service"
	"github.com/cfgis/cfgms/features/steward/client"
	"github.com/cfgis/cfgms/pkg/logging"
)

// A stored identity is enough to start: a token file defect or a missing
// controller URL is reported as a heartbeat reason instead of stopping the
// steward. The registration token is only needed to enrol or re-register.

const (
	// tokenReasonComponent and trustReasonComponent are the heartbeat reason
	// components for the startup conditions below.
	tokenReasonComponent = "registration_token"
	trustReasonComponent = "trust"

	// controllerURLMissingCode is the reason code when no controller URL is
	// configured and the stored identity's address is used instead.
	controllerURLMissingCode = "controller_url.missing"
)

// startupReasons holds the reasons found while starting. They are applied to the
// client before its initial heartbeat, and then carried into the subsystem
// reasons, so every heartbeat reports them.
var startupReasons = client.NewHealthReasonRegistry()

// tokenFileReasonMessages are fixed so a reason never carries a path or content.
var tokenFileReasonMessages = map[service.TokenFileErrorKind]string{
	service.TokenFileMissing:     "registration token file is missing; connecting with the stored identity",
	service.TokenFileEmpty:       "registration token file is empty; connecting with the stored identity",
	service.TokenFilePermissions: "registration token file is not safe to read; connecting with the stored identity",
	service.TokenFileInvalid:     "registration token file is unusable; connecting with the stored identity",
}

// hasStoredIdentity reports whether a parseable stored identity exists.
func hasStoredIdentity() bool {
	id, err := loadIdentity(certStoreDirResolver())
	return err == nil && id != nil
}

// tokenFromFile reads the registration token from path. A refused file is an
// error, unless a stored identity exists: then the steward starts with an EMPTY
// token (the unsafe file's content is never used) and reports
// registration_token / token_file.<kind>. Without a stored identity the error is
// returned unchanged, because the token is then needed to enrol.
//
// Whether an identity exists is decided here, before the data directory check
// in runStewardInternal; its content is not used here. runStewardInternal
// applies that check before the identity's address or certificates are used.
func tokenFromFile(path string) (string, error) {
	token, err := service.ReadTokenFile(path)
	if err == nil {
		return token, nil
	}
	tfe, ok := service.AsTokenFileError(err)
	if !ok || !hasStoredIdentity() {
		return "", err
	}
	startupReasons.Set(tokenReasonComponent, "token_file."+string(tfe.Kind), tokenFileReasonMessages[tfe.Kind])
	return "", nil
}

// resolveTrustSourceForStart resolves the trust source and controller URL like
// resolveTrustSource. When no controller URL is configured and a stored
// identity carries an address, that address is used with the stored trust mode
// (never a weaker one) and controller_url.missing is reported. An identity with
// an unrecorded mode (a legacy record) gets the strictest source.
func resolveTrustSourceForStart(compiledURL, installURL, installCA string, id *StewardIdentity) (TrustSource, string, error) {
	src, url, err := resolveTrustSource(compiledURL, installURL, installCA)
	if err == nil || id == nil || id.TransportAddress == "" || installURL != "" || compiledURL != "" {
		return src, url, err
	}
	stored := trustSourceFromMode(id.TrustMode)
	if stored == 0 {
		stored = trustSourceCompileBaked
	}
	startupReasons.Set(trustReasonComponent, controllerURLMissingCode,
		"no controller URL is configured; using the address recorded in the stored identity")
	return stored, id.TransportAddress, nil
}

// applyStartupReasons copies the startup reasons onto tc and reports whether any
// are set.
func applyStartupReasons(tc *client.TransportClient) bool {
	list := startupReasons.List()
	for _, r := range list {
		tc.SetHealthReason(r.Component, r.Code, r.Message)
	}
	return len(list) > 0
}

// errNoRegistrationToken is returned by the register and refresh fallbacks when
// the steward has no usable token. The connect loop keeps retrying the stored
// identity.
var errNoRegistrationToken = errors.New("no usable registration token: registration needs a valid token file; the stored identity is retried")

// logStoredIdentityStart logs that the steward runs on its stored identity.
func logStoredIdentityStart(logger logging.Logger) {
	for _, r := range startupReasons.List() {
		logger.Warn("Starting on the stored identity",
			"operation", "stored_identity_start",
			"component", r.Component,
			"code", r.Code)
	}
}
