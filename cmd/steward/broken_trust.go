// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/cfgis/cfgms/cmd/steward/service"
	"github.com/cfgis/cfgms/features/steward/client"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration/identity"
)

// Broken-trust fallback (ADR-034). When the steward's own secrets or trust
// material cannot be trusted at all and a registration token is available, it
// re-keys and registers as a new device naming the old identity (clone_of),
// declaring clone_reason "broken_trust" so the controller admits it locked.
//
// Every trigger is a local file or verification failure, or the controller's
// answer on the pinned refresh channel that it has no record of this device key.
// No ControlMessage starts this path, and the registration token (never the old
// or an expired certificate) authenticates the new registration.

const (
	// cloneReasonBrokenTrust is the wire value of clone_reason.
	cloneReasonBrokenTrust = "broken_trust"

	brokenTrustReasonComponent = "identity"
	brokenTrustReasonCode      = "identity.broken_trust"
	brokenTrustReasonMessage   = "this steward could not trust its stored identity and registered again as a new device; it stays locked until an operator links it"
)

// brokenTrustCause is the local failure that makes the fallback a candidate.
type brokenTrustCause string

const (
	causeIdentityCorrupt   brokenTrustCause = "identity_corrupt"
	causeCloneMarkerBad    brokenTrustCause = "clone_marker_corrupt"
	causeCAUnverifiable    brokenTrustCause = "pinned_ca_unverifiable"
	causeDeviceKeyUnusable brokenTrustCause = "device_key_unusable"
)

// errBrokenTrustNotAllowed is returned when a trigger fired but the fallback may
// not run (no token, no trusted anchor, tampered data directory). The connect
// loop logs it and retries; nothing was sent.
var errBrokenTrustNotAllowed = errors.New("broken trust: re-registration not allowed")

// brokenTrustInput is everything decideBrokenTrust looks at.
type brokenTrustInput struct {
	cause          brokenTrustCause
	tokenAvailable bool
	// trustSrc is how the controller is trusted for the new registration.
	trustSrc TrustSource
	// hasKeyStore reports whether a device key store is open to re-key.
	hasKeyStore bool
	// dataDirTampered is the data directory tamper case, which has its own alarm.
	dataDirTampered bool
}

// decideBrokenTrust reports whether the fallback may run and, when it may not,
// the reason. It is the only place the guards live.
func decideBrokenTrust(in brokenTrustInput) (bool, string) {
	switch {
	case in.cause == "":
		return false, "no broken-trust trigger"
	case in.dataDirTampered:
		return false, "data directory is not secure; the tamper alarm owns this case"
	case !in.tokenAvailable:
		return false, "no usable registration token"
	case !in.hasKeyStore:
		return false, "no device key store to re-key"
	case in.trustSrc != trustSourceCompileBaked && in.trustSrc != trustSourceInstallPinned:
		// The token is never sent to a controller whose CA came from the network.
		return false, "no install-pinned or compile-time trust anchor for the controller"
	}
	return true, ""
}

// recoverOldStewardID returns the old steward ID from whatever is still
// readable: the identity file, the clone marker, then the client certificate's
// subject. It returns "" when none yields one.
func recoverOldStewardID(dir string) string {
	if id := tolerantStewardID(filepath.Join(dir, identityFileName), "steward_id"); id != "" {
		return id
	}
	if id := tolerantStewardID(filepath.Join(dir, cloneMarkerFileName), "clone_of"); id != "" {
		return id
	}
	mgr, err := cert.NewManager(&cert.ManagerConfig{StoragePath: dir, LoadExistingCA: true})
	if err != nil {
		return ""
	}
	certs, err := mgr.ListCertificates()
	if err != nil {
		return ""
	}
	for _, c := range certs {
		if c.Type == cert.CertificateTypeClient && c.CommonName != "" {
			return c.CommonName
		}
	}
	return ""
}

// tolerantStewardID reads one string field from a JSON file without requiring
// the rest of the file to be valid.
func tolerantStewardID(path, field string) string {
	// #nosec G304 -- fixed file names under the steward's private identity directory.
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(data, &m) != nil {
		return ""
	}
	var v string
	if json.Unmarshal(m[field], &v) != nil {
		return ""
	}
	return v
}

// setBrokenTrustReason makes the next heartbeat name the broken-trust state.
func setBrokenTrustReason() {
	startupReasons.Set(brokenTrustReasonComponent, brokenTrustReasonCode, brokenTrustReasonMessage)
}

// clearBrokenTrustReason drops the reason once a link restored the old identity.
func clearBrokenTrustReason() {
	startupReasons.Clear(brokenTrustReasonComponent)
}

// beginBrokenTrust persists the marker, and only then re-keys and discards the
// old identity (marker first, as registerAsClone). A failed key step leaves the
// marker in place so the next attempt resumes the same fallback.
func beginBrokenTrust(ctx context.Context, dir, cloneOf string, ks identity.KeyStore) error {
	if err := saveCloneMarkerDetail(dir, cloneMarker{CloneOf: cloneOf, Reason: cloneReasonBrokenTrust, Rekey: true}); err != nil {
		return err
	}
	return completeBrokenTrustRekey(ctx, dir, cloneOf, ks)
}

// completeBrokenTrustRekey regenerates the device key, discards the identity and
// registration state of the old device and records that the re-key is done.
func completeBrokenTrustRekey(ctx context.Context, dir, cloneOf string, ks identity.KeyStore) error {
	if ks == nil {
		return errors.New("broken trust: no device key store to re-key")
	}
	if _, _, err := ks.Regenerate(ctx); err != nil {
		return fmt.Errorf("regenerate device key: %w", err)
	}
	if err := clearStoredIdentity(dir); err != nil {
		return err
	}
	clearReadmissionState(dir)
	_ = clearPendingState(dir)
	return saveCloneMarkerDetail(dir, cloneMarker{CloneOf: cloneOf, Reason: cloneReasonBrokenTrust})
}

// connectParams are the registerAndConnect inputs the fallback passes along.
type connectParams struct {
	certStoreDir, token, controllerURL string
	trustSrc                           TrustSource
	installCAPEM, priorCAPin           string
	ks                                 identity.KeyStore
	runtimeCfg                         stewardconfig.StewardConfig
	publicBeta                         bool
	logger                             logging.Logger
}

// registerNew registers as a new device naming cloneOf.
func (c connectParams) registerNew(ctx context.Context, cloneOf string) (*client.TransportClient, error) {
	return registerNewDevice(ctx, c.certStoreDir, c.token, c.controllerURL, c.trustSrc, c.installCAPEM, c.priorCAPin, c.ks, cloneOf, c.runtimeCfg, c.publicBeta, c.logger)
}

// registerBrokenTrust runs the fallback from the connect path: it re-keys and
// registers as a new device naming the old one.
func registerBrokenTrust(ctx context.Context, c connectParams, cause brokenTrustCause) (*client.TransportClient, error) {
	if ok, why := decideBrokenTrust(brokenTrustInput{
		cause:          cause,
		tokenAvailable: c.token != "",
		trustSrc:       c.trustSrc,
		hasKeyStore:    c.ks != nil,
	}); !ok {
		c.logger.Warn("Stored trust material is unusable but re-registration is not allowed; retrying",
			"operation", "broken_trust", "cause", string(cause), "why", why)
		return nil, fmt.Errorf("%w: %s (%s)", errBrokenTrustNotAllowed, why, cause)
	}
	cloneOf := recoverOldStewardID(c.certStoreDir)
	c.logger.Warn("Stored trust material is unusable; generating a new device key and registering as a new device",
		"operation", "broken_trust", "cause", string(cause), "clone_of", logging.SanitizeLogValue(cloneOf))
	setBrokenTrustReason()
	if err := beginBrokenTrust(ctx, c.certStoreDir, cloneOf, c.ks); err != nil {
		return nil, err
	}
	return c.registerNew(ctx, cloneOf)
}

// resumeBrokenTrust continues a fallback a previous run began: it finishes the
// re-key if that was interrupted and registers (resuming a pending
// registration) as the same new device.
func resumeBrokenTrust(ctx context.Context, c connectParams, m *cloneMarker) (*client.TransportClient, error) {
	setBrokenTrustReason()
	if m.Rekey {
		if c.token == "" {
			return nil, errNoRegistrationToken
		}
		if err := completeBrokenTrustRekey(ctx, c.certStoreDir, m.CloneOf, c.ks); err != nil {
			return nil, err
		}
	}
	c.logger.Info("Resuming registration as a new device after broken trust",
		"clone_of", logging.SanitizeLogValue(m.CloneOf))
	return c.registerNew(ctx, m.CloneOf)
}

// cloneReasonForMarker is the clone_reason to send with a registration naming
// cloneOf: only the broken-trust fallback sends one.
func cloneReasonForMarker(dir, cloneOf string) string {
	m, err := loadCloneMarker(dir)
	if err != nil || m == nil || m.Reason != cloneReasonBrokenTrust || m.CloneOf != cloneOf {
		return ""
	}
	return m.Reason
}

// brokenTrustRestart carries the device-key trigger out of a running steward:
// the lifecycle hook persists the marker, then asks the connected run to end so
// the next connect re-keys and registers. It holds nothing the controller sent.
type brokenTrustRestart struct {
	dir      string
	token    string
	trustSrc TrustSource
	ks       identity.KeyStore
	cancel   context.CancelFunc
	logger   logging.Logger
	fired    atomic.Bool
}

// Requested reports whether the hook started the fallback.
func (b *brokenTrustRestart) Requested() bool { return b.fired.Load() }

// onDeviceKeyUnusable is the identityLifecycle.onDeviceKeyUnusable hook.
func (b *brokenTrustRestart) onDeviceKeyUnusable() {
	if ok, why := decideBrokenTrust(brokenTrustInput{
		cause:          causeDeviceKeyUnusable,
		tokenAvailable: b.token != "",
		trustSrc:       b.trustSrc,
		hasKeyStore:    b.ks != nil,
	}); !ok {
		b.logger.Warn("Device key is unusable but re-registration is not allowed",
			"operation", "broken_trust", "why", why)
		return
	}
	cloneOf := recoverOldStewardID(b.dir)
	if err := saveCloneMarkerDetail(b.dir, cloneMarker{CloneOf: cloneOf, Reason: cloneReasonBrokenTrust, Rekey: true}); err != nil {
		b.logger.Error("Broken-trust marker could not be saved",
			"operation", "broken_trust", "error", logging.SanitizeLogValue(err.Error()))
		return
	}
	setBrokenTrustReason()
	b.fired.Store(true)
	b.logger.Warn("Device key unusable; restarting the connection to register as a new device",
		"operation", "broken_trust", "clone_of", logging.SanitizeLogValue(cloneOf))
	b.cancel()
}

// alarmToken reads the registration token for the alarm path with the same
// ownership and permission check as every other token read. It returns "" when
// the file is missing or refused.
func alarmToken(ctx context.Context) string {
	path := regTokenFileFrom(ctx)
	if path == "" {
		return ""
	}
	t, err := service.ReadTokenFile(path)
	if err != nil {
		return ""
	}
	return t
}

// alarmTrustSource is the trust source the new registration would use: the
// install-pinned CA when it verifies, else the compile-time source. A CA that is
// absent or does not verify never stands in for either, so an install URL
// without a verified CA resolves to TOFU, which the fallback refuses.
func alarmTrustSource(storedID *StewardIdentity, controllerURL string, logger logging.Logger) (TrustSource, bool) {
	installCAPEM, caErr := loadInstallCAPEM(storedID, logger)
	if caErr != nil {
		installCAPEM = ""
	}
	src, _, err := resolveTrustSource(ControllerURL, controllerURL, installCAPEM)
	return src, err == nil
}

// rekeyFromAlarm is the tamper alarm's way out when the pinned CA cannot be
// verified: with a token that passes the token-file check, and a trust anchor
// from an install-pinned or compile-time source, it re-keys and clears the
// stored identity. It reports whether the fallback began.
func rekeyFromAlarm(ctx context.Context, latch *tamperLatch, controllerURL string, logger logging.Logger) bool {
	if !latch.onlyCode(cpTypes.ReasonCodeTamperCAMismatch) {
		return false // data directory tamper, downgrade, controller lock: other paths own them
	}
	dir := certStoreDirResolver()
	storedID, _ := loadIdentity(dir)
	src, srcOK := alarmTrustSource(storedID, controllerURL, logger)
	token := alarmToken(ctx)
	ks, ksErr := openDeviceKeyStore(ctx, dir, logger)
	if ksErr != nil {
		ks = nil
	}
	ok, why := decideBrokenTrust(brokenTrustInput{
		cause:          causeCAUnverifiable,
		tokenAvailable: token != "",
		trustSrc:       src,
		hasKeyStore:    ks != nil,
	})
	if !ok || !srcOK {
		logger.Warn("Pinned CA is unverifiable and re-registration is not allowed; staying report-only",
			"operation", "broken_trust", "why", why)
		return false
	}
	cloneOf := recoverOldStewardID(dir)
	logger.Warn("Pinned CA is unverifiable; generating a new device key to register as a new device",
		"operation", "broken_trust", "clone_of", logging.SanitizeLogValue(cloneOf))
	if err := beginBrokenTrust(ctx, dir, cloneOf, ks); err != nil {
		logger.Error("Broken-trust re-key failed; will retry",
			"operation", "broken_trust", "error", logging.SanitizeLogValue(err.Error()))
		return false
	}
	setBrokenTrustReason()
	return true
}

// errLinkIDMismatch is returned when a re-admission response names a steward ID
// this device may not adopt.
var errLinkIDMismatch = errors.New("re-admission response names a different steward ID than this device may adopt")

const linkMismatchReasonCode = "identity.link_mismatch"

// adoptLinkedStewardID completes a link on the steward. The stored steward ID
// normally wins over the response's. With a clone marker set, a response that
// carries the marker's recorded CloneOf ID is adopted (cred.bundle takes that
// ID); any other differing ID is refused and reported, and the marker is kept.
func adoptLinkedStewardID(dir string, id *StewardIdentity, cred *refreshedCredential, logger logging.Logger) (bool, error) {
	if id == nil || cred.responseStewardID == "" || cred.responseStewardID == id.StewardID {
		return false, nil
	}
	marker, err := loadCloneMarker(dir)
	if err != nil || marker == nil {
		return false, nil // no marker: the stored ID stays, as before
	}
	if marker.CloneOf != "" && cred.responseStewardID == marker.CloneOf {
		logger.Warn("Controller linked this device to its previous identity; adopting it",
			"operation", "broken_trust_link", "steward_id", logging.SanitizeLogValue(marker.CloneOf))
		cred.bundle.StewardID = marker.CloneOf
		return true, nil
	}
	logger.Error("Re-admission named a steward ID this device may not adopt; refusing",
		"operation", "broken_trust_link",
		"response_steward_id", logging.SanitizeLogValue(cred.responseStewardID))
	startupReasons.Set(brokenTrustReasonComponent, linkMismatchReasonCode,
		"the controller named a steward ID this device does not hold a link for; refused")
	return false, errLinkIDMismatch
}

// finishLink clears the clone marker and the broken-trust reason once the stored
// identity carries the old steward ID the marker recorded. tc may be nil.
func finishLink(dir string, tc *client.TransportClient) {
	m, err := loadCloneMarker(dir)
	if err != nil || m == nil {
		return
	}
	if id, _ := loadIdentity(dir); id == nil || id.StewardID != m.CloneOf {
		return
	}
	_ = clearCloneMarker(dir)
	clearBrokenTrustReason()
	if tc != nil {
		tc.ClearHealthReason(brokenTrustReasonComponent)
	}
}

// resumeFromLocalState decides the connect path from the clone marker and the
// stored identity before any reconnect. handled is false when neither applies
// and the normal reconnect and registration flow continues.
//
// A clone marker means this steward was refused as a copy and already re-keyed
// (ADR-034 §4), or began the broken-trust fallback. It resumes registering as
// the new device and never goes back to the old identity. A marker made stale
// by a stored new identity is dropped, except a broken-trust marker, which stays
// until a link rebinds the old ID.
func (c connectParams) resumeFromLocalState(ctx context.Context, storedID *StewardIdentity, idLoadErr error) (*client.TransportClient, bool, error) {
	marker, markerErr := loadCloneMarker(c.certStoreDir)
	if markerErr != nil {
		// A corrupt marker is broken trust: with a token it re-keys and registers
		// as a new device instead of failing forever.
		c.logger.Warn("Clone marker is corrupt", "error", logging.SanitizeLogValue(markerErr.Error()))
		tc, err := registerBrokenTrust(ctx, c, causeCloneMarkerBad)
		return tc, true, err
	}
	marker = c.settleRegisteredMarker(marker, storedID)
	switch {
	case marker != nil && marker.Reason == cloneReasonBrokenTrust:
		tc, err := resumeBrokenTrust(ctx, c, marker)
		return tc, true, err
	case marker != nil:
		c.logger.Info("Resuming registration as a new device after being refused as a copy",
			"clone_of", logging.SanitizeLogValue(marker.CloneOf))
		tc, err := c.registerNew(ctx, marker.CloneOf)
		return tc, true, err
	case idLoadErr != nil:
		// A stored identity that cannot be read or parsed cannot be trusted.
		c.logger.Warn("Stored identity is unreadable", "error", logging.SanitizeLogValue(idLoadErr.Error()))
		tc, err := registerBrokenTrust(ctx, c, causeIdentityCorrupt)
		return tc, true, err
	}
	return nil, false, nil
}

// settleRegisteredMarker drops a marker whose new identity is already stored.
// An ordinary clone's marker is done; a broken-trust marker stays until the
// stored identity carries the old ID the marker recorded. It returns the marker
// still to resume, or nil.
func (c connectParams) settleRegisteredMarker(marker *cloneMarker, storedID *StewardIdentity) *cloneMarker {
	if marker == nil || marker.Rekey || storedID == nil || c.ks == nil || c.ks.DeviceID() == "" || storedID.DeviceID != c.ks.DeviceID() {
		return marker
	}
	if marker.Reason != cloneReasonBrokenTrust {
		_ = clearCloneMarker(c.certStoreDir)
		return nil
	}
	if storedID.StewardID == marker.CloneOf {
		_ = clearCloneMarker(c.certStoreDir)
		clearBrokenTrustReason()
	} else {
		setBrokenTrustReason()
	}
	return nil
}

// afterConnected says what the steward loop does after a connected run: again
// is false when the loop returns err; keepToken is true when the next connect
// reuses the registration token (the device key became unusable).
func afterConnected(relatch, rekey bool, err error) (again, keepToken bool) {
	switch {
	case err != nil:
		return false, false
	case rekey:
		return true, true
	case relatch:
		return true, false
	}
	return false, false
}

// clearPendingUnlessStopped discards the pending registration state after a
// failed poll. A stop mid-poll keeps it so the next start resumes the same
// pending registration instead of filing a second one.
func clearPendingUnlessStopped(ctx context.Context, dir string) {
	if ctx.Err() == nil {
		_ = clearPendingState(dir)
	}
}
