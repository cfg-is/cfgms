// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/steward/client"
	"github.com/cfgis/cfgms/features/steward/registration"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration/identity"
)

const (
	// clientCertReasonComponent is the health-reason component the runner owns.
	clientCertReasonComponent = "client_cert"
	// Reason codes the runner reports on the heartbeat.
	clientCertReasonRenewalFailed     = "client_cert.renewal_failed"
	clientCertReasonDeviceKeyUnusable = "client_cert.device_key_unusable"

	// Renewal starts once less than max(25% of the certificate's lifetime, 7 days)
	// remains, so a certificate is replaced well before it can lapse.
	renewWindowFraction  = 4
	renewWindowFloor     = 7 * 24 * time.Hour
	lifecycleTick        = time.Minute
	lifecycleInterval    = 10 * time.Minute
	lifecycleJitter      = time.Minute
	lifecycleBackoffBase = time.Minute
	lifecycleBackoffCap  = 10 * time.Minute
	renewAttemptTimeout  = 2 * time.Minute
)

// errDeviceKeyUnusable marks a failure to use the device identity key (missing,
// corrupt, or unable to sign). Renewal never falls back to a weaker credential.
var errDeviceKeyUnusable = errors.New("device identity key unusable")

// defaultRenewWindow is how long before expiry a certificate of the given
// lifetime is renewed.
func defaultRenewWindow(lifetime time.Duration) time.Duration {
	w := lifetime / renewWindowFraction
	if w < renewWindowFloor {
		w = renewWindowFloor
	}
	return w
}

// identityLifecycle keeps a running steward's client certificate current. It
// renews through the device-key proof-of-possession refresh flow — the steward
// generates the mTLS key, the controller signs only a CSR — imports the result
// into the client's certificate manager and re-dials on the SAME TransportClient.
// A failed renewal only reports; it never enforces from weaker material.
type identityLifecycle struct {
	tc            *client.TransportClient
	ks            identity.KeyStore
	certStoreDir  string
	controllerURL string
	trustSrc      TrustSource
	installCAPEM  string
	logger        logging.Logger

	// mu is shared with the boot connect loop so renewal and connecting never
	// run at the same time.
	mu *sync.Mutex

	// onDeviceKeyUnusable, when set, is called once each time the device key
	// becomes unusable (cleared by a later successful renewal).
	onDeviceKeyUnusable func()

	// Tunables; zero values select the production defaults.
	tick        time.Duration
	interval    time.Duration
	jitter      time.Duration
	renewWindow func(lifetime time.Duration) time.Duration
	now         func() time.Time

	keyUnusableNotified bool
	reconnectPending    bool
	failures            int
}

func (l *identityLifecycle) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

func (l *identityLifecycle) durations() (tick, interval, jitter time.Duration) {
	tick, interval, jitter = l.tick, l.interval, l.jitter
	if tick <= 0 {
		tick = lifecycleTick
	}
	if interval <= 0 {
		interval = lifecycleInterval
	}
	if jitter <= 0 {
		jitter = lifecycleJitter
	}
	return tick, interval, jitter
}

// Run checks on a timer until ctx ends. A check also runs after a wake from
// sleep, detected as a tick that arrives much later than scheduled.
func (l *identityLifecycle) Run(ctx context.Context) {
	tick, interval, jitter := l.durations()
	next := l.clock()
	last := l.clock()
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		woke := l.clock().Sub(last) > 3*tick
		if !l.clock().Before(next) || woke {
			wait := interval + randomJitter(jitter)
			if !l.checkOnce(ctx) {
				wait = l.backoff()
			}
			next = l.clock().Add(wait)
		}
		last = l.clock()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (l *identityLifecycle) backoff() time.Duration {
	d := lifecycleBackoffBase
	for i := 1; i < l.failures && d < lifecycleBackoffCap; i++ {
		d *= 2
	}
	if d > lifecycleBackoffCap {
		d = lifecycleBackoffCap
	}
	return d
}

// checkOnce renews if the newest valid client certificate is inside the renewal
// window (or none is valid). It returns false when an attempt failed.
func (l *identityLifecycle) checkOnce(ctx context.Context) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.reconnectPending {
		return l.reconnect(ctx)
	}
	certMgr := l.tc.CertManager()
	if certMgr == nil {
		return l.fail("renewal unavailable: no certificate manager", errors.New("no certificate manager"))
	}
	due, err := l.renewalDue(certMgr)
	if err != nil {
		return l.fail("certificate expiry could not be determined", err)
	}
	if !due {
		return true
	}
	return l.renew(ctx, certMgr)
}

// renewalDue reports whether the newest valid client certificate has less than
// the renewal window left, or no valid client certificate remains.
func (l *identityLifecycle) renewalDue(certMgr *cert.Manager) (bool, error) {
	certs, err := certMgr.ListCertificates()
	if err != nil {
		return false, fmt.Errorf("list certificates: %w", err)
	}
	now := l.clock()
	var best *cert.CertificateInfo
	for _, c := range certs {
		if c.Type != cert.CertificateTypeClient || !c.ExpiresAt.After(now) {
			continue
		}
		if best == nil || c.ExpiresAt.After(best.ExpiresAt) {
			best = c
		}
	}
	if best == nil {
		return true, nil // expired or absent: the proof flow does not need the old certificate
	}
	window := defaultRenewWindow
	if l.renewWindow != nil {
		window = l.renewWindow
	}
	return best.ExpiresAt.Sub(now) < window(best.ExpiresAt.Sub(best.CreatedAt)), nil
}

func (l *identityLifecycle) renew(ctx context.Context, certMgr *cert.Manager) bool {
	id, err := loadIdentity(l.certStoreDir)
	if err != nil || id == nil {
		if err == nil {
			err = errors.New("no stored identity")
		}
		return l.fail("stored identity unavailable", err)
	}
	if l.ks == nil || l.ks.DeviceID() == "" {
		return l.keyUnusable(errors.New("device identity key store unavailable"))
	}

	attemptCtx, cancel := context.WithTimeout(ctx, renewAttemptTimeout)
	defer cancel()
	serial, err := renewIntoCertStore(attemptCtx, id, l.ks, certMgr, l.certStoreDir, l.controllerURL, l.trustSrc, l.installCAPEM, l.logger)
	switch {
	case err == nil:
	case errors.Is(err, errDeviceKeyUnusable), errors.Is(err, registration.ErrRefreshUnknownDevice):
		return l.keyUnusable(err)
	default:
		return l.fail("client certificate renewal failed", err)
	}
	l.logger.Info("Client certificate renewed", "serial", logging.SanitizeLogValue(serial))
	l.reconnectPending = true
	return l.reconnect(ctx)
}

// reconnect re-dials on the same client so the renewed certificate is presented.
func (l *identityLifecycle) reconnect(ctx context.Context) bool {
	if err := l.tc.ReconnectWithNewCredentials(ctx); err != nil {
		return l.fail("renewed certificate stored but reconnect failed", err)
	}
	l.reconnectPending = false
	l.failures = 0
	l.keyUnusableNotified = false
	l.tc.ClearHealthReason(clientCertReasonComponent)
	return true
}

func (l *identityLifecycle) fail(msg string, err error) bool {
	l.failures++
	l.logger.Warn("Client certificate renewal failed; will retry",
		"operation", "client_cert_renewal",
		"detail", msg,
		"error", logging.SanitizeLogValue(err.Error()),
		"failures", l.failures)
	l.tc.SetHealthReason(clientCertReasonComponent, clientCertReasonRenewalFailed, "client certificate renewal failed: "+msg)
	return false
}

// keyUnusable reports the device key as unusable and tells the hook once. No
// renewal is attempted with any other credential.
func (l *identityLifecycle) keyUnusable(err error) bool {
	l.failures++
	l.logger.Error("Device identity key unusable; client certificate cannot be renewed",
		"operation", "client_cert_renewal",
		"error", logging.SanitizeLogValue(err.Error()))
	l.tc.SetHealthReason(clientCertReasonComponent, clientCertReasonDeviceKeyUnusable, "device identity key is unusable; client certificate cannot be renewed")
	if !l.keyUnusableNotified {
		l.keyUnusableNotified = true
		if l.onDeviceKeyUnusable != nil {
			l.onDeviceKeyUnusable()
		}
	}
	return false
}
