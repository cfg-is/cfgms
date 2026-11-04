// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"context"
	"errors"
	"math/rand"
	"time"

	"github.com/cfgis/cfgms/cmd/steward/service"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/logging/subscribers/systemlog"
)

// A steward with no usable identity and no registration token keeps running:
// it retries with capped backoff, writes the reason to the local system log and
// enrols by the normal path as soon as a registration token file appears. It
// never creates an identity itself; it only reads the token file and the cert
// store.

const (
	noIdentityInitialBackoff = 5 * time.Second
	noIdentityMaxBackoff     = 5 * time.Minute
	// noIdentityRepeatInterval is how long an unchanged reason stays quiet in the
	// system log before it is written again.
	noIdentityRepeatInterval = time.Hour

	reasonNoToken          = "no_registration_token"
	reasonIdentityUnusable = "identity_unreadable"
	reasonTokenFilePrefix  = "token_file."
)

// reasonMessages are fixed so a log entry never carries a path or token.
var reasonMessages = map[string]string{
	reasonNoToken:          "no stored identity and no registration token file configured; waiting for a registration token",
	reasonIdentityUnusable: "the certificate store cannot be read as an identity and no registration token is available; waiting for a registration token",
	reasonTokenFilePrefix + string(service.TokenFileMissing):     "no stored identity and the registration token file is missing; waiting for a registration token",
	reasonTokenFilePrefix + string(service.TokenFileEmpty):       "no stored identity and the registration token file is empty; waiting for a registration token",
	reasonTokenFilePrefix + string(service.TokenFilePermissions): "no stored identity and the registration token file is not safe to read; waiting for a registration token",
	reasonTokenFilePrefix + string(service.TokenFileInvalid):     "no stored identity and the registration token file is unusable; waiting for a registration token",
}

// systemLogWriter is the S18 local system log sink.
type systemLogWriter interface {
	WriteOnce(level systemlog.Level, key, message string) error
}

// enrollmentWaiter holds the injectable pieces of waitForEnrollment.
type enrollmentWaiter struct {
	// sleep waits d or returns ctx's error when it is cancelled first.
	sleep func(ctx context.Context, d time.Duration) error
	now   func() time.Time
	// jitter returns a value in [0, n).
	jitter func(n time.Duration) time.Duration
	sink   systemLogWriter
}

// newEnrollmentWaiter builds the waiter runStewardInternal uses; a variable so
// tests can inject a clock.
var newEnrollmentWaiter = defaultEnrollmentWaiter

func defaultEnrollmentWaiter(sink systemLogWriter) enrollmentWaiter {
	return enrollmentWaiter{
		sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		},
		now: time.Now,
		jitter: func(n time.Duration) time.Duration {
			if n <= 0 {
				return 0
			}
			return time.Duration(rand.Int63n(int64(n))) // #nosec G404 -- retry jitter, not security relevant
		},
		sink: sink,
	}
}

// newSystemLogSink opens the local system log; it is nil when the platform log
// is unavailable, in which case reasons go to the steward's own logger only.
// A variable so tests can observe the writes.
var newSystemLogSink = func() systemLogWriter {
	sub := systemlog.NewSubscriber()
	if err := sub.Initialize(nil); err != nil {
		return nil
	}
	return sub
}

// waitForEnrollment blocks until the steward can start: it returns the
// registration token once the token file at regTokenFile holds a valid one, or
// "" with a nil error once a stored identity exists. It returns ctx's error when
// ctx is cancelled. It never enrols and never writes to the cert store; the
// caller proceeds into its normal connect path with the result.
func waitForEnrollment(ctx context.Context, regTokenFile string, w enrollmentWaiter, logger logging.Logger) (string, error) {
	backoff := noIdentityInitialBackoff
	lastReason := ""
	var lastWritten time.Time
	for {
		token, reason := checkEnrollment(regTokenFile)
		if reason == "" {
			return token, nil
		}
		now := w.now()
		if reason != lastReason || now.Sub(lastWritten) >= noIdentityRepeatInterval {
			msg := reasonMessages[reason]
			logger.Warn(msg, "operation", "wait_for_enrollment", "reason", reason)
			if w.sink != nil {
				if err := w.sink.WriteOnce(systemlog.LevelWarning, reason, msg); err != nil {
					logger.Warn("system log write failed", "operation", "wait_for_enrollment",
						"error", logging.SanitizeLogValue(err.Error()))
				}
			}
			lastReason, lastWritten = reason, now
		}

		delay := backoff + w.jitter(backoff/10)
		if delay > noIdentityMaxBackoff {
			delay = noIdentityMaxBackoff
		}
		if err := w.sleep(ctx, delay); err != nil {
			return "", err
		}
		if backoff *= 2; backoff > noIdentityMaxBackoff {
			backoff = noIdentityMaxBackoff
		}
	}
}

// checkEnrollment returns ("", "") when a stored identity exists, (token, "")
// when a valid token is available, and otherwise the reason class. The token
// file permission check lives in service.ReadTokenFile; an unsafe file is never
// read for enrolment.
func checkEnrollment(regTokenFile string) (token, reason string) {
	id, idErr := loadIdentity(certStoreDirResolver())
	if idErr == nil && id != nil {
		return "", ""
	}
	if regTokenFile != "" {
		tok, err := service.ReadTokenFile(regTokenFile)
		if err == nil {
			return tok, ""
		}
		if tfe, ok := service.AsTokenFileError(err); ok {
			return "", reasonTokenFilePrefix + string(tfe.Kind)
		}
		return "", reasonTokenFilePrefix + string(service.TokenFileInvalid)
	}
	if idErr != nil {
		return "", reasonIdentityUnusable
	}
	return "", reasonNoToken
}

// resolveStartupIdentity loads the stored identity. When there is no token, no
// identity and no config it waits for enrollment (waitForEnrollment) and returns
// the token or the identity stored meanwhile. waitErr is non-nil only when ctx
// was cancelled during the wait; the token and identity are then empty.
func resolveStartupIdentity(ctx context.Context, regToken, configPath string, logger logging.Logger) (string, *StewardIdentity, error) {
	storedID, _ := loadIdentity(certStoreDirResolver())
	if regToken != "" || storedID != nil || configPath != "" {
		return regToken, storedID, nil
	}
	token, waitErr := waitForEnrollment(ctx, regTokenFileFrom(ctx),
		newEnrollmentWaiter(newSystemLogSink()), logger)
	if waitErr != nil {
		return "", nil, waitErr
	}
	storedID, _ = loadIdentity(certStoreDirResolver())
	return token, storedID, nil
}

// enrollmentWaitResult is runStewardInternal's result when it has no token,
// identity or config after resolveStartupIdentity. A cancelled wait is a clean
// shutdown; any other outcome is a startup invariant violation.
func enrollmentWaitResult(waitErr error, logger logging.Logger) error {
	if waitErr != nil {
		logger.Info("Steward stopped while waiting for enrollment", "operation", "steward_shutdown")
		return nil
	}
	return errors.New("steward has no token, identity or config after waiting for enrollment")
}

type regTokenFileKey struct{}

// withRegTokenFile carries the --regtoken-file path to runStewardInternal so
// the no-identity loop can re-read it.
func withRegTokenFile(ctx context.Context, path string) context.Context {
	return context.WithValue(ctx, regTokenFileKey{}, path)
}

func regTokenFileFrom(ctx context.Context) string {
	p, _ := ctx.Value(regTokenFileKey{}).(string)
	return p
}

// startupTokenFromFile reads the token file at startup. A refused file is not
// fatal: without a usable token the steward waits for one (waitForEnrollment).
func startupTokenFromFile(path string) string {
	if path == "" {
		return ""
	}
	token, err := tokenFromFile(path)
	if err != nil {
		return ""
	}
	return token
}
