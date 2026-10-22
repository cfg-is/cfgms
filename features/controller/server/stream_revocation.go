// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/logging"
)

// defaultStreamRevocationRecheckInterval bounds how long an already-open
// steward stream survives the revocation of its client-certificate serial. It
// matches the ControlChannel re-check interval.
const defaultStreamRevocationRecheckInterval = 30 * time.Second

// streamRevocationChecker reports whether a client-certificate serial is
// revoked. *cert.Manager satisfies it. A non-nil error means the status cannot
// be determined and callers must fail closed.
type streamRevocationChecker interface {
	IsRevoked(serial string) (bool, error)
}

// streamPeerIdentity returns the decimal serial and common name of the
// verified client certificate carried in the stream context.
func streamPeerIdentity(ctx context.Context) (serial, commonName string, err error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", "", fmt.Errorf("no peer info in context")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return "", "", fmt.Errorf("no peer certificate")
	}
	leaf := tlsInfo.State.PeerCertificates[0]
	return leaf.SerialNumber.String(), leaf.Subject.CommonName, nil
}

// revocationStream overrides Context so handlers see the cancellable context.
type revocationStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *revocationStream) Context() context.Context { return s.ctx }

// newStreamRevocationInterceptor returns a stream interceptor that refuses a
// peer whose certificate serial is revoked (PermissionDenied), whose status
// cannot be determined (Unavailable, fail closed) or that presents no
// certificate (Unauthenticated), and re-checks the serial every interval while
// the stream is open, cancelling the stream context once it is revoked. A
// lookup error during a re-check keeps the stream open until the next tick.
// ControlChannel is skipped: the control-plane provider already checks it.
func newStreamRevocationInterceptor(checker streamRevocationChecker, logger logging.Logger, interval time.Duration) grpc.StreamServerInterceptor {
	if interval <= 0 {
		interval = defaultStreamRevocationRecheckInterval
	}
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if info.FullMethod == transportpb.StewardTransport_ControlChannel_FullMethodName {
			return handler(srv, ss)
		}

		serial, stewardID, err := streamPeerIdentity(ss.Context())
		if err != nil {
			return status.Error(codes.Unauthenticated, "failed to read peer certificate")
		}
		revoked, err := checker.IsRevoked(serial)
		if err != nil {
			logger.Error("certificate revocation check error, rejecting stream (fail-closed)",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"serial", logging.SanitizeLogValue(serial),
				"error", logging.SanitizeLogValue(err.Error()))
			return status.Error(codes.Unavailable, "certificate revocation service unavailable")
		}
		if revoked {
			logger.Warn("steward stream rejected: client certificate revoked",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"serial", logging.SanitizeLogValue(serial))
			return status.Error(codes.PermissionDenied, "client certificate revoked")
		}

		ctx, cancel := context.WithCancel(ss.Context())
		done := make(chan struct{})
		var revokedWhileOpen atomic.Bool
		go func() {
			defer close(done)
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
				isRevoked, rerr := checker.IsRevoked(serial)
				if rerr != nil {
					logger.Warn("certificate revocation re-check error, keeping stream open until next check",
						"steward_id", logging.SanitizeLogValue(stewardID),
						"serial", logging.SanitizeLogValue(serial),
						"error", logging.SanitizeLogValue(rerr.Error()))
					continue
				}
				if isRevoked {
					logger.Warn("steward stream closed: client certificate revoked",
						"steward_id", logging.SanitizeLogValue(stewardID),
						"serial", logging.SanitizeLogValue(serial))
					revokedWhileOpen.Store(true)
					cancel()
					return
				}
			}
		}()
		defer func() {
			cancel()
			<-done
		}()

		herr := handler(srv, &revocationStream{ServerStream: ss, ctx: ctx})
		if revokedWhileOpen.Load() {
			return status.Error(codes.PermissionDenied, "client certificate revoked")
		}
		return herr
	}
}
