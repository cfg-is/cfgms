// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package interfaces_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cfgis/cfgms/pkg/notification/interfaces"
	"github.com/cfgis/cfgms/pkg/notification/interfaces/contracttest"
)

// strictRecorder is a reference Notifier that satisfies the contract: it
// validates before "sending" and reports per-recipient outcomes. It proves the
// shared contract is satisfiable by a conforming implementation; the SMTP
// provider runs the same contract against a real SMTP server.
type strictRecorder struct {
	reject string
	sent   int
}

func (s *strictRecorder) Name() string { return "strict-recorder" }
func (s *strictRecorder) Send(_ context.Context, m interfaces.Message) (*interfaces.DeliveryResult, error) {
	if len(m.To) == 0 {
		return nil, errors.New("no recipients")
	}
	if strings.ContainsAny(m.Subject, "\r\n") {
		return nil, errors.New("bad subject")
	}
	for _, to := range m.To {
		if strings.ContainsAny(to, "\r\n ") || !strings.Contains(to, "@") {
			return nil, errors.New("bad address")
		}
	}
	s.sent++
	res := &interfaces.DeliveryResult{}
	for _, to := range m.To {
		rr := interfaces.RecipientResult{Address: to, Accepted: to != s.reject}
		if !rr.Accepted {
			rr.Reason = "rejected"
		}
		res.Recipients = append(res.Recipients, rr)
	}
	return res, nil
}

func TestReferenceNotifierPassesContract(t *testing.T) {
	n := &strictRecorder{reject: "rejected@example.com"}
	contracttest.Run(t, contracttest.Harness{
		Notifier:        n,
		GoodAddress:     "good@example.com",
		RejectedAddress: "rejected@example.com",
		Sent:            func() int { return n.sent },
	})
}
