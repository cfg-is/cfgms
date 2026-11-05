// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlstore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func TestTicket_RoundTrip(t *testing.T) {
	in := business.Ticket{
		Title:    business.TicketField{Value: "Outage", Source: business.TicketFieldSourceEmail, Filled: true},
		Client:   business.TicketField{Value: "acme-corp", Source: business.TicketFieldSourceCallerID, Filled: true},
		Contact:  business.TicketField{Value: "bob@acme-corp.example", Source: business.TicketFieldSourcePSA},
		Priority: business.TicketField{Value: "high", Source: business.TicketFieldSourceOperator, Filled: true},
		Category: business.TicketField{Value: "patch", Source: business.TicketFieldSourceInferred},
	}
	s, err := MarshalTicket(in)
	require.NoError(t, err)
	assert.Contains(t, s, `"title":{"value":"Outage","source":"email","filled":true}`)
	out, err := UnmarshalTicket(s)
	require.NoError(t, err)
	assert.Equal(t, in, out)
}

func TestTicket_UnmarshalEmptyAndInvalid(t *testing.T) {
	for _, s := range []string{"", "{}"} {
		out, err := UnmarshalTicket(s)
		require.NoError(t, err)
		assert.Equal(t, business.Ticket{}, out)
	}
	_, err := UnmarshalTicket("{bad")
	assert.Error(t, err)
}
