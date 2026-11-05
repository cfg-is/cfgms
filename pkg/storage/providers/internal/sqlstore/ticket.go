// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package sqlstore holds the dialect-independent code shared by the SQL-backed storage
// providers (database and sqlite). Each provider keeps its own SQL text, placeholders and
// error prefixes; only row decoding, mapping and marshalling live here.
package sqlstore

import (
	"encoding/json"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// ticketFieldJSON is the stored JSON form of a business.TicketField.
type ticketFieldJSON struct {
	Value  string `json:"value"`
	Source string `json:"source"`
	Filled bool   `json:"filled"`
}

// ticketJSON is the stored JSON form of a business.Ticket.
type ticketJSON struct {
	Title    ticketFieldJSON `json:"title"`
	Client   ticketFieldJSON `json:"client"`
	Contact  ticketFieldJSON `json:"contact"`
	Priority ticketFieldJSON `json:"priority"`
	Category ticketFieldJSON `json:"category"`
}

func fieldToJSON(f business.TicketField) ticketFieldJSON {
	return ticketFieldJSON{Value: f.Value, Source: string(f.Source), Filled: f.Filled}
}

func fieldFromJSON(f ticketFieldJSON) business.TicketField {
	return business.TicketField{Value: f.Value, Source: business.TicketFieldSource(f.Source), Filled: f.Filled}
}

// MarshalTicket encodes a ticket for a text/JSON column.
func MarshalTicket(t business.Ticket) (string, error) {
	b, err := json.Marshal(ticketJSON{
		Title:    fieldToJSON(t.Title),
		Client:   fieldToJSON(t.Client),
		Contact:  fieldToJSON(t.Contact),
		Priority: fieldToJSON(t.Priority),
		Category: fieldToJSON(t.Category),
	})
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// UnmarshalTicket is the inverse of MarshalTicket; an empty string or "{}" is the zero ticket.
func UnmarshalTicket(s string) (business.Ticket, error) {
	if s == "" || s == "{}" {
		return business.Ticket{}, nil
	}
	var tj ticketJSON
	if err := json.Unmarshal([]byte(s), &tj); err != nil {
		return business.Ticket{}, err
	}
	return business.Ticket{
		Title:    fieldFromJSON(tj.Title),
		Client:   fieldFromJSON(tj.Client),
		Contact:  fieldFromJSON(tj.Contact),
		Priority: fieldFromJSON(tj.Priority),
		Category: fieldFromJSON(tj.Category),
	}, nil
}
