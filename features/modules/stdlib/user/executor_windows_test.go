// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package user

import (
	"reflect"
	"testing"
)

// TestParseWindowsGroups verifies extraction of "*"-prefixed group names from
// the "Local Group Memberships" field of "net user" output.
func TestParseWindowsGroups(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "empty input",
			in:   "",
			want: nil,
		},
		{
			name: "no groups (asterisks absent)",
			in:   "   None",
			want: nil,
		},
		{
			name: "single group",
			in:   "*Administrators",
			want: []string{"Administrators"},
		},
		{
			name: "multiple groups space separated",
			in:   "*Administrators       *Users",
			want: []string{"Administrators", "Users"},
		},
		{
			name: "group name with embedded space is split on whitespace",
			in:   "*Remote Desktop Users",
			want: []string{"Remote"},
		},
		{
			name: "bare asterisk yields no group",
			in:   "*   *Users",
			want: []string{"Users"},
		},
		{
			name: "non-asterisk tokens ignored",
			in:   "Local Group Memberships *Administrators",
			want: []string{"Administrators"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseWindowsGroups(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseWindowsGroups(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}

// TestParseNetUserOutput verifies that a full "net user <username>" fixture is
// parsed into the expected userState, including full name, active/locked state,
// password-required flag, and sorted group memberships.
func TestParseNetUserOutput(t *testing.T) {
	const fixture = `User name                    alice
Full Name                    Alice Smith
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/1/2026 10:00:00 AM
Password expires             Never
Password changeable          1/1/2026 10:00:00 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Users                *Administrators
Global Group memberships     *None
The command completed successfully.
`

	got := parseNetUserOutput(fixture)

	if !got.Exists {
		t.Error("parseNetUserOutput: Exists should be true")
	}
	if got.FullName != "Alice Smith" {
		t.Errorf("FullName = %q, want %q", got.FullName, "Alice Smith")
	}
	if got.Locked {
		t.Error("Locked should be false for an active account")
	}
	if !got.PasswordSet {
		t.Error("PasswordSet should be true when 'Password required' is Yes")
	}
	want := []string{"Administrators", "Users"} // sorted
	if !reflect.DeepEqual(got.Groups, want) {
		t.Errorf("Groups = %#v, want %#v (sorted)", got.Groups, want)
	}
}

// TestParseNetUserOutput_DisabledAndNoPassword verifies the locked/no-password
// branches of the parser.
func TestParseNetUserOutput_DisabledAndNoPassword(t *testing.T) {
	const fixture = `User name                    svc
Full Name                    Service Account
Account active               No
Password required            No
Local Group Memberships      *Users
`

	got := parseNetUserOutput(fixture)

	if !got.Locked {
		t.Error("Locked should be true when 'Account active' is No")
	}
	if got.PasswordSet {
		t.Error("PasswordSet should be false when 'Password required' is No")
	}
	if got.FullName != "Service Account" {
		t.Errorf("FullName = %q, want %q", got.FullName, "Service Account")
	}
	want := []string{"Users"}
	if !reflect.DeepEqual(got.Groups, want) {
		t.Errorf("Groups = %#v, want %#v", got.Groups, want)
	}
}
