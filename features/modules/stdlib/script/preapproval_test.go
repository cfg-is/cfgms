// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePreapprovalRequest(t *testing.T) {
	tests := []struct {
		name    string
		shell   ShellType
		content string
		want    bool
		wantErr bool
	}{
		{"bash declared", ShellBash, "#!/bin/bash\n# cfgms-preapproved: automation\necho hi\n", true, false},
		{"sh declared no space", ShellSh, "#!/bin/sh\n#cfgms-preapproved:automation\necho hi\n", true, false},
		{"zsh declared", ShellZsh, "# cfgms-preapproved: automation\n", true, false},
		{"powershell line comment", ShellPowerShell, "# cfgms-preapproved: automation\nWrite-Host hi\n", true, false},
		{"pwsh block comment", ShellPwsh, "<#\n.SYNOPSIS\n  thing\ncfgms-preapproved: automation\n#>\nWrite-Host hi\n", true, false},
		{"powershell single-line block", ShellPowerShell, "<# cfgms-preapproved: automation #>\nWrite-Host hi\n", true, false},
		{"cmd REM", ShellCmd, "REM cfgms-preapproved: automation\r\necho hi\r\n", true, false},
		{"cmd rem lowercase", ShellCmd, "rem cfgms-preapproved: automation\necho hi\n", true, false},
		{"cmd double colon", ShellCmd, ":: cfgms-preapproved: automation\necho hi\n", true, false},
		{"no declaration", ShellBash, "#!/bin/bash\n# just a comment\necho hi\n", false, false},
		{"empty content", ShellBash, "", false, false},
		{"CRLF bash", ShellBash, "#!/bin/bash\r\n# cfgms-preapproved: automation\r\necho hi\r\n", true, false},
		{"BOM powershell", ShellPowerShell, "\ufeff# cfgms-preapproved: automation\r\nWrite-Host hi\r\n", true, false},
		{"BOM and shebang", ShellBash, "\ufeff#!/bin/bash\n# cfgms-preapproved: automation\n", true, false},
		{"blank line inside header", ShellBash, "#!/bin/bash\n\n# cfgms-preapproved: automation\necho hi\n", true, false},
		{"after code ignored", ShellBash, "#!/bin/bash\necho hi\n# cfgms-preapproved: automation\n", false, false},
		{"after code typo ignored", ShellBash, "echo hi\n# cfgms-preaproved: automation\n", false, false},
		{"inside heredoc ignored", ShellBash, "cat <<EOF\n# cfgms-preapproved: automation\nEOF\n", false, false},
		{"inside string ignored", ShellBash, "echo \"\n# cfgms-preapproved: automation\n\"\n", false, false},
		{"powershell here-string ignored", ShellPowerShell, "$x = @'\n# cfgms-preapproved: automation\n'@\n", false, false},
		{"powershell block after code ignored", ShellPowerShell, "Write-Host hi\n<#\ncfgms-preapproved: automation\n#>\n", false, false},
		{"powershell text after block close ignored", ShellPowerShell, "<# x #>\nWrite-Host hi\n# cfgms-preapproved: automation\n", false, false},
		{"cmd after code ignored", ShellCmd, "@echo off\nREM cfgms-preapproved: automation\n", false, false},
		{"prose mention ignored", ShellBash, "# see cfgms-preapproved: automation docs\necho hi\n", false, false},
		{"typo key errors", ShellBash, "# cfgms-preaproved: automation\necho hi\n", false, true},
		{"typo key errors powershell block", ShellPowerShell, "<#\ncfgms-preaproved: automation\n#>\n", false, true},
		{"typo key errors cmd", ShellCmd, "REM cfgms-preaproved: automation\n", false, true},
		{"uppercase key errors", ShellBash, "# CFGMS-Preapproved: automation\n", false, true},
		{"unknown value errors", ShellBash, "# cfgms-preapproved: yes\n", false, true},
		{"empty value errors", ShellBash, "# cfgms-preapproved:\n", false, true},
		{"bare cfgms key errors", ShellBash, "# cfgms-foo\n", false, true},
		{"unsupported shell errors", ShellType("fish"), "# cfgms-preapproved: automation\n", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePreapprovalRequest(tt.content, tt.shell)
			if tt.wantErr {
				require.Error(t, err)
				assert.False(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
