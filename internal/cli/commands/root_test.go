package commands

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRootCommand(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "no args shows help",
			args:     []string{},
			wantErr:  false,
			contains: "Command line interface for CFGMS",
		},
		{
			name:     "help flag shows help",
			args:     []string{"--help"},
			wantErr:  false,
			contains: "Command line interface for CFGMS",
		},
		{
			name:     "invalid command returns error",
			args:     []string{"invalid"},
			wantErr:  true,
			contains: "unknown command",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewRootCommand()
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			output := buf.String()
			assert.Contains(t, output, tt.contains)
		})
	}
}

func TestSubcommands(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		wantErr  bool
		contains string
	}{
		{
			name:     "config command exists",
			command:  "config",
			wantErr:  false,
			contains: "Manage CFGMS configuration",
		},
		{
			name:     "agent command exists",
			command:  "agent",
			wantErr:  false,
			contains: "Manage CFGMS agents",
		},
		{
			name:     "controller command exists",
			command:  "controller",
			wantErr:  false,
			contains: "Manage CFGMS controller",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewRootCommand()
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs([]string{tt.command, "--help"})

			err := cmd.Execute()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			output := buf.String()
			assert.Contains(t, output, tt.contains)
		})
	}
}
