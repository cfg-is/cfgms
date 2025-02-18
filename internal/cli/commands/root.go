package commands

import (
	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cfgctl",
		Short: "Command line interface for CFGMS",
		Long:  `A complete command line interface for managing the Configuration Management System.`,
	}

	// Add subcommands
	cmd.AddCommand(
		newConfigCommand(),
		newAgentCommand(),
		newControllerCommand(),
	)

	return cmd
}
