// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package commands

import (
	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cfg",
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

func newConfigCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Manage CFGMS configuration",
		Long:  `Manage CFGMS configuration settings and files.`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cmd.Help(); err != nil {
				// Help failed, but we can't do much about it
				_ = err // Explicitly ignore help display errors
			}
		},
	}
}

func newAgentCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "agent",
		Short: "Manage CFGMS agents",
		Long:  `Manage CFGMS agent lifecycle and operations.`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cmd.Help(); err != nil {
				// Help failed, but we can't do much about it
				_ = err // Explicitly ignore help display errors
			}
		},
	}
}

func newControllerCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "controller",
		Short: "Manage CFGMS controller",
		Long:  `Manage CFGMS controller operations and status.`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cmd.Help(); err != nil {
				// Help failed, but we can't do much about it
				_ = err // Explicitly ignore help display errors
			}
		},
	}
}
