// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"github.com/cfgis/cfgms/pkg/version"
	"github.com/spf13/cobra"
)

var (
	// Global flags
	verbose bool
	output  string

	// Admin bundle flags (persistent — available to all subcommands)
	bundlePath string
	noBundle   bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cfg",
	Short: "CFGMS Configuration Management CLI",
	Long: `cfg is the command-line interface for CFGMS (Config Management System).
It provides tools for comparing, validating, and managing configuration files
across different environments and versions.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "text", "output format (text, json, html, unified, side-by-side, markdown)")

	// Admin bundle flags for mTLS authentication
	rootCmd.PersistentFlags().StringVar(&bundlePath, "bundle", "", "Path to admin bundle file for mTLS auth (env: CFGMS_ADMIN_BUNDLE)")
	rootCmd.PersistentFlags().BoolVar(&noBundle, "no-bundle", false, "Skip admin bundle auto-discovery and use API key auth")

	// Add subcommands
	rootCmd.AddCommand(diffCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(regcodeCmd)
	rootCmd.AddCommand(tokenCmd)
	rootCmd.AddCommand(controllerCmd)
	rootCmd.AddCommand(traceCmd)
	rootCmd.AddCommand(storageCmd)
	rootCmd.AddCommand(stewardCmd)
	rootCmd.AddCommand(workflowCmd)
	rootCmd.AddCommand(configCmd)
}

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Printf("cfg %s\n", version.Info())
		cmd.Println("CFGMS Configuration Management System")
	},
}
