// Package cmd implements the CLI commands for cfgctl
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	// Global flags
	verbose bool
	output  string
	config  string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cfgctl",
	Short: "CFGMS Configuration Management CLI",
	Long: `cfgctl is the command-line interface for CFGMS (Config Management System).
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
	rootCmd.PersistentFlags().StringVarP(&config, "config", "c", "", "config file path")

	// Add subcommands
	rootCmd.AddCommand(diffCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(regcodeCmd)
}

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("cfgctl version 0.3.0-alpha")
		fmt.Println("CFGMS Configuration Management System")
	},
}