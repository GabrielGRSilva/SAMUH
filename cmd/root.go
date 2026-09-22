package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	// Version is the application version, set by ldflags
	Version = "dev"
	// Commit is the git commit hash, set by ldflags
	Commit = "none"
	// Date is the build date, set by ldflags
	Date = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "samuh",
	Short: "SAMUH - Secure Application Makes U Happy",
	Long:  "SAMUH (Secure Application Makes U Happy) — Security vulnerability scanner for PHP, Node.js, and JS/TS projects",
}

var (
	verbose bool
	quiet   bool
)

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress all output except errors and final report")
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
