package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("SAMUH Version: %s\n", Version)
		fmt.Printf("Commit: %s\n", Commit)
		fmt.Printf("Build Date: %s\n", Date)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
