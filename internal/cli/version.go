package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Injected at build time via ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("k8s-eu-audit %s (commit: %s, built: %s)\n", version, commit, date)
		},
	}
}
