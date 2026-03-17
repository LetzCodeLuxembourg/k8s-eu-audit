package cli

import "github.com/spf13/cobra"

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "k8s-eu-audit",
		Short: "Kubernetes compliance scanner for EU regulations (NIS2, DORA)",
		Long: `k8s-eu-audit scans Kubernetes clusters and maps findings to EU regulatory
frameworks (NIS2 Article 21, DORA ICT Risk). Reports are designed for
auditors, not DevOps engineers.`,
	}

	root.AddCommand(
		newScanCmd(),
		newListCmd(),
		newVersionCmd(),
	)

	return root
}
