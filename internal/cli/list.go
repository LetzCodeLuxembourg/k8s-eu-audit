package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/letzcode/k8s-eu-audit/internal/mapping"
	"github.com/letzcode/k8s-eu-audit/internal/scanner"
)

func newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available frameworks, controls, or scanners",
	}
	cmd.AddCommand(
		newListFrameworksCmd(),
		newListControlsCmd(),
		newListScannersCmd(),
	)
	return cmd
}

func newListFrameworksCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "frameworks",
		Short: "List available compliance frameworks",
		RunE: func(cmd *cobra.Command, args []string) error {
			ids, err := mapping.AvailableIDs()
			if err != nil {
				return err
			}
			fmt.Println("Available frameworks:")
			for _, id := range ids {
				fw, err := mapping.Load(id)
				if err != nil {
					continue
				}
				fmt.Printf("  %-10s  %s (%s)\n", id, fw.Name, fw.Version)
			}
			return nil
		},
	}
}

func newListControlsCmd() *cobra.Command {
	var fwID string
	cmd := &cobra.Command{
		Use:   "controls",
		Short: "List all controls for a framework",
		RunE: func(cmd *cobra.Command, args []string) error {
			fw, err := mapping.Load(fwID)
			if err != nil {
				return err
			}
			fmt.Printf("Controls for %s:\n\n", fw.Name)
			fmt.Printf("  %-12s  %-12s  %-10s  %s\n", "ID", "Article", "Severity", "Name")
			fmt.Printf("  %s\n", "────────────────────────────────────────────────────────────────")
			for _, c := range fw.Controls {
				fmt.Printf("  %-12s  %-12s  %-10s  %s\n", c.ID, c.Article, c.Severity, c.Name)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&fwID, "framework", "nis2", "Framework to list controls for")
	return cmd
}

func newListScannersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scanners",
		Short: "Show which external scanners are installed",
		RunE: func(cmd *cobra.Command, args []string) error {
			scanners := []struct {
				name    string
				scanner interface{ Available() bool }
			}{
				{"kubescape", scanner.NewKubescapeScanner()},
				{"trivy", scanner.NewTrivyScanner()},
				{"kube-bench", scanner.NewKubeBenchScanner()},
			}
			fmt.Println("External scanners:")
			for _, s := range scanners {
				status := "✗ not found"
				if s.scanner.Available() {
					status = "✓ available"
				}
				fmt.Printf("  %-15s  %s\n", s.name, status)
			}
			return nil
		},
	}
}
