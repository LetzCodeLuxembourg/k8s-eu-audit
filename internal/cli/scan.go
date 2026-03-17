package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/letzcode/k8s-eu-audit/internal/mapping"
	"github.com/letzcode/k8s-eu-audit/internal/model"
	"github.com/letzcode/k8s-eu-audit/internal/report"
	"github.com/letzcode/k8s-eu-audit/internal/scanner"
	"github.com/letzcode/k8s-eu-audit/internal/scoring"
)

type scanOptions struct {
	frameworks []string
	namespace  string
	kubeconfig string
	output     string
	format     string
	failOn     int
	licenseKey string
}

func newScanCmd() *cobra.Command {
	opts := &scanOptions{}

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a cluster for EU regulatory compliance",
		Example: `  k8s-eu-audit scan --framework nis2
  k8s-eu-audit scan --framework nis2,dora --output report.html
  k8s-eu-audit scan --framework nis2 --fail-on 70`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(opts)
		},
	}

	cmd.Flags().StringSliceVar(&opts.frameworks, "framework", []string{"nis2"}, "Frameworks to scan against (nis2, dora)")
	cmd.Flags().StringVar(&opts.namespace, "namespace", "", "Limit scan to a specific namespace")
	cmd.Flags().StringVar(&opts.kubeconfig, "kubeconfig", "", "Path to kubeconfig (defaults to KUBECONFIG or ~/.kube/config)")
	cmd.Flags().StringVarP(&opts.output, "output", "o", "", "Write report to file (e.g. report.html, report.md)")
	cmd.Flags().StringVar(&opts.format, "format", "terminal", "Output format: terminal, html, markdown, json")
	cmd.Flags().IntVar(&opts.failOn, "fail-on", 0, "Exit code 1 if overall score is below this threshold (0 = disabled)")
	cmd.Flags().StringVar(&opts.licenseKey, "license-key", "", "Pro license key (or set K8S_EU_AUDIT_LICENSE env var)")

	return cmd
}

func runScan(opts *scanOptions) error {
	// 1. Run scanners
	orch := scanner.NewOrchestrator()
	runOpts := scanner.RunOptions{
		Kubeconfig: opts.kubeconfig,
		Namespace:  opts.namespace,
	}

	findings, usedScanners, warnings, err := orch.RunAll(runOpts)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, w)
	}

	if len(usedScanners) == 0 {
		return fmt.Errorf("no scanners available — install kubescape, trivy, or kube-bench")
	}

	// 2. For each framework: map → score → report
	for _, fwID := range opts.frameworks {
		fw, err := mapping.Load(fwID)
		if err != nil {
			return err
		}

		engine := mapping.NewEngine(fw)
		controlResults := engine.Map(findings)
		scoredResults, summary := scoring.Calculate(controlResults)

		compReport := model.ComplianceReport{
			Metadata: model.ReportMetadata{
				Framework:   fw.Name,
				ClusterName: "current-context", // TODO: read from kubeconfig
				Scanners:    usedScanners,
			},
			Summary:  summary,
			Controls: scoredResults,
		}

		if err := writeReport(opts, compReport); err != nil {
			return err
		}

		if opts.failOn > 0 && int(summary.OverallScore) < opts.failOn {
			fmt.Fprintf(os.Stderr, "\n✗ Overall score %.0f%% is below threshold %d%% — failing\n",
				summary.OverallScore, opts.failOn)
			os.Exit(1)
		}
	}

	return nil
}

func writeReport(opts *scanOptions, r model.ComplianceReport) error {
	// Determine format from --format or infer from --output extension
	format := opts.format
	if opts.output != "" {
		switch {
		case len(opts.output) > 5 && opts.output[len(opts.output)-5:] == ".html":
			format = "html"
		case len(opts.output) > 3 && opts.output[len(opts.output)-3:] == ".md":
			format = "markdown"
		case len(opts.output) > 5 && opts.output[len(opts.output)-5:] == ".json":
			format = "json"
		}
	}

	// Determine writer
	var w *os.File
	if opts.output != "" {
		f, err := os.Create(opts.output)
		if err != nil {
			return fmt.Errorf("cannot create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	switch format {
	case "html":
		if w == nil {
			w = os.Stdout
		}
		return report.WriteHTML(w, r)
	case "markdown":
		if w == nil {
			w = os.Stdout
		}
		return report.WriteMarkdown(w, r)
	case "json":
		if w == nil {
			w = os.Stdout
		}
		return report.WriteJSON(w, r)
	default:
		report.PrintTerminal(r)
		if opts.output != "" && w != nil {
			return report.WriteHTML(w, r)
		}
	}

	return nil
}
