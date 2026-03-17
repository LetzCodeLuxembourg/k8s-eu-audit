package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	mode       string // kubernetes | host | hybrid
	sshHost    string // user@host for remote host scan
	sshKey     string // path to SSH private key
}

func newScanCmd() *cobra.Command {
	opts := &scanOptions{}

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan for EU regulatory compliance",
		Long: `Scan Kubernetes clusters and/or host operating systems for NIS2/DORA compliance.

Scan modes:
  kubernetes  Scan Kubernetes cluster only (default)
  host        Scan local host OS only (Linux/macOS/Windows)
  hybrid      Scan both Kubernetes cluster and local host OS`,
		Example: `  # Kubernetes only (default)
  k8s-eu-audit scan --framework nis2

  # Host OS only (Linux requires sudo for Lynis)
  k8s-eu-audit scan --framework nis2 --mode host
  sudo k8s-eu-audit scan --framework nis2 --mode host

  # Kubernetes + host together
  sudo k8s-eu-audit scan --framework nis2 --mode hybrid

  # Both frameworks, HTML report
  sudo k8s-eu-audit scan --framework nis2,dora --mode hybrid -o report.html

  # CI/CD: fail if score below 70%
  k8s-eu-audit scan --framework nis2 --fail-on 70`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(opts)
		},
	}

	cmd.Flags().StringSliceVar(&opts.frameworks, "framework", []string{"nis2"},
		"Frameworks to scan against: nis2, dora (comma-separated)")
	cmd.Flags().StringVar(&opts.mode, "mode", "kubernetes",
		"Scan mode: kubernetes, host, hybrid")
	cmd.Flags().StringVar(&opts.namespace, "namespace", "",
		"Limit Kubernetes scan to a specific namespace")
	cmd.Flags().StringVar(&opts.kubeconfig, "kubeconfig", "",
		"Path to kubeconfig (default: KUBECONFIG env or ~/.kube/config)")
	cmd.Flags().StringVarP(&opts.output, "output", "o", "",
		"Write report to file (e.g. report.html, report.md, report.json)")
	cmd.Flags().StringVar(&opts.format, "format", "terminal",
		"Output format when not writing to file: terminal, json")
	cmd.Flags().IntVar(&opts.failOn, "fail-on", 0,
		"Exit with code 1 if overall score is below this threshold (0 = disabled)")
	cmd.Flags().StringVar(&opts.licenseKey, "license-key", "",
		"Pro license key (or set K8S_EU_AUDIT_LICENSE env var)")
	cmd.Flags().StringVar(&opts.sshHost, "ssh-host", "",
		"Remote host for host scan via SSH (e.g. user@192.168.1.10)")
	cmd.Flags().StringVar(&opts.sshKey, "ssh-key", "",
		"Path to SSH private key for remote host scan")

	return cmd
}

func runScan(opts *scanOptions) error {
	// -------------------------------------------------------------------------
	// 1. Validate options
	// -------------------------------------------------------------------------
	mode := scanner.ScanMode(opts.mode)
	switch mode {
	case scanner.ModeKubernetes, scanner.ModeHost, scanner.ModeHybrid:
		// ok
	case "":
		mode = scanner.ModeKubernetes
	default:
		return fmt.Errorf("invalid --mode %q — must be: kubernetes, host, hybrid", opts.mode)
	}

	// License key from env fallback
	if opts.licenseKey == "" {
		opts.licenseKey = os.Getenv("K8S_EU_AUDIT_LICENSE")
	}

	// -------------------------------------------------------------------------
	// 2. Run scanners
	// -------------------------------------------------------------------------
	runOpts := scanner.RunOptions{
		Kubeconfig: opts.kubeconfig,
		Namespace:  opts.namespace,
		Mode:       mode,
		SSHHost:    opts.sshHost,
		SSHKey:     opts.sshKey,
	}

	orch := scanner.NewOrchestrator()

	fmt.Fprintf(os.Stderr, "🔍 Scanning [mode=%s] ...\n", mode)
	findings, usedScanners, warnings, err := orch.RunAll(runOpts)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Print warnings to stderr (missing scanners etc.)
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, w)
	}

	if len(usedScanners) == 0 {
		return fmt.Errorf(
			"no scanners available for mode %q — install at least one scanner:\n"+
				"  kubernetes: kubescape, trivy, kube-bench\n"+
				"  host (linux): lynis (sudo apt install lynis)\n"+
				"  host (macos): built-in — no install needed\n"+
				"  host (windows): built-in — no install needed",
			mode)
	}

	fmt.Fprintf(os.Stderr, "✓ Scanners used: %s — %d findings collected\n",
		strings.Join(usedScanners, ", "), len(findings))

	// -------------------------------------------------------------------------
	// 3. Map + score per framework
	// -------------------------------------------------------------------------
	// Detect cluster name from kubeconfig context
	clusterName := detectClusterName(opts.kubeconfig)

	// Collect lowest overall score across frameworks for --fail-on
	lowestScore := 100.0

	for _, fwID := range opts.frameworks {
		fw, loadErr := mapping.Load(fwID)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "⚠  framework %q not found — skipping (%v)\n", fwID, loadErr)
			continue
		}

		engine := mapping.NewEngine(fw)
		controlResults := engine.Map(findings)
		scored, summary := scoring.Calculate(controlResults)

		if summary.OverallScore < lowestScore {
			lowestScore = summary.OverallScore
		}

		rep := model.ComplianceReport{
			Metadata: model.ReportMetadata{
				GeneratedAt: time.Now(),
				ClusterName: clusterName,
				Framework:   strings.ToUpper(fwID),
				Scanners:    usedScanners,
			},
			Summary:  summary,
			Controls: scored,
		}

		// -------------------------------------------------------------------
		// 4. Output
		// -------------------------------------------------------------------
		if err := outputReport(rep, opts, fwID); err != nil {
			return err
		}
	}

	// -------------------------------------------------------------------------
	// 5. --fail-on exit code
	// -------------------------------------------------------------------------
	if opts.failOn > 0 && lowestScore < float64(opts.failOn) {
		fmt.Fprintf(os.Stderr,
			"\n❌ Score %.0f%% is below threshold %d%% — exiting with code 1\n",
			lowestScore, opts.failOn)
		os.Exit(1)
	}

	return nil
}

// outputReport writes the report to the correct destination in the correct format.
func outputReport(rep model.ComplianceReport, opts *scanOptions, fwID string) error {
	// Determine output file — if multiple frameworks, suffix the filename
	outputFile := opts.output
	if outputFile != "" && len(opts.frameworks) > 1 {
		ext := filepath.Ext(outputFile)
		base := strings.TrimSuffix(outputFile, ext)
		outputFile = fmt.Sprintf("%s-%s%s", base, strings.ToLower(fwID), ext)
	}

	// Determine format from file extension if --output given
	format := opts.format
	if outputFile != "" {
		switch strings.ToLower(filepath.Ext(outputFile)) {
		case ".html":
			format = "html"
		case ".md", ".markdown":
			format = "markdown"
		case ".json":
			format = "json"
		}
	}

	switch format {
	case "terminal", "":
		report.PrintTerminal(rep)

	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if outputFile != "" {
			f, err := os.Create(outputFile)
			if err != nil {
				return fmt.Errorf("create %s: %w", outputFile, err)
			}
			defer f.Close()
			enc = json.NewEncoder(f)
			enc.SetIndent("", "  ")
			if encErr := enc.Encode(rep); encErr != nil {
				return encErr
			}
			fmt.Fprintf(os.Stderr, "✓ Report written to %s\n", outputFile)
			return nil
		}
		return enc.Encode(rep)

	case "html":
		html := report.RenderHTML(rep)
		if outputFile == "" {
			outputFile = fmt.Sprintf("%s-report.html", strings.ToLower(fwID))
		}
		if err := os.WriteFile(outputFile, []byte(html), 0644); err != nil {
			return fmt.Errorf("write %s: %w", outputFile, err)
		}
		fmt.Fprintf(os.Stderr, "✓ HTML report written to %s\n", outputFile)

	case "markdown":
		md := report.RenderMarkdown(rep)
		if outputFile == "" {
			outputFile = fmt.Sprintf("%s-report.md", strings.ToLower(fwID))
		}
		if err := os.WriteFile(outputFile, []byte(md), 0644); err != nil {
			return fmt.Errorf("write %s: %w", outputFile, err)
		}
		fmt.Fprintf(os.Stderr, "✓ Markdown report written to %s\n", outputFile)

	default:
		return fmt.Errorf("unknown format %q — use: terminal, html, markdown, json", format)
	}

	return nil
}

// detectClusterName reads the current-context name from kubeconfig.
func detectClusterName(kubeconfig string) string {
	if kubeconfig == "" {
		kubeconfig = os.Getenv("KUBECONFIG")
	}
	if kubeconfig == "" {
		home, _ := os.UserHomeDir()
		kubeconfig = filepath.Join(home, ".kube", "config")
	}
	data, err := os.ReadFile(kubeconfig)
	if err != nil {
		return "unknown-cluster"
	}
	// Quick parse — find "current-context:" line
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "current-context:") {
			ctx := strings.TrimSpace(strings.TrimPrefix(line, "current-context:"))
			if ctx != "" && ctx != "null" {
				return ctx
			}
		}
	}
	return "unknown-cluster"
}
