package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/letzcode/k8s-eu-audit/internal/logger"
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
	mode       string
	sshHost    string
	sshKey     string
	quiet      bool
	noBanner   bool
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
		Example: `  k8s-eu-audit scan --framework nis2
  k8s-eu-audit scan --framework nis2 --mode host
  sudo k8s-eu-audit scan --framework nis2,dora --mode hybrid -o report.html
  k8s-eu-audit scan --framework nis2 --fail-on 70 --quiet`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(opts)
		},
	}

	cmd.Flags().StringSliceVar(&opts.frameworks, "framework", []string{"nis2"},
		"Frameworks: nis2, dora (comma-separated)")
	cmd.Flags().StringVar(&opts.mode, "mode", "kubernetes",
		"Scan mode: kubernetes, host, hybrid")
	cmd.Flags().StringVar(&opts.namespace, "namespace", "",
		"Limit Kubernetes scan to a specific namespace")
	cmd.Flags().StringVar(&opts.kubeconfig, "kubeconfig", "",
		"Path to kubeconfig (default: ~/.kube/config)")
	cmd.Flags().StringVarP(&opts.output, "output", "o", "",
		"Write report to file (e.g. report.html, report.md, report.json)")
	cmd.Flags().StringVar(&opts.format, "format", "terminal",
		"Output format: terminal, html, markdown, json")
	cmd.Flags().IntVar(&opts.failOn, "fail-on", 0,
		"Exit 1 if overall score is below this threshold")
	cmd.Flags().StringVar(&opts.licenseKey, "license-key", "",
		"Pro license key (or K8S_EU_AUDIT_LICENSE env)")
	cmd.Flags().StringVar(&opts.sshHost, "ssh-host", "",
		"Remote host for SSH scan (e.g. user@192.168.1.10)")
	cmd.Flags().StringVar(&opts.sshKey, "ssh-key", "",
		"Path to SSH private key")
	cmd.Flags().BoolVarP(&opts.quiet, "quiet", "q", false,
		"Suppress all progress output (errors only, good for CI)")
	cmd.Flags().BoolVar(&opts.noBanner, "no-banner", false,
		"Skip the startup banner")

	return cmd
}

func runScan(opts *scanOptions) error {
	start := time.Now()

	// ── 0. Banner ─────────────────────────────────────────────────────────────
	if !opts.quiet && !opts.noBanner {
		logger.PrintBanner(version, opts.mode, opts.frameworks)
	}

	// ── 1. Validate mode ──────────────────────────────────────────────────────
	mode := scanner.ScanMode(opts.mode)
	switch mode {
	case scanner.ModeKubernetes, scanner.ModeHost, scanner.ModeHybrid, "":
	default:
		return fmt.Errorf("invalid --mode %q — must be: kubernetes, host, hybrid", opts.mode)
	}
	if mode == "" {
		mode = scanner.ModeKubernetes
	}

	if opts.licenseKey == "" {
		opts.licenseKey = os.Getenv("K8S_EU_AUDIT_LICENSE")
	}

	clusterName := detectClusterName(opts.kubeconfig)

	// ── 2. Scanners ───────────────────────────────────────────────────────────
	if !opts.quiet {
		logger.Step(1, 3, "Running scanners")
		logger.Info(fmt.Sprintf("Cluster: %s   Mode: %s", clusterName, string(mode)))
		if opts.namespace != "" {
			logger.Detail("Namespace filter: " + opts.namespace)
		}
	}

	runOpts := scanner.RunOptions{
		Kubeconfig: opts.kubeconfig,
		Namespace:  opts.namespace,
		Mode:       mode,
		SSHHost:    opts.sshHost,
		SSHKey:     opts.sshKey,
	}

	orch := scanner.NewOrchestrator()

	progressHandler := func(e scanner.ScannerEvent) {
		if opts.quiet {
			return
		}
		switch e.State {
		case "start":
			logger.ScannerStart(e.Scanner)
		case "done":
			logger.ScannerDone(e.Scanner, e.Count, e.Elapsed)
		case "skip":
			logger.ScannerSkip(e.Scanner, e.Reason)
		case "error":
			logger.ScannerError(e.Scanner, e.Err)
		}
	}

	findings, usedScanners, warnings, err := orch.RunAll(runOpts, progressHandler)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	for _, w := range warnings {
		if !opts.quiet {
			logger.Warn(w)
		}
	}

	if len(usedScanners) == 0 {
		return fmt.Errorf(
			"no scanners available for mode=%q\n"+
				"  kubernetes: install kubescape, trivy, or kube-bench\n"+
				"  host (linux): sudo apt install lynis\n"+
				"  host (macos/windows): built-in, no install needed",
			mode)
	}

	if !opts.quiet {
		logger.Success(fmt.Sprintf(
			"Scan complete — %d findings from %d scanner(s)",
			len(findings), len(usedScanners),
		))
	}

	// ── 3. Map + score per framework ──────────────────────────────────────────
	if !opts.quiet {
		logger.Step(2, 3, "Mapping to regulatory controls")
	}

	lowestScore := 100.0
	var reports []model.ComplianceReport

	for _, fwID := range opts.frameworks {
		fw, loadErr := mapping.Load(fwID)
		if loadErr != nil {
			logger.Warn(fmt.Sprintf("framework %q not found — skipping", fwID))
			continue
		}

		if !opts.quiet {
			logger.MappingStart(fwID, len(findings))
		}

		engine := mapping.NewEngine(fw)
		controlResults := engine.Map(findings)
		scored, summary := scoring.Calculate(controlResults)

		if !opts.quiet {
			logger.MappingDone(fwID, len(scored),
				summary.TotalPass, summary.TotalWarn,
				summary.TotalFail, summary.TotalSkip)
		}

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
		reports = append(reports, rep)
	}

	// ── 4. Output ─────────────────────────────────────────────────────────────
	if !opts.quiet {
		logger.Step(3, 3, "Generating reports")
	}

	isTerminal := opts.format == "terminal" || opts.format == ""

	for i, rep := range reports {
		fwID := strings.ToLower(opts.frameworks[i])

		// Score reveal + progress bar before the table
		if !opts.quiet && isTerminal && opts.output == "" {
			logger.PrintScoreLine(rep.Metadata.Framework, rep.Summary.OverallScore, rep.Summary.Status)
			logger.PrintProgressBar(rep.Summary.OverallScore, rep.Summary.Status)
			logger.PrintReportSection(rep.Metadata.Framework)
		}

		if err := outputReport(rep, opts, fwID); err != nil {
			return err
		}

		// Priority findings after the table
		if !opts.quiet && isTerminal && opts.output == "" {
			pf := buildPriorityFindings(rep)
			logger.PrintPriorityFindings(pf)
		}
	}

	// ── 5. Final summary ──────────────────────────────────────────────────────
	if !opts.quiet {
		logger.PrintScanSummary(clusterName, usedScanners, time.Since(start))
	}

	// ── 6. --fail-on ──────────────────────────────────────────────────────────
	if opts.failOn > 0 {
		passed := lowestScore >= float64(opts.failOn)
		if !opts.quiet {
			logger.PrintFailOnResult(lowestScore, opts.failOn, passed)
		}
		if !passed {
			os.Exit(1)
		}
	}

	return nil
}

// buildPriorityFindings extracts CRITICAL/HIGH failures for the priority display.
func buildPriorityFindings(rep model.ComplianceReport) []logger.PriorityFinding {
	var out []logger.PriorityFinding
	for _, cr := range rep.Controls {
		if cr.Status != "FAIL" && cr.Status != "WARN" {
			continue
		}
		if cr.Control.Severity != "CRITICAL" && cr.Control.Severity != "HIGH" {
			continue
		}
		out = append(out, logger.PriorityFinding{
			Article:     cr.Control.Article,
			Name:        cr.Control.Name,
			Severity:    cr.Control.Severity,
			Status:      cr.Status,
			Score:       cr.Score,
			Remediation: cr.Control.Remediation,
		})
	}
	return out
}

// outputReport writes the report to the correct destination in the correct format.
func outputReport(rep model.ComplianceReport, opts *scanOptions, fwID string) error {
	outputFile := opts.output
	if outputFile != "" && len(opts.frameworks) > 1 {
		ext := filepath.Ext(outputFile)
		base := strings.TrimSuffix(outputFile, ext)
		outputFile = fmt.Sprintf("%s-%s%s", base, strings.ToLower(fwID), ext)
	}

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
		if outputFile != "" {
			f, err := os.Create(outputFile)
			if err != nil {
				return fmt.Errorf("create %s: %w", outputFile, err)
			}
			defer f.Close()
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			if err := enc.Encode(rep); err != nil {
				return err
			}
			logger.PrintReportWritten(outputFile)
			return nil
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)

	case "html":
		html := report.RenderHTML(rep)
		if outputFile == "" {
			outputFile = fmt.Sprintf("%s-report.html", fwID)
		}
		if err := os.WriteFile(outputFile, []byte(html), 0644); err != nil {
			return fmt.Errorf("write %s: %w", outputFile, err)
		}
		logger.PrintReportWritten(outputFile)

	case "markdown":
		md := report.RenderMarkdown(rep)
		if outputFile == "" {
			outputFile = fmt.Sprintf("%s-report.md", fwID)
		}
		if err := os.WriteFile(outputFile, []byte(md), 0644); err != nil {
			return fmt.Errorf("write %s: %w", outputFile, err)
		}
		logger.PrintReportWritten(outputFile)

	default:
		return fmt.Errorf("unknown format %q — use: terminal, html, markdown, json", format)
	}

	return nil
}

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
