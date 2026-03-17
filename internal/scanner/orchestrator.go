package scanner

import (
	"fmt"

	"github.com/letzcode/k8s-eu-audit/internal/model"
)

// Orchestrator runs all registered scanners and merges their findings.
type Orchestrator struct {
	scanners []Scanner
}

// NewOrchestrator returns an Orchestrator with all supported scanners registered.
func NewOrchestrator() *Orchestrator {
	return &Orchestrator{
		scanners: []Scanner{
			// Kubernetes layer
			NewKubescapeScanner(),
			NewTrivyScanner(),
			NewKubeBenchScanner(),
			// Host / VM layer
			NewLynisScanner(),   // Linux VMs (requires root)
			NewMacOSScanner(),   // macOS hosts
			NewWindowsScanner(), // Windows hosts
		},
	}
}

// RunAll executes every available scanner appropriate for the requested mode.
// Missing scanners emit a warning but never abort the run.
func (o *Orchestrator) RunAll(opts RunOptions) (findings []model.Finding, usedScanners []string, warnings []string, err error) {
	for _, s := range o.scanners {
		if !s.Available() {
			// Only warn about K8s scanners when doing a K8s scan
			// Host scanners silently skip when not on their platform
			if opts.IsK8sScan() {
				switch s.Name() {
				case "kubescape", "trivy", "kube-bench":
					warnings = append(warnings, fmt.Sprintf("⚠  %s not found in PATH — skipping", s.Name()))
				}
			}
			continue
		}

		result, runErr := s.Run(opts)
		if runErr != nil {
			warnings = append(warnings, fmt.Sprintf("⚠  %s error: %v", s.Name(), runErr))
			continue
		}
		if len(result) == 0 {
			continue // scanner returned nothing (e.g. host scanner skipped in k8s-only mode)
		}

		findings = append(findings, result...)
		usedScanners = append(usedScanners, s.Name())
	}

	return findings, usedScanners, warnings, nil
}
