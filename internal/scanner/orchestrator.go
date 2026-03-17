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
			NewKubescapeScanner(),
			NewTrivyScanner(),
			NewKubeBenchScanner(),
		},
	}
}

// RunAll executes every available scanner and returns merged findings.
// Missing or failing scanners emit warnings but never abort the run.
func (o *Orchestrator) RunAll(opts RunOptions) (findings []model.Finding, used []string, warnings []string, err error) {
	for _, s := range o.scanners {
		if !s.Available() {
			warnings = append(warnings, fmt.Sprintf("⚠  %s not found in PATH — skipping", s.Name()))
			continue
		}
		result, runErr := s.Run(opts)
		if runErr != nil {
			warnings = append(warnings, fmt.Sprintf("⚠  %s error: %v", s.Name(), runErr))
			continue
		}
		findings = append(findings, result...)
		used = append(used, s.Name())
	}
	return
}
