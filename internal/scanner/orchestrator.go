package scanner

import (
	"fmt"
	"time"

	"github.com/letzcode/k8s-eu-audit/internal/model"
)

// ScannerEvent is emitted by the orchestrator during scanning.
type ScannerEvent struct {
	Scanner string
	State   string // "start" | "done" | "skip" | "error"
	Count   int
	Elapsed time.Duration
	Reason  string
	Err     error
}

// EventHandler receives ScannerEvents in real time.
type EventHandler func(ScannerEvent)

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
			NewLynisScanner(),
			NewMacOSScanner(),
			NewWindowsScanner(),
		},
	}
}

// RunAll executes every available scanner and returns merged findings.
// The optional handler receives real-time progress events.
func (o *Orchestrator) RunAll(opts RunOptions, handler ...EventHandler) (
	findings []model.Finding,
	usedScanners []string,
	warnings []string,
	err error,
) {
	emit := func(e ScannerEvent) {
		for _, h := range handler {
			if h != nil {
				h(e)
			}
		}
	}

	for _, s := range o.scanners {
		if !s.Available() {
			reason := "not found in PATH"
			// Host-platform scanners silently skip on wrong OS
			switch s.Name() {
			case "macos", "windows", "lynis":
				reason = "not applicable on this OS"
			}
			if opts.IsK8sScan() {
				switch s.Name() {
				case "kubescape", "trivy", "kube-bench":
					warnings = append(warnings, fmt.Sprintf("⚠  %s not found in PATH", s.Name()))
					emit(ScannerEvent{Scanner: s.Name(), State: "skip", Reason: "not found in PATH"})
				default:
					emit(ScannerEvent{Scanner: s.Name(), State: "skip", Reason: reason})
				}
			} else {
				emit(ScannerEvent{Scanner: s.Name(), State: "skip", Reason: reason})
			}
			continue
		}

		emit(ScannerEvent{Scanner: s.Name(), State: "start"})
		start := time.Now()

		result, runErr := s.Run(opts)
		elapsed := time.Since(start)

		if runErr != nil {
			warnings = append(warnings, fmt.Sprintf("⚠  %s error: %v", s.Name(), runErr))
			emit(ScannerEvent{Scanner: s.Name(), State: "error", Elapsed: elapsed, Err: runErr})
			continue
		}
		if len(result) == 0 {
			emit(ScannerEvent{Scanner: s.Name(), State: "skip", Reason: "no findings (mode mismatch)"})
			continue
		}

		findings = append(findings, result...)
		usedScanners = append(usedScanners, s.Name())
		emit(ScannerEvent{Scanner: s.Name(), State: "done", Count: len(result), Elapsed: elapsed})
	}

	return findings, usedScanners, warnings, nil
}
