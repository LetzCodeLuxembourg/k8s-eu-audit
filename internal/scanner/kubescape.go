package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/letzcode/k8s-eu-audit/internal/model"
)

type kubescapeScanner struct{}

func NewKubescapeScanner() Scanner       { return &kubescapeScanner{} }
func (k *kubescapeScanner) Name() string { return "kubescape" }
func (k *kubescapeScanner) Available() bool {
	_, err := exec.LookPath("kubescape")
	return err == nil
}

func (k *kubescapeScanner) Run(opts RunOptions) ([]model.Finding, error) {
	tmpFile, err := os.CreateTemp("", "kubescape-*.json")
	if err != nil {
		return nil, fmt.Errorf("cannot create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	args := []string{
		"scan",
		"--format", "json",
		"--output", tmpFile.Name(),
		"--logger", "fatal",
	}
	if opts.Namespace != "" {
		args = append(args, "--namespace", opts.Namespace)
	}

	cmd := exec.Command("kubescape", args...)
	if err := cmd.Run(); err != nil {
		info, statErr := os.Stat(tmpFile.Name())
		if statErr != nil || info.Size() == 0 {
			return nil, fmt.Errorf("kubescape failed and produced no output: %w", err)
		}
		// exit code != 0 jest normalny gdy są faile — kontynuujemy
	}

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("cannot read kubescape output: %w", err)
	}

	return parseKubescapeOutput(data)
}

// kubescapeControl obsługuje dwa formaty severity:
//
//	stary: "severity": { "severity": "High" }
//	nowy:  "severity": "High"
type kubescapeControl struct {
	ControlID string `json:"controlID"`
	Name      string `json:"name"`
	Status    struct {
		Status string `json:"status"`
	} `json:"status"`
	// RawMessage pozwala nam samodzielnie zdekodować severity
	SeverityRaw json.RawMessage `json:"severity"`
}

// parseSeverity dekoduje severity niezależnie od formatu
func (c *kubescapeControl) parseSeverity() string {
	if len(c.SeverityRaw) == 0 {
		return ""
	}

	// Próbuj format nowy: plain string "High"
	var s string
	if err := json.Unmarshal(c.SeverityRaw, &s); err == nil {
		return s
	}

	// Próbuj format stary: { "severity": "High" }
	var obj struct {
		Severity string `json:"severity"`
	}
	if err := json.Unmarshal(c.SeverityRaw, &obj); err == nil {
		return obj.Severity
	}

	// Próbuj format z scoreFactor: { "severity": "High", "scoreFactor": 8.0 }
	var objFull struct {
		Severity    string  `json:"severity"`
		ScoreFactor float64 `json:"scoreFactor"`
	}
	if err := json.Unmarshal(c.SeverityRaw, &objFull); err == nil {
		return objFull.Severity
	}

	return ""
}

type kubescapeReport struct {
	Results []struct {
		Controls []kubescapeControl `json:"controls"`
	} `json:"results"`
}

func parseKubescapeOutput(raw []byte) ([]model.Finding, error) {
	// Odrzuć wszystko przed pierwszym '{'
	if idx := strings.IndexByte(string(raw), '{'); idx > 0 {
		raw = raw[idx:]
	}

	var r kubescapeReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("kubescape JSON parse error: %w", err)
	}

	var findings []model.Finding
	for _, result := range r.Results {
		for _, c := range result.Controls {
			findings = append(findings, model.Finding{
				ID:          strings.ToUpper(c.ControlID), // ← dodaj ToUpper
				Source:      "kubescape",
				ControlID:   strings.ToUpper(c.ControlID), // ← i tutaj
				ControlName: c.Name,
				Status:      kubescapeStatus(c.Status.Status),
				Severity:    normSeverity(c.parseSeverity()),
			})
		}
	}
	return findings, nil
}

func kubescapeStatus(s string) model.FindingStatus {
	switch s {
	case "passed":
		return model.StatusPass
	case "failed":
		return model.StatusFail
	case "skipped":
		return model.StatusSkip
	default:
		return model.StatusWarn
	}
}

func normSeverity(s string) model.Severity {
	switch s {
	case "Critical":
		return model.SeverityCritical
	case "High":
		return model.SeverityHigh
	case "Medium":
		return model.SeverityMedium
	default:
		return model.SeverityLow
	}
}
