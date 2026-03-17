package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"

	"github.com/letzcode/k8s-eu-audit/internal/model"
)

type kubeBenchScanner struct{}

func NewKubeBenchScanner() Scanner       { return &kubeBenchScanner{} }
func (k *kubeBenchScanner) Name() string { return "kube-bench" }

func (k *kubeBenchScanner) Available() bool {
	if runtime.GOOS == "darwin" {
		// kube-bench nie działa natywnie na macOS —
		// wymaga węzła Linux z plikami /etc/kubernetes/
		return false
	}
	_, err := exec.LookPath("kube-bench")
	return err == nil
}

func (k *kubeBenchScanner) Run(opts RunOptions) ([]model.Finding, error) {
	out, err := exec.Command("kube-bench", "--json").Output()
	if err != nil {
		return nil, fmt.Errorf("kube-bench: %w", err)
	}
	return parseKubeBenchOutput(out)
}

type kubeBenchReport struct {
	Controls []struct {
		Tests []struct {
			Results []struct {
				TestNumber  string `json:"test_number"`
				TestDesc    string `json:"test_desc"`
				Status      string `json:"status"`
				Remediation string `json:"remediation"`
			} `json:"results"`
		} `json:"tests"`
	} `json:"Controls"`
}

func parseKubeBenchOutput(raw []byte) ([]model.Finding, error) {
	var r kubeBenchReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("kube-bench JSON parse: %w", err)
	}
	var findings []model.Finding
	for _, section := range r.Controls {
		for _, test := range section.Tests {
			for _, res := range test.Results {
				findings = append(findings, model.Finding{
					ID:          res.TestNumber,
					Source:      "kube-bench",
					ControlID:   res.TestNumber,
					ControlName: res.TestDesc,
					Status:      kubeBenchStatus(res.Status),
					Severity:    model.SeverityMedium,
					Remediation: res.Remediation,
				})
			}
		}
	}
	return findings, nil
}

func kubeBenchStatus(s string) model.FindingStatus {
	switch s {
	case "PASS":
		return model.StatusPass
	case "FAIL":
		return model.StatusFail
	case "WARN":
		return model.StatusWarn
	default:
		return model.StatusSkip
	}
}
