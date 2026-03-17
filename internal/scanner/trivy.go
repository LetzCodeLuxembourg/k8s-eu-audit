package scanner

import (
	"encoding/json"
	"os/exec"

	"github.com/letzcode/k8s-eu-audit/internal/model"
)

type trivyScanner struct{}

func NewTrivyScanner() Scanner { return &trivyScanner{} }
func (t *trivyScanner) Name() string { return "trivy" }
func (t *trivyScanner) Available() bool {
	_, err := exec.LookPath("trivy")
	return err == nil
}

func (t *trivyScanner) Run(opts RunOptions) ([]model.Finding, error) {
	args := []string{"k8s", "--report", "all", "--format", "json"}
	if opts.Namespace != "" {
		args = append(args, "--namespace", opts.Namespace)
	}
	out, err := exec.Command("trivy", args...).Output()
	if err != nil {
		return nil, err
	}
	return parseTrivyOutput(out)
}

type trivyReport struct {
	Findings []struct {
		Misconfigurations []struct {
			ID          string `json:"ID"`
			Title       string `json:"Title"`
			Description string `json:"Description"`
			Resolution  string `json:"Resolution"`
			Severity    string `json:"Severity"`
			Status      string `json:"Status"`
		} `json:"Misconfigurations"`
	} `json:"Findings"`
}

func parseTrivyOutput(raw []byte) ([]model.Finding, error) {
	var r trivyReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	var findings []model.Finding
	for _, f := range r.Findings {
		for _, mc := range f.Misconfigurations {
			findings = append(findings, model.Finding{
				ID:          mc.ID,
				Source:      "trivy",
				ControlID:   mc.ID,
				ControlName: mc.Title,
				Status:      trivyStatus(mc.Status),
				Severity:    normSeverity(mc.Severity),
				Description: mc.Description,
				Remediation: mc.Resolution,
			})
		}
	}
	return findings, nil
}

func trivyStatus(s string) model.FindingStatus {
	switch s {
	case "PASS":
		return model.StatusPass
	case "FAIL":
		return model.StatusFail
	default:
		return model.StatusWarn
	}
}
