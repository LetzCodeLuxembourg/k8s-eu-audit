package model

import "time"

// ComplianceReport is the full output of a scan run.
type ComplianceReport struct {
	Metadata    ReportMetadata  `json:"metadata"`
	Summary     ReportSummary   `json:"summary"`
	Controls    []ControlResult `json:"controls"`
	TopFindings []Finding       `json:"top_findings"`
}

// ReportMetadata holds contextual information about the scan.
type ReportMetadata struct {
	GeneratedAt time.Time `json:"generated_at"`
	ClusterName string    `json:"cluster_name"`
	Framework   string    `json:"framework"`
	Scanners    []string  `json:"scanners_used"`
}

// ReportSummary is the high-level compliance overview.
type ReportSummary struct {
	OverallScore float64 `json:"overall_score"`
	Status       string  `json:"status"` // PASS | WARN | FAIL
	TotalPass    int     `json:"total_pass"`
	TotalWarn    int     `json:"total_warn"`
	TotalFail    int     `json:"total_fail"`
	TotalSkip    int     `json:"total_skip"`
}

// ControlResult holds the evaluated result for a single regulatory control.
type ControlResult struct {
	Control         Control          `json:"control"`
	Score           float64          `json:"score"`
	Status          string           `json:"status"` // PASS | WARN | FAIL | SKIP
	Findings        []Finding        `json:"findings"`
	Recommendations []Recommendation `json:"recommendations,omitempty"`
}

// Recommendation is an actionable remediation step for a failing or warning control.
type Recommendation struct {
	ControlID   string `json:"control_id"`
	Article     string `json:"article"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Remediation string `json:"remediation"`
	FailCount   int    `json:"fail_count"`
}
