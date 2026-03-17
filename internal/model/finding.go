package model

// FindingStatus is the result of a single scanner check.
type FindingStatus string

const (
	StatusPass FindingStatus = "PASS"
	StatusFail FindingStatus = "FAIL"
	StatusWarn FindingStatus = "WARN"
	StatusSkip FindingStatus = "SKIP"
)

// Severity maps to EU regulatory risk levels.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// Resource identifies a Kubernetes object affected by a finding.
type Resource struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// Finding is a normalised result from any scanner.
// All scanner-specific formats are converted into this struct before mapping.
type Finding struct {
	ID          string        `json:"id"`
	Source      string        `json:"source"`      // "kubescape" | "trivy" | "kube-bench"
	ControlID   string        `json:"control_id"`  // Scanner-native ID, e.g. "C-0004"
	ControlName string        `json:"control_name"`
	Status      FindingStatus `json:"status"`
	Severity    Severity      `json:"severity"`
	Description string        `json:"description"`
	Remediation string        `json:"remediation"`
	Resources   []Resource    `json:"resources,omitempty"`
}
