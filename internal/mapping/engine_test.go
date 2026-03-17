package mapping

import (
	"testing"

	"github.com/letzcode/k8s-eu-audit/internal/model"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

func testFramework() model.Framework {
	return model.Framework{
		ID:   "test",
		Name: "Test Framework",
		Controls: []model.Control{
			{
				ID:           "ctrl-a",
				Article:      "1.1",
				Name:         "Access Control",
				Severity:     "CRITICAL",
				MappedChecks: []string{"C-0088", "C-0262", "C-0005"},
			},
			{
				ID:           "ctrl-b",
				Article:      "1.2",
				Name:         "Audit Logging",
				Severity:     "HIGH",
				MappedChecks: []string{"C-0067"},
			},
			{
				ID:           "ctrl-c",
				Article:      "1.3",
				Name:         "Pod Security",
				Severity:     "HIGH",
				MappedChecks: []string{"C-0013", "C-0057", "C-0017"},
			},
			{
				ID:           "ctrl-d",
				Article:      "1.4",
				Name:         "No scanner coverage",
				Severity:     "MEDIUM",
				MappedChecks: []string{"SYNTHETIC-001"},
			},
		},
	}
}

func testFindings() []model.Finding {
	return []model.Finding{
		{ControlID: "C-0088", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityCritical},
		{ControlID: "C-0262", Source: "kubescape", Status: model.StatusFail, Severity: model.SeverityCritical},
		{ControlID: "C-0005", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityCritical},
		{ControlID: "C-0067", Source: "kubescape", Status: model.StatusFail, Severity: model.SeverityHigh},
		{ControlID: "C-0013", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityHigh},
		{ControlID: "C-0057", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityCritical},
		{ControlID: "C-0017", Source: "kubescape", Status: model.StatusFail, Severity: model.SeverityHigh},
		// Extra finding not in any framework control — should be ignored
		{ControlID: "C-9999", Source: "kubescape", Status: model.StatusFail, Severity: model.SeverityLow},
	}
}

// ---------------------------------------------------------------------------
// Tests: Map
// ---------------------------------------------------------------------------

func TestEngine_Map_CorrectNumberOfResults(t *testing.T) {
	fw := testFramework()
	engine := NewEngine(fw)
	results := engine.Map(testFindings())

	if len(results) != len(fw.Controls) {
		t.Errorf("expected %d results (one per control), got %d", len(fw.Controls), len(results))
	}
}

func TestEngine_Map_CorrectFindingsPerControl(t *testing.T) {
	engine := NewEngine(testFramework())
	results := engine.Map(testFindings())

	byArticle := make(map[string]model.ControlResult)
	for _, r := range results {
		byArticle[r.Control.Article] = r
	}

	// ctrl-a maps 3 check IDs → should get 3 findings
	if len(byArticle["1.1"].Findings) != 3 {
		t.Errorf("ctrl-a: expected 3 findings, got %d", len(byArticle["1.1"].Findings))
	}

	// ctrl-b maps 1 check ID → should get 1 finding
	if len(byArticle["1.2"].Findings) != 1 {
		t.Errorf("ctrl-b: expected 1 finding, got %d", len(byArticle["1.2"].Findings))
	}

	// ctrl-c maps 3 check IDs → should get 3 findings
	if len(byArticle["1.3"].Findings) != 3 {
		t.Errorf("ctrl-c: expected 3 findings, got %d", len(byArticle["1.3"].Findings))
	}

	// ctrl-d maps synthetic ID with no findings → should get 0 findings
	if len(byArticle["1.4"].Findings) != 0 {
		t.Errorf("ctrl-d: expected 0 findings (synthetic ID), got %d", len(byArticle["1.4"].Findings))
	}
}

func TestEngine_Map_UnknownFindingsAreIgnored(t *testing.T) {
	engine := NewEngine(testFramework())
	results := engine.Map(testFindings())

	// C-9999 is not in any MappedChecks — verify it doesn't appear in any result
	for _, r := range results {
		for _, f := range r.Findings {
			if f.ControlID == "C-9999" {
				t.Errorf("control %s: C-9999 should not be mapped to any framework control", r.Control.ID)
			}
		}
	}
}

func TestEngine_Map_EmptyFindings(t *testing.T) {
	engine := NewEngine(testFramework())
	results := engine.Map([]model.Finding{})

	if len(results) != len(testFramework().Controls) {
		t.Errorf("expected %d results even with empty findings", len(testFramework().Controls))
	}
	for _, r := range results {
		if len(r.Findings) != 0 {
			t.Errorf("control %s: expected 0 findings with empty input, got %d", r.Control.ID, len(r.Findings))
		}
	}
}

func TestEngine_Map_PreservesControlMetadata(t *testing.T) {
	fw := testFramework()
	engine := NewEngine(fw)
	results := engine.Map(testFindings())

	for i, r := range results {
		if r.Control.ID != fw.Controls[i].ID {
			t.Errorf("position %d: control ID mismatch: got %q, want %q", i, r.Control.ID, fw.Controls[i].ID)
		}
		if r.Control.Severity != fw.Controls[i].Severity {
			t.Errorf("%s: severity lost in mapping", r.Control.ID)
		}
	}
}

func TestEngine_Map_MultipleScannersForSameControl(t *testing.T) {
	fw := model.Framework{
		Controls: []model.Control{
			{
				ID:           "ctrl-multi",
				Article:      "2.1",
				Severity:     "HIGH",
				MappedChecks: []string{"C-0067"},
			},
		},
	}

	// Same control ID from two different scanners
	findings := []model.Finding{
		{ControlID: "C-0067", Source: "kubescape", Status: model.StatusFail},
		{ControlID: "C-0067", Source: "kube-bench", Status: model.StatusPass},
	}

	engine := NewEngine(fw)
	results := engine.Map(findings)

	if len(results[0].Findings) != 2 {
		t.Errorf("expected 2 findings from 2 scanners for same check ID, got %d", len(results[0].Findings))
	}
}

// ---------------------------------------------------------------------------
// Tests: Load (embedded YAML)
// ---------------------------------------------------------------------------

func TestLoad_NIS2(t *testing.T) {
	fw, err := Load("nis2")
	if err != nil {
		t.Fatalf("Load(nis2) failed: %v", err)
	}

	if fw.ID != "nis2" {
		t.Errorf("expected id=nis2, got %q", fw.ID)
	}
	if len(fw.Controls) == 0 {
		t.Error("NIS2 framework has no controls")
	}

	// NIS2 Article 21 has exactly 10 sub-requirements (a–j)
	if len(fw.Controls) != 10 {
		t.Errorf("NIS2 should have 10 controls (21.2a–j), got %d", len(fw.Controls))
	}
}

func TestLoad_DORA(t *testing.T) {
	fw, err := Load("dora")
	if err != nil {
		t.Fatalf("Load(dora) failed: %v", err)
	}

	if fw.ID != "dora" {
		t.Errorf("expected id=dora, got %q", fw.ID)
	}
	if len(fw.Controls) == 0 {
		t.Error("DORA framework has no controls")
	}
}

func TestLoad_UnknownFramework(t *testing.T) {
	_, err := Load("nonexistent")
	if err == nil {
		t.Error("expected error for unknown framework, got nil")
	}
}

func TestLoad_NIS2_AllControlsHaveRequiredFields(t *testing.T) {
	fw, _ := Load("nis2")
	for _, c := range fw.Controls {
		if c.ID == "" {
			t.Errorf("control with article %q has empty ID", c.Article)
		}
		if c.Article == "" {
			t.Errorf("control %q has empty Article", c.ID)
		}
		if c.Severity == "" {
			t.Errorf("control %q has empty Severity", c.ID)
		}
		if len(c.MappedChecks) == 0 {
			t.Errorf("control %q (%s) has no mapped_checks", c.ID, c.Article)
		}
		if c.Remediation == "" {
			t.Errorf("control %q has no remediation text", c.ID)
		}
	}
}

func TestLoad_NIS2_SeverityValuesAreValid(t *testing.T) {
	valid := map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true}
	fw, _ := Load("nis2")
	for _, c := range fw.Controls {
		if !valid[c.Severity] {
			t.Errorf("control %q has invalid severity %q", c.ID, c.Severity)
		}
	}
}

func TestLoad_NIS2_ArticlesAreUnique(t *testing.T) {
	fw, _ := Load("nis2")
	seen := make(map[string]bool)
	for _, c := range fw.Controls {
		if seen[c.Article] {
			t.Errorf("duplicate article %q in NIS2 framework", c.Article)
		}
		seen[c.Article] = true
	}
}

func TestAvailableIDs(t *testing.T) {
	ids, err := AvailableIDs()
	if err != nil {
		t.Fatalf("AvailableIDs() error: %v", err)
	}
	if len(ids) < 2 {
		t.Errorf("expected at least 2 frameworks (nis2, dora), got %d", len(ids))
	}

	hasNIS2, hasDORA := false, false
	for _, id := range ids {
		if id == "nis2" {
			hasNIS2 = true
		}
		if id == "dora" {
			hasDORA = true
		}
	}
	if !hasNIS2 {
		t.Error("nis2 not in available frameworks")
	}
	if !hasDORA {
		t.Error("dora not in available frameworks")
	}
}
