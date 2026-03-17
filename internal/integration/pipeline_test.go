package integration

import (
	"strings"
	"testing"

	"github.com/letzcode/k8s-eu-audit/internal/mapping"
	"github.com/letzcode/k8s-eu-audit/internal/model"
	"github.com/letzcode/k8s-eu-audit/internal/scoring"
)

// ---------------------------------------------------------------------------
// Full pipeline integration test
// Simulates what happens when you run: k8s-eu-audit scan --framework nis2
// Uses real framework YAML + synthetic findings that match actual Kubescape IDs
// ---------------------------------------------------------------------------

// realKubescapeFindings simulates the findings your cluster actually returns
// based on the controlIDs we saw from kubescape scan output.
func realKubescapeFindings() []model.Finding {
	return []model.Finding{
		// art21-2-a: Risk analysis (C-0013, C-0017, C-0057, C-0016, C-0020, C-0055)
		{ControlID: "C-0013", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityHigh},
		{ControlID: "C-0017", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityMedium},
		{ControlID: "C-0057", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityCritical},
		{ControlID: "C-0016", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityHigh},
		{ControlID: "C-0020", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityMedium},
		{ControlID: "C-0055", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityMedium},

		// art21-2-b: Incident handling (C-0067) — FAIL on dev cluster (no audit log)
		{ControlID: "C-0067", Source: "kubescape", Status: model.StatusFail, Severity: model.SeverityHigh},

		// art21-2-c: Business continuity (C-0068, C-0069) — FAIL (no PDBs on dev)
		{ControlID: "C-0068", Source: "kubescape", Status: model.StatusFail, Severity: model.SeverityMedium},
		{ControlID: "C-0069", Source: "kubescape", Status: model.StatusFail, Severity: model.SeverityMedium},

		// art21-2-d: Supply chain (C-0036, C-0014, C-0270, C-0046)
		{ControlID: "C-0036", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityMedium},
		{ControlID: "C-0014", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityMedium},
		{ControlID: "C-0270", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityLow},
		{ControlID: "C-0046", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityMedium},

		// art21-2-e: Network security (C-0030, C-0031, C-0066)
		{ControlID: "C-0030", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityHigh},
		{ControlID: "C-0031", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityHigh},
		{ControlID: "C-0066", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityHigh},

		// art21-2-f: Vulnerability (C-0270, C-0016, C-0057) — overlap with others
		// (already added above, engine will find them via lookup)

		// art21-2-g: Effectiveness (C-0005, C-0088, C-0053, C-0063)
		{ControlID: "C-0005", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityCritical},
		{ControlID: "C-0088", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityCritical},
		{ControlID: "C-0053", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityHigh},
		{ControlID: "C-0063", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityHigh},

		// art21-2-h: Hygiene (C-0035, C-0041, C-0044, C-0048, C-0038)
		{ControlID: "C-0035", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityCritical},
		{ControlID: "C-0041", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityHigh},
		{ControlID: "C-0044", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityMedium},
		{ControlID: "C-0048", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityMedium},
		{ControlID: "C-0038", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityHigh},

		// art21-2-i: Access control (C-0015, C-0058, C-0036, C-0187, C-0188)
		{ControlID: "C-0015", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityCritical},
		{ControlID: "C-0058", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityHigh},
		{ControlID: "C-0187", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityMedium},
		{ControlID: "C-0188", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityMedium},

		// art21-2-j: MFA/auth (C-0005, C-0088, C-0262, C-0256)
		{ControlID: "C-0262", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityCritical},
		{ControlID: "C-0256", Source: "kubescape", Status: model.StatusPass, Severity: model.SeverityMedium},
	}
}

// ---------------------------------------------------------------------------
// Pipeline test
// ---------------------------------------------------------------------------

func TestFullPipeline_NIS2(t *testing.T) {
	// 1. Load real framework YAML
	fw, err := mapping.Load("nis2")
	if err != nil {
		t.Fatalf("failed to load NIS2 framework: %v", err)
	}

	// 2. Map findings to controls
	engine := mapping.NewEngine(fw)
	controlResults := engine.Map(realKubescapeFindings())

	// 3. Score
	scored, summary := scoring.Calculate(controlResults)

	// 4. Verify structure
	if len(scored) != 10 {
		t.Errorf("NIS2 should have 10 control results, got %d", len(scored))
	}

	// 5. Verify no unexpected panics or zero-value controls
	for _, cr := range scored {
		if cr.Control.ID == "" {
			t.Error("ControlResult has empty Control.ID")
		}
		if cr.Control.Article == "" {
			t.Error("ControlResult has empty Article")
		}
	}

	// 6. Verify our known FAILs are detected
	byID := indexByID(scored)

	if byID["art21-2-b"].Status != "FAIL" {
		t.Errorf("art21-2-b (no audit log on dev cluster): expected FAIL, got %s (score=%.1f%%)",
			byID["art21-2-b"].Status, byID["art21-2-b"].Score)
	}
	if byID["art21-2-c"].Status != "FAIL" {
		t.Errorf("art21-2-c (no PDBs on dev cluster): expected FAIL, got %s (score=%.1f%%)",
			byID["art21-2-c"].Status, byID["art21-2-c"].Score)
	}

	// 7. Verify our known PASSes are detected
	passingControls := []string{"art21-2-a", "art21-2-e", "art21-2-g", "art21-2-h", "art21-2-i", "art21-2-j"}
	for _, id := range passingControls {
		if byID[id].Status != "PASS" {
			t.Errorf("%s: expected PASS, got %s (score=%.1f%%)",
				id, byID[id].Status, byID[id].Score)
		}
	}

	// 8. Verify summary counts
	if summary.TotalFail < 1 {
		t.Error("expected at least 1 FAIL in summary")
	}
	if summary.TotalPass < 1 {
		t.Error("expected at least 1 PASS in summary")
	}

	// 9. Verify overall score is in valid range
	if summary.OverallScore < 0 || summary.OverallScore > 100 {
		t.Errorf("overall score out of range: %.2f", summary.OverallScore)
	}

	// 10. Print report for visibility in test output
	t.Logf("\n=== NIS2 Compliance Report (Integration Test) ===")
	t.Logf("Overall: %.1f%% %s  |  Pass=%d Warn=%d Fail=%d Skip=%d",
		summary.OverallScore, summary.Status,
		summary.TotalPass, summary.TotalWarn, summary.TotalFail, summary.TotalSkip)
	t.Logf("%-12s  %-50s  %6s  %s", "Article", "Control", "Score", "Status")
	t.Logf("%s", strings.Repeat("─", 80))
	for _, cr := range scored {
		t.Logf("%-12s  %-50s  %5.0f%%  %s",
			cr.Control.Article,
			truncate(cr.Control.Name, 50),
			cr.Score,
			cr.Status,
		)
	}
}

func TestFullPipeline_DORA(t *testing.T) {
	fw, err := mapping.Load("dora")
	if err != nil {
		t.Fatalf("failed to load DORA framework: %v", err)
	}

	engine := mapping.NewEngine(fw)
	controlResults := engine.Map(realKubescapeFindings())
	scored, summary := scoring.Calculate(controlResults)

	if len(scored) == 0 {
		t.Fatal("DORA pipeline produced no results")
	}

	// DORA shares many check IDs with NIS2 — results should be non-empty
	hasData := false
	for _, cr := range scored {
		if cr.Status != "SKIP" {
			hasData = true
			break
		}
	}
	if !hasData {
		t.Error("all DORA controls are SKIP — mapped_checks likely don't match any findings")
	}

	t.Logf("DORA overall: %.1f%% %s", summary.OverallScore, summary.Status)
}

// ---------------------------------------------------------------------------
// Regression tests — verify specific NIS2 articles produce correct results
// ---------------------------------------------------------------------------

func TestNIS2Article21b_AuditLogging(t *testing.T) {
	// 21.2(b) Incident handling maps to C-0067 (audit logs)
	// A cluster with audit logs disabled should FAIL this control
	fw, _ := mapping.Load("nis2")
	engine := mapping.NewEngine(fw)

	// Scenario A: audit logs disabled
	noAuditFindings := []model.Finding{
		{ControlID: "C-0067", Source: "kubescape", Status: model.StatusFail},
	}
	results := engine.Map(noAuditFindings)
	scored, _ := scoring.Calculate(results)
	cr := findControlByID(scored, "art21-2-b")
	if cr == nil {
		t.Fatal("art21-2-b not found in results")
	}
	if cr.Status != "FAIL" {
		t.Errorf("audit logs disabled: expected art21-2-b=FAIL, got %s", cr.Status)
	}

	// Scenario B: audit logs enabled
	auditOKFindings := []model.Finding{
		{ControlID: "C-0067", Source: "kubescape", Status: model.StatusPass},
	}
	results = engine.Map(auditOKFindings)
	scored, _ = scoring.Calculate(results)
	cr = findControlByID(scored, "art21-2-b")
	if cr.Status != "PASS" {
		t.Errorf("audit logs enabled: expected art21-2-b=PASS, got %s", cr.Status)
	}
}

func TestNIS2Article21j_Authentication(t *testing.T) {
	// 21.2(j) MFA maps to C-0005, C-0088, C-0262, C-0256
	// Anonymous auth enabled (C-0262 FAIL) should degrade the score
	fw, _ := mapping.Load("nis2")
	engine := mapping.NewEngine(fw)

	findings := []model.Finding{
		{ControlID: "C-0005", Source: "kubescape", Status: model.StatusPass},
		{ControlID: "C-0088", Source: "kubescape", Status: model.StatusPass},
		{ControlID: "C-0262", Source: "kubescape", Status: model.StatusFail}, // anonymous auth ON
		{ControlID: "C-0256", Source: "kubescape", Status: model.StatusPass},
	}

	results := engine.Map(findings)
	scored, _ := scoring.Calculate(results)
	cr := findControlByID(scored, "art21-2-j")
	if cr == nil {
		t.Fatal("art21-2-j not found")
	}

	// 3 pass, 1 fail = 75% → WARN (not PASS)
	if cr.Status == "PASS" {
		t.Errorf("anonymous auth enabled should prevent PASS on art21-2-j, got %s (%.1f%%)",
			cr.Status, cr.Score)
	}
	if cr.Score < 70 || cr.Score > 80 {
		t.Errorf("3/4 passing: expected score ~75%%, got %.1f%%", cr.Score)
	}
}

func TestNIS2Article21c_BusinessContinuity(t *testing.T) {
	// 21.2(c) maps to C-0068, C-0069
	// Typical dev cluster: no PDBs, single replicas → both FAIL
	fw, _ := mapping.Load("nis2")
	engine := mapping.NewEngine(fw)

	findings := []model.Finding{
		{ControlID: "C-0068", Source: "kubescape", Status: model.StatusFail}, // single replicas
		{ControlID: "C-0069", Source: "kubescape", Status: model.StatusFail}, // no PDBs
	}

	results := engine.Map(findings)
	scored, _ := scoring.Calculate(results)
	cr := findControlByID(scored, "art21-2-c")
	if cr == nil {
		t.Fatal("art21-2-c not found")
	}
	if cr.Status != "FAIL" {
		t.Errorf("no PDBs/single replicas: expected FAIL, got %s (%.1f%%)", cr.Status, cr.Score)
	}
	if cr.Score != 0 {
		t.Errorf("all fail: expected score=0, got %.1f", cr.Score)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func indexByID(results []model.ControlResult) map[string]model.ControlResult {
	m := make(map[string]model.ControlResult, len(results))
	for _, r := range results {
		m[r.Control.ID] = r
	}
	return m
}

func findControlByID(results []model.ControlResult, id string) *model.ControlResult {
	for i := range results {
		if results[i].Control.ID == id {
			return &results[i]
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}
