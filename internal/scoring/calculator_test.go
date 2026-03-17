package scoring

import (
	"math"
	"testing"

	"github.com/letzcode/k8s-eu-audit/internal/model"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func makeFindings(pass, fail, warn, skip int) []model.Finding {
	var findings []model.Finding
	for i := 0; i < pass; i++ {
		findings = append(findings, model.Finding{Status: model.StatusPass})
	}
	for i := 0; i < fail; i++ {
		findings = append(findings, model.Finding{Status: model.StatusFail})
	}
	for i := 0; i < warn; i++ {
		findings = append(findings, model.Finding{Status: model.StatusWarn})
	}
	for i := 0; i < skip; i++ {
		findings = append(findings, model.Finding{Status: model.StatusSkip})
	}
	return findings
}

func makeControl(id, severity string, findings []model.Finding) model.ControlResult {
	return model.ControlResult{
		Control: model.Control{
			ID:       id,
			Severity: severity,
		},
		Findings: findings,
	}
}

func approxEqual(a, b, epsilon float64) bool {
	return math.Abs(a-b) <= epsilon
}

// ---------------------------------------------------------------------------
// Tests: scoreControl
// ---------------------------------------------------------------------------

func TestScoreControl_AllPass(t *testing.T) {
	score, status := scoreControl(makeFindings(10, 0, 0, 0))
	if score != 100 {
		t.Errorf("all pass: expected score=100, got %.1f", score)
	}
	if status != "PASS" {
		t.Errorf("all pass: expected PASS, got %s", status)
	}
}

func TestScoreControl_AllFail(t *testing.T) {
	score, status := scoreControl(makeFindings(0, 10, 0, 0))
	if score != 0 {
		t.Errorf("all fail: expected score=0, got %.1f", score)
	}
	if status != "FAIL" {
		t.Errorf("all fail: expected FAIL, got %s", status)
	}
}

func TestScoreControl_Empty(t *testing.T) {
	score, status := scoreControl([]model.Finding{})
	if score != 0 {
		t.Errorf("empty: expected score=0, got %.1f", score)
	}
	if status != "SKIP" {
		t.Errorf("empty: expected SKIP, got %s", status)
	}
}

func TestScoreControl_OnlyWarnAndSkip(t *testing.T) {
	// WARN and SKIP don't count as PASS or FAIL → no scoreable findings → SKIP
	score, status := scoreControl(makeFindings(0, 0, 5, 5))
	if status != "SKIP" {
		t.Errorf("warn+skip only: expected SKIP, got %s (score=%.1f)", status, score)
	}
}

func TestScoreControl_StatusThresholds(t *testing.T) {
	cases := []struct {
		pass, fail     int
		expectedStatus string
	}{
		{80, 20, "PASS"}, // 80% → PASS
		{79, 21, "WARN"}, // 79% → WARN
		{50, 50, "WARN"}, // 50% → WARN
		{49, 51, "FAIL"}, // 49% → FAIL
		{0, 10, "FAIL"},  // 0%  → FAIL
	}
	for _, tc := range cases {
		_, status := scoreControl(makeFindings(tc.pass, tc.fail, 0, 0))
		if status != tc.expectedStatus {
			t.Errorf("%d pass / %d fail: expected %s, got %s",
				tc.pass, tc.fail, tc.expectedStatus, status)
		}
	}
}

func TestScoreControl_ExactScore(t *testing.T) {
	// 3 pass, 1 fail → 75%
	score, _ := scoreControl(makeFindings(3, 1, 0, 0))
	if !approxEqual(score, 75.0, 0.01) {
		t.Errorf("3 pass / 1 fail: expected 75.0, got %.2f", score)
	}
}

// ---------------------------------------------------------------------------
// Tests: Calculate (overall)
// ---------------------------------------------------------------------------

func TestCalculate_AllSkip(t *testing.T) {
	results := []model.ControlResult{
		makeControl("ctrl-1", "CRITICAL", []model.Finding{}),
		makeControl("ctrl-2", "HIGH", []model.Finding{}),
	}
	_, summary := Calculate(results)

	if summary.TotalSkip != 2 {
		t.Errorf("expected 2 skips, got %d", summary.TotalSkip)
	}
	if summary.OverallScore != 0 {
		t.Errorf("all skip: expected overall 0, got %.1f", summary.OverallScore)
	}
}

func TestCalculate_SeverityWeighting(t *testing.T) {
	// CRITICAL control: 100% (all pass)
	// MEDIUM control:    0% (all fail)
	// CRITICAL weight=3, MEDIUM weight=1
	// Expected overall = (100*3 + 0*1) / (3+1) = 75%
	results := []model.ControlResult{
		makeControl("critical", "CRITICAL", makeFindings(10, 0, 0, 0)),
		makeControl("medium", "MEDIUM", makeFindings(0, 10, 0, 0)),
	}
	_, summary := Calculate(results)

	if !approxEqual(summary.OverallScore, 75.0, 0.1) {
		t.Errorf("severity weighting: expected 75.0, got %.2f", summary.OverallScore)
	}
}

func TestCalculate_SkipExcludedFromWeightedAverage(t *testing.T) {
	// SKIP controls must not affect the overall score
	results := []model.ControlResult{
		makeControl("ctrl-pass", "HIGH", makeFindings(10, 0, 0, 0)), // 100%
		makeControl("ctrl-skip", "CRITICAL", []model.Finding{}),     // SKIP
	}
	_, summary := Calculate(results)

	// Without weighting skip: (100 * 2) / 2 = 100
	if !approxEqual(summary.OverallScore, 100.0, 0.1) {
		t.Errorf("SKIP should not affect score: expected 100.0, got %.2f", summary.OverallScore)
	}
}

func TestCalculate_SummaryCounts(t *testing.T) {
	results := []model.ControlResult{
		makeControl("c1", "CRITICAL", makeFindings(10, 0, 0, 0)), // PASS
		makeControl("c2", "HIGH", makeFindings(0, 10, 0, 0)),     // FAIL
		makeControl("c3", "MEDIUM", makeFindings(6, 4, 0, 0)),    // WARN (60%)
		makeControl("c4", "LOW", []model.Finding{}),              // SKIP
	}
	_, summary := Calculate(results)

	if summary.TotalPass != 1 {
		t.Errorf("expected 1 pass, got %d", summary.TotalPass)
	}
	if summary.TotalFail != 1 {
		t.Errorf("expected 1 fail, got %d", summary.TotalFail)
	}
	if summary.TotalWarn != 1 {
		t.Errorf("expected 1 warn, got %d", summary.TotalWarn)
	}
	if summary.TotalSkip != 1 {
		t.Errorf("expected 1 skip, got %d", summary.TotalSkip)
	}
}

func TestCalculate_OverallStatusLabels(t *testing.T) {
	cases := []struct {
		pass, fail     int
		severity       string
		expectedStatus string
	}{
		{10, 0, "HIGH", "PASS"}, // 100% → PASS
		{6, 4, "HIGH", "WARN"},  // 60%  → WARN
		{3, 7, "HIGH", "FAIL"},  // 30%  → FAIL
	}

	for _, tc := range cases {
		results := []model.ControlResult{
			makeControl("ctrl", tc.severity, makeFindings(tc.pass, tc.fail, 0, 0)),
		}
		_, summary := Calculate(results)
		if summary.Status != tc.expectedStatus {
			t.Errorf("%d/%d %s: expected overall status %s, got %s",
				tc.pass, tc.fail, tc.severity, tc.expectedStatus, summary.Status)
		}
	}
}

func TestCalculate_ScoresAreSetOnResults(t *testing.T) {
	results := []model.ControlResult{
		makeControl("c1", "HIGH", makeFindings(3, 1, 0, 0)), // 75%
		makeControl("c2", "HIGH", makeFindings(0, 0, 0, 0)), // SKIP
	}
	scored, _ := Calculate(results)

	if !approxEqual(scored[0].Score, 75.0, 0.1) {
		t.Errorf("c1 score: expected 75.0, got %.2f", scored[0].Score)
	}
	if scored[0].Status != "WARN" {
		t.Errorf("c1 status: expected WARN, got %s", scored[0].Status)
	}
	if scored[1].Status != "SKIP" {
		t.Errorf("c2 status: expected SKIP, got %s", scored[1].Status)
	}
}

func TestCalculate_UnknownSeverityDefaultsToWeight1(t *testing.T) {
	// Controls with unrecognised severity should not panic or produce wrong results
	results := []model.ControlResult{
		makeControl("ctrl", "UNKNOWN_SEVERITY", makeFindings(8, 2, 0, 0)), // 80%
	}
	scored, summary := Calculate(results)

	if scored[0].Status != "PASS" {
		t.Errorf("80%% with unknown severity should be PASS, got %s", scored[0].Status)
	}
	if summary.OverallScore != scored[0].Score {
		t.Errorf("single control: overall should equal control score")
	}
}

// ---------------------------------------------------------------------------
// Tests: NIS2 real-world simulation
// Simulates a realistic cluster scan result and verifies the report makes sense
// ---------------------------------------------------------------------------

func TestCalculate_NIS2RealWorldSimulation(t *testing.T) {
	// Simulates what you'd see on a typical dev cluster:
	// - Good RBAC (PASS)
	// - No audit logging (FAIL)
	// - No PDBs (FAIL)
	// - Good network policies (PASS)
	// - Mixed pod security (WARN)
	results := []model.ControlResult{
		{
			Control:  model.Control{ID: "art21-2-a", Severity: "HIGH"},
			Findings: makeFindings(23, 2, 0, 0), // 92% → PASS
		},
		{
			Control:  model.Control{ID: "art21-2-b", Severity: "CRITICAL"},
			Findings: makeFindings(0, 1, 0, 0), // 0% → FAIL
		},
		{
			Control:  model.Control{ID: "art21-2-c", Severity: "HIGH"},
			Findings: makeFindings(0, 1, 0, 0), // 0% → FAIL
		},
		{
			Control:  model.Control{ID: "art21-2-e", Severity: "HIGH"},
			Findings: makeFindings(49, 1, 0, 0), // 98% → PASS
		},
		{
			Control:  model.Control{ID: "art21-2-h", Severity: "MEDIUM"},
			Findings: makeFindings(143, 1, 0, 0), // 99% → PASS
		},
		{
			Control:  model.Control{ID: "art21-2-i", Severity: "HIGH"},
			Findings: makeFindings(32, 1, 0, 0), // 97% → PASS
		},
		{
			Control:  model.Control{ID: "art21-2-j", Severity: "CRITICAL"},
			Findings: makeFindings(99, 1, 0, 0), // 99% → PASS
		},
	}

	scored, summary := Calculate(results)

	// Verify individual control statuses
	byID := make(map[string]model.ControlResult)
	for _, r := range scored {
		byID[r.Control.ID] = r
	}

	if byID["art21-2-b"].Status != "FAIL" {
		t.Errorf("art21-2-b (no audit logs): expected FAIL, got %s", byID["art21-2-b"].Status)
	}
	if byID["art21-2-c"].Status != "FAIL" {
		t.Errorf("art21-2-c (no PDBs): expected FAIL, got %s", byID["art21-2-c"].Status)
	}
	if byID["art21-2-j"].Status != "PASS" {
		t.Errorf("art21-2-j (good auth): expected PASS, got %s", byID["art21-2-j"].Status)
	}

	// With 2 CRITICAL FAILs pulling down the score, overall should be WARN not PASS
	if summary.Status == "PASS" {
		t.Errorf("cluster with CRITICAL FAILs should not be overall PASS, got %s (%.1f%%)",
			summary.Status, summary.OverallScore)
	}

	t.Logf("Simulated NIS2 overall score: %.1f%% (%s)", summary.OverallScore, summary.Status)
	t.Logf("Pass=%d Warn=%d Fail=%d Skip=%d",
		summary.TotalPass, summary.TotalWarn, summary.TotalFail, summary.TotalSkip)
}
