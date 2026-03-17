package scoring

import "github.com/letzcode/k8s-eu-audit/internal/model"

var severityWeight = map[string]float64{
	"CRITICAL": 3.0,
	"HIGH":     2.0,
	"MEDIUM":   1.0,
	"LOW":      0.5,
}

// Calculate scores each ControlResult and returns the weighted overall score.
func Calculate(results []model.ControlResult) ([]model.ControlResult, model.ReportSummary) {
	var weightedSum, totalWeight float64
	var summary model.ReportSummary

	for i, cr := range results {
		score, status := scoreControl(cr.Findings)
		results[i].Score = score
		results[i].Status = status

		// Attach recommendations for any non-passing control
		if status == "FAIL" || status == "WARN" {
			results[i].Recommendations = buildRecommendations(cr, score)
		}

		switch status {
		case "PASS":
			summary.TotalPass++
		case "WARN":
			summary.TotalWarn++
		case "FAIL":
			summary.TotalFail++
		case "SKIP":
			summary.TotalSkip++
			continue // excluded from weighted average
		}

		w := severityWeight[cr.Control.Severity]
		if w == 0 {
			w = 1.0
		}
		weightedSum += score * w
		totalWeight += w
	}

	if totalWeight > 0 {
		summary.OverallScore = weightedSum / totalWeight
	}
	summary.Status = statusLabel(summary.OverallScore)
	return results, summary
}

func scoreControl(findings []model.Finding) (float64, string) {
	if len(findings) == 0 {
		return 0, "SKIP"
	}
	var pass, fail int
	for _, f := range findings {
		switch f.Status {
		case model.StatusPass:
			pass++
		case model.StatusFail:
			fail++
		}
	}
	total := pass + fail
	if total == 0 {
		return 0, "SKIP"
	}
	score := float64(pass) / float64(total) * 100
	return score, statusLabel(score)
}

func statusLabel(score float64) string {
	switch {
	case score >= 80:
		return "PASS"
	case score >= 50:
		return "WARN"
	default:
		return "FAIL"
	}
}

func buildRecommendations(cr model.ControlResult, score float64) []model.Recommendation {
	if cr.Control.Remediation == "" {
		return nil
	}

	failCount := 0
	for _, f := range cr.Findings {
		if f.Status == model.StatusFail {
			failCount++
		}
	}

	return []model.Recommendation{
		{
			ControlID:   cr.Control.ID,
			Article:     cr.Control.Article,
			Severity:    cr.Control.Severity,
			Title:       cr.Control.Name,
			Remediation: cr.Control.Remediation,
			FailCount:   failCount,
		},
	}
}
