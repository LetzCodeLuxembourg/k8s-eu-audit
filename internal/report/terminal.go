package report

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/fatih/color"

	"github.com/letzcode/k8s-eu-audit/internal/model"
)

const (
	colArticle = 10
	colName    = 52
	colScore   = 6
)

func PrintTerminal(r model.ComplianceReport) {
	fmt.Printf("\n%s Compliance Report\n", r.Metadata.Framework)
	fmt.Println(strings.Repeat("━", 84))
	fmt.Println()

	fmt.Printf("  %-*s  %-*s  %-*s  %s\n",
		colArticle, "Article",
		colName, "Requirement",
		colScore, "Score",
		"Status",
	)
	fmt.Printf("  %s\n", strings.Repeat("─", 80))

	for _, cr := range r.Controls {
		article := padRight(cr.Control.Article, colArticle)
		name := truncate(cr.Control.Name, colName)
		score := fmt.Sprintf("%.0f%%", cr.Score)
		status := colorStatus(cr.Status)
		fmt.Printf("  %s  %-*s  %-*s  %s\n",
			article,
			colName, name,
			colScore, score,
			status,
		)
	}

	fmt.Println()
	fmt.Printf("Overall Score: ")
	switch r.Summary.Status {
	case "PASS":
		color.New(color.FgGreen, color.Bold).Printf("%.0f%%  PASS\n", r.Summary.OverallScore)
	case "WARN":
		color.New(color.FgYellow, color.Bold).Printf("%.0f%%  WARN\n", r.Summary.OverallScore)
	default:
		color.New(color.FgRed, color.Bold).Printf("%.0f%%  FAIL\n", r.Summary.OverallScore)
	}
	fmt.Println()

	if r.Summary.TotalFail > 0 {
		color.Red("%d control(s) FAIL — immediate attention required.\n", r.Summary.TotalFail)
	}

	printRecommendations(r)
}

func printRecommendations(r model.ComplianceReport) {
	var recs []model.ControlResult
	for _, cr := range r.Controls {
		if len(cr.Recommendations) > 0 {
			recs = append(recs, cr)
		}
	}
	if len(recs) == 0 {
		return
	}

	sort.Slice(recs, func(i, j int) bool {
		return severityRank(recs[i].Control.Severity) > severityRank(recs[j].Control.Severity)
	})

	fmt.Println()
	fmt.Println(strings.Repeat("━", 84))
	color.New(color.FgWhite, color.Bold).Println("  RECOMMENDATIONS")
	fmt.Println(strings.Repeat("━", 84))

	for idx, cr := range recs {
		rec := cr.Recommendations[0]

		severityFn := severityColorFunc(rec.Severity)
		fmt.Printf("\n  %d. [%s] %s — %s\n",
			idx+1,
			severityFn(rec.Severity),
			color.New(color.Bold).Sprint(rec.Article),
			rec.Title,
		)
		fmt.Printf("     Score: %.0f%%  |  Failing checks: %d\n", cr.Score, rec.FailCount)
		fmt.Println()
		for _, line := range wordWrap(rec.Remediation, 76) {
			fmt.Printf("     %s\n", line)
		}
	}

	fmt.Println()
}

func colorStatus(status string) string {
	switch status {
	case "PASS":
		return color.GreenString("✓ PASS")
	case "WARN":
		return color.YellowString("⚠ WARN")
	case "FAIL":
		return color.RedString("✗ FAIL")
	default:
		return color.HiBlackString("– SKIP")
	}
}

func severityRank(s string) int {
	switch s {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	default:
		return 1
	}
}

func severityColorFunc(s string) func(a ...interface{}) string {
	switch s {
	case "CRITICAL":
		return color.New(color.FgRed, color.Bold).SprintFunc()
	case "HIGH":
		return color.New(color.FgRed).SprintFunc()
	case "MEDIUM":
		return color.New(color.FgYellow).SprintFunc()
	default:
		return color.New(color.FgWhite).SprintFunc()
	}
}

func padRight(s string, width int) string {
	n := utf8.RuneCountInString(s)
	if n >= width {
		return s
	}
	return s + strings.Repeat(" ", width-n)
}

func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max-1]) + "…"
}

func wordWrap(text string, maxWidth int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	current := words[0]
	for _, w := range words[1:] {
		if len(current)+1+len(w) > maxWidth {
			lines = append(lines, current)
			current = w
		} else {
			current += " " + w
		}
	}
	return append(lines, current)
}
