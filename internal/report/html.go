package report

import (
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/letzcode/k8s-eu-audit/internal/model"
)

const htmlTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ .Metadata.Framework }} Compliance Report</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,sans-serif;background:#f8f9fa;color:#212529;padding:2rem 1rem}
  .wrap{max-width:960px;margin:0 auto}
  h1{font-size:1.4rem;font-weight:700;margin-bottom:.25rem}
  h2{font-size:1.1rem;font-weight:600;margin:2rem 0 1rem}
  .meta{font-size:.85rem;color:#6c757d;margin-bottom:2rem}
  .badge{display:inline-block;padding:.2rem .6rem;border-radius:4px;font-weight:600;font-size:.8rem}
  .PASS{background:#d1e7dd;color:#0a3622}
  .WARN{background:#fff3cd;color:#664d03}
  .FAIL{background:#f8d7da;color:#58151c}
  .SKIP{background:#e2e3e5;color:#41464b}
  .CRITICAL{background:#f8d7da;color:#58151c}
  .HIGH{background:#ffe5d0;color:#6e2a00}
  .MEDIUM{background:#fff3cd;color:#664d03}
  .LOW{background:#e2e3e5;color:#41464b}
  table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}
  th{background:#f1f3f5;text-align:left;padding:.6rem 1rem;font-size:.78rem;text-transform:uppercase;letter-spacing:.06em;color:#495057}
  td{padding:.65rem 1rem;border-bottom:1px solid #e9ecef;font-size:.88rem}
  tr:last-child td{border-bottom:none}
  .score-bar{display:flex;align-items:center;gap:.5rem}
  .bar{height:6px;border-radius:3px;flex:1;background:#e9ecef}
  .bar-fill{height:100%;border-radius:3px}
  .summary{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin:1.5rem 0}
  .card{background:#fff;border-radius:8px;padding:1rem;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.08)}
  .card-num{font-size:2rem;font-weight:700}
  .card-label{font-size:.78rem;color:#6c757d;text-transform:uppercase;letter-spacing:.06em}
  .rec-card{background:#fff;border-radius:8px;padding:1.25rem;margin-bottom:1rem;box-shadow:0 1px 3px rgba(0,0,0,.08)}
  .rec-header{display:flex;align-items:center;gap:.75rem;margin-bottom:.75rem;flex-wrap:wrap}
  .rec-meta{margin-left:auto;font-size:.82rem;color:#6c757d}
  .rec-body{font-size:.88rem;color:#343a40;line-height:1.65}
  footer{margin-top:2rem;font-size:.75rem;color:#adb5bd;text-align:center}
</style>
</head>
<body>
<div class="wrap">
  <h1>{{ .Metadata.Framework }} Compliance Report</h1>
  <div class="meta">
    Cluster: <strong>{{ .Metadata.ClusterName }}</strong> &nbsp;·&nbsp;
    {{ formatTime .Metadata.GeneratedAt }} &nbsp;·&nbsp;
    Scanners: {{ join .Metadata.Scanners }} &nbsp;·&nbsp;
    Overall: <span class="badge {{ .Summary.Status }}">{{ printf "%.0f" .Summary.OverallScore }}% {{ .Summary.Status }}</span>
  </div>

  <div class="summary">
    <div class="card"><div class="card-num" style="color:#0a3622">{{ .Summary.TotalPass }}</div><div class="card-label">Pass</div></div>
    <div class="card"><div class="card-num" style="color:#664d03">{{ .Summary.TotalWarn }}</div><div class="card-label">Warn</div></div>
    <div class="card"><div class="card-num" style="color:#58151c">{{ .Summary.TotalFail }}</div><div class="card-label">Fail</div></div>
    <div class="card"><div class="card-num" style="color:#41464b">{{ .Summary.TotalSkip }}</div><div class="card-label">Skip</div></div>
  </div>

  <table>
    <thead>
      <tr><th>Article</th><th>Requirement</th><th>Severity</th><th style="width:160px">Score</th><th>Status</th></tr>
    </thead>
    <tbody>
    {{ range .Controls }}
      <tr>
        <td><code>{{ .Control.Article }}</code></td>
        <td>{{ .Control.Name }}</td>
        <td><span class="badge {{ .Control.Severity }}">{{ .Control.Severity }}</span></td>
        <td>
          <div class="score-bar">
            <div class="bar"><div class="bar-fill" style="width:{{ printf "%.0f" .Score }}%;background:{{ barColor .Score }}"></div></div>
            <span style="font-size:.8rem;white-space:nowrap">{{ printf "%.0f" .Score }}%</span>
          </div>
        </td>
        <td><span class="badge {{ .Status }}">{{ .Status }}</span></td>
      </tr>
    {{ end }}
    </tbody>
  </table>

  {{ if hasRecs .Controls }}
  <h2>Recommendations</h2>
  {{ range .Controls }}{{ if .Recommendations }}
  <div class="rec-card" style="border-left:4px solid {{ severityBorder .Control.Severity }}">
    <div class="rec-header">
      <span class="badge {{ .Control.Severity }}">{{ .Control.Severity }}</span>
      <strong>{{ .Control.Article }}</strong>
      <span style="color:#495057">{{ .Control.Name }}</span>
      <span class="rec-meta">
        Score: {{ printf "%.0f" .Score }}%
        &nbsp;·&nbsp;
        {{ index .Recommendations 0 | recFailCount }} failing checks
      </span>
    </div>
    <div class="rec-body">{{ .Control.Remediation }}</div>
  </div>
  {{ end }}{{ end }}
  {{ end }}

  <footer>
    Generated by <a href="https://github.com/letzcode/k8s-eu-audit">k8s-eu-audit</a> &nbsp;·&nbsp; Not legal advice
  </footer>
</div>
</body>
</html>`

func WriteHTML(w io.Writer, r model.ComplianceReport) error {
	fm := template.FuncMap{
		"formatTime": func(t time.Time) string {
			return t.UTC().Format("2006-01-02 15:04 UTC")
		},
		"join": func(s []string) string {
			return strings.Join(s, ", ")
		},
		"barColor": func(score float64) string {
			switch {
			case score >= 80:
				return "#198754"
			case score >= 50:
				return "#ffc107"
			default:
				return "#dc3545"
			}
		},
		"hasRecs": func(controls []model.ControlResult) bool {
			for _, cr := range controls {
				if len(cr.Recommendations) > 0 {
					return true
				}
			}
			return false
		},
		"severityBorder": func(s string) string {
			switch s {
			case "CRITICAL":
				return "#dc3545"
			case "HIGH":
				return "#fd7e14"
			case "MEDIUM":
				return "#ffc107"
			default:
				return "#6c757d"
			}
		},
		"recFailCount": func(rec model.Recommendation) int {
			return rec.FailCount
		},
	}

	tmpl, err := template.New("html").Funcs(fm).Parse(htmlTmpl)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, r)
}
