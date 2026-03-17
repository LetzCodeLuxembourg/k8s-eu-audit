package mapping

import "github.com/letzcode/k8s-eu-audit/internal/model"

// Engine maps raw scanner findings to compliance framework controls.
type Engine struct {
	framework model.Framework
}

func NewEngine(fw model.Framework) *Engine {
	return &Engine{framework: fw}
}

// Map correlates findings to controls using the MappedChecks in the framework YAML.
func (e *Engine) Map(findings []model.Finding) []model.ControlResult {
	byID := make(map[string][]model.Finding, len(findings))
	for _, f := range findings {
		byID[f.ControlID] = append(byID[f.ControlID], f)
	}

	results := make([]model.ControlResult, 0, len(e.framework.Controls))
	for _, ctrl := range e.framework.Controls {
		var matched []model.Finding
		for _, checkID := range ctrl.MappedChecks {
			matched = append(matched, byID[checkID]...)
		}
		results = append(results, model.ControlResult{
			Control:  ctrl,
			Findings: matched,
		})
	}
	return results
}
