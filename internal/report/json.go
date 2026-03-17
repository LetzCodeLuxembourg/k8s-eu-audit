package report

import (
	"encoding/json"
	"io"

	"github.com/letzcode/k8s-eu-audit/internal/model"
)

func WriteJSON(w io.Writer, r model.ComplianceReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
