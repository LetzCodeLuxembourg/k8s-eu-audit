package scanner

import (
	"encoding/json"
	"testing"

	"github.com/letzcode/k8s-eu-audit/internal/model"
)

// ---------------------------------------------------------------------------
// Fixtures — minimal but realistic Kubescape JSON samples
// ---------------------------------------------------------------------------

// kubescapeFixtureNewFormat — severity as plain string (Kubescape >= 3.x)
var kubescapeFixtureNewFormat = []byte(`{
  "results": [
    {
      "controls": [
        {
          "controlID": "C-0067",
          "name": "Audit logs enabled",
          "status": { "status": "failed" },
          "severity": "Critical"
        },
        {
          "controlID": "C-0013",
          "name": "Non-root containers",
          "status": { "status": "passed" },
          "severity": "High"
        },
        {
          "controlID": "C-0088",
          "name": "RBAC enabled",
          "status": { "status": "passed" },
          "severity": "Critical"
        }
      ]
    }
  ]
}`)

// kubescapeFixtureOldFormat — severity as nested object (Kubescape < 3.x)
var kubescapeFixtureOldFormat = []byte(`{
  "results": [
    {
      "controls": [
        {
          "controlID": "C-0057",
          "name": "Privileged container",
          "status": { "status": "failed" },
          "severity": { "severity": "Critical" }
        },
        {
          "controlID": "C-0030",
          "name": "Ingress and Egress blocked",
          "status": { "status": "passed" },
          "severity": { "severity": "High" }
        }
      ]
    }
  ]
}`)

// kubescapeFixtureLowercaseIDs — some versions emit lowercase controlIDs
var kubescapeFixtureLowercaseIDs = []byte(`{
  "results": [
    {
      "controls": [
        {
          "controlID": "c-0013",
          "name": "Non-root containers",
          "status": { "status": "passed" },
          "severity": "Medium"
        },
        {
          "controlID": "c-0017",
          "name": "Immutable container filesystem",
          "status": { "status": "failed" },
          "severity": "High"
        }
      ]
    }
  ]
}`)

// kubescapeFixtureMixedStatuses — realistic mix of pass/fail/skipped
var kubescapeFixtureMixedStatuses = []byte(`{
  "results": [
    {
      "controls": [
        { "controlID": "C-0035", "name": "Cluster admin binding",    "status": { "status": "passed"  }, "severity": "Critical" },
        { "controlID": "C-0041", "name": "SA token automount",       "status": { "status": "failed"  }, "severity": "High"     },
        { "controlID": "C-0262", "name": "Anonymous access enabled", "status": { "status": "failed"  }, "severity": "Critical" },
        { "controlID": "C-0069", "name": "No PDB defined",           "status": { "status": "skipped" }, "severity": "Medium"   },
        { "controlID": "C-0005", "name": "API server insecure port", "status": { "status": "passed"  }, "severity": "Critical" }
      ]
    }
  ]
}`)

// kubescapeFixturePrefixNoise — output with noise before the JSON (progress output)
var kubescapeFixturePrefixNoise = []byte(`Scanning... done.
{"results":[{"controls":[{"controlID":"C-0067","name":"Audit logs","status":{"status":"failed"},"severity":"Critical"}]}]}`)

// ---------------------------------------------------------------------------
// Tests: parseKubescapeOutput
// ---------------------------------------------------------------------------

func TestParseKubescapeOutput_NewSeverityFormat(t *testing.T) {
	findings, err := parseKubescapeOutput(kubescapeFixtureNewFormat)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	// C-0067 should be FAIL / CRITICAL
	f := findByID(findings, "C-0067")
	if f == nil {
		t.Fatal("C-0067 not found in findings")
	}
	assertFinding(t, *f, "C-0067", model.StatusFail, model.SeverityCritical, "kubescape")

	// C-0013 should be PASS / HIGH
	f = findByID(findings, "C-0013")
	assertFinding(t, *f, "C-0013", model.StatusPass, model.SeverityHigh, "kubescape")
}

func TestParseKubescapeOutput_OldSeverityFormat(t *testing.T) {
	findings, err := parseKubescapeOutput(kubescapeFixtureOldFormat)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	f := findByID(findings, "C-0057")
	if f == nil {
		t.Fatal("C-0057 not found")
	}
	assertFinding(t, *f, "C-0057", model.StatusFail, model.SeverityCritical, "kubescape")
}

func TestParseKubescapeOutput_LowercaseIDsNormalized(t *testing.T) {
	findings, err := parseKubescapeOutput(kubescapeFixtureLowercaseIDs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.ControlID != "C-0013" && f.ControlID != "C-0017" {
			t.Errorf("expected uppercase ControlID, got %q", f.ControlID)
		}
	}

	// Mapping engine uses uppercase — verify lookup works
	f := findByID(findings, "C-0013")
	if f == nil {
		t.Error("C-0013 (normalised from c-0013) not found — lowercase IDs not normalised")
	}
}

func TestParseKubescapeOutput_PrefixNoiseStripped(t *testing.T) {
	findings, err := parseKubescapeOutput(kubescapeFixturePrefixNoise)
	if err != nil {
		t.Fatalf("prefix noise should be stripped, got error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings after stripping prefix noise")
	}
}

func TestParseKubescapeOutput_StatusMapping(t *testing.T) {
	findings, err := parseKubescapeOutput(kubescapeFixtureMixedStatuses)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cases := []struct {
		id     string
		status model.FindingStatus
	}{
		{"C-0035", model.StatusPass},
		{"C-0041", model.StatusFail},
		{"C-0262", model.StatusFail},
		{"C-0069", model.StatusSkip},
		{"C-0005", model.StatusPass},
	}

	for _, tc := range cases {
		f := findByID(findings, tc.id)
		if f == nil {
			t.Errorf("finding %s not found", tc.id)
			continue
		}
		if f.Status != tc.status {
			t.Errorf("%s: expected status %s, got %s", tc.id, tc.status, f.Status)
		}
	}
}

func TestParseKubescapeOutput_EmptyResults(t *testing.T) {
	empty := []byte(`{"results": []}`)
	findings, err := parseKubescapeOutput(empty)
	if err != nil {
		t.Fatalf("empty results should not error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseKubescapeOutput_InvalidJSON(t *testing.T) {
	_, err := parseKubescapeOutput([]byte(`not json at all`))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestParseKubescapeOutput_AllFindingsHaveSource(t *testing.T) {
	findings, _ := parseKubescapeOutput(kubescapeFixtureNewFormat)
	for _, f := range findings {
		if f.Source != "kubescape" {
			t.Errorf("expected source=kubescape, got %q for %s", f.Source, f.ControlID)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests: kubescapeStatus mapping
// ---------------------------------------------------------------------------

func TestKubescapeStatus(t *testing.T) {
	cases := []struct {
		input    string
		expected model.FindingStatus
	}{
		{"passed", model.StatusPass},
		{"failed", model.StatusFail},
		{"skipped", model.StatusSkip},
		{"unknown", model.StatusWarn},
		{"", model.StatusWarn},
	}
	for _, tc := range cases {
		got := kubescapeStatus(tc.input)
		if got != tc.expected {
			t.Errorf("kubescapeStatus(%q) = %s, want %s", tc.input, got, tc.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests: normSeverity mapping
// ---------------------------------------------------------------------------

func TestNormSeverity(t *testing.T) {
	cases := []struct {
		input    string
		expected model.Severity
	}{
		{"Critical", model.SeverityCritical},
		{"High", model.SeverityHigh},
		{"Medium", model.SeverityMedium},
		{"Low", model.SeverityLow},
		{"Unknown", model.SeverityLow},
		{"", model.SeverityLow},
	}
	for _, tc := range cases {
		got := normSeverity(tc.input)
		if got != tc.expected {
			t.Errorf("normSeverity(%q) = %s, want %s", tc.input, got, tc.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests: JSON round-trip (findings can be serialised)
// ---------------------------------------------------------------------------

func TestKubescapeFindings_JSONRoundTrip(t *testing.T) {
	findings, err := parseKubescapeOutput(kubescapeFixtureNewFormat)
	if err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("findings should be JSON serialisable: %v", err)
	}

	var restored []model.Finding
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("round-trip failed: %v", err)
	}

	if len(restored) != len(findings) {
		t.Errorf("round-trip lost findings: got %d, want %d", len(restored), len(findings))
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func findByID(findings []model.Finding, id string) *model.Finding {
	for i := range findings {
		if findings[i].ControlID == id {
			return &findings[i]
		}
	}
	return nil
}

func assertFinding(t *testing.T, f model.Finding, id string, status model.FindingStatus, severity model.Severity, source string) {
	t.Helper()
	if f.ControlID != id {
		t.Errorf("ControlID: got %q, want %q", f.ControlID, id)
	}
	if f.Status != status {
		t.Errorf("%s status: got %q, want %q", id, f.Status, status)
	}
	if f.Severity != severity {
		t.Errorf("%s severity: got %q, want %q", id, f.Severity, severity)
	}
	if f.Source != source {
		t.Errorf("%s source: got %q, want %q", id, f.Source, source)
	}
}
