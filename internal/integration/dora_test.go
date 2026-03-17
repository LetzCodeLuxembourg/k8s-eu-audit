package integration

// =============================================================================
// DORA Compliance Tests
// =============================================================================
// Weryfikuje że k8s-eu-audit poprawnie wykrywa naruszenia DORA ICT Risk.
//
// DORA dotyczy ~22,000 podmiotów finansowych w EU.
// W Luksemburgu nadzoruje CSSF (cyrkulary 25/880–25/883).
//
// Pięć filarów DORA:
//   dora-rm-*   : ICT Risk Management (Art. 5–14)
//   dora-inc-*  : Incident Management (Art. 17–23)
//   dora-test-* : Resilience Testing (Art. 24–27)
//   dora-tpp-*  : Third-Party Risk (Art. 28–44)
//   dora-share-*: Information Sharing (Art. 45–56)
//   dora-auth-* : Authentication (Art. 9(2))
// =============================================================================

import (
	"strings"
	"testing"

	"github.com/letzcode/k8s-eu-audit/internal/mapping"
	"github.com/letzcode/k8s-eu-audit/internal/model"
	"github.com/letzcode/k8s-eu-audit/internal/scoring"
)

// =============================================================================
// DORA framework loading
// =============================================================================

func TestDORA_FrameworkLoads(t *testing.T) {
	fw, err := mapping.Load("dora")
	if err != nil {
		t.Fatalf("Load(dora) failed: %v", err)
	}
	if fw.ID != "dora" {
		t.Errorf("expected id=dora, got %q", fw.ID)
	}
	if len(fw.Controls) == 0 {
		t.Error("DORA framework has no controls")
	}
	t.Logf("DORA framework: %d controls loaded", len(fw.Controls))
	for _, c := range fw.Controls {
		t.Logf("  %-14s  %-12s  %s", c.ID, c.Article, c.Name)
	}
}

func TestDORA_AllControlsHaveRequiredFields(t *testing.T) {
	fw, _ := mapping.Load("dora")
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

func TestDORA_ExpectedControlIDs(t *testing.T) {
	fw, _ := mapping.Load("dora")
	expectedIDs := []string{
		"dora-rm-1",    // ICT risk management governance
		"dora-rm-2",    // Asset identification and protection
		"dora-rm-3",    // Detection of anomalous activities
		"dora-rm-4",    // Business continuity and recovery
		"dora-rm-5",    // Security awareness and training
		"dora-inc-1",   // Incident detection and reporting
		"dora-inc-2",   // Incident response and recovery
		"dora-test-1",  // Resilience testing programme
		"dora-test-2",  // TLPT requirements
		"dora-tpp-1",   // Third-party risk policy
		"dora-tpp-2",   // Contractual provisions
		"dora-tpp-3",   // Oversight of CTPPs
		"dora-share-1", // Information sharing
		"dora-auth-1",  // Strong authentication (Art. 9(2))
	}

	byID := make(map[string]bool)
	for _, c := range fw.Controls {
		byID[c.ID] = true
	}
	for _, id := range expectedIDs {
		if !byID[id] {
			t.Errorf("expected control %q in DORA framework, not found", id)
		}
	}
}

func TestDORA_SeverityValuesValid(t *testing.T) {
	valid := map[string]bool{
		"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true,
	}
	fw, _ := mapping.Load("dora")
	for _, c := range fw.Controls {
		if !valid[c.Severity] {
			t.Errorf("control %q has invalid severity %q", c.ID, c.Severity)
		}
	}
}

func TestDORA_CriticalControlsExist(t *testing.T) {
	fw, _ := mapping.Load("dora")
	criticalCount := 0
	for _, c := range fw.Controls {
		if c.Severity == "CRITICAL" {
			criticalCount++
		}
	}
	if criticalCount == 0 {
		t.Error("DORA framework should have CRITICAL severity controls")
	}
	t.Logf("DORA has %d CRITICAL controls", criticalCount)
}

// =============================================================================
// DORA Pillar 1: ICT Risk Management
// =============================================================================

func TestDORA_RM1_GovernanceAndStrategy(t *testing.T) {
	// dora-rm-1: ICT risk management framework
	// Covers: workload security (K8s) + firewall (all hosts) + SIP/UAC
	runDORAScenarios(t, []doraScenario{
		{
			name:       "compliant_full_protection",
			controlID:  "dora-rm-1",
			wantStatus: "PASS",
			findings: []model.Finding{
				pass("C-0013", "kubescape"), pass("C-0017", "kubescape"),
				pass("C-0057", "kubescape"), pass("C-0016", "kubescape"),
				pass("C-0088", "kubescape"), pass("C-0004", "kubescape"),
				pass("LYNIS-KERN-001", "lynis"), pass("LYNIS-FW-001", "lynis"),
				pass("LYNIS-FW-002", "lynis"), pass("MACOS-SIP-001", "macos"),
				pass("MACOS-FW-001", "macos"), pass("WIN-UAC-001", "windows"),
				pass("WIN-FW-001", "windows"), pass("WIN-FW-002", "windows"),
				pass("WIN-FW-003", "windows"),
			},
		},
		{
			name:       "violation_privileged_containers_no_firewall",
			controlID:  "dora-rm-1",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// K8s: all bad
				fail("C-0013", "kubescape"), fail("C-0017", "kubescape"),
				fail("C-0057", "kubescape"), fail("C-0016", "kubescape"),
				fail("C-0088", "kubescape"), fail("C-0004", "kubescape"),
				// Host: all bad
				fail("LYNIS-KERN-001", "lynis"), fail("LYNIS-FW-001", "lynis"),
				fail("LYNIS-FW-002", "lynis"), fail("MACOS-SIP-001", "macos"),
				fail("MACOS-FW-001", "macos"), fail("WIN-UAC-001", "windows"),
				fail("WIN-FW-001", "windows"), fail("WIN-FW-002", "windows"),
				fail("WIN-FW-003", "windows"),
			},
		},
		{
			name:       "partial_k8s_good_host_bad",
			controlID:  "dora-rm-1",
			wantStatus: "WARN",
			findings: []model.Finding{
				// K8s good
				pass("C-0013", "kubescape"), pass("C-0017", "kubescape"),
				pass("C-0057", "kubescape"), pass("C-0016", "kubescape"),
				pass("C-0088", "kubescape"),
				// Host bad — firewall off
				fail("LYNIS-FW-001", "lynis"), fail("LYNIS-FW-002", "lynis"),
				fail("WIN-UAC-001", "windows"), fail("WIN-FW-001", "windows"),
				fail("WIN-FW-002", "windows"), fail("WIN-FW-003", "windows"),
				fail("MACOS-FW-001", "macos"),
			},
		},
	})
}

func TestDORA_RM2_AssetProtection(t *testing.T) {
	// dora-rm-2: Asset identification and encryption
	runDORAScenarios(t, []doraScenario{
		{
			name:       "compliant_encrypted_and_segmented",
			controlID:  "dora-rm-2",
			wantStatus: "PASS",
			findings: []model.Finding{
				pass("C-0030", "kubescape"), pass("C-0031", "kubescape"),
				pass("C-0066", "kubescape"), pass("C-0079", "kubescape"),
				pass("LYNIS-ENC-001", "lynis"), pass("LYNIS-INT-001", "lynis"),
				pass("MACOS-FV-001", "macos"), pass("WIN-BL-001", "windows"),
				pass("WIN-SMB-001", "windows"),
			},
		},
		{
			name:       "violation_no_encryption_no_network_control",
			controlID:  "dora-rm-2",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0030", "kubescape"), fail("C-0031", "kubescape"),
				fail("C-0066", "kubescape"), fail("C-0079", "kubescape"),
				fail("LYNIS-ENC-001", "lynis"), fail("LYNIS-INT-001", "lynis"),
				fail("MACOS-FV-001", "macos"), fail("WIN-BL-001", "windows"),
				fail("WIN-SMB-001", "windows"),
			},
		},
		{
			name:       "violation_no_disk_encryption",
			controlID:  "dora-rm-2",
			wantStatus: "WARN",
			findings: []model.Finding{
				// K8s ok
				pass("C-0030", "kubescape"), pass("C-0031", "kubescape"),
				pass("C-0066", "kubescape"), pass("C-0079", "kubescape"),
				pass("C-0036", "kubescape"),
				// No disk encryption on hosts
				fail("MACOS-FV-001", "macos"),
				fail("WIN-BL-001", "windows"),
				pass("LYNIS-ENC-001", "lynis"),
				pass("LYNIS-INT-001", "lynis"),
				pass("WIN-SMB-001", "windows"),
			},
		},
	})
}

func TestDORA_RM3_AnomalyDetection(t *testing.T) {
	// dora-rm-3: Continuous monitoring and anomaly detection
	// All checks are about logging — zero logging = zero detection
	runDORAScenarios(t, []doraScenario{
		{
			name:       "compliant_full_audit_trail",
			controlID:  "dora-rm-3",
			wantStatus: "PASS",
			findings: []model.Finding{
				pass("C-0067", "kubescape"),         // K8s audit
				pass("LYNIS-LOG-001", "lynis"),       // syslog
				pass("LYNIS-LOG-002", "lynis"),       // auditd
				pass("LYNIS-LOG-003", "lynis"),       // log rotation
				pass("MACOS-LOG-001", "macos"),       // OpenBSM
				pass("WIN-AUD-001", "windows"),       // logon audit
				pass("WIN-AUD-002", "windows"),       // priv audit
				pass("WIN-AUD-003", "windows"),       // log size
			},
		},
		{
			name:       "violation_no_logging_anywhere",
			controlID:  "dora-rm-3",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0067", "kubescape"),
				fail("LYNIS-LOG-001", "lynis"),
				fail("LYNIS-LOG-002", "lynis"),
				fail("LYNIS-LOG-003", "lynis"),
				fail("MACOS-LOG-001", "macos"),
				fail("WIN-AUD-001", "windows"),
				fail("WIN-AUD-002", "windows"),
				fail("WIN-AUD-003", "windows"),
			},
		},
		{
			name:       "violation_no_k8s_audit_no_auditd",
			controlID:  "dora-rm-3",
			wantStatus: "FAIL",
			// DORA Art.10 requires CONTINUOUS monitoring — missing auditd+k8s audit = FAIL
			findings: []model.Finding{
				fail("C-0067", "kubescape"),    // no K8s audit
				pass("LYNIS-LOG-001", "lynis"), // syslog ok
				fail("LYNIS-LOG-002", "lynis"), // no auditd
				pass("LYNIS-LOG-003", "lynis"),
				fail("MACOS-LOG-001", "macos"), // no macOS audit
				fail("WIN-AUD-001", "windows"), // no logon audit
				pass("WIN-AUD-002", "windows"),
				pass("WIN-AUD-003", "windows"),
			},
		},
	})
}

func TestDORA_RM4_BusinessContinuity(t *testing.T) {
	// dora-rm-4: RTO/RPO — K8s only checks
	runDORAScenarios(t, []doraScenario{
		{
			name:      "compliant_ha_with_pdb",
			controlID: "dora-rm-4",
			wantStatus: "PASS",
			findings: []model.Finding{
				pass("C-0068", "kubescape"), // multi-replica
				pass("C-0069", "kubescape"), // PDB defined
			},
		},
		{
			name:      "violation_single_replica_no_pdb",
			controlID: "dora-rm-4",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0068", "kubescape"), // single replica
				fail("C-0069", "kubescape"), // no PDB
			},
		},
	})
}

// =============================================================================
// DORA Pillar 2: Incident Management
// =============================================================================

func TestDORA_INC1_IncidentDetection(t *testing.T) {
	// dora-inc-1: Detection and reporting within CSSF timelines
	// 4h initial → 24h detailed → 1 month final (via SERIMA portal)
	runDORAScenarios(t, []doraScenario{
		{
			name:       "compliant_full_detection_capability",
			controlID:  "dora-inc-1",
			wantStatus: "PASS",
			findings: []model.Finding{
				pass("C-0067", "kubescape"),
				pass("LYNIS-LOG-001", "lynis"), pass("LYNIS-LOG-002", "lynis"),
				pass("MACOS-LOG-001", "macos"),
				pass("WIN-AUD-001", "windows"), pass("WIN-AUD-002", "windows"),
				pass("WIN-AUD-003", "windows"),
			},
		},
		{
			name:       "violation_cssf_cannot_investigate_no_logs",
			controlID:  "dora-inc-1",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// Without these, CSSF cannot reconstruct incident timeline
				fail("C-0067", "kubescape"),
				fail("LYNIS-LOG-001", "lynis"),
				fail("LYNIS-LOG-002", "lynis"),
				fail("MACOS-LOG-001", "macos"),
				fail("WIN-AUD-001", "windows"),
				fail("WIN-AUD-002", "windows"),
				fail("WIN-AUD-003", "windows"),
			},
		},
	})
}

// =============================================================================
// DORA Pillar 3: Resilience Testing
// =============================================================================

func TestDORA_TEST1_ResilienceTesting(t *testing.T) {
	// dora-test-1: Annual vulnerability assessments
	runDORAScenarios(t, []doraScenario{
		{
			name:       "compliant_all_patched_and_monitored",
			controlID:  "dora-test-1",
			wantStatus: "PASS",
			findings: []model.Finding{
				pass("C-0005", "kubescape"), pass("C-0088", "kubescape"),
				pass("C-0053", "kubescape"), pass("C-0063", "kubescape"),
				pass("LYNIS-UPD-001", "lynis"), pass("LYNIS-UPD-002", "lynis"),
				pass("LYNIS-INT-001", "lynis"),
				pass("MACOS-UPD-001", "macos"),
				pass("WIN-AV-001", "windows"), pass("WIN-AV-002", "windows"),
				pass("WIN-UPD-001", "windows"), pass("WIN-UPD-002", "windows"),
			},
		},
		{
			name:       "violation_unpatched_systems",
			controlID:  "dora-test-1",
			wantStatus: "FAIL",
			findings: []model.Finding{
				pass("C-0005", "kubescape"), pass("C-0088", "kubescape"),
				fail("LYNIS-UPD-001", "lynis"), // updates not applied
				fail("LYNIS-UPD-002", "lynis"), // vulnerable packages
				fail("MACOS-UPD-001", "macos"), // pending macOS updates
				fail("WIN-AV-001", "windows"),  // Defender off
				fail("WIN-AV-002", "windows"),  // definitions outdated
				fail("WIN-UPD-001", "windows"), // WSUS off
				fail("WIN-UPD-002", "windows"), // auto-update off
				pass("C-0053", "kubescape"), pass("C-0063", "kubescape"),
				pass("LYNIS-INT-001", "lynis"),
			},
		},
	})
}

// =============================================================================
// DORA Pillar 4: Third-Party Risk
// =============================================================================

func TestDORA_TPP1_ThirdPartyRisk(t *testing.T) {
	// dora-tpp-1: Supply chain and register of information
	runDORAScenarios(t, []doraScenario{
		{
			name:       "compliant_verified_supply_chain",
			controlID:  "dora-tpp-1",
			wantStatus: "PASS",
			findings: []model.Finding{
				pass("C-0078", "kubescape"), // trusted registries
				pass("C-0079", "kubescape"), // pinned tags
				pass("C-0036", "kubescape"), // no sudo
				pass("C-0270", "kubescape"), // always pull
				pass("MACOS-GK-001", "macos"),
				pass("WIN-AV-001", "windows"),
			},
		},
		{
			name:       "violation_unverified_supply_chain",
			controlID:  "dora-tpp-1",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0078", "kubescape"), // untrusted registries
				fail("C-0079", "kubescape"), // :latest tags
				fail("C-0036", "kubescape"), // sudo in entrypoint
				fail("C-0270", "kubescape"), // IfNotPresent
				fail("MACOS-GK-001", "macos"), // Gatekeeper off
				fail("WIN-AV-001", "windows"), // Defender off
			},
		},
		{
			name:       "violation_latest_tags_only",
			controlID:  "dora-tpp-1",
			wantStatus: "WARN",
			findings: []model.Finding{
				pass("C-0078", "kubescape"),    // trusted registry ✓
				fail("C-0079", "kubescape"),    // :latest tag ✗
				pass("C-0036", "kubescape"),
				fail("C-0270", "kubescape"),    // IfNotPresent ✗
				pass("MACOS-GK-001", "macos"),
				pass("WIN-AV-001", "windows"),
			},
		},
	})
}

// =============================================================================
// DORA Authentication (Art. 9(2)) — cross-pillar requirement
// =============================================================================

func TestDORA_AUTH1_StrongAuthentication(t *testing.T) {
	// dora-auth-1: MFA required for all critical ICT system access
	// This is the most comprehensive control in DORA for Kubernetes+VM environments
	runDORAScenarios(t, []doraScenario{
		{
			name:       "compliant_mfa_everywhere",
			controlID:  "dora-auth-1",
			wantStatus: "PASS",
			findings: []model.Finding{
				// K8s: no anonymous, RBAC, no insecure port
				pass("C-0005", "kubescape"), pass("C-0088", "kubescape"),
				pass("C-0262", "kubescape"), pass("C-0035", "kubescape"),
				// Linux: SSH hardened, MFA via PAM, password policy
				pass("LYNIS-SSH-001", "lynis"), pass("LYNIS-SSH-002", "lynis"),
				pass("LYNIS-SSH-003", "lynis"), pass("LYNIS-AUTH-001", "lynis"),
				pass("LYNIS-AUTH-002", "lynis"), pass("LYNIS-AUTH-003", "lynis"),
				// macOS: screen lock, SSH controlled
				pass("MACOS-SCR-001", "macos"), pass("MACOS-SSH-001", "macos"),
				// Windows: RDP+NLA, password, screen lock
				pass("WIN-RDP-001", "windows"), pass("WIN-RDP-002", "windows"),
				pass("WIN-PWD-001", "windows"), pass("WIN-PWD-002", "windows"),
				pass("WIN-SCR-001", "windows"),
			},
		},
		{
			name:       "violation_no_mfa_on_any_system",
			controlID:  "dora-auth-1",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0005", "kubescape"),    // insecure port
				fail("C-0088", "kubescape"),    // no RBAC
				fail("C-0262", "kubescape"),    // anonymous auth
				fail("LYNIS-SSH-001", "lynis"), // root SSH allowed
				fail("LYNIS-AUTH-003", "lynis"),// no MFA
				fail("MACOS-SCR-001", "macos"), // no screen lock
				fail("WIN-RDP-002", "windows"), // RDP without NLA
				fail("WIN-SCR-001", "windows"), // no screen lock
				// Some passing to avoid all-FAIL
				pass("C-0035", "kubescape"),
				pass("LYNIS-SSH-002", "lynis"),
				pass("LYNIS-AUTH-001", "lynis"),
				pass("LYNIS-AUTH-002", "lynis"),
				pass("MACOS-SSH-001", "macos"),
				pass("WIN-PWD-001", "windows"),
				pass("WIN-PWD-002", "windows"),
				pass("WIN-RDP-001", "windows"),
			},
		},
		{
			name:       "violation_no_mfa_pam_module",
			controlID:  "dora-auth-1",
			wantStatus: "WARN",
			findings: []model.Finding{
				// K8s good
				pass("C-0005", "kubescape"), pass("C-0088", "kubescape"),
				pass("C-0262", "kubescape"), pass("C-0035", "kubescape"),
				// SSH hardened but no MFA PAM
				pass("LYNIS-SSH-001", "lynis"), pass("LYNIS-SSH-002", "lynis"),
				pass("LYNIS-SSH-003", "lynis"), pass("LYNIS-AUTH-001", "lynis"),
				pass("LYNIS-AUTH-002", "lynis"),
				fail("LYNIS-AUTH-003", "lynis"), // no MFA module — critical gap
				// macOS ok
				pass("MACOS-SCR-001", "macos"), pass("MACOS-SSH-001", "macos"),
				// Windows ok
				pass("WIN-RDP-001", "windows"), pass("WIN-RDP-002", "windows"),
				pass("WIN-PWD-001", "windows"), pass("WIN-PWD-002", "windows"),
				pass("WIN-SCR-001", "windows"),
			},
		},
	})
}

// =============================================================================
// Full DORA pipeline simulation — financial institution in Luxembourg
// =============================================================================

func TestDORA_FullPipeline_LuxembourgFinancialEntity(t *testing.T) {
	// Simulates a typical Luxembourg financial entity (bank / investment firm)
	// under CSSF supervision, running Kubernetes + Windows workstations + Linux servers
	fw, err := mapping.Load("dora")
	if err != nil {
		t.Fatalf("failed to load DORA: %v", err)
	}

	// Realistic findings for a mid-size LU financial entity
	// Good at K8s security, weak on host hardening and MFA
	findings := []model.Finding{
		// === Kubernetes: well-configured ===
		pass("C-0013", "kubescape"), pass("C-0017", "kubescape"),
		pass("C-0057", "kubescape"), pass("C-0016", "kubescape"),
		pass("C-0088", "kubescape"), pass("C-0004", "kubescape"),
		pass("C-0030", "kubescape"), pass("C-0031", "kubescape"),
		pass("C-0066", "kubescape"), pass("C-0079", "kubescape"),
		pass("C-0078", "kubescape"), pass("C-0270", "kubescape"),
		pass("C-0067", "kubescape"), // audit logging OK
		pass("C-0068", "kubescape"), pass("C-0069", "kubescape"),
		pass("C-0005", "kubescape"), pass("C-0262", "kubescape"),
		pass("C-0035", "kubescape"), pass("C-0036", "kubescape"),
		pass("C-0053", "kubescape"), pass("C-0063", "kubescape"),
		pass("C-0015", "kubescape"), pass("C-0058", "kubescape"),
		pass("C-0044", "kubescape"), pass("C-0041", "kubescape"),

		// === Linux servers: partial compliance ===
		pass("LYNIS-FW-001", "lynis"), pass("LYNIS-FW-002", "lynis"),
		pass("LYNIS-LOG-001", "lynis"),
		fail("LYNIS-LOG-002", "lynis"),  // auditd not running — gap
		pass("LYNIS-LOG-003", "lynis"),
		pass("LYNIS-ENC-001", "lynis"),
		pass("LYNIS-UPD-001", "lynis"),
		fail("LYNIS-UPD-002", "lynis"),  // some vulnerable packages
		pass("LYNIS-INT-001", "lynis"),
		pass("LYNIS-SSH-001", "lynis"), pass("LYNIS-SSH-002", "lynis"),
		fail("LYNIS-SSH-003", "lynis"),  // password SSH still enabled — gap
		pass("LYNIS-AUTH-001", "lynis"), pass("LYNIS-AUTH-002", "lynis"),
		fail("LYNIS-AUTH-003", "lynis"), // no MFA PAM — critical gap for DORA
		pass("LYNIS-KERN-001", "lynis"), pass("LYNIS-KERN-002", "lynis"),
		pass("LYNIS-USB-001", "lynis"),

		// === Windows workstations: good ===
		pass("WIN-BL-001", "windows"),
		pass("WIN-FW-001", "windows"), pass("WIN-FW-002", "windows"),
		pass("WIN-FW-003", "windows"),
		pass("WIN-AV-001", "windows"), pass("WIN-AV-002", "windows"),
		pass("WIN-UPD-001", "windows"), pass("WIN-UPD-002", "windows"),
		pass("WIN-AUD-001", "windows"), pass("WIN-AUD-002", "windows"),
		pass("WIN-AUD-003", "windows"),
		pass("WIN-PWD-001", "windows"), pass("WIN-PWD-002", "windows"),
		pass("WIN-RDP-001", "windows"), pass("WIN-RDP-002", "windows"),
		pass("WIN-UAC-001", "windows"),
		pass("WIN-SCR-001", "windows"), pass("WIN-SMB-001", "windows"),

		// === macOS (BYOD / management laptops): partial ===
		pass("MACOS-FV-001", "macos"),
		pass("MACOS-FW-001", "macos"), pass("MACOS-FW-002", "macos"),
		pass("MACOS-SIP-001", "macos"), pass("MACOS-GK-001", "macos"),
		pass("MACOS-UPD-001", "macos"),
		fail("MACOS-SCR-001", "macos"),  // screen lock not immediate — gap
		pass("MACOS-SSH-001", "macos"),
		pass("MACOS-LOG-001", "macos"),
		pass("MACOS-SHR-001", "macos"), pass("MACOS-SHR-002", "macos"),
		pass("MACOS-SHR-003", "macos"),
	}

	engine := mapping.NewEngine(fw)
	results := engine.Map(findings)
	scored, summary := scoring.Calculate(results)
	byID := indexByID(scored)

	// Print full DORA report
	t.Logf("\n=== DORA Compliance Report — LU Financial Entity ===")
	t.Logf("%-16s  %-36s  %-8s  %6s  %s",
		"Control", "Article / Name", "Severity", "Score", "Status")
	t.Logf("%s", strings.Repeat("─", 90))

	for _, cr := range scored {
		shortName := truncate(cr.Control.Name, 36)
		t.Logf("%-16s  %-36s  %-8s  %5.0f%%  %s",
			cr.Control.ID, shortName,
			cr.Control.Severity, cr.Score, cr.Status)
	}

	t.Logf("%s", strings.Repeat("─", 90))
	t.Logf("Overall DORA: %.1f%% %s | Pass=%d Warn=%d Fail=%d Skip=%d",
		summary.OverallScore, summary.Status,
		summary.TotalPass, summary.TotalWarn, summary.TotalFail, summary.TotalSkip)

	// Assertions about the realistic scenario
	// Auth should be WARN because MFA PAM is missing
	if byID["dora-auth-1"].Status == "PASS" {
		t.Error("dora-auth-1: should not be PASS without MFA PAM module on Linux")
	}

	// K8s business continuity should be PASS (well configured)
	if byID["dora-rm-4"].Status != "PASS" {
		t.Errorf("dora-rm-4: K8s is well configured, expected PASS, got %s",
			byID["dora-rm-4"].Status)
	}

	// Overall should not be FAIL (K8s is good, host has gaps)
	if summary.Status == "FAIL" && summary.OverallScore > 60 {
		t.Errorf("overall score %.1f%% should not be FAIL", summary.OverallScore)
	}

	// Log the gaps for the consultant
	t.Logf("\n=== Key Gaps for CSSF Audit ===")
	for _, cr := range scored {
		if cr.Status == "FAIL" || cr.Status == "WARN" {
			t.Logf("  [%s] %s — %s (%.0f%%): %s",
				cr.Control.Severity, cr.Control.ID,
				cr.Control.Article, cr.Score, cr.Control.Name)
		}
	}
}

// =============================================================================
// DORA vs NIS2 overlap test
// Many check IDs are shared between DORA and NIS2
// =============================================================================

func TestDORA_NIS2_SharedCheckIDs(t *testing.T) {
	doraFW, _ := mapping.Load("dora")
	nis2FW, _ := mapping.Load("nis2")

	doraChecks := make(map[string]bool)
	for _, c := range doraFW.Controls {
		for _, id := range c.MappedChecks {
			doraChecks[id] = true
		}
	}

	nis2Checks := make(map[string]bool)
	for _, c := range nis2FW.Controls {
		for _, id := range c.MappedChecks {
			nis2Checks[id] = true
		}
	}

	// Count overlapping check IDs
	overlap := 0
	for id := range doraChecks {
		if nis2Checks[id] {
			overlap++
		}
	}

	t.Logf("DORA check IDs: %d", len(doraChecks))
	t.Logf("NIS2 check IDs: %d", len(nis2Checks))
	t.Logf("Shared check IDs: %d", overlap)

	// There should be significant overlap — one scan covers both frameworks
	if overlap == 0 {
		t.Error("expected overlap between DORA and NIS2 check IDs — frameworks share technical controls")
	}

	overlapPct := float64(overlap) / float64(len(doraChecks)) * 100
	t.Logf("Overlap: %.0f%% of DORA checks also appear in NIS2", overlapPct)
}

func TestDORA_ScanBothFrameworks_SingleScan(t *testing.T) {
	// Verify that a single set of findings can score both DORA and NIS2
	// This is the key value proposition: one scan, two compliance reports
	findings := []model.Finding{
		pass("C-0067", "kubescape"), pass("C-0088", "kubescape"),
		pass("C-0030", "kubescape"), pass("C-0031", "kubescape"),
		pass("LYNIS-LOG-002", "lynis"), pass("LYNIS-FW-001", "lynis"),
		pass("WIN-AUD-001", "windows"), pass("WIN-FW-001", "windows"),
	}

	for _, fwID := range []string{"nis2", "dora"} {
		fw, err := mapping.Load(fwID)
		if err != nil {
			t.Fatalf("Load(%s) failed: %v", fwID, err)
		}
		engine := mapping.NewEngine(fw)
		results := engine.Map(findings)
		scored, summary := scoring.Calculate(results)

		hasData := false
		for _, cr := range scored {
			if cr.Status != "SKIP" {
				hasData = true
				break
			}
		}
		if !hasData {
			t.Errorf("%s: all controls SKIP — shared findings not mapping correctly", fwID)
		}
		t.Logf("%s: %.1f%% %s (Pass=%d Warn=%d Fail=%d Skip=%d)",
			fwID, summary.OverallScore, summary.Status,
			summary.TotalPass, summary.TotalWarn, summary.TotalFail, summary.TotalSkip)
	}
}

// =============================================================================
// Helpers
// =============================================================================

type doraScenario struct {
	name       string
	findings   []model.Finding
	controlID  string
	wantStatus string
}

func runDORAScenarios(t *testing.T, scenarios []doraScenario) {
	t.Helper()
	fw, err := mapping.Load("dora")
	if err != nil {
		t.Fatalf("failed to load DORA: %v", err)
	}
	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			engine := mapping.NewEngine(fw)
			results := engine.Map(s.findings)
			scored, _ := scoring.Calculate(results)
			cr := findControlByID(scored, s.controlID)
			if cr == nil {
				t.Fatalf("control %s not found", s.controlID)
			}
			if cr.Status != s.wantStatus {
				t.Errorf("%s: expected %s, got %s (score=%.1f%%)",
					s.controlID, s.wantStatus, cr.Status, cr.Score)
			}
			t.Logf("%-42s  %-5s  score=%.0f%%", s.name, cr.Status, cr.Score)
		})
	}
}
