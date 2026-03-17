package integration

// =============================================================================
// NIS2 Non-Compliance Detection Tests
// =============================================================================
// Każdy test weryfikuje że k8s-eu-audit poprawnie wykrywa naruszenia NIS2.
//
// PROGI SCORINGU:
//   score >= 80%  → PASS
//   score >= 50%  → WARN
//   score <  50%  → FAIL
//   brak findings → SKIP
//
// Żeby kontrolka była FAIL, więcej niż 50% jej mapped_checks musi być FAIL.
// Żeby była WARN, 50–79% musi być FAIL.
//
// Uruchom:
//   go test ./internal/integration/... -v -run TestViolation
//   go test ./internal/integration/... -v -run TestViolation_21a
// =============================================================================

import (
	"testing"

	"github.com/letzcode/k8s-eu-audit/internal/mapping"
	"github.com/letzcode/k8s-eu-audit/internal/model"
	"github.com/letzcode/k8s-eu-audit/internal/scoring"
)

// =============================================================================
// Helpers
// =============================================================================

type violationScenario struct {
	name       string
	findings   []model.Finding
	controlID  string
	wantStatus string
	// wantScoreAbove / wantScoreBelow — opcjonalne granice dla score
	wantScoreBelow float64 // 0 = nie sprawdzaj
	wantScoreAbove float64 // 0 = nie sprawdzaj
}

func runViolationScenarios(t *testing.T, scenarios []violationScenario) {
	t.Helper()
	fw, err := mapping.Load("nis2")
	if err != nil {
		t.Fatalf("failed to load NIS2 framework: %v", err)
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			engine := mapping.NewEngine(fw)
			results := engine.Map(s.findings)
			scored, _ := scoring.Calculate(results)
			cr := findControlByID(scored, s.controlID)
			if cr == nil {
				t.Fatalf("control %s not found in results", s.controlID)
			}
			if cr.Status != s.wantStatus {
				t.Errorf("control %s: expected %s, got %s (score=%.1f%%)",
					s.controlID, s.wantStatus, cr.Status, cr.Score)
			}
			if s.wantScoreBelow > 0 && cr.Score >= s.wantScoreBelow {
				t.Errorf("control %s: expected score < %.0f%%, got %.1f%%",
					s.controlID, s.wantScoreBelow, cr.Score)
			}
			if s.wantScoreAbove > 0 && cr.Score <= s.wantScoreAbove {
				t.Errorf("control %s: expected score > %.0f%%, got %.1f%%",
					s.controlID, s.wantScoreAbove, cr.Score)
			}
			t.Logf("%-42s  %-5s  score=%.0f%%", s.name, cr.Status, cr.Score)
		})
	}
}

// finding helpers
func pass(controlID, source string) model.Finding {
	return model.Finding{ControlID: controlID, Source: source, Status: model.StatusPass, Severity: model.SeverityHigh}
}
func fail(controlID, source string) model.Finding {
	return model.Finding{ControlID: controlID, Source: source, Status: model.StatusFail, Severity: model.SeverityHigh}
}

// =============================================================================
// 21.2(a) — Risk analysis & IS policies
//
// mapped_checks dla art21-2-a: C-0013, C-0017, C-0057, C-0016, C-0020, C-0055
// (6 checks)
//
// Progi:
//   6/6 pass = 100% → PASS
//   5/6 pass =  83% → PASS  (powyżej 80%)
//   4/6 pass =  67% → WARN
//   3/6 pass =  50% → WARN  (dokładnie 50%)
//   2/6 pass =  33% → FAIL
//   0/6 pass =   0% → FAIL
// =============================================================================

func TestViolation_21a_PrivilegedContainer(t *testing.T) {
	runViolationScenarios(t, []violationScenario{
		{
			// 6/6 pass = 100% → PASS
			name:       "compliant_all_checks_pass",
			controlID:  "art21-2-a",
			wantStatus: "PASS",
			findings: []model.Finding{
				pass("C-0013", "kubescape"),
				pass("C-0017", "kubescape"),
				pass("C-0057", "kubescape"),
				pass("C-0016", "kubescape"),
				pass("C-0020", "kubescape"),
				pass("C-0055", "kubescape"),
			},
		},
		{
			// 1/6 pass = 17% → FAIL
			// privileged:true + root + escalation + writable fs + unsafe caps + SA mount
			// Odwzorowanie namespace noncompliant-21a z YAML (5 FAILów, 1 PASS)
			name:           "violation_majority_failing",
			controlID:      "art21-2-a",
			wantStatus:     "FAIL",
			wantScoreBelow: 50,
			findings: []model.Finding{
				fail("C-0057", "kubescape"), // privileged: true
				fail("C-0013", "kubescape"), // runs as root
				fail("C-0016", "kubescape"), // allowPrivilegeEscalation: true
				fail("C-0017", "kubescape"), // readOnlyRootFilesystem: false
				fail("C-0046", "kubescape"), // NET_ADMIN + SYS_ADMIN caps
				pass("C-0020", "kubescape"), // jedyna dobra rzecz
			},
		},
		{
			// 0/6 pass = 0% → FAIL (wszystko złe)
			name:       "violation_all_checks_fail",
			controlID:  "art21-2-a",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0013", "kubescape"),
				fail("C-0017", "kubescape"),
				fail("C-0057", "kubescape"),
				fail("C-0016", "kubescape"),
				fail("C-0020", "kubescape"),
				fail("C-0055", "kubescape"),
			},
		},
		{
			// 3/6 pass = 50% → WARN (dokładnie na granicy WARN)
			// Połowa checks dobra, połowa zła
			name:       "partial_half_failing",
			controlID:  "art21-2-a",
			wantStatus: "WARN",
			findings: []model.Finding{
				fail("C-0057", "kubescape"),
				fail("C-0013", "kubescape"),
				fail("C-0016", "kubescape"),
				pass("C-0017", "kubescape"),
				pass("C-0020", "kubescape"),
				pass("C-0055", "kubescape"),
			},
		},
		{
			// 4/6 pass = 67% → WARN
			// Jeden krytyczny problem (privileged) przy reszcie ok
			name:       "partial_one_critical_violation",
			controlID:  "art21-2-a",
			wantStatus: "WARN",
			findings: []model.Finding{
				fail("C-0057", "kubescape"), // tylko privileged fail
				fail("C-0013", "kubescape"), // i root
				pass("C-0017", "kubescape"),
				pass("C-0016", "kubescape"),
				pass("C-0020", "kubescape"),
				pass("C-0055", "kubescape"),
			},
		},
		{
			// 5/6 pass = 83% → PASS (powyżej progu 80%)
			// Jedna drobna rzecz zła nie obniża do WARN
			name:           "near_compliant_one_minor_issue",
			controlID:      "art21-2-a",
			wantStatus:     "PASS",
			wantScoreAbove: 80,
			findings: []model.Finding{
				pass("C-0013", "kubescape"),
				pass("C-0057", "kubescape"),
				pass("C-0016", "kubescape"),
				pass("C-0017", "kubescape"),
				pass("C-0020", "kubescape"),
				fail("C-0055", "kubescape"), // tylko seccomp brak
			},
		},
	})
}

// =============================================================================
// 21.2(b) — Incident handling
//
// mapped_checks: C-0067
// (1 check — zero/jedynkowy: albo audit jest albo go nie ma)
//
// Progi:
//   1/1 pass = 100% → PASS
//   0/1 pass =   0% → FAIL
//   brak        = SKIP
// =============================================================================

func TestViolation_21b_AuditLogging(t *testing.T) {
	runViolationScenarios(t, []violationScenario{
		{
			// kube-apiserver z --audit-log-path i --audit-policy-file
			name:       "compliant_audit_fully_configured",
			controlID:  "art21-2-b",
			wantStatus: "PASS",
			findings: []model.Finding{
				pass("C-0067", "kubescape"),
			},
		},
		{
			// Domyślna instalacja minikube/kind — brak --audit-log-path
			// JEDEN check, JEDEN FAIL = 0% → FAIL
			name:       "violation_no_audit_log_path",
			controlID:  "art21-2-b",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0067", "kubescape"),
			},
		},
		{
			// Skaner niedostępny lub nie zwrócił wyników → SKIP
			name:       "skip_no_scanner_data",
			controlID:  "art21-2-b",
			wantStatus: "SKIP",
			findings:   []model.Finding{},
		},
	})
}

// =============================================================================
// 21.2(c) — Business continuity
//
// mapped_checks: C-0068, C-0069
// (2 checks)
//
// Progi:
//   2/2 pass = 100% → PASS
//   1/2 pass =  50% → WARN
//   0/2 pass =   0% → FAIL
// =============================================================================

func TestViolation_21c_BusinessContinuity(t *testing.T) {
	runViolationScenarios(t, []violationScenario{
		{
			// replicas: 2+, PDB zdefiniowany dla każdego deployment
			name:       "compliant_multi_replica_with_pdb",
			controlID:  "art21-2-c",
			wantStatus: "PASS",
			findings: []model.Finding{
				pass("C-0068", "kubescape"),
				pass("C-0069", "kubescape"),
			},
		},
		{
			// replicas: 1 AND brak PDB — oba checks fail = 0% → FAIL
			// Odwzorowanie namespace noncompliant-21c z YAML
			name:       "violation_single_replica_and_no_pdb",
			controlID:  "art21-2-c",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0068", "kubescape"), // single replica
				fail("C-0069", "kubescape"), // no PDB
			},
		},
		{
			// replicas: 1 ale PDB istnieje — 1/2 = 50% → WARN
			name:       "partial_single_replica_but_pdb_exists",
			controlID:  "art21-2-c",
			wantStatus: "WARN",
			findings: []model.Finding{
				fail("C-0068", "kubescape"), // single replica — ryzyko
				pass("C-0069", "kubescape"), // ale PDB jest
			},
		},
		{
			// multi replica ale brak PDB — 1/2 = 50% → WARN
			name:       "partial_multi_replica_but_no_pdb",
			controlID:  "art21-2-c",
			wantStatus: "WARN",
			findings: []model.Finding{
				pass("C-0068", "kubescape"), // multi replica ok
				fail("C-0069", "kubescape"), // brak PDB
			},
		},
	})
}

// =============================================================================
// 21.2(d) — Supply chain security
//
// mapped_checks: C-0036, C-0014, C-0270, C-0046
// (4 checks)
//
// Progi:
//   4/4 pass = 100% → PASS
//   3/4 pass =  75% → WARN
//   2/4 pass =  50% → WARN
//   1/4 pass =  25% → FAIL
//   0/4 pass =   0% → FAIL
// =============================================================================

func TestViolation_21d_SupplyChain(t *testing.T) {
	runViolationScenarios(t, []violationScenario{
		{
			// image: nginx:1.25.3, imagePullPolicy: Always, no sudo, no unsafe caps
			name:       "compliant_pinned_tag_always_pull",
			controlID:  "art21-2-d",
			wantStatus: "PASS",
			findings: []model.Finding{
				pass("C-0036", "kubescape"),
				pass("C-0014", "kubescape"),
				pass("C-0270", "kubescape"),
				pass("C-0046", "kubescape"),
			},
		},
		{
			// image:latest + IfNotPresent + unsafe caps + no memory request = 0% → FAIL
			// Odwzorowanie namespace noncompliant-21d z YAML
			name:       "violation_all_supply_chain_bad",
			controlID:  "art21-2-d",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0036", "kubescape"), // latest tag
				fail("C-0014", "kubescape"), // no memory request
				fail("C-0270", "kubescape"), // IfNotPresent
				fail("C-0046", "kubescape"), // unsafe capabilities
			},
		},
		{
			// Tylko latest tag, reszta ok — 3/4 = 75% → WARN
			name:       "partial_only_latest_tag",
			controlID:  "art21-2-d",
			wantStatus: "WARN",
			findings: []model.Finding{
				fail("C-0036", "kubescape"), // nginx:latest
				pass("C-0014", "kubescape"),
				pass("C-0270", "kubescape"),
				pass("C-0046", "kubescape"),
			},
		},
		{
			// Latest + IfNotPresent, reszta ok — 2/4 = 50% → WARN
			name:       "partial_latest_and_wrong_pullpolicy",
			controlID:  "art21-2-d",
			wantStatus: "WARN",
			findings: []model.Finding{
				fail("C-0036", "kubescape"), // latest tag
				fail("C-0270", "kubescape"), // IfNotPresent
				pass("C-0014", "kubescape"),
				pass("C-0046", "kubescape"),
			},
		},
		{
			// 3 złe, 1 dobra = 25% → FAIL
			name:       "violation_three_of_four_failing",
			controlID:  "art21-2-d",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0036", "kubescape"),
				fail("C-0014", "kubescape"),
				fail("C-0270", "kubescape"),
				pass("C-0046", "kubescape"),
			},
		},
	})
}

// =============================================================================
// 21.2(e) — Network & IS security
//
// mapped_checks: C-0030, C-0031, C-0066
// (3 checks)
//
// Progi:
//   3/3 pass = 100% → PASS
//   2/3 pass =  67% → WARN
//   1/3 pass =  33% → FAIL
//   0/3 pass =   0% → FAIL
// =============================================================================

func TestViolation_21e_NetworkSecurity(t *testing.T) {
	runViolationScenarios(t, []violationScenario{
		{
			// NetworkPolicy default-deny + allow rules + etcd encryption
			name:       "compliant_full_network_isolation",
			controlID:  "art21-2-e",
			wantStatus: "PASS",
			findings: []model.Finding{
				pass("C-0030", "kubescape"),
				pass("C-0031", "kubescape"),
				pass("C-0066", "kubescape"),
			},
		},
		{
			// Brak NetworkPolicy w namespace — C-0030 i C-0031 FAIL
			// 1/3 = 33% → FAIL
			// Odwzorowanie namespace noncompliant-21e
			name:       "violation_no_network_policy",
			controlID:  "art21-2-e",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0030", "kubescape"),
				fail("C-0031", "kubescape"),
				pass("C-0066", "kubescape"),
			},
		},
		{
			// Kompletnie brak jakiejkolwiek NetworkPolicy, brak etcd encryption
			// 0/3 = 0% → FAIL
			name:       "violation_no_network_policy_no_etcd_encryption",
			controlID:  "art21-2-e",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0030", "kubescape"),
				fail("C-0031", "kubescape"),
				fail("C-0066", "kubescape"),
			},
		},
		{
			// NetworkPolicy istnieje ale nie blokuje egress — 2/3 = 67% → WARN
			name:       "partial_ingress_only_no_egress_control",
			controlID:  "art21-2-e",
			wantStatus: "WARN",
			findings: []model.Finding{
				fail("C-0030", "kubescape"), // brak egress blocking
				pass("C-0031", "kubescape"), // NetworkPolicy istnieje
				pass("C-0066", "kubescape"),
			},
		},
	})
}

// =============================================================================
// 21.2(g) — Assess effectiveness
//
// mapped_checks: C-0005, C-0088, C-0053, C-0063
// (4 checks)
//
// Progi:
//   4/4 = 100% → PASS
//   3/4 =  75% → WARN
//   2/4 =  50% → WARN
//   1/4 =  25% → FAIL
//   0/4 =   0% → FAIL
// =============================================================================

func TestViolation_21g_Effectiveness(t *testing.T) {
	runViolationScenarios(t, []violationScenario{
		{
			// RBAC enabled, no insecure port, minimal SA scope, etcd TLS
			name:       "compliant_fully_hardened_apiserver",
			controlID:  "art21-2-g",
			wantStatus: "PASS",
			findings: []model.Finding{
				pass("C-0005", "kubescape"),
				pass("C-0088", "kubescape"),
				pass("C-0053", "kubescape"),
				pass("C-0063", "kubescape"),
			},
		},
		{
			// Wildcard SA permissions + RBAC off + insecure port + no etcd TLS = 0% → FAIL
			// Najgorsza możliwa konfiguracja
			name:       "violation_all_effectiveness_checks_fail",
			controlID:  "art21-2-g",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0005", "kubescape"), // insecure port
				fail("C-0088", "kubescape"), // no RBAC
				fail("C-0053", "kubescape"), // wildcard SA
				fail("C-0063", "kubescape"), // no etcd peer TLS
			},
		},
		{
			// Tylko wildcard SA — reszta ok — 3/4 = 75% → WARN
			// Odwzorowanie namespace noncompliant-21g
			name:       "partial_wildcard_sa_only",
			controlID:  "art21-2-g",
			wantStatus: "WARN",
			findings: []model.Finding{
				fail("C-0053", "kubescape"), // wildcard SA permissions
				pass("C-0005", "kubescape"),
				pass("C-0088", "kubescape"),
				pass("C-0063", "kubescape"),
			},
		},
		{
			// RBAC off + insecure port — 2/4 = 50% → WARN
			name:       "partial_rbac_and_port_failing",
			controlID:  "art21-2-g",
			wantStatus: "WARN",
			findings: []model.Finding{
				fail("C-0005", "kubescape"), // insecure port
				fail("C-0088", "kubescape"), // no RBAC
				pass("C-0053", "kubescape"),
				pass("C-0063", "kubescape"),
			},
		},
		{
			// 3 złe = 25% → FAIL
			name:       "violation_three_of_four_failing",
			controlID:  "art21-2-g",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0005", "kubescape"),
				fail("C-0088", "kubescape"),
				fail("C-0053", "kubescape"),
				pass("C-0063", "kubescape"),
			},
		},
	})
}

// =============================================================================
// 21.2(h) — Basic cyber hygiene
//
// mapped_checks: C-0035, C-0041, C-0044, C-0048, C-0038
// (5 checks)
//
// Progi:
//   5/5 = 100% → PASS
//   4/5 =  80% → PASS  (dokładnie na granicy)
//   3/5 =  60% → WARN
//   2/5 =  40% → FAIL
//   0/5 =   0% → FAIL
// =============================================================================

func TestViolation_21h_CyberHygiene(t *testing.T) {
	runViolationScenarios(t, []violationScenario{
		{
			// Żadnego cluster-admin, automount off, no hostPort, no hostPath, no hostPID
			name:       "compliant_minimal_privileges",
			controlID:  "art21-2-h",
			wantStatus: "PASS",
			findings: []model.Finding{
				pass("C-0035", "kubescape"),
				pass("C-0041", "kubescape"),
				pass("C-0044", "kubescape"),
				pass("C-0048", "kubescape"),
				pass("C-0038", "kubescape"),
			},
		},
		{
			// cluster-admin + automount + hostPort = 3 FAILy, 2 PASSy
			// 2/5 = 40% → FAIL
			// Odwzorowanie namespace noncompliant-21h
			name:       "violation_cluster_admin_plus_hostport",
			controlID:  "art21-2-h",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0035", "kubescape"), // cluster-admin binding
				fail("C-0041", "kubescape"), // automountServiceAccountToken: true
				fail("C-0044", "kubescape"), // hostPort: 80
				pass("C-0048", "kubescape"),
				pass("C-0038", "kubescape"),
			},
		},
		{
			// Wszystko złe = 0% → FAIL
			name:       "violation_all_hygiene_checks_fail",
			controlID:  "art21-2-h",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0035", "kubescape"),
				fail("C-0041", "kubescape"),
				fail("C-0044", "kubescape"),
				fail("C-0048", "kubescape"),
				fail("C-0038", "kubescape"),
			},
		},
		{
			// Tylko 1 problem (cluster-admin) — 4/5 = 80% → PASS
			// Jeden cluster-admin binding nie obniża do WARN przy 5 checks
			name:           "near_compliant_only_cluster_admin",
			controlID:      "art21-2-h",
			wantStatus:     "PASS",
			wantScoreAbove: 79,
			findings: []model.Finding{
				fail("C-0035", "kubescape"), // cluster-admin
				pass("C-0041", "kubescape"),
				pass("C-0044", "kubescape"),
				pass("C-0048", "kubescape"),
				pass("C-0038", "kubescape"),
			},
		},
		{
			// 2 problemy — 3/5 = 60% → WARN
			name:       "partial_two_violations",
			controlID:  "art21-2-h",
			wantStatus: "WARN",
			findings: []model.Finding{
				fail("C-0035", "kubescape"),
				fail("C-0044", "kubescape"),
				pass("C-0041", "kubescape"),
				pass("C-0048", "kubescape"),
				pass("C-0038", "kubescape"),
			},
		},
	})
}

// =============================================================================
// 21.2(i) — Access control & asset management
//
// mapped_checks: C-0015, C-0058, C-0036, C-0187, C-0188
// (5 checks — uwaga: C-0036 jest też w 21.2(d))
//
// Progi identyczne jak 21.2(h) — 5 checks
// =============================================================================

func TestViolation_21i_AccessControl(t *testing.T) {
	runViolationScenarios(t, []violationScenario{
		{
			// Żadnej roli z dostępem do secrets, brak delete perms
			name:       "compliant_minimal_access_control",
			controlID:  "art21-2-i",
			wantStatus: "PASS",
			findings: []model.Finding{
				pass("C-0015", "kubescape"),
				pass("C-0058", "kubescape"),
				pass("C-0036", "kubescape"),
				pass("C-0187", "kubescape"),
				pass("C-0188", "kubescape"),
			},
		},
		{
			// ClusterRole z secrets + delete perms + privileged role = 3 FAILy
			// 2/5 = 40% → FAIL
			// Odwzorowanie namespace noncompliant-21i
			name:       "violation_secrets_and_delete_access",
			controlID:  "art21-2-i",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0015", "kubescape"), // privileged RBAC
				fail("C-0058", "kubescape"), // secrets: [get, list]
				fail("C-0187", "kubescape"), // pods: [delete]
				pass("C-0036", "kubescape"),
				pass("C-0188", "kubescape"),
			},
		},
		{
			// Wszystkie checks fail = 0% → FAIL
			name:       "violation_all_access_controls_fail",
			controlID:  "art21-2-i",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0015", "kubescape"),
				fail("C-0058", "kubescape"),
				fail("C-0036", "kubescape"),
				fail("C-0187", "kubescape"),
				fail("C-0188", "kubescape"),
			},
		},
		{
			// Tylko role która czyta secrets — 4/5 = 80% → PASS
			// Jeden problem niewystarczający żeby zejść do WARN
			name:           "near_compliant_only_secrets_reader",
			controlID:      "art21-2-i",
			wantStatus:     "PASS",
			wantScoreAbove: 79,
			findings: []model.Finding{
				pass("C-0015", "kubescape"),
				fail("C-0058", "kubescape"), // jedna rola czyta secrets
				pass("C-0036", "kubescape"),
				pass("C-0187", "kubescape"),
				pass("C-0188", "kubescape"),
			},
		},
		{
			// 2 problemy — 3/5 = 60% → WARN
			name:       "partial_secrets_and_delete",
			controlID:  "art21-2-i",
			wantStatus: "WARN",
			findings: []model.Finding{
				pass("C-0015", "kubescape"),
				fail("C-0058", "kubescape"),
				pass("C-0036", "kubescape"),
				fail("C-0187", "kubescape"),
				pass("C-0188", "kubescape"),
			},
		},
	})
}

// =============================================================================
// 21.2(j) — MFA and continuous authentication
//
// mapped_checks: C-0005, C-0088, C-0262, C-0256
// (4 checks)
//
// Progi:
//   4/4 = 100% → PASS
//   3/4 =  75% → WARN
//   2/4 =  50% → WARN
//   1/4 =  25% → FAIL
//   0/4 =   0% → FAIL
// =============================================================================

func TestViolation_21j_Authentication(t *testing.T) {
	runViolationScenarios(t, []violationScenario{
		{
			// anonymous-auth=false, RBAC enabled, no insecure port, probes set
			name:       "compliant_strong_authentication",
			controlID:  "art21-2-j",
			wantStatus: "PASS",
			findings: []model.Finding{
				pass("C-0005", "kubescape"),
				pass("C-0088", "kubescape"),
				pass("C-0262", "kubescape"),
				pass("C-0256", "kubescape"),
			},
		},
		{
			// anonymous-auth=true — 3/4 = 75% → WARN
			// Odwzorowanie violation-21j-marker z YAML
			// (minikube domyślnie może mieć anonymous auth)
			name:       "partial_anonymous_auth_enabled",
			controlID:  "art21-2-j",
			wantStatus: "WARN",
			findings: []model.Finding{
				pass("C-0005", "kubescape"),
				pass("C-0088", "kubescape"),
				fail("C-0262", "kubescape"), // anonymous auth ON
				pass("C-0256", "kubescape"),
			},
		},
		{
			// Insecure port + no RBAC = 2/4 = 50% → WARN
			name:       "partial_no_rbac_and_insecure_port",
			controlID:  "art21-2-j",
			wantStatus: "WARN",
			findings: []model.Finding{
				fail("C-0005", "kubescape"), // insecure port open
				fail("C-0088", "kubescape"), // no RBAC
				pass("C-0262", "kubescape"),
				pass("C-0256", "kubescape"),
			},
		},
		{
			// 3 złe = 25% → FAIL
			name:       "violation_three_auth_checks_fail",
			controlID:  "art21-2-j",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0005", "kubescape"),
				fail("C-0088", "kubescape"),
				fail("C-0262", "kubescape"),
				pass("C-0256", "kubescape"),
			},
		},
		{
			// Wszystko złe — insecure port + no RBAC + anonymous + no probes = 0% → FAIL
			name:       "violation_all_auth_controls_fail",
			controlID:  "art21-2-j",
			wantStatus: "FAIL",
			findings: []model.Finding{
				fail("C-0005", "kubescape"),
				fail("C-0088", "kubescape"),
				fail("C-0262", "kubescape"),
				fail("C-0256", "kubescape"),
			},
		},
	})
}

// =============================================================================
// Cross-article tests
// =============================================================================

func TestViolation_CrossArticle_PrivilegedNamespace(t *testing.T) {
	t.Run("namespace_without_podsecurity_affects_21a_and_21h", func(t *testing.T) {
		fw, _ := mapping.Load("nis2")
		engine := mapping.NewEngine(fw)

		findings := []model.Finding{
			// art21-2-a: 5 FAILy / 1 PASS = 17% → FAIL
			fail("C-0057", "kubescape"),
			fail("C-0013", "kubescape"),
			fail("C-0016", "kubescape"),
			fail("C-0017", "kubescape"),
			fail("C-0046", "kubescape"),
			pass("C-0020", "kubescape"),
			// art21-2-h: 3 FAILy / 2 PASSy = 40% → FAIL
			fail("C-0044", "kubescape"),
			fail("C-0048", "kubescape"),
			fail("C-0038", "kubescape"),
			pass("C-0041", "kubescape"),
			pass("C-0035", "kubescape"),
			// inne — ok
			pass("C-0088", "kubescape"),
			pass("C-0031", "kubescape"),
		}

		results := engine.Map(findings)
		scored, summary := scoring.Calculate(results)
		byID := indexByID(scored)

		if byID["art21-2-a"].Status != "FAIL" {
			t.Errorf("art21-2-a: expected FAIL, got %s (score=%.1f%%)",
				byID["art21-2-a"].Status, byID["art21-2-a"].Score)
		}
		if byID["art21-2-h"].Status != "FAIL" {
			t.Errorf("art21-2-h: expected FAIL, got %s (score=%.1f%%)",
				byID["art21-2-h"].Status, byID["art21-2-h"].Score)
		}
		if summary.Status == "PASS" {
			t.Error("cluster with privileged namespace should not be overall PASS")
		}

		t.Logf("Cross-article: 21a=%s(%.0f%%) 21h=%s(%.0f%%) overall=%.1f%% %s",
			byID["art21-2-a"].Status, byID["art21-2-a"].Score,
			byID["art21-2-h"].Status, byID["art21-2-h"].Score,
			summary.OverallScore, summary.Status)
	})
}

func TestViolation_CrossArticle_MissingNetworkAndAudit(t *testing.T) {
	t.Run("no_network_policy_and_no_audit", func(t *testing.T) {
		fw, _ := mapping.Load("nis2")
		engine := mapping.NewEngine(fw)

		findings := []model.Finding{
			fail("C-0067", "kubescape"), // no audit — art21-2-b → FAIL (1/1)
			fail("C-0030", "kubescape"), // no NetworkPolicy
			fail("C-0031", "kubescape"), // no NetworkPolicy → art21-2-e: 1/3 = 33% → FAIL
			pass("C-0066", "kubescape"),
			pass("C-0057", "kubescape"),
			pass("C-0088", "kubescape"),
		}

		results := engine.Map(findings)
		scored, _ := scoring.Calculate(results)
		byID := indexByID(scored)

		if byID["art21-2-b"].Status != "FAIL" {
			t.Errorf("art21-2-b: expected FAIL, got %s", byID["art21-2-b"].Status)
		}
		if byID["art21-2-e"].Status != "FAIL" {
			t.Errorf("art21-2-e: expected FAIL, got %s", byID["art21-2-e"].Status)
		}
		t.Logf("No audit + no network: 21b=%s 21e=%s",
			byID["art21-2-b"].Status, byID["art21-2-e"].Status)
	})
}

// =============================================================================
// Snapshot test — pełna symulacja kubectl apply -f nis2-noncompliant-cluster.yaml
// =============================================================================

func TestViolation_AllNonCompliantNamespaces(t *testing.T) {
	fw, err := mapping.Load("nis2")
	if err != nil {
		t.Fatalf("failed to load NIS2: %v", err)
	}

	// Findings po zastosowaniu całego nis2-noncompliant-cluster.yaml
	// Każda sekcja jest zaprojektowana żeby mieć większość checks jako FAIL
	allViolationFindings := []model.Finding{
		// art21-2-a: 5/6 FAIL = 17% → FAIL
		fail("C-0057", "kubescape"),
		fail("C-0013", "kubescape"),
		fail("C-0016", "kubescape"),
		fail("C-0017", "kubescape"),
		fail("C-0046", "kubescape"),
		pass("C-0020", "kubescape"),
		fail("C-0055", "kubescape"),

		// art21-2-b: 1/1 FAIL = 0% → FAIL
		fail("C-0067", "kubescape"),

		// art21-2-c: 2/2 FAIL = 0% → FAIL
		fail("C-0068", "kubescape"),
		fail("C-0069", "kubescape"),

		// art21-2-d: 4/4 FAIL = 0% → FAIL
		fail("C-0036", "kubescape"),
		fail("C-0014", "kubescape"),
		fail("C-0270", "kubescape"),
		fail("C-0046", "kubescape"),

		// art21-2-e: 2/3 FAIL = 33% → FAIL
		fail("C-0030", "kubescape"),
		fail("C-0031", "kubescape"),
		pass("C-0066", "kubescape"),

		// art21-2-g: 3/4 FAIL = 25% → FAIL
		fail("C-0053", "kubescape"),
		fail("C-0005", "kubescape"),
		fail("C-0063", "kubescape"),
		pass("C-0088", "kubescape"),

		// art21-2-h: 3/5 FAIL = 40% → FAIL
		fail("C-0035", "kubescape"),
		fail("C-0041", "kubescape"),
		fail("C-0044", "kubescape"),
		pass("C-0048", "kubescape"),
		pass("C-0038", "kubescape"),

		// art21-2-i: 3/5 FAIL = 40% → FAIL
		fail("C-0015", "kubescape"),
		fail("C-0058", "kubescape"),
		fail("C-0187", "kubescape"),
		pass("C-0188", "kubescape"),

		// art21-2-j: 3/4 FAIL = 25% → FAIL
		fail("C-0262", "kubescape"),
		fail("C-0005", "kubescape"),
		fail("C-0088", "kubescape"),
		pass("C-0256", "kubescape"),
	}

	engine := mapping.NewEngine(fw)
	results := engine.Map(allViolationFindings)
	scored, summary := scoring.Calculate(results)
	byID := indexByID(scored)

	// Wszystkie artykuły powinny być FAIL przy tak wielu naruszeniach
	expected := map[string]string{
		"art21-2-a": "FAIL",
		"art21-2-b": "FAIL",
		"art21-2-c": "FAIL",
		"art21-2-d": "FAIL",
		"art21-2-e": "FAIL",
		"art21-2-g": "FAIL",
		"art21-2-h": "FAIL",
		"art21-2-i": "FAIL",
		"art21-2-j": "FAIL",
	}

	t.Logf("\n=== All Non-Compliant Namespaces Scan ===")
	t.Logf("%-14s  %-8s  %-8s  %s", "Control", "Expected", "Got", "")
	t.Logf("%s", "─────────────────────────────────────────")

	allPassed := true
	for controlID, want := range expected {
		cr := byID[controlID]
		icon := "✓"
		if cr.Status != want {
			icon = "✗"
			allPassed = false
			t.Errorf("%s: expected %s, got %s (score=%.1f%%)",
				controlID, want, cr.Status, cr.Score)
		}
		t.Logf("%-14s  %-8s  %-8s  %s  score=%.0f%%",
			controlID, want, cr.Status, icon, cr.Score)
	}

	t.Logf("%s", "─────────────────────────────────────────")
	t.Logf("Overall: %.1f%% %s | Pass=%d Warn=%d Fail=%d Skip=%d",
		summary.OverallScore, summary.Status,
		summary.TotalPass, summary.TotalWarn, summary.TotalFail, summary.TotalSkip)

	if summary.Status == "PASS" {
		t.Error("cluster with violations across all articles should NOT be PASS")
	}
	if summary.OverallScore > 50 {
		t.Errorf("heavily violated cluster should score below 50%%, got %.1f%%",
			summary.OverallScore)
	}

	if allPassed {
		t.Log("\n✓ All violation detections correct")
	}
}
