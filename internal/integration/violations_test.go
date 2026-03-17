package integration

// =============================================================================
// NIS2 Non-Compliance Detection Tests
// =============================================================================
// Każdy test weryfikuje że k8s-eu-audit poprawnie wykrywa
// JEDNO konkretne naruszenie z nis2-noncompliant-cluster.yaml.
//
// Struktura każdego testu:
//   1. COMPLIANT   — konfiguracja spełniająca wymóg → oczekiwany PASS
//   2. VIOLATION   — konfiguracja łamiąca wymóg     → oczekiwany FAIL/WARN
//   3. PARTIAL     — częściowe naruszenie            → oczekiwany WARN
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
	name      string
	findings  []model.Finding
	controlID string
	wantStatus string
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
			t.Logf("%-20s  %s  score=%.0f%%  ✓", s.name, cr.Status, cr.Score)
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
func passLow(controlID, source string) model.Finding {
	return model.Finding{ControlID: controlID, Source: source, Status: model.StatusPass, Severity: model.SeverityLow}
}

// =============================================================================
// 21.2(a) — Risk analysis & IS policies
// Violations: privileged container, no readOnlyRootFilesystem,
//             allowPrivilegeEscalation, runs as root, unsafe capabilities
// =============================================================================

func TestViolation_21a_PrivilegedContainer(t *testing.T) {
	// Maps to: C-0057 (privileged), C-0013 (non-root), C-0016 (escalation),
	//          C-0017 (readOnly), C-0055 (hardening), C-0020 (SA mount)
	runViolationScenarios(t, []violationScenario{
		{
			name:       "compliant_all_pass",
			controlID:  "art21-2-a",
			wantStatus: "PASS",
			findings: []model.Finding{
				pass("C-0013", "kubescape"), // non-root ✓
				pass("C-0017", "kubescape"), // readOnly ✓
				pass("C-0057", "kubescape"), // not privileged ✓
				pass("C-0016", "kubescape"), // no escalation ✓
				pass("C-0020", "kubescape"), // no SA mount ✓
				pass("C-0055", "kubescape"), // hardening ✓
			},
		},
		{
			name:       "violation_privileged_true",
			controlID:  "art21-2-a",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// privileged: true → C-0057 FAIL
				fail("C-0057", "kubescape"),
				pass("C-0013", "kubescape"),
				pass("C-0017", "kubescape"),
				pass("C-0016", "kubescape"),
			},
		},
		{
			name:       "violation_runs_as_root",
			controlID:  "art21-2-a",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// runAsNonRoot: false → C-0013 FAIL
				fail("C-0013", "kubescape"),
				pass("C-0057", "kubescape"),
				pass("C-0017", "kubescape"),
				pass("C-0016", "kubescape"),
			},
		},
		{
			name:       "violation_allow_privilege_escalation",
			controlID:  "art21-2-a",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// allowPrivilegeEscalation: true → C-0016 FAIL
				fail("C-0016", "kubescape"),
				pass("C-0013", "kubescape"),
				pass("C-0057", "kubescape"),
				pass("C-0017", "kubescape"),
			},
		},
		{
			name:       "violation_writable_filesystem",
			controlID:  "art21-2-a",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// readOnlyRootFilesystem: false → C-0017 FAIL
				fail("C-0017", "kubescape"),
				pass("C-0013", "kubescape"),
				pass("C-0057", "kubescape"),
				pass("C-0016", "kubescape"),
			},
		},
		{
			name:       "violation_all_bad_namespace_noncompliant_21a",
			controlID:  "art21-2-a",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// Odwzorowanie namespace noncompliant-21a z YAML:
				// privileged: true, runAsRoot, allowPrivilegeEscalation,
				// NET_ADMIN + SYS_ADMIN capabilities
				fail("C-0057", "kubescape"), // privileged: true
				fail("C-0013", "kubescape"), // runs as root
				fail("C-0016", "kubescape"), // allowPrivilegeEscalation: true
				fail("C-0017", "kubescape"), // readOnlyRootFilesystem: false
				fail("C-0046", "kubescape"), // capabilities: NET_ADMIN, SYS_ADMIN
			},
		},
		{
			name:       "partial_one_of_six_failing",
			controlID:  "art21-2-a",
			wantStatus: "WARN",
			findings: []model.Finding{
				// 5 pass, 1 fail = 83%? Zależy od weights — test reality
				pass("C-0013", "kubescape"),
				pass("C-0057", "kubescape"),
				pass("C-0016", "kubescape"),
				pass("C-0017", "kubescape"),
				pass("C-0020", "kubescape"),
				fail("C-0055", "kubescape"), // tylko hardening fail
			},
		},
	})
}

// =============================================================================
// 21.2(b) — Incident handling
// Violation: brak audit logów (C-0067)
// =============================================================================

func TestViolation_21b_AuditLogging(t *testing.T) {
	runViolationScenarios(t, []violationScenario{
		{
			name:       "compliant_audit_enabled",
			controlID:  "art21-2-b",
			wantStatus: "PASS",
			findings: []model.Finding{
				// kube-apiserver z --audit-log-path skonfigurowanym
				pass("C-0067", "kubescape"),
			},
		},
		{
			name:       "violation_no_audit_log_path",
			controlID:  "art21-2-b",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// Domyślna instalacja minikube/kind: brak --audit-log-path
				// C-0067 = FAIL
				fail("C-0067", "kubescape"),
			},
		},
		{
			name:       "violation_no_audit_findings_at_all",
			controlID:  "art21-2-b",
			wantStatus: "SKIP",
			findings:   []model.Finding{
				// Skaner nie zwrócił żadnych wyników dla audit checks
				// (np. skaner niedostępny) → SKIP
			},
		},
	})
}

// =============================================================================
// 21.2(c) — Business continuity
// Violations: single replica (C-0068), brak PDB (C-0069)
// =============================================================================

func TestViolation_21c_BusinessContinuity(t *testing.T) {
	runViolationScenarios(t, []violationScenario{
		{
			name:       "compliant_multi_replica_with_pdb",
			controlID:  "art21-2-c",
			wantStatus: "PASS",
			findings: []model.Finding{
				// replicas: 2+, PDB zdefiniowany
				pass("C-0068", "kubescape"), // no single-replica deployments
				pass("C-0069", "kubescape"), // PDB exists
			},
		},
		{
			name:       "violation_single_replica",
			controlID:  "art21-2-c",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// replicas: 1 → C-0068 FAIL
				fail("C-0068", "kubescape"),
				pass("C-0069", "kubescape"),
			},
		},
		{
			name:       "violation_no_pdb",
			controlID:  "art21-2-c",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// Brak PodDisruptionBudget → C-0069 FAIL
				pass("C-0068", "kubescape"),
				fail("C-0069", "kubescape"),
			},
		},
		{
			name:       "violation_namespace_noncompliant_21c",
			controlID:  "art21-2-c",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// Odwzorowanie namespace noncompliant-21c:
				// replicas: 1, brak PDB w namespace
				fail("C-0068", "kubescape"), // single replica deployment
				fail("C-0069", "kubescape"), // no PDB defined
			},
		},
		{
			name:       "partial_only_some_deployments_compliant",
			controlID:  "art21-2-c",
			wantStatus: "WARN",
			findings: []model.Finding{
				// 1 deployment z single replica, 1 z multi replica
				// 1 pass + 1 fail = 50% = WARN
				pass("C-0068", "kubescape"),
				fail("C-0068", "kubescape"),
				pass("C-0069", "kubescape"),
			},
		},
	})
}

// =============================================================================
// 21.2(d) — Supply chain security
// Violations: latest tag (C-0036, C-0079), imagePullPolicy (C-0270)
// =============================================================================

func TestViolation_21d_SupplyChain(t *testing.T) {
	runViolationScenarios(t, []violationScenario{
		{
			name:       "compliant_pinned_tag_always_pull",
			controlID:  "art21-2-d",
			wantStatus: "PASS",
			findings: []model.Finding{
				// image: nginx:1.25.3 (pinned), imagePullPolicy: Always
				pass("C-0036", "kubescape"), // no sudo in entrypoint
				pass("C-0014", "kubescape"), // memory request set
				pass("C-0270", "kubescape"), // imagePullPolicy: Always
				pass("C-0046", "kubescape"), // no insecure capabilities
			},
		},
		{
			name:       "violation_latest_tag",
			controlID:  "art21-2-d",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// image: nginx:latest → C-0036 FAIL
				fail("C-0036", "kubescape"),
				pass("C-0014", "kubescape"),
				pass("C-0270", "kubescape"),
			},
		},
		{
			name:       "violation_ifnotpresent_pullpolicy",
			controlID:  "art21-2-d",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// imagePullPolicy: IfNotPresent → C-0270 FAIL
				// może używać starego podatnego obrazu z cache
				pass("C-0036", "kubescape"),
				fail("C-0270", "kubescape"),
				pass("C-0014", "kubescape"),
			},
		},
		{
			name:       "violation_namespace_noncompliant_21d",
			controlID:  "art21-2-d",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// Odwzorowanie namespace noncompliant-21d:
				// nginx:latest + redis (bez tagu) + imagePullPolicy: IfNotPresent
				fail("C-0036", "kubescape"), // latest tag
				fail("C-0270", "kubescape"), // IfNotPresent pull policy
				pass("C-0014", "kubescape"),
				pass("C-0046", "kubescape"),
			},
		},
	})
}

// =============================================================================
// 21.2(e) — Network & IS security
// Violation: brak NetworkPolicy (C-0030, C-0031)
// =============================================================================

func TestViolation_21e_NetworkSecurity(t *testing.T) {
	runViolationScenarios(t, []violationScenario{
		{
			name:       "compliant_network_policies_set",
			controlID:  "art21-2-e",
			wantStatus: "PASS",
			findings: []model.Finding{
				// NetworkPolicy default-deny + allow rules zdefiniowane
				pass("C-0030", "kubescape"), // ingress/egress blocked (NetworkPolicy exists)
				pass("C-0031", "kubescape"), // network policy configured
				pass("C-0066", "kubescape"), // etcd encryption
			},
		},
		{
			name:       "violation_no_network_policy",
			controlID:  "art21-2-e",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// Namespace bez NetworkPolicy → C-0030, C-0031 FAIL
				// Każdy pod może komunikować się z każdym bez ograniczeń
				fail("C-0030", "kubescape"),
				fail("C-0031", "kubescape"),
				pass("C-0066", "kubescape"),
			},
		},
		{
			name:       "violation_namespace_noncompliant_21e",
			controlID:  "art21-2-e",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// Odwzorowanie namespace noncompliant-21e:
				// namespace istnieje ale nie ma żadnej NetworkPolicy
				fail("C-0030", "kubescape"),
				fail("C-0031", "kubescape"),
			},
		},
		{
			name:       "partial_ingress_only_no_egress",
			controlID:  "art21-2-e",
			wantStatus: "WARN",
			findings: []model.Finding{
				// NetworkPolicy tylko na Ingress, brak Egress control
				pass("C-0031", "kubescape"), // policy exists
				fail("C-0030", "kubescape"), // no egress blocking
				pass("C-0066", "kubescape"),
			},
		},
	})
}

// =============================================================================
// 21.2(g) — Assess effectiveness of cybersecurity measures
// Violation: overprivileged ServiceAccount (C-0053)
// =============================================================================

func TestViolation_21g_Effectiveness(t *testing.T) {
	runViolationScenarios(t, []violationScenario{
		{
			name:       "compliant_minimal_sa_permissions",
			controlID:  "art21-2-g",
			wantStatus: "PASS",
			findings: []model.Finding{
				// RBAC enabled, API server hardened, minimal SA scope
				pass("C-0005", "kubescape"), // no insecure port
				pass("C-0088", "kubescape"), // RBAC enabled
				pass("C-0053", "kubescape"), // SA has minimal access
				pass("C-0063", "kubescape"), // etcd peer TLS
			},
		},
		{
			name:       "violation_wildcard_sa_permissions",
			controlID:  "art21-2-g",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// ClusterRole z resources:["*"] verbs:["*"] → C-0053 FAIL
				// Odwzorowanie violation-21g-overprivileged z YAML
				fail("C-0053", "kubescape"),
				pass("C-0005", "kubescape"),
				pass("C-0088", "kubescape"),
			},
		},
		{
			name:       "violation_rbac_disabled",
			controlID:  "art21-2-g",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// --authorization-mode=AlwaysAllow (bez RBAC) → C-0088 FAIL
				fail("C-0088", "kubescape"),
				pass("C-0005", "kubescape"),
				pass("C-0053", "kubescape"),
			},
		},
		{
			name:       "violation_insecure_api_port",
			controlID:  "art21-2-g",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// --insecure-port != 0 → C-0005 FAIL
				fail("C-0005", "kubescape"),
				pass("C-0088", "kubescape"),
				pass("C-0053", "kubescape"),
			},
		},
		{
			name:       "violation_namespace_noncompliant_21g",
			controlID:  "art21-2-g",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// Odwzorowanie namespace noncompliant-21g:
				// overprivileged-sa z ClusterRole resources:["*"] verbs:["*"]
				fail("C-0053", "kubescape"), // SA container service account — wildcard
				pass("C-0088", "kubescape"),
				pass("C-0005", "kubescape"),
			},
		},
	})
}

// =============================================================================
// 21.2(h) — Basic cyber hygiene
// Violations: cluster-admin (C-0035), SA automount (C-0041), hostPort (C-0044)
// =============================================================================

func TestViolation_21h_CyberHygiene(t *testing.T) {
	runViolationScenarios(t, []violationScenario{
		{
			name:       "compliant_minimal_rbac_no_hostport",
			controlID:  "art21-2-h",
			wantStatus: "PASS",
			findings: []model.Finding{
				pass("C-0035", "kubescape"), // no unnecessary cluster-admin
				pass("C-0041", "kubescape"), // automount disabled
				pass("C-0044", "kubescape"), // no hostPort
				pass("C-0048", "kubescape"), // no hostPath
				pass("C-0038", "kubescape"), // no hostPID/hostIPC
			},
		},
		{
			name:       "violation_cluster_admin_binding",
			controlID:  "art21-2-h",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// developer@example.com z cluster-admin → C-0035 FAIL
				// Odwzorowanie violation-21h-cluster-admin z YAML
				fail("C-0035", "kubescape"),
				pass("C-0041", "kubescape"),
				pass("C-0044", "kubescape"),
			},
		},
		{
			name:       "violation_sa_token_automounted",
			controlID:  "art21-2-h",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// automountServiceAccountToken: true → C-0041 FAIL
				pass("C-0035", "kubescape"),
				fail("C-0041", "kubescape"),
				pass("C-0044", "kubescape"),
			},
		},
		{
			name:       "violation_hostport_used",
			controlID:  "art21-2-h",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// hostPort: 80 → C-0044 FAIL
				// Omija NetworkPolicy, przywiązuje do konkretnego węzła
				pass("C-0035", "kubescape"),
				pass("C-0041", "kubescape"),
				fail("C-0044", "kubescape"),
			},
		},
		{
			name:       "violation_hostpath_mount",
			controlID:  "art21-2-h",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// hostPath mount → C-0048 FAIL
				// Kontener może czytać/pisać pliki hosta
				pass("C-0035", "kubescape"),
				pass("C-0041", "kubescape"),
				pass("C-0044", "kubescape"),
				fail("C-0048", "kubescape"),
			},
		},
		{
			name:       "violation_namespace_noncompliant_21h",
			controlID:  "art21-2-h",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// Odwzorowanie namespace noncompliant-21h:
				// developer z cluster-admin + hostPort:80 + automountToken
				fail("C-0035", "kubescape"), // cluster-admin binding
				fail("C-0041", "kubescape"), // automountServiceAccountToken: true
				fail("C-0044", "kubescape"), // hostPort: 80
			},
		},
		{
			name:       "partial_only_cluster_admin_bad",
			controlID:  "art21-2-h",
			wantStatus: "WARN",
			findings: []model.Finding{
				// 4 pass, 1 fail = 80% = granica PASS/WARN
				fail("C-0035", "kubescape"), // jeden problem
				pass("C-0041", "kubescape"),
				pass("C-0044", "kubescape"),
				pass("C-0048", "kubescape"),
				pass("C-0038", "kubescape"),
			},
		},
	})
}

// =============================================================================
// 21.2(i) — Access control & asset management
// Violations: secrets access (C-0058, C-0188), delete perms (C-0187),
//             privileged RBAC roles (C-0015)
// =============================================================================

func TestViolation_21i_AccessControl(t *testing.T) {
	runViolationScenarios(t, []violationScenario{
		{
			name:       "compliant_no_secrets_access",
			controlID:  "art21-2-i",
			wantStatus: "PASS",
			findings: []model.Finding{
				pass("C-0015", "kubescape"), // no privileged RBAC roles
				pass("C-0058", "kubescape"), // no secrets access
				pass("C-0187", "kubescape"), // no delete capabilities
				pass("C-0188", "kubescape"), // no read secrets permissions
			},
		},
		{
			name:       "violation_role_reads_secrets",
			controlID:  "art21-2-i",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// Role z secrets: [get, list] → C-0058, C-0188 FAIL
				// Odwzorowanie violation-21i-secrets-reader z YAML
				fail("C-0058", "kubescape"),
				pass("C-0015", "kubescape"),
				pass("C-0187", "kubescape"),
			},
		},
		{
			name:       "violation_role_can_delete_pods",
			controlID:  "art21-2-i",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// Role z pods: [delete] → C-0187 FAIL
				// Może wywoływać downtime przez usuwanie podów
				fail("C-0187", "kubescape"),
				pass("C-0015", "kubescape"),
				pass("C-0058", "kubescape"),
			},
		},
		{
			name:       "violation_privileged_clusterrole",
			controlID:  "art21-2-i",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// ClusterRole z broad secrets i delete access → C-0015 FAIL
				// Odwzorowanie violation-21i-privileged-role z YAML
				fail("C-0015", "kubescape"),
				fail("C-0058", "kubescape"),
				fail("C-0187", "kubescape"),
				fail("C-0188", "kubescape"),
			},
		},
		{
			name:       "violation_namespace_noncompliant_21i",
			controlID:  "art21-2-i",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// Pełne odwzorowanie namespace noncompliant-21i:
				// secrets-reader role + privileged clusterrole
				fail("C-0015", "kubescape"), // privileged RBAC
				fail("C-0058", "kubescape"), // secrets access
				fail("C-0187", "kubescape"), // delete capabilities
				fail("C-0188", "kubescape"), // read secrets permissions
			},
		},
	})
}

// =============================================================================
// 21.2(j) — MFA and continuous authentication
// Violations: anonymous auth (C-0262), no RBAC (C-0088),
//             insecure port (C-0005)
// =============================================================================

func TestViolation_21j_Authentication(t *testing.T) {
	runViolationScenarios(t, []violationScenario{
		{
			name:       "compliant_rbac_no_anonymous",
			controlID:  "art21-2-j",
			wantStatus: "PASS",
			findings: []model.Finding{
				// --anonymous-auth=false, RBAC enabled, no insecure port
				pass("C-0005", "kubescape"),  // no insecure port
				pass("C-0088", "kubescape"),  // RBAC enabled
				pass("C-0262", "kubescape"),  // anonymous auth disabled
				pass("C-0256", "kubescape"),  // liveness probes configured
			},
		},
		{
			name:       "violation_anonymous_auth_enabled",
			controlID:  "art21-2-j",
			wantStatus: "WARN",
			findings: []model.Finding{
				// --anonymous-auth=true → C-0262 FAIL
				// Odwzorowanie violation-21j-marker z YAML:
				// minikube start bez --extra-config=apiserver.anonymous-auth=false
				pass("C-0005", "kubescape"),
				pass("C-0088", "kubescape"),
				fail("C-0262", "kubescape"), // anonymous auth ON
				pass("C-0256", "kubescape"),
			},
		},
		{
			name:       "violation_no_rbac",
			controlID:  "art21-2-j",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// --authorization-mode=AlwaysAllow → C-0088 FAIL
				pass("C-0005", "kubescape"),
				fail("C-0088", "kubescape"), // RBAC disabled
				pass("C-0262", "kubescape"),
			},
		},
		{
			name:       "violation_insecure_port_open",
			controlID:  "art21-2-j",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// --insecure-port=8080 (nie 0) → C-0005 FAIL
				// HTTP bez TLS na API serverze
				fail("C-0005", "kubescape"), // insecure port open
				pass("C-0088", "kubescape"),
				pass("C-0262", "kubescape"),
			},
		},
		{
			name:       "violation_all_auth_controls_bad",
			controlID:  "art21-2-j",
			wantStatus: "FAIL",
			findings: []model.Finding{
				// Najgorsza możliwa konfiguracja auth:
				// insecure port + no RBAC + anonymous auth
				// minikube --extra-config=apiserver.anonymous-auth=true
				//          --extra-config=apiserver.authorization-mode=AlwaysAllow
				fail("C-0005", "kubescape"),  // insecure port
				fail("C-0088", "kubescape"),  // no RBAC
				fail("C-0262", "kubescape"),  // anonymous auth
				pass("C-0256", "kubescape"),
			},
		},
	})
}

// =============================================================================
// Cross-article tests — naruszenia wpływające na wiele artykułów
// =============================================================================

func TestViolation_CrossArticle_PrivilegedNamespace(t *testing.T) {
	// Namespace bez PodSecurity = brak wymuszenia restricted profile
	// Wpływa na: 21.2(a), 21.2(h)
	t.Run("namespace_without_podsecurity_affects_21a_and_21h", func(t *testing.T) {
		fw, _ := mapping.Load("nis2")
		engine := mapping.NewEngine(fw)

		// Findings z namespace'u bez PodSecurity enforcement
		// (odpowiednik noncompliant-21a — brak labela pod-security.kubernetes.io/enforce)
		findings := []model.Finding{
			fail("C-0057", "kubescape"), // privileged allowed — art21-2-a
			fail("C-0013", "kubescape"), // root allowed — art21-2-a
			fail("C-0016", "kubescape"), // escalation allowed — art21-2-a
			fail("C-0044", "kubescape"), // hostPort allowed — art21-2-h
			fail("C-0048", "kubescape"), // hostPath allowed — art21-2-h
			pass("C-0088", "kubescape"),
			pass("C-0031", "kubescape"),
		}

		results := engine.Map(findings)
		scored, summary := scoring.Calculate(results)

		byID := indexByID(scored)

		// Oba artykuły powinny być FAIL
		if byID["art21-2-a"].Status != "FAIL" {
			t.Errorf("art21-2-a: expected FAIL, got %s", byID["art21-2-a"].Status)
		}
		if byID["art21-2-h"].Status != "FAIL" {
			t.Errorf("art21-2-h: expected FAIL, got %s", byID["art21-2-h"].Status)
		}

		// Overall score powinien być FAIL lub WARN, nie PASS
		if summary.Status == "PASS" {
			t.Errorf("cluster with privileged namespace should not be PASS overall")
		}

		t.Logf("Cross-article impact: 21a=%s 21h=%s overall=%.1f%% %s",
			byID["art21-2-a"].Status,
			byID["art21-2-h"].Status,
			summary.OverallScore,
			summary.Status,
		)
	})
}

func TestViolation_CrossArticle_MissingNetworkAndAudit(t *testing.T) {
	// Brak NetworkPolicy + brak audit logów =
	// niemożność wykrycia ataku I niemożność zatrzymania lateral movement
	// Wpływa na: 21.2(b) + 21.2(e)
	t.Run("no_network_policy_and_no_audit_worst_case", func(t *testing.T) {
		fw, _ := mapping.Load("nis2")
		engine := mapping.NewEngine(fw)

		findings := []model.Finding{
			fail("C-0067", "kubescape"), // no audit — art21-2-b
			fail("C-0030", "kubescape"), // no network policy — art21-2-e
			fail("C-0031", "kubescape"), // no network policy — art21-2-e
			pass("C-0057", "kubescape"),
			pass("C-0088", "kubescape"),
			pass("C-0035", "kubescape"),
		}

		results := engine.Map(findings)
		scored, _ := scoring.Calculate(results)
		byID := indexByID(scored)

		if byID["art21-2-b"].Status != "FAIL" {
			t.Errorf("art21-2-b: no audit logs should be FAIL, got %s", byID["art21-2-b"].Status)
		}
		if byID["art21-2-e"].Status != "FAIL" {
			t.Errorf("art21-2-e: no network policy should be FAIL, got %s", byID["art21-2-e"].Status)
		}

		t.Logf("Worst case: no audit + no network isolation: 21b=%s 21e=%s",
			byID["art21-2-b"].Status,
			byID["art21-2-e"].Status,
		)
	})
}

// =============================================================================
// Snapshot test — pełne odwzorowanie wszystkich namespace z YAML
// Jeden test który uruchamia wszystkie naruszenia naraz
// =============================================================================

func TestViolation_AllNonCompliantNamespaces(t *testing.T) {
	// Symuluje wynik skanu po kubectl apply -f nis2-noncompliant-cluster.yaml
	// Łączy findings ze wszystkich noncompliant namespace'ów
	fw, err := mapping.Load("nis2")
	if err != nil {
		t.Fatalf("failed to load NIS2: %v", err)
	}

	// Findings które zwróciłby kubescape po zastosowaniu całego YAML-a
	allViolationFindings := []model.Finding{
		// === noncompliant-21a ===
		fail("C-0057", "kubescape"), // privileged: true
		fail("C-0013", "kubescape"), // runs as root
		fail("C-0016", "kubescape"), // allowPrivilegeEscalation: true
		fail("C-0017", "kubescape"), // readOnlyRootFilesystem: false
		fail("C-0046", "kubescape"), // NET_ADMIN + SYS_ADMIN capabilities

		// === noncompliant-21b (apiserver — brak audit) ===
		fail("C-0067", "kubescape"), // no audit-log-path

		// === noncompliant-21c ===
		fail("C-0068", "kubescape"), // single replica
		fail("C-0069", "kubescape"), // no PDB

		// === noncompliant-21d ===
		fail("C-0036", "kubescape"), // nginx:latest, redis (no tag)
		fail("C-0270", "kubescape"), // imagePullPolicy: IfNotPresent

		// === noncompliant-21e ===
		fail("C-0030", "kubescape"), // no NetworkPolicy (ingress/egress)
		fail("C-0031", "kubescape"), // no NetworkPolicy configured

		// === noncompliant-21g ===
		fail("C-0053", "kubescape"), // wildcard SA permissions

		// === noncompliant-21h ===
		fail("C-0035", "kubescape"), // cluster-admin for developer
		fail("C-0041", "kubescape"), // automountServiceAccountToken: true
		fail("C-0044", "kubescape"), // hostPort: 80

		// === noncompliant-21i ===
		fail("C-0015", "kubescape"), // privileged RBAC clusterrole
		fail("C-0058", "kubescape"), // secrets: [get, list]
		fail("C-0187", "kubescape"), // pods: [delete]
		fail("C-0188", "kubescape"), // secrets read permissions

		// === noncompliant-21j (apiserver) ===
		fail("C-0262", "kubescape"), // anonymous-auth=true
		// C-0088 pass (RBAC jest włączony — tylko anonymous auth jest problem)
		pass("C-0088", "kubescape"),
		pass("C-0005", "kubescape"),
	}

	engine := mapping.NewEngine(fw)
	results := engine.Map(allViolationFindings)
	scored, summary := scoring.Calculate(results)
	byID := indexByID(scored)

	// Tabela oczekiwanych statusów dla każdego artykułu
	expected := map[string]string{
		"art21-2-a": "FAIL", // privileged container + runs as root
		"art21-2-b": "FAIL", // no audit logging
		"art21-2-c": "FAIL", // single replica + no PDB
		"art21-2-d": "FAIL", // latest image tags
		"art21-2-e": "FAIL", // no network policies
		"art21-2-g": "FAIL", // wildcard SA
		"art21-2-h": "FAIL", // cluster-admin + hostPort + automount
		"art21-2-i": "FAIL", // secrets access + delete perms
		"art21-2-j": "WARN", // anonymous auth (3/4 checks pass)
	}

	t.Logf("\n=== All Non-Compliant Namespaces — Full Scan Simulation ===")
	t.Logf("%-14s  %-8s  %-8s  %s", "Control", "Expected", "Got", "Result")
	t.Logf("%s", "─────────────────────────────────────────────────")

	allPassed := true
	for controlID, wantStatus := range expected {
		cr := byID[controlID]
		icon := "✓"
		if cr.Status != wantStatus {
			icon = "✗"
			allPassed = false
			t.Errorf("%s: expected %s, got %s (score=%.1f%%)",
				controlID, wantStatus, cr.Status, cr.Score)
		}
		t.Logf("%-14s  %-8s  %-8s  %s (score=%.0f%%)",
			controlID, wantStatus, cr.Status, icon, cr.Score)
	}

	t.Logf("%s", "─────────────────────────────────────────────────")
	t.Logf("Overall: %.1f%% %s | Pass=%d Warn=%d Fail=%d Skip=%d",
		summary.OverallScore, summary.Status,
		summary.TotalPass, summary.TotalWarn, summary.TotalFail, summary.TotalSkip)

	// Overall score nie powinien być PASS przy tylu naruszeniach
	if summary.Status == "PASS" {
		t.Error("cluster with violations across all articles should NOT be overall PASS")
	}

	if allPassed {
		t.Log("\n✓ All violation detections working correctly")
	}
}
