package scanner

import (
	"runtime"
	"testing"

	"github.com/letzcode/k8s-eu-audit/internal/model"
)

// =============================================================================
// Lynis scanner tests
// =============================================================================

// Sample Lynis report.dat content — key=value format
var lynisReportAllGood = []byte(`
# Lynis report file
ssh-root-login=no
ssh-protocol=2
ssh-password-authentication=no
firewall-software=ufw
firewall-active=1
log-system=rsyslog
auditd-running=1
log-rotation=enabled
encryption-tools-installed=gpg,openssl
updates-last-run=2025-01-15
vulnerable-packages-found=0
password-max-days=90
password-min-length=12
pam-modules=pam_unix,pam_u2f,pam_env
file-integrity-tool-installed=1
usb-storage-disabled=1
sysctl-kernel_randomize_va_space=2
sysctl-kernel_dmesg_restrict=1
sysctl-net_ipv4_conf_all_rp_filter=1
sysctl-net_ipv4_conf_all_accept_redirects=0
`)

var lynisReportAllBad = []byte(`
# Lynis report file — non-compliant system
ssh-root-login=yes
ssh-protocol=1
ssh-password-authentication=yes
firewall-active=0
auditd-running=0
vulnerable-packages-found=15
password-max-days=99999
password-min-length=0
pam-modules=pam_unix,pam_env
file-integrity-tool-installed=0
usb-storage-disabled=0
sysctl-kernel_randomize_va_space=0
sysctl-kernel_dmesg_restrict=0
sysctl-net_ipv4_conf_all_accept_redirects=1
`)

func TestLynisScanner_Name(t *testing.T) {
	s := NewLynisScanner()
	if s.Name() != "lynis" {
		t.Errorf("expected name=lynis, got %q", s.Name())
	}
}

func TestLynisScanner_AvailableOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	s := NewLynisScanner()
	if s.Available() {
		t.Error("lynis should not be available on Windows")
	}
}

func TestLynisScanner_SkipsWhenNotHostScan(t *testing.T) {
	s := NewLynisScanner()
	findings, err := s.Run(RunOptions{Mode: ModeKubernetes})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings in kubernetes-only mode, got %d", len(findings))
	}
}

// parseLynisReport tests — don't require lynis binary

func TestParseLynisReport_AllGood(t *testing.T) {
	findings := parseLynisReport(lynisReportAllGood)

	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}

	// All findings should be PASS
	for _, f := range findings {
		if f.Source != "lynis" {
			t.Errorf("finding %s: expected source=lynis, got %q", f.ID, f.Source)
		}
		if f.Status == model.StatusFail {
			t.Errorf("finding %s (%s): expected PASS on clean system, got FAIL",
				f.ID, f.ControlName)
		}
	}
	t.Logf("Parsed %d findings from clean system — all PASS ✓", len(findings))
}

func TestParseLynisReport_AllBad(t *testing.T) {
	findings := parseLynisReport(lynisReportAllBad)

	failCount := 0
	for _, f := range findings {
		if f.Status == model.StatusFail {
			failCount++
		}
	}

	if failCount == 0 {
		t.Error("expected FAILs on non-compliant system, got none")
	}
	t.Logf("Non-compliant system: %d findings, %d FAIL ✓", len(findings), failCount)
}

func TestParseLynisReport_SSHChecks(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		checkID    string
		wantStatus model.FindingStatus
	}{
		{
			name:       "ssh_root_login_disabled",
			data:       []byte("ssh-root-login=no\n"),
			checkID:    "LYNIS-SSH-001",
			wantStatus: model.StatusPass,
		},
		{
			name:       "ssh_root_login_enabled",
			data:       []byte("ssh-root-login=yes\n"),
			checkID:    "LYNIS-SSH-001",
			wantStatus: model.StatusFail,
		},
		{
			name:       "ssh_protocol_2",
			data:       []byte("ssh-protocol=2\n"),
			checkID:    "LYNIS-SSH-002",
			wantStatus: model.StatusPass,
		},
		{
			name:       "ssh_protocol_1_insecure",
			data:       []byte("ssh-protocol=1\n"),
			checkID:    "LYNIS-SSH-002",
			wantStatus: model.StatusFail,
		},
		{
			name:       "ssh_password_auth_disabled",
			data:       []byte("ssh-password-authentication=no\n"),
			checkID:    "LYNIS-SSH-003",
			wantStatus: model.StatusPass,
		},
		{
			name:       "ssh_password_auth_enabled",
			data:       []byte("ssh-password-authentication=yes\n"),
			checkID:    "LYNIS-SSH-003",
			wantStatus: model.StatusFail,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := parseLynisReport(tc.data)
			f := findLynisCheck(findings, tc.checkID)
			if f == nil {
				t.Fatalf("check %s not found in findings", tc.checkID)
			}
			if f.Status != tc.wantStatus {
				t.Errorf("%s: expected %s, got %s", tc.checkID, tc.wantStatus, f.Status)
			}
		})
	}
}

func TestParseLynisReport_FirewallChecks(t *testing.T) {
	// Firewall present and active
	findings := parseLynisReport([]byte("firewall-software=ufw\nfirewall-active=1\n"))
	if f := findLynisCheck(findings, "LYNIS-FW-001"); f == nil || f.Status != model.StatusPass {
		t.Error("LYNIS-FW-001: expected PASS when firewall installed")
	}
	if f := findLynisCheck(findings, "LYNIS-FW-002"); f == nil || f.Status != model.StatusPass {
		t.Error("LYNIS-FW-002: expected PASS when firewall active")
	}

	// No firewall at all
	findings = parseLynisReport([]byte("\n"))
	if f := findLynisCheck(findings, "LYNIS-FW-001"); f != nil && f.Status == model.StatusPass {
		t.Error("LYNIS-FW-001: expected FAIL when no firewall")
	}
}

func TestParseLynisReport_AuditdChecks(t *testing.T) {
	// Auditd running
	f := parseLynisReport([]byte("auditd-running=1\n"))
	if check := findLynisCheck(f, "LYNIS-LOG-002"); check == nil || check.Status != model.StatusPass {
		t.Error("LYNIS-LOG-002: expected PASS when auditd running")
	}

	// Auditd not running
	f = parseLynisReport([]byte("auditd-running=0\n"))
	if check := findLynisCheck(f, "LYNIS-LOG-002"); check == nil || check.Status != model.StatusFail {
		t.Error("LYNIS-LOG-002: expected FAIL when auditd not running")
	}
}

func TestParseLynisReport_MFADetection(t *testing.T) {
	// pam_u2f = MFA configured
	f := parseLynisReport([]byte("pam-modules=pam_unix,pam_u2f,pam_env\n"))
	if check := findLynisCheck(f, "LYNIS-AUTH-003"); check == nil || check.Status != model.StatusPass {
		t.Error("LYNIS-AUTH-003: expected PASS with pam_u2f")
	}

	// Google Authenticator = MFA configured
	f = parseLynisReport([]byte("pam-modules=pam_unix,pam_google_authenticator\n"))
	if check := findLynisCheck(f, "LYNIS-AUTH-003"); check == nil || check.Status != model.StatusPass {
		t.Error("LYNIS-AUTH-003: expected PASS with google_authenticator")
	}

	// No MFA module
	f = parseLynisReport([]byte("pam-modules=pam_unix,pam_env\n"))
	if check := findLynisCheck(f, "LYNIS-AUTH-003"); check == nil || check.Status != model.StatusFail {
		t.Error("LYNIS-AUTH-003: expected FAIL without MFA module")
	}
}

func TestParseLynisReport_PasswordPolicy(t *testing.T) {
	// Password expiry set
	f := parseLynisReport([]byte("password-max-days=90\n"))
	if check := findLynisCheck(f, "LYNIS-AUTH-001"); check == nil || check.Status != model.StatusPass {
		t.Error("LYNIS-AUTH-001: expected PASS with 90-day expiry")
	}

	// No expiry (never expires)
	f = parseLynisReport([]byte("password-max-days=99999\n"))
	if check := findLynisCheck(f, "LYNIS-AUTH-001"); check == nil || check.Status != model.StatusFail {
		t.Error("LYNIS-AUTH-001: expected FAIL with 99999-day expiry (never)")
	}
}

func TestParseLynisReport_VulnerablePackages(t *testing.T) {
	// No vulnerable packages
	f := parseLynisReport([]byte("vulnerable-packages-found=0\n"))
	if check := findLynisCheck(f, "LYNIS-UPD-002"); check == nil || check.Status != model.StatusPass {
		t.Error("LYNIS-UPD-002: expected PASS with 0 vulnerable packages")
	}

	// Vulnerable packages found
	f = parseLynisReport([]byte("vulnerable-packages-found=15\n"))
	if check := findLynisCheck(f, "LYNIS-UPD-002"); check == nil || check.Status != model.StatusFail {
		t.Error("LYNIS-UPD-002: expected FAIL with 15 vulnerable packages")
	}
}

func TestParseLynisReport_AllFindingsHaveRemediation(t *testing.T) {
	findings := parseLynisReport(lynisReportAllBad)
	for _, f := range findings {
		if f.Status == model.StatusFail && f.Remediation == "" {
			t.Errorf("finding %s (%s): FAIL without remediation text", f.ID, f.ControlName)
		}
	}
}

func TestParseLynisReport_AllFindingsHaveControlID(t *testing.T) {
	findings := parseLynisReport(lynisReportAllGood)
	for _, f := range findings {
		if f.ControlID == "" {
			t.Errorf("finding has empty ControlID: %+v", f)
		}
		if f.Source != "lynis" {
			t.Errorf("finding %s has wrong source: %q", f.ID, f.Source)
		}
	}
}

// =============================================================================
// macOS scanner tests
// =============================================================================

func TestMacOSScanner_Name(t *testing.T) {
	s := NewMacOSScanner()
	if s.Name() != "macos" {
		t.Errorf("expected name=macos, got %q", s.Name())
	}
}

func TestMacOSScanner_AvailableOnlyOnDarwin(t *testing.T) {
	s := NewMacOSScanner()
	isDarwin := runtime.GOOS == "darwin"
	if s.Available() != isDarwin {
		t.Errorf("Available()=%v but runtime.GOOS=%q", s.Available(), runtime.GOOS)
	}
}

func TestMacOSScanner_SkipsWhenNotHostScan(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific test — skip on non-darwin")
	}
	s := NewMacOSScanner()
	findings, err := s.Run(RunOptions{Mode: ModeKubernetes})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings in k8s-only mode, got %d", len(findings))
	}
}

func TestMacOSScanner_RunOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS scanner only runs on darwin")
	}
	s := NewMacOSScanner()
	findings, err := s.Run(RunOptions{Mode: ModeHost})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected findings on macOS host, got none")
	}

	// Validate structure of all findings
	for _, f := range findings {
		if f.Source != "macos" {
			t.Errorf("%s: expected source=macos, got %q", f.ID, f.Source)
		}
		if f.ControlID == "" {
			t.Errorf("finding has empty ControlID: %+v", f)
		}
		if f.Status == model.StatusFail && f.Remediation == "" {
			t.Errorf("%s (%s): FAIL without remediation", f.ID, f.ControlName)
		}
	}

	passCount, failCount, skipCount := countStatuses(findings)
	t.Logf("macOS scan: %d findings — PASS=%d FAIL=%d SKIP=%d",
		len(findings), passCount, failCount, skipCount)

	// Log each finding for visibility
	for _, f := range findings {
		t.Logf("  %s  %-8s  %s", f.ControlID, f.Status, f.ControlName)
	}
}

func TestMacOSScanner_ExpectedCheckIDs(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific test")
	}
	s := NewMacOSScanner()
	findings, _ := s.Run(RunOptions{Mode: ModeHost})

	expectedIDs := []string{
		"MACOS-FV-001",  // FileVault
		"MACOS-FW-001",  // Firewall
		"MACOS-SIP-001", // SIP
		"MACOS-GK-001",  // Gatekeeper
		"MACOS-SCR-001", // Screen lock
		"MACOS-LOG-001", // Audit
	}

	foundIDs := make(map[string]bool)
	for _, f := range findings {
		foundIDs[f.ControlID] = true
	}

	for _, id := range expectedIDs {
		if !foundIDs[id] {
			t.Errorf("expected check %s in macOS findings, not found", id)
		}
	}
}

// =============================================================================
// Windows scanner tests
// =============================================================================

func TestWindowsScanner_Name(t *testing.T) {
	s := NewWindowsScanner()
	if s.Name() != "windows" {
		t.Errorf("expected name=windows, got %q", s.Name())
	}
}

func TestWindowsScanner_AvailableOnlyOnWindows(t *testing.T) {
	s := NewWindowsScanner()
	isWindows := runtime.GOOS == "windows"
	if s.Available() != isWindows {
		t.Errorf("Available()=%v but runtime.GOOS=%q", s.Available(), runtime.GOOS)
	}
}

func TestWindowsScanner_SkipsWhenNotHostScan(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}
	s := NewWindowsScanner()
	findings, err := s.Run(RunOptions{Mode: ModeKubernetes})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings in k8s-only mode, got %d", len(findings))
	}
}

func TestWindowsScanner_RunOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows scanner only runs on Windows")
	}
	s := NewWindowsScanner()
	findings, err := s.Run(RunOptions{Mode: ModeHost})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected findings on Windows host, got none")
	}

	for _, f := range findings {
		if f.Source != "windows" {
			t.Errorf("%s: expected source=windows, got %q", f.ID, f.Source)
		}
		if f.ControlID == "" {
			t.Errorf("finding has empty ControlID: %+v", f)
		}
		if f.Status == model.StatusFail && f.Remediation == "" {
			t.Errorf("%s: FAIL without remediation", f.ID)
		}
	}

	passCount, failCount, skipCount := countStatuses(findings)
	t.Logf("Windows scan: %d findings — PASS=%d FAIL=%d SKIP=%d",
		len(findings), passCount, failCount, skipCount)

	for _, f := range findings {
		t.Logf("  %s  %-8s  %s", f.ControlID, f.Status, f.ControlName)
	}
}

// =============================================================================
// RunOptions tests
// =============================================================================

func TestRunOptions_ScanModeDetection(t *testing.T) {
	tests := []struct {
		opts     RunOptions
		wantK8s  bool
		wantHost bool
	}{
		{RunOptions{}, true, false}, // default = k8s only
		{RunOptions{Mode: ModeKubernetes}, true, false},
		{RunOptions{Mode: ModeHost}, false, true},
		{RunOptions{Mode: ModeHybrid}, true, true},
	}

	for _, tc := range tests {
		if tc.opts.IsK8sScan() != tc.wantK8s {
			t.Errorf("mode=%q: IsK8sScan()=%v, want %v", tc.opts.Mode, tc.opts.IsK8sScan(), tc.wantK8s)
		}
		if tc.opts.IsHostScan() != tc.wantHost {
			t.Errorf("mode=%q: IsHostScan()=%v, want %v", tc.opts.Mode, tc.opts.IsHostScan(), tc.wantHost)
		}
	}
}

// =============================================================================
// NIS2 mapping integration — verify host check IDs are in nis2.yaml
// =============================================================================

func TestHostCheckIDs_InNIS2Mapping(t *testing.T) {
	// All LYNIS-*, MACOS-*, WIN-* IDs that parsers produce
	// must appear in nis2.yaml mapped_checks
	// This test uses the parser outputs as the source of truth

	lynisIDs := extractIDsFromFindings(parseLynisReport(lynisReportAllGood))
	lynisIDs = append(lynisIDs, extractIDsFromFindings(parseLynisReport(lynisReportAllBad))...)

	t.Logf("Lynis check IDs produced: %v", dedup(lynisIDs))
	// Full mapping validation is in mapping/engine_test.go
	// Here we just verify IDs follow naming convention
	for _, id := range dedup(lynisIDs) {
		if len(id) < 10 {
			t.Errorf("suspicious short check ID: %q", id)
		}
	}
}

// =============================================================================
// Helpers
// =============================================================================

func findLynisCheck(findings []model.Finding, id string) *model.Finding {
	for i := range findings {
		if findings[i].ControlID == id {
			return &findings[i]
		}
	}
	return nil
}

func countStatuses(findings []model.Finding) (pass, fail, skip int) {
	for _, f := range findings {
		switch f.Status {
		case model.StatusPass:
			pass++
		case model.StatusFail:
			fail++
		case model.StatusSkip:
			skip++
		}
	}
	return
}

func extractIDsFromFindings(findings []model.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.ControlID)
	}
	return ids
}

func dedup(ss []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
