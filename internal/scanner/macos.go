package scanner

// macos.go — macOS security scanner using Apple's built-in tools.
//
// Uses native macOS commands — no external dependencies required:
//   - system_profiler    → hardware and software inventory
//   - defaults read      → system preference checks
//   - spctl              → Gatekeeper status
//   - fdesetup           → FileVault encryption status
//   - csrutil            → SIP (System Integrity Protection) status
//   - socketfilterfw     → Application Firewall status
//   - softwareupdate     → pending security updates
//
// NIS2 mapping:
//   MACOS-FV-*    → art21-2-e  (encryption / network & IS security)
//   MACOS-FW-*    → art21-2-e  (network security)
//   MACOS-SIP-*   → art21-2-a  (IS security policies)
//   MACOS-GK-*    → art21-2-d  (supply chain / software integrity)
//   MACOS-UPD-*   → art21-2-f  (vulnerability handling)
//   MACOS-SCR-*   → art21-2-j  (authentication)
//   MACOS-SSH-*   → art21-2-j  (authentication)
//   MACOS-SHR-*   → art21-2-e  (network security / sharing services)
//   MACOS-LOG-*   → art21-2-b  (incident handling)

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/letzcode/k8s-eu-audit/internal/model"
)

type macOSScanner struct{}

func NewMacOSScanner() Scanner { return &macOSScanner{} }

func (m *macOSScanner) Name() string { return "macos" }

func (m *macOSScanner) Available() bool {
	return runtime.GOOS == "darwin"
}

func (m *macOSScanner) Run(opts RunOptions) ([]model.Finding, error) {
	if !opts.IsHostScan() {
		return nil, nil
	}
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("macOS scanner only runs on macOS")
	}
	return runMacOSChecks(), nil
}

// run executes a command and returns trimmed stdout. Errors are silently ignored
// — unavailable commands simply return empty string.
func run(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// contains checks if s contains any of the given substrings.
func contains(s string, subs ...string) bool {
	sl := strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(sl, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

func macPass(id, name string, sev model.Severity) model.Finding {
	return model.Finding{
		ID: id, Source: "macos", ControlID: id,
		ControlName: name, Status: model.StatusPass, Severity: sev,
	}
}
func macFail(id, name string, sev model.Severity, rem string) model.Finding {
	return model.Finding{
		ID: id, Source: "macos", ControlID: id,
		ControlName: name, Status: model.StatusFail, Severity: sev,
		Remediation: rem,
	}
}
func macSkip(id, name string, sev model.Severity) model.Finding {
	return model.Finding{
		ID: id, Source: "macos", ControlID: id,
		ControlName: name, Status: model.StatusSkip, Severity: sev,
	}
}

func runMacOSChecks() []model.Finding {
	var f []model.Finding

	// -------------------------------------------------------------------------
	// FileVault — maps to art21-2-e (encryption)
	// -------------------------------------------------------------------------
	fvStatus := run("fdesetup", "status")
	if contains(fvStatus, "filevault is on") {
		f = append(f, macPass("MACOS-FV-001", "FileVault disk encryption enabled", model.SeverityCritical))
	} else if fvStatus != "" {
		f = append(f, macFail("MACOS-FV-001", "FileVault disk encryption enabled", model.SeverityCritical,
			"Enable FileVault: System Settings → Privacy & Security → FileVault → Turn On. "+
				"Required to protect data at rest per NIS2 Art.21(e)."))
	} else {
		f = append(f, macSkip("MACOS-FV-001", "FileVault disk encryption enabled", model.SeverityCritical))
	}

	// -------------------------------------------------------------------------
	// Application Firewall — maps to art21-2-e (network security)
	// -------------------------------------------------------------------------
	fwStatus := run("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
	if contains(fwStatus, "enabled") {
		f = append(f, macPass("MACOS-FW-001", "Application Firewall enabled", model.SeverityHigh))
	} else if fwStatus != "" {
		f = append(f, macFail("MACOS-FW-001", "Application Firewall enabled", model.SeverityHigh,
			"Enable Firewall: System Settings → Network → Firewall → Turn On. "+
				"Also enable stealth mode to hide the machine from network probes."))
	} else {
		f = append(f, macSkip("MACOS-FW-001", "Application Firewall enabled", model.SeverityHigh))
	}

	// Stealth mode
	stealthStatus := run("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode")
	if contains(stealthStatus, "enabled") {
		f = append(f, macPass("MACOS-FW-002", "Firewall stealth mode enabled", model.SeverityMedium))
	} else if stealthStatus != "" {
		f = append(f, macFail("MACOS-FW-002", "Firewall stealth mode enabled", model.SeverityMedium,
			"Enable stealth mode: 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on'"))
	}

	// -------------------------------------------------------------------------
	// System Integrity Protection — maps to art21-2-a (IS security policies)
	// -------------------------------------------------------------------------
	sipStatus := run("csrutil", "status")
	if contains(sipStatus, "enabled") {
		f = append(f, macPass("MACOS-SIP-001", "System Integrity Protection (SIP) enabled", model.SeverityCritical))
	} else if sipStatus != "" {
		f = append(f, macFail("MACOS-SIP-001", "System Integrity Protection (SIP) enabled", model.SeverityCritical,
			"Re-enable SIP: boot into Recovery Mode (hold Cmd+R), open Terminal, run 'csrutil enable'. "+
				"SIP prevents modification of critical system files even by root."))
	} else {
		f = append(f, macSkip("MACOS-SIP-001", "System Integrity Protection (SIP) enabled", model.SeverityCritical))
	}

	// -------------------------------------------------------------------------
	// Gatekeeper — maps to art21-2-d (supply chain security)
	// -------------------------------------------------------------------------
	gkStatus := run("spctl", "--status")
	if contains(gkStatus, "assessments enabled") {
		f = append(f, macPass("MACOS-GK-001", "Gatekeeper enabled (software signing enforced)", model.SeverityHigh))
	} else if gkStatus != "" {
		f = append(f, macFail("MACOS-GK-001", "Gatekeeper enabled (software signing enforced)", model.SeverityHigh,
			"Enable Gatekeeper: 'sudo spctl --master-enable'. "+
				"Prevents execution of unsigned or malicious software."))
	}

	// -------------------------------------------------------------------------
	// Software Updates — maps to art21-2-f (vulnerability handling)
	// -------------------------------------------------------------------------
	updates := run("softwareupdate", "--list")
	if contains(updates, "no new software available") || updates == "" {
		f = append(f, macPass("MACOS-UPD-001", "No pending security updates", model.SeverityHigh))
	} else if contains(updates, "recommended") || contains(updates, "*") {
		f = append(f, macFail("MACOS-UPD-001", "No pending security updates", model.SeverityHigh,
			"Apply updates: 'sudo softwareupdate --install --all' or via System Settings → General → Software Update. "+
				"Prioritise security updates immediately per NIS2 Art.21(f)."))
	}

	// -------------------------------------------------------------------------
	// Screen lock / auto-lock — maps to art21-2-j (authentication)
	// -------------------------------------------------------------------------
	askForPassword := run("defaults", "read", "com.apple.screensaver", "askForPassword")
	askDelay := run("defaults", "read", "com.apple.screensaver", "askForPasswordDelay")
	if askForPassword == "1" && (askDelay == "0" || askDelay == "") {
		f = append(f, macPass("MACOS-SCR-001", "Screen lock requires password immediately", model.SeverityHigh))
	} else {
		f = append(f, macFail("MACOS-SCR-001", "Screen lock requires password immediately", model.SeverityHigh,
			"Set immediate password on wake: System Settings → Lock Screen → Require password → Immediately. "+
				"'defaults write com.apple.screensaver askForPassword -int 1' "+
				"&& 'defaults write com.apple.screensaver askForPasswordDelay -int 0'"))
	}

	// -------------------------------------------------------------------------
	// Remote Login (SSH) — maps to art21-2-j (authentication)
	// -------------------------------------------------------------------------
	sshStatus := run("systemsetup", "-getremotelogin")
	if contains(sshStatus, "off") {
		f = append(f, macPass("MACOS-SSH-001", "Remote Login (SSH) disabled", model.SeverityHigh))
	} else if contains(sshStatus, "on") {
		// SSH is on — check if root login is disabled
		sshdConfig := run("grep", "-i", "PermitRootLogin", "/etc/ssh/sshd_config")
		if contains(sshdConfig, "no") {
			f = append(f, macPass("MACOS-SSH-002", "SSH root login disabled", model.SeverityHigh))
		} else {
			f = append(f, macFail("MACOS-SSH-002", "SSH root login disabled", model.SeverityHigh,
				"Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd. "+
					"Or disable SSH entirely if not needed: System Settings → Sharing → Remote Login → Off."))
		}
		f = append(f, macFail("MACOS-SSH-001", "Remote Login (SSH) disabled", model.SeverityMedium,
			"If SSH is not needed, disable it: System Settings → Sharing → Remote Login → Off. "+
				"If required, ensure key-based auth only and disable password authentication."))
	} else {
		f = append(f, macSkip("MACOS-SSH-001", "Remote Login (SSH) disabled", model.SeverityHigh))
	}

	// -------------------------------------------------------------------------
	// Sharing services — maps to art21-2-e (network security)
	// Attack surface: each sharing service is an open port
	// -------------------------------------------------------------------------
	sharingChecks := []struct {
		cmd  []string
		id   string
		name string
		rem  string
	}{
		{
			[]string{"defaults", "read", "/var/db/launchd.db/com.apple.launchd/overrides.plist", "com.apple.screensharing"},
			"MACOS-SHR-001", "Screen Sharing disabled",
			"Disable Screen Sharing: System Settings → Sharing → Screen Sharing → Off.",
		},
		{
			[]string{"launchctl", "list", "com.apple.smbd"},
			"MACOS-SHR-002", "File Sharing (SMB) disabled",
			"Disable File Sharing: System Settings → Sharing → File Sharing → Off. " +
				"SMB exposes files on the network — disable if not needed.",
		},
		{
			[]string{"launchctl", "list", "com.apple.remotedesktop.agent"},
			"MACOS-SHR-003", "Remote Management (ARD) disabled",
			"Disable Remote Management: System Settings → Sharing → Remote Management → Off.",
		},
	}

	for _, sc := range sharingChecks {
		out := run(sc.cmd[0], sc.cmd[1:]...)
		if contains(out, "disabled") || out == "" {
			f = append(f, macPass(sc.id, sc.name, model.SeverityMedium))
		} else {
			f = append(f, macFail(sc.id, sc.name, model.SeverityMedium, sc.rem))
		}
	}

	// -------------------------------------------------------------------------
	// Unified Log / Audit — maps to art21-2-b (incident handling)
	// -------------------------------------------------------------------------
	// Check if audit is configured (macOS uses OpenBSM)
	auditControl := run("cat", "/etc/security/audit_control")
	if auditControl != "" && contains(auditControl, "flags") {
		f = append(f, macPass("MACOS-LOG-001", "OpenBSM audit configured", model.SeverityCritical))
	} else {
		f = append(f, macFail("MACOS-LOG-001", "OpenBSM audit configured", model.SeverityCritical,
			"Configure OpenBSM audit: ensure /etc/security/audit_control has appropriate flags. "+
				"Enable: 'sudo audit -i' and verify with 'sudo praudit /var/audit/current'."))
	}

	return f
}
