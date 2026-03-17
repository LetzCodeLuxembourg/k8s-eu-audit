package scanner

// lynis.go — Lynis security auditing adapter for Linux VMs.
//
// Lynis is an open-source security auditing tool for Unix-based systems.
// It performs comprehensive security checks and produces a report file
// at /var/log/lynis-report.dat in key=value format.
//
// Installation:
//   Ubuntu/Debian:  apt install lynis
//   RHEL/CentOS:    yum install lynis
//   macOS:          brew install lynis   (limited checks on macOS)
//
// Requirements:
//   - Must run as root (sudo) — many checks require privileged access
//   - Produces findings mapped to NIS2 Article 21 controls via LYNIS-* IDs
//
// NIS2 mapping:
//   LYNIS-SSH-*   → art21-2-j  (authentication, MFA)
//   LYNIS-FW-*    → art21-2-e  (network security)
//   LYNIS-LOG-*   → art21-2-b  (incident handling / audit logging)
//   LYNIS-ENC-*   → art21-2-e  (encryption)
//   LYNIS-UPD-*   → art21-2-f  (vulnerability handling)
//   LYNIS-AUTH-*  → art21-2-j  (authentication policies)
//   LYNIS-INT-*   → art21-2-g  (effectiveness / file integrity)
//   LYNIS-PKG-*   → art21-2-f  (package security)
//   LYNIS-KERN-*  → art21-2-a  (kernel hardening)
//   LYNIS-USB-*   → art21-2-h  (device control / cyber hygiene)

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/letzcode/k8s-eu-audit/internal/model"
)

type lynisScanner struct{}

func NewLynisScanner() Scanner { return &lynisScanner{} }

func (l *lynisScanner) Name() string { return "lynis" }

func (l *lynisScanner) Available() bool {
	// Lynis is supported on Linux and macOS only
	if runtime.GOOS == "windows" {
		return false
	}
	_, err := exec.LookPath("lynis")
	return err == nil
}

func (l *lynisScanner) Run(opts RunOptions) ([]model.Finding, error) {
	if !opts.IsHostScan() {
		return nil, nil // not requested
	}
	if os.Getuid() != 0 {
		return nil, fmt.Errorf("lynis requires root — run with: sudo k8s-eu-audit scan --mode hybrid")
	}

	reportFile := "/tmp/k8s-eu-audit-lynis.dat"
	defer os.Remove(reportFile)
	defer os.Remove("/tmp/k8s-eu-audit-lynis.log")

	cmd := exec.Command("lynis", "audit", "system",
		"--quiet",
		"--no-colors",
		"--report-file", reportFile,
		"--logfile", "/tmp/k8s-eu-audit-lynis.log",
	)
	// Lynis exits non-zero when it finds issues — that is normal
	_ = cmd.Run()

	data, err := os.ReadFile(reportFile)
	if err != nil {
		return nil, fmt.Errorf("lynis report not found — scan may have failed: %w", err)
	}

	return parseLynisReport(data), nil
}

// parseLynisReport reads the key=value report file and produces findings.
func parseLynisReport(data []byte) []model.Finding {
	props := make(map[string][]string)
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '='); i > 0 {
			k := line[:i]
			v := line[i+1:]
			props[k] = append(props[k], v)
		}
	}
	return buildLynisFindings(props)
}

// prop returns the first value for a key, or "" if absent.
func prop(props map[string][]string, key string) string {
	if v, ok := props[key]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

// hasValue returns true when the key has any non-empty value.
func hasValue(props map[string][]string, key string) bool {
	v := prop(props, key)
	return v != "" && v != "0"
}

func lyPass(id, name string, sev model.Severity) model.Finding {
	return model.Finding{
		ID: id, Source: "lynis", ControlID: id,
		ControlName: name, Status: model.StatusPass, Severity: sev,
	}
}
func lyFail(id, name string, sev model.Severity, rem string) model.Finding {
	return model.Finding{
		ID: id, Source: "lynis", ControlID: id,
		ControlName: name, Status: model.StatusFail, Severity: sev,
		Remediation: rem,
	}
}

// buildLynisFindings converts Lynis report properties to NIS2-mapped findings.
func buildLynisFindings(p map[string][]string) []model.Finding {
	var f []model.Finding

	// -------------------------------------------------------------------------
	// SSH hardening — maps to art21-2-j (MFA & authentication)
	// -------------------------------------------------------------------------
	if v := prop(p, "ssh-root-login"); v != "" {
		if v == "no" || v == "NO" {
			f = append(f, lyPass("LYNIS-SSH-001", "SSH root login disabled", model.SeverityHigh))
		} else {
			f = append(f, lyFail("LYNIS-SSH-001", "SSH root login disabled", model.SeverityHigh,
				"Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd."))
		}
	}

	if v := prop(p, "ssh-protocol"); v != "" {
		if v == "2" {
			f = append(f, lyPass("LYNIS-SSH-002", "SSH Protocol 2 enforced", model.SeverityHigh))
		} else {
			f = append(f, lyFail("LYNIS-SSH-002", "SSH Protocol 2 enforced", model.SeverityHigh,
				"Set 'Protocol 2' in /etc/ssh/sshd_config. Protocol 1 is deprecated and insecure."))
		}
	}

	if v := prop(p, "ssh-password-authentication"); v != "" {
		if v == "no" || v == "NO" {
			f = append(f, lyPass("LYNIS-SSH-003", "SSH password authentication disabled", model.SeverityHigh))
		} else {
			f = append(f, lyFail("LYNIS-SSH-003", "SSH password authentication disabled", model.SeverityHigh,
				"Set 'PasswordAuthentication no' and use key-based or certificate authentication."))
		}
	}

	// -------------------------------------------------------------------------
	// Firewall — maps to art21-2-e (network security)
	// -------------------------------------------------------------------------
	if hasValue(p, "firewall-software") {
		f = append(f, lyPass("LYNIS-FW-001", "Firewall software installed", model.SeverityHigh))
	} else {
		f = append(f, lyFail("LYNIS-FW-001", "Firewall software installed", model.SeverityHigh,
			"Install and configure a firewall: ufw (Ubuntu), firewalld (RHEL), or iptables."))
	}

	if v := prop(p, "firewall-active"); v == "1" || v == "yes" {
		f = append(f, lyPass("LYNIS-FW-002", "Firewall active and running", model.SeverityCritical))
	} else if prop(p, "firewall-software") != "" {
		f = append(f, lyFail("LYNIS-FW-002", "Firewall active and running", model.SeverityCritical,
			"Enable and start the firewall: 'ufw enable' or 'systemctl start firewalld'."))
	}

	// -------------------------------------------------------------------------
	// Audit logging — maps to art21-2-b (incident handling)
	// -------------------------------------------------------------------------
	if v := prop(p, "log-system"); hasValue(p, "log-system") || v != "" {
		f = append(f, lyPass("LYNIS-LOG-001", "System logging daemon configured", model.SeverityCritical))
	} else {
		f = append(f, lyFail("LYNIS-LOG-001", "System logging daemon configured", model.SeverityCritical,
			"Install and start rsyslog or syslog-ng: 'apt install rsyslog && systemctl enable rsyslog'."))
	}

	if v := prop(p, "auditd-running"); v == "1" {
		f = append(f, lyPass("LYNIS-LOG-002", "Auditd running (kernel audit)", model.SeverityCritical))
	} else {
		f = append(f, lyFail("LYNIS-LOG-002", "Auditd running (kernel audit)", model.SeverityCritical,
			"Install and enable auditd: 'apt install auditd && systemctl enable auditd --now'. "+
				"Configure audit rules for privileged commands, user auth, and file integrity."))
	}

	if v := prop(p, "log-rotation"); v == "enabled" || hasValue(p, "log-rotation") {
		f = append(f, lyPass("LYNIS-LOG-003", "Log rotation configured", model.SeverityMedium))
	} else {
		f = append(f, lyFail("LYNIS-LOG-003", "Log rotation configured", model.SeverityMedium,
			"Configure logrotate to prevent disk exhaustion and maintain log history for NIS2 incident handling."))
	}

	// -------------------------------------------------------------------------
	// Encryption — maps to art21-2-e (network & IS security)
	// -------------------------------------------------------------------------
	if hasValue(p, "encryption-tools-installed") {
		f = append(f, lyPass("LYNIS-ENC-001", "Encryption tools installed", model.SeverityHigh))
	} else {
		f = append(f, lyFail("LYNIS-ENC-001", "Encryption tools installed", model.SeverityHigh,
			"Install encryption tools: 'apt install gnupg openssl cryptsetup'."))
	}

	// -------------------------------------------------------------------------
	// Updates — maps to art21-2-f (vulnerability handling)
	// -------------------------------------------------------------------------
	if hasValue(p, "updates-last-run") {
		f = append(f, lyPass("LYNIS-UPD-001", "System updates recently applied", model.SeverityHigh))
	} else {
		f = append(f, lyFail("LYNIS-UPD-001", "System updates recently applied", model.SeverityHigh,
			"Run 'apt update && apt upgrade' or 'yum update'. Configure unattended-upgrades for security patches."))
	}

	if v := prop(p, "vulnerable-packages-found"); v == "0" || v == "" {
		f = append(f, lyPass("LYNIS-UPD-002", "No vulnerable packages found", model.SeverityHigh))
	} else {
		f = append(f, lyFail("LYNIS-UPD-002", "No vulnerable packages found", model.SeverityHigh,
			fmt.Sprintf("Found %s vulnerable packages. Run 'apt upgrade' or use 'debsecan' for details.", v)))
	}

	// -------------------------------------------------------------------------
	// Authentication policies — maps to art21-2-j (MFA & authentication)
	// -------------------------------------------------------------------------
	if v := prop(p, "password-max-days"); v != "" && v != "99999" && v != "0" {
		f = append(f, lyPass("LYNIS-AUTH-001", "Password expiry policy configured", model.SeverityMedium))
	} else {
		f = append(f, lyFail("LYNIS-AUTH-001", "Password expiry policy configured", model.SeverityMedium,
			"Set password expiry in /etc/login.defs: PASS_MAX_DAYS 90. Or per user: 'chage -M 90 username'."))
	}

	if v := prop(p, "password-min-length"); v != "" && v != "0" {
		f = append(f, lyPass("LYNIS-AUTH-002", "Minimum password length enforced", model.SeverityMedium))
	} else {
		f = append(f, lyFail("LYNIS-AUTH-002", "Minimum password length enforced", model.SeverityMedium,
			"Configure PAM: add 'minlen=12' to /etc/pam.d/common-password or use pam_pwquality."))
	}

	// Check for MFA modules in PAM
	mfaModules := []string{"google_authenticator", "pam_duo", "pam_u2f", "pam_oath"}
	hasMFA := false
	for _, mod := range mfaModules {
		for _, v := range p["pam-modules"] {
			if strings.Contains(v, mod) {
				hasMFA = true
				break
			}
		}
	}
	if hasMFA {
		f = append(f, lyPass("LYNIS-AUTH-003", "MFA PAM module configured", model.SeverityCritical))
	} else {
		f = append(f, lyFail("LYNIS-AUTH-003", "MFA PAM module configured", model.SeverityCritical,
			"Configure MFA via PAM. Options: pam_u2f (FIDO2/YubiKey), pam_google_authenticator (TOTP), "+
				"or pam_duo. Required for NIS2 Art.21(j) MFA compliance."))
	}

	// -------------------------------------------------------------------------
	// File integrity — maps to art21-2-g (assess effectiveness)
	// -------------------------------------------------------------------------
	if v := prop(p, "file-integrity-tool-installed"); v == "1" || hasValue(p, "file-integrity-tool") {
		f = append(f, lyPass("LYNIS-INT-001", "File integrity monitoring tool installed", model.SeverityHigh))
	} else {
		f = append(f, lyFail("LYNIS-INT-001", "File integrity monitoring tool installed", model.SeverityHigh,
			"Install AIDE or Tripwire: 'apt install aide && aideinit'. "+
				"Schedule daily checks via cron. Required to detect unauthorized changes."))
	}

	// -------------------------------------------------------------------------
	// Kernel hardening — maps to art21-2-a (risk analysis / IS security policies)
	// -------------------------------------------------------------------------
	kernelChecks := map[string]struct {
		id, name, rem string
		sev           model.Severity
	}{
		"kernel.randomize_va_space": {
			id:   "LYNIS-KERN-001",
			name: "ASLR enabled (randomize_va_space=2)",
			rem:  "Set 'kernel.randomize_va_space = 2' in /etc/sysctl.conf and run 'sysctl -p'.",
			sev:  model.SeverityHigh,
		},
		"kernel.dmesg_restrict": {
			id:   "LYNIS-KERN-002",
			name: "dmesg restricted to root (dmesg_restrict=1)",
			rem:  "Set 'kernel.dmesg_restrict = 1' in /etc/sysctl.conf to prevent info leakage.",
			sev:  model.SeverityMedium,
		},
		"net.ipv4.conf.all.rp_filter": {
			id:   "LYNIS-KERN-003",
			name: "Reverse path filtering enabled",
			rem:  "Set 'net.ipv4.conf.all.rp_filter = 1' in /etc/sysctl.conf to prevent IP spoofing.",
			sev:  model.SeverityMedium,
		},
		"net.ipv4.conf.all.accept_redirects": {
			id:   "LYNIS-KERN-004",
			name: "ICMP redirects disabled",
			rem:  "Set 'net.ipv4.conf.all.accept_redirects = 0' to prevent MITM via ICMP redirects.",
			sev:  model.SeverityMedium,
		},
	}

	for sysctlKey, check := range kernelChecks {
		if v := prop(p, "sysctl-"+strings.ReplaceAll(sysctlKey, ".", "_")); v == "1" || v == "2" {
			f = append(f, lyPass(check.id, check.name, check.sev))
		} else if v != "" {
			f = append(f, lyFail(check.id, check.name, check.sev, check.rem))
		}
	}

	// -------------------------------------------------------------------------
	// USB / removable media — maps to art21-2-h (cyber hygiene)
	// -------------------------------------------------------------------------
	if v := prop(p, "usb-storage-disabled"); v == "1" {
		f = append(f, lyPass("LYNIS-USB-001", "USB storage disabled", model.SeverityMedium))
	} else if v != "" {
		f = append(f, lyFail("LYNIS-USB-001", "USB storage disabled", model.SeverityMedium,
			"Disable USB storage: add 'install usb-storage /bin/true' to /etc/modprobe.d/disable-usb.conf. "+
				"Prevents unauthorized data exfiltration via USB devices."))
	}

	return f
}
