package scanner

// windows.go — Windows security scanner using PowerShell and built-in tools.
//
// Uses only built-in Windows tools — no external dependencies:
//   - PowerShell     → most checks
//   - Get-BitLockerVolume  → disk encryption status
//   - Get-NetFirewallProfile → firewall status
//   - Get-WindowsUpdate    → pending updates (requires PSWindowsUpdate module)
//   - auditpol            → audit policy configuration
//   - net accounts        → password policy
//   - sc query            → service status
//
// NIS2 mapping:
//   WIN-BL-*    → art21-2-e  (BitLocker encryption)
//   WIN-FW-*    → art21-2-e  (Windows Defender Firewall)
//   WIN-AV-*    → art21-2-f  (antivirus / vulnerability)
//   WIN-UPD-*   → art21-2-f  (Windows Update)
//   WIN-AUD-*   → art21-2-b  (audit policy / incident handling)
//   WIN-PWD-*   → art21-2-j  (password policy / authentication)
//   WIN-RDP-*   → art21-2-j  (Remote Desktop / authentication)
//   WIN-SMB-*   → art21-2-e  (SMB / network security)
//   WIN-UAC-*   → art21-2-a  (UAC / IS security policies)
//   WIN-SCR-*   → art21-2-j  (screen lock / authentication)

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/letzcode/k8s-eu-audit/internal/model"
)

type windowsScanner struct{}

func NewWindowsScanner() Scanner { return &windowsScanner{} }

func (w *windowsScanner) Name() string { return "windows" }

func (w *windowsScanner) Available() bool {
	return runtime.GOOS == "windows"
}

func (w *windowsScanner) Run(opts RunOptions) ([]model.Finding, error) {
	if !opts.IsHostScan() {
		return nil, nil
	}
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("Windows scanner only runs on Windows")
	}
	return runWindowsChecks(), nil
}

// ps runs a PowerShell command and returns trimmed stdout.
func ps(script string) string {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-Command", script).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func winPass(id, name string, sev model.Severity) model.Finding {
	return model.Finding{
		ID: id, Source: "windows", ControlID: id,
		ControlName: name, Status: model.StatusPass, Severity: sev,
	}
}
func winFail(id, name string, sev model.Severity, rem string) model.Finding {
	return model.Finding{
		ID: id, Source: "windows", ControlID: id,
		ControlName: name, Status: model.StatusFail, Severity: sev,
		Remediation: rem,
	}
}
func winSkip(id, name string, sev model.Severity) model.Finding {
	return model.Finding{
		ID: id, Source: "windows", ControlID: id,
		ControlName: name, Status: model.StatusSkip, Severity: sev,
	}
}

func runWindowsChecks() []model.Finding {
	var f []model.Finding

	// -------------------------------------------------------------------------
	// BitLocker — maps to art21-2-e (encryption)
	// -------------------------------------------------------------------------
	blStatus := ps(`(Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue).ProtectionStatus`)
	switch blStatus {
	case "On":
		f = append(f, winPass("WIN-BL-001", "BitLocker encryption enabled on system drive", model.SeverityCritical))
	case "Off":
		f = append(f, winFail("WIN-BL-001", "BitLocker encryption enabled on system drive", model.SeverityCritical,
			"Enable BitLocker: Settings → System → BitLocker → Turn on BitLocker. "+
				"Or via PowerShell: 'Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256'. "+
				"Required for data protection at rest per NIS2 Art.21(e)."))
	default:
		f = append(f, winSkip("WIN-BL-001", "BitLocker encryption enabled on system drive", model.SeverityCritical))
	}

	// -------------------------------------------------------------------------
	// Windows Defender Firewall — maps to art21-2-e (network security)
	// -------------------------------------------------------------------------
	fwProfiles := []struct {
		profile string
		id      string
		name    string
	}{
		{"Domain", "WIN-FW-001", "Firewall enabled for Domain profile"},
		{"Private", "WIN-FW-002", "Firewall enabled for Private profile"},
		{"Public", "WIN-FW-003", "Firewall enabled for Public profile"},
	}
	for _, fp := range fwProfiles {
		result := ps(fmt.Sprintf(
			`(Get-NetFirewallProfile -Profile %s -ErrorAction SilentlyContinue).Enabled`, fp.profile))
		if result == "True" {
			f = append(f, winPass(fp.id, fp.name, model.SeverityHigh))
		} else if result == "False" {
			f = append(f, winFail(fp.id, fp.name, model.SeverityHigh,
				fmt.Sprintf("Enable %s firewall profile: 'Set-NetFirewallProfile -Profile %s -Enabled True'",
					fp.profile, fp.profile)))
		} else {
			f = append(f, winSkip(fp.id, fp.name, model.SeverityHigh))
		}
	}

	// -------------------------------------------------------------------------
	// Windows Defender Antivirus — maps to art21-2-f (vulnerability handling)
	// -------------------------------------------------------------------------
	avStatus := ps(`(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled`)
	if avStatus == "True" {
		f = append(f, winPass("WIN-AV-001", "Windows Defender Antivirus enabled", model.SeverityHigh))
	} else if avStatus == "False" {
		f = append(f, winFail("WIN-AV-001", "Windows Defender Antivirus enabled", model.SeverityHigh,
			"Enable Windows Defender: Settings → Windows Security → Virus & Threat Protection → Turn on. "+
				"Or PowerShell: 'Set-MpPreference -DisableRealtimeMonitoring $false'"))
	} else {
		f = append(f, winSkip("WIN-AV-001", "Windows Defender Antivirus enabled", model.SeverityHigh))
	}

	// Antivirus definitions up to date
	avUpToDate := ps(`(Get-MpComputerStatus -ErrorAction SilentlyContinue).DefenderSignaturesOutOfDate`)
	if avUpToDate == "False" {
		f = append(f, winPass("WIN-AV-002", "Antivirus definitions up to date", model.SeverityHigh))
	} else if avUpToDate == "True" {
		f = append(f, winFail("WIN-AV-002", "Antivirus definitions up to date", model.SeverityHigh,
			"Update Defender signatures: 'Update-MpSignature'. "+
				"Enable automatic updates to keep definitions current."))
	}

	// -------------------------------------------------------------------------
	// Windows Update — maps to art21-2-f (vulnerability handling)
	// -------------------------------------------------------------------------
	wuaService := ps(`(Get-Service -Name wuauserv -ErrorAction SilentlyContinue).Status`)
	if wuaService == "Running" {
		f = append(f, winPass("WIN-UPD-001", "Windows Update service running", model.SeverityHigh))
	} else {
		f = append(f, winFail("WIN-UPD-001", "Windows Update service running", model.SeverityHigh,
			"Start Windows Update service: 'Start-Service wuauserv; Set-Service wuauserv -StartupType Automatic'. "+
				"Ensure automatic updates are configured via Group Policy."))
	}

	// Check auto-update setting via registry
	autoUpdate := ps(`(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name AUOptions -ErrorAction SilentlyContinue).AUOptions`)
	// AUOptions 4 = auto download and install
	if autoUpdate == "4" {
		f = append(f, winPass("WIN-UPD-002", "Automatic updates configured", model.SeverityHigh))
	} else if autoUpdate != "" {
		f = append(f, winFail("WIN-UPD-002", "Automatic updates configured", model.SeverityHigh,
			"Configure automatic updates: Settings → Windows Update → Advanced Options → Automatic Updates. "+
				"Or via Group Policy: Computer Configuration → Administrative Templates → Windows Update."))
	}

	// -------------------------------------------------------------------------
	// Audit Policy — maps to art21-2-b (incident handling)
	// -------------------------------------------------------------------------
	auditLogon := ps(`auditpol /get /subcategory:"Logon" 2>$null`)
	if contains(auditLogon, "success and failure") || contains(auditLogon, "success") {
		f = append(f, winPass("WIN-AUD-001", "Logon events auditing enabled", model.SeverityCritical))
	} else {
		f = append(f, winFail("WIN-AUD-001", "Logon events auditing enabled", model.SeverityCritical,
			"Enable logon auditing: 'auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable'. "+
				"Required for incident detection and forensics per NIS2 Art.21(b)."))
	}

	auditPriv := ps(`auditpol /get /subcategory:"Sensitive Privilege Use" 2>$null`)
	if contains(auditPriv, "success and failure") {
		f = append(f, winPass("WIN-AUD-002", "Privileged operations auditing enabled", model.SeverityCritical))
	} else {
		f = append(f, winFail("WIN-AUD-002", "Privileged operations auditing enabled", model.SeverityCritical,
			"Enable privilege auditing: 'auditpol /set /subcategory:\"Sensitive Privilege Use\" /success:enable /failure:enable'."))
	}

	// Security Event Log size
	logSize := ps(`(Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue).MaximumSizeInBytes`)
	if logSize != "" {
		// Default 20MB (20971520) is too small for NIS2 — recommend at least 256MB
		if logSize > "104857600" { // > 100MB
			f = append(f, winPass("WIN-AUD-003", "Security event log size adequate (>100MB)", model.SeverityMedium))
		} else {
			f = append(f, winFail("WIN-AUD-003", "Security event log size adequate (>100MB)", model.SeverityMedium,
				"Increase Security log size: Event Viewer → Windows Logs → Security → Properties → "+
					"Maximum log size: 262144 KB (256MB). Or PowerShell: "+
					"'wevtutil sl Security /ms:268435456'"))
		}
	}

	// -------------------------------------------------------------------------
	// Password Policy — maps to art21-2-j (authentication)
	// -------------------------------------------------------------------------
	passPolicy := ps(`net accounts 2>$null`)
	if contains(passPolicy, "maximum password age") {
		// Parse max age — look for anything less than 999 days
		if !contains(passPolicy, "maximum password age: unlimited") &&
			!contains(passPolicy, "maximum password age: never") {
			f = append(f, winPass("WIN-PWD-001", "Password expiry policy configured", model.SeverityMedium))
		} else {
			f = append(f, winFail("WIN-PWD-001", "Password expiry policy configured", model.SeverityMedium,
				"Set password expiry: 'net accounts /maxpwage:90'. "+
					"Or via Group Policy: Account Policies → Password Policy → Maximum Password Age: 90."))
		}
	}

	// Check minimum password length
	minLen := ps(`(Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue).MinPasswordLength`)
	if minLen == "" {
		// Non-domain machine — check local policy
		minLen = ps(`(net accounts 2>$null | Select-String "Minimum password length").ToString() -replace ".*:\s*", ""`)
	}
	if minLen != "" && minLen != "0" {
		f = append(f, winPass("WIN-PWD-002", "Minimum password length configured", model.SeverityMedium))
	} else {
		f = append(f, winFail("WIN-PWD-002", "Minimum password length configured", model.SeverityMedium,
			"Set minimum password length: 'net accounts /minpwlen:12'. "+
				"Recommended: 12+ characters per NIS2 security baseline."))
	}

	// -------------------------------------------------------------------------
	// Remote Desktop — maps to art21-2-j (authentication)
	// -------------------------------------------------------------------------
	rdpStatus := ps(`(Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections`)
	if rdpStatus == "1" {
		f = append(f, winPass("WIN-RDP-001", "Remote Desktop disabled", model.SeverityHigh))
	} else if rdpStatus == "0" {
		// RDP is on — check NLA
		nlaStatus := ps(`(Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication`)
		if nlaStatus == "1" {
			f = append(f, winPass("WIN-RDP-002", "RDP requires Network Level Authentication (NLA)", model.SeverityHigh))
		} else {
			f = append(f, winFail("WIN-RDP-002", "RDP requires Network Level Authentication (NLA)", model.SeverityHigh,
				"Enable NLA for RDP: 'Set-ItemProperty -Path \"HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" -Name UserAuthentication -Value 1'. "+
					"NLA enforces authentication before establishing RDP session."))
		}
		f = append(f, winFail("WIN-RDP-001", "Remote Desktop disabled", model.SeverityMedium,
			"If RDP is not needed, disable it: 'Set-ItemProperty -Path \"HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\" -Name fDenyTSConnections -Value 1'. "+
				"If required, restrict access via firewall rules and enable NLA."))
	} else {
		f = append(f, winSkip("WIN-RDP-001", "Remote Desktop disabled", model.SeverityHigh))
	}

	// -------------------------------------------------------------------------
	// SMBv1 — maps to art21-2-e (network security)
	// SMBv1 is a known attack vector (EternalBlue/WannaCry)
	// -------------------------------------------------------------------------
	smb1Status := ps(`(Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol`)
	if smb1Status == "False" {
		f = append(f, winPass("WIN-SMB-001", "SMBv1 protocol disabled", model.SeverityHigh))
	} else if smb1Status == "True" {
		f = append(f, winFail("WIN-SMB-001", "SMBv1 protocol disabled", model.SeverityHigh,
			"Disable SMBv1: 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force'. "+
				"SMBv1 is exploited by EternalBlue (WannaCry, NotPetya). Should be disabled per NIS2 Art.21(e)."))
	}

	// -------------------------------------------------------------------------
	// UAC (User Account Control) — maps to art21-2-a (IS security policies)
	// -------------------------------------------------------------------------
	uacStatus := ps(`(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA`)
	if uacStatus == "1" {
		f = append(f, winPass("WIN-UAC-001", "User Account Control (UAC) enabled", model.SeverityCritical))
	} else {
		f = append(f, winFail("WIN-UAC-001", "User Account Control (UAC) enabled", model.SeverityCritical,
			"Enable UAC: 'Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" -Name EnableLUA -Value 1'. "+
				"UAC prevents unauthorized privilege escalation per NIS2 Art.21(a)."))
	}

	// -------------------------------------------------------------------------
	// Screen Lock — maps to art21-2-j (authentication)
	// -------------------------------------------------------------------------
	screenTimeout := ps(`(Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaveTimeOut -ErrorAction SilentlyContinue).ScreenSaveTimeOut`)
	screenSecure := ps(`(Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaverIsSecure -ErrorAction SilentlyContinue).ScreenSaverIsSecure`)
	if screenTimeout != "" && screenTimeout != "0" && screenSecure == "1" {
		f = append(f, winPass("WIN-SCR-001", "Screen lock with password on resume", model.SeverityHigh))
	} else {
		f = append(f, winFail("WIN-SCR-001", "Screen lock with password on resume", model.SeverityHigh,
			"Configure screen lock: Settings → Personalization → Lock Screen → Screen Timeout → "+
				"Require sign-in when PC wakes from sleep. "+
				"Recommended timeout: 5–10 minutes per NIS2 security baseline."))
	}

	return f
}
