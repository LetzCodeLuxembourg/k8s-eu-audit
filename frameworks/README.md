# Framework Mappings

This directory is informational. The actual YAML files consumed by the binary
are embedded directly from `internal/mapping/nis2.yaml` and `internal/mapping/dora.yaml`.

## Adding a new framework

1. Create `internal/mapping/<id>.yaml` following the schema of existing files.
2. Add `//go:embed <id>.yaml` and register it in `internal/mapping/loader.go`.
3. Run `k8s-eu-audit list frameworks` — it will appear automatically.
4. No changes to scanner or scoring code required.

## Mapped check ID prefixes

### Kubernetes scanners

| Prefix | Scanner | Example | Notes |
|--------|---------|---------|-------|
| `C-XXXX` | Kubescape | `C-0057` | Kubescape control IDs — always uppercase |
| `KSV` | Trivy misconfig | `KSV001` | Trivy Kubernetes Security checks |
| `"N.N.N"` | kube-bench CIS | `1.2.19` | CIS Kubernetes Benchmark section numbers |
| `VULN_*` | Trivy CVE counts | `VULN_CRITICAL` | Synthetic aggregates from Trivy vulnerability scan |
| `OVERALL_*` | Synthetic | `OVERALL_CIS_SCORE` | Computed aggregate scores |

### Linux VM — Lynis

| Prefix | Category | Example | NIS2 | DORA |
|--------|----------|---------|------|------|
| `LYNIS-SSH-*` | SSH hardening | `LYNIS-SSH-001` | 21.2(j) | dora-auth-1 |
| `LYNIS-FW-*` | Firewall | `LYNIS-FW-001` | 21.2(e) | dora-rm-1 |
| `LYNIS-LOG-*` | Logging & auditd | `LYNIS-LOG-002` | 21.2(b) | dora-rm-3 |
| `LYNIS-ENC-*` | Encryption tools | `LYNIS-ENC-001` | 21.2(e) | dora-rm-2 |
| `LYNIS-UPD-*` | System updates | `LYNIS-UPD-002` | 21.2(f) | dora-test-1 |
| `LYNIS-AUTH-*` | Authentication & MFA | `LYNIS-AUTH-003` | 21.2(j) | dora-auth-1 |
| `LYNIS-INT-*` | File integrity (AIDE) | `LYNIS-INT-001` | 21.2(g) | dora-test-1 |
| `LYNIS-KERN-*` | Kernel hardening | `LYNIS-KERN-001` | 21.2(a) | dora-rm-1 |
| `LYNIS-USB-*` | Device control | `LYNIS-USB-001` | 21.2(h) | dora-rm-5 |

### macOS — built-in tools (no external dependencies)

| Prefix | Category | Example | NIS2 | DORA |
|--------|----------|---------|------|------|
| `MACOS-FV-*` | FileVault encryption | `MACOS-FV-001` | 21.2(e) | dora-rm-2 |
| `MACOS-FW-*` | Application Firewall | `MACOS-FW-001` | 21.2(e) | dora-rm-1 |
| `MACOS-SIP-*` | System Integrity Protection | `MACOS-SIP-001` | 21.2(a) | dora-rm-1 |
| `MACOS-GK-*` | Gatekeeper | `MACOS-GK-001` | 21.2(d) | dora-tpp-1 |
| `MACOS-UPD-*` | Software updates | `MACOS-UPD-001` | 21.2(f) | dora-test-1 |
| `MACOS-SCR-*` | Screen lock | `MACOS-SCR-001` | 21.2(j) | dora-auth-1 |
| `MACOS-SSH-*` | Remote Login / SSH | `MACOS-SSH-001` | 21.2(j) | dora-auth-1 |
| `MACOS-SHR-*` | Sharing services | `MACOS-SHR-002` | 21.2(e) | dora-share-1 |
| `MACOS-LOG-*` | OpenBSM audit | `MACOS-LOG-001` | 21.2(b) | dora-inc-1 |

### Windows — PowerShell only (no external dependencies)

| Prefix | Category | Example | NIS2 | DORA |
|--------|----------|---------|------|------|
| `WIN-BL-*` | BitLocker encryption | `WIN-BL-001` | 21.2(e) | dora-rm-2 |
| `WIN-FW-*` | Defender Firewall | `WIN-FW-001` | 21.2(e) | dora-rm-1 |
| `WIN-AV-*` | Windows Defender AV | `WIN-AV-002` | 21.2(f) | dora-tpp-1 |
| `WIN-UPD-*` | Windows Update | `WIN-UPD-001` | 21.2(f) | dora-test-1 |
| `WIN-AUD-*` | Security audit policy | `WIN-AUD-001` | 21.2(b) | dora-inc-1 |
| `WIN-PWD-*` | Password policy | `WIN-PWD-002` | 21.2(j) | dora-auth-1 |
| `WIN-RDP-*` | Remote Desktop | `WIN-RDP-002` | 21.2(j) | dora-auth-1 |
| `WIN-UAC-*` | User Account Control | `WIN-UAC-001` | 21.2(a) | dora-rm-1 |
| `WIN-SCR-*` | Screen lock | `WIN-SCR-001` | 21.2(j) | dora-auth-1 |
| `WIN-SMB-*` | SMB protocol | `WIN-SMB-001` | 21.2(e) | dora-rm-2 |

## Framework schema

```yaml
id: nis2                          # used in --framework flag
name: "NIS2 Article 21 — ..."
version: "Directive (EU) 2022/2555"
controls:
  - id: art21-2-a                 # used internally by scoring engine
    article: "21.2(a)"            # displayed in reports
    name: "Risk analysis ..."
    severity: HIGH                # CRITICAL | HIGH | MEDIUM | LOW
    description: >
      Full regulatory text summary.
    remediation: >
      Actionable fix per layer (K8s, Linux, macOS, Windows).
    mapped_checks:
      - C-0057        # Kubernetes
      - LYNIS-SSH-001 # Linux VM
      - MACOS-SIP-001 # macOS
      - WIN-UAC-001   # Windows
```

## Scoring

Each control score is computed from all its `mapped_checks` across every scanner and scan layer:

```
score = PASS findings / (PASS + FAIL findings) × 100

≥ 80%  →  PASS
≥ 50%  →  WARN
< 50%  →  FAIL
no data → SKIP
```

WARN/SKIP findings are excluded from the denominator — only PASS and FAIL count.

Overall framework score is a weighted average: CRITICAL × 3, HIGH × 2, MEDIUM × 1, LOW × 0.5. SKIP controls are excluded from the average.

## Disclaimer

These mappings represent a reasonable technical interpretation of NIS2 and DORA
requirements as they apply to Kubernetes infrastructure and host-level systems.
They are not legal advice. Always validate with a qualified compliance
professional or legal counsel before relying on results for regulatory purposes.