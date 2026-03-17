# k8s-eu-audit

> EU compliance scanner for Kubernetes clusters and host infrastructure — built for auditors, not DevOps engineers.

[![GitHub release](https://img.shields.io/github/v/release/LetzCodeLuxembourg/k8s-eu-audit)](https://github.com/letzcode/k8s-eu-audit/releases)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/LetzCodeLuxembourg/k8s-eu-audit)](https://goreportcard.com/report/github.com/LetzCodeLuxembourg/k8s-eu-audit)

```
$ k8s-eu-audit scan --framework nis2 --mode hybrid

Scanning cluster: prod-eu-west (3 nodes, 12 namespaces)
Scanning host:    linux-node-01 (lynis)
Running: kubescape ✓  trivy ✓  kube-bench ✓  lynis ✓

NIS2 Article 21 Compliance Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Article   Requirement                        K8s    Host   Status
──────────────────────────────────────────────────────────────────
21.2(a)   Risk analysis & IS policies         72%    85%   ⚠ WARN
21.2(b)   Incident handling                   45%     0%   ✗ FAIL
21.2(c)   Business continuity                 88%     —    ✓ PASS
21.2(d)   Supply chain security               91%    80%   ✓ PASS
21.2(e)   Network & IS security               67%    60%   ⚠ WARN
21.2(f)   Vulnerability handling              54%    40%   ⚠ WARN
21.2(g)   Effectiveness assessment            80%    75%   ✓ PASS
21.2(h)   Cyber hygiene & training            76%    90%   ⚠ WARN
21.2(i)   Access control & asset mgmt         43%     —    ✗ FAIL
21.2(j)   MFA & authentication                55%    30%   ✗ FAIL

Overall NIS2 Compliance Score: 63%  ⚠ WARN

3 CRITICAL findings require immediate attention:
  ✗ [21.2(b)] No audit logging on kube-apiserver
  ✗ [21.2(j)] SSH password authentication enabled (LYNIS-SSH-003)
  ✗ [21.2(j)] No MFA PAM module configured (LYNIS-AUTH-003)

Full report: k8s-eu-audit-nis2-2026-03-17.html
```

---

## The problem

Security scanners like Kubescape, Trivy, and kube-bench are excellent tools — but they produce output for **DevOps engineers**, not auditors. They speak in CVE IDs and CIS benchmark numbers. Your compliance officer speaks in NIS2 articles and DORA pillars.

And they only look at Kubernetes. NIS2 and DORA cover your **entire ICT infrastructure** — Linux servers, Windows workstations, macOS endpoints. A Kubernetes cluster running on a node with FileVault disabled and SSH root login enabled is not compliant.

`k8s-eu-audit` is the translator. It scans your full infrastructure stack, collects findings from open-source tools, and maps everything to the EU regulatory frameworks your auditors actually care about.

**No other tool combines:**
- Deep Kubernetes scanning (not surface-level API checks)
- Host-level scanning: Linux VMs, macOS, Windows
- Native mapping to NIS2 Article 21 and DORA — all 14 DORA controls across 5 pillars
- Reports designed for auditors, not engineers
- EU-native: Luxembourg-based, Apache 2.0, open mappings

---

## Who this is for

| Role | How you use it |
|------|---------------|
| **Compliance auditors** | Run a scan, get a report structured around NIS2/DORA articles — no Kubernetes or Linux knowledge required to read the output |
| **IT consultancies** | Deliver NIS2/DORA gap assessments in hours, not days. `--output report.html` produces client-ready deliverables |
| **CISOs & security leads** | Continuous compliance monitoring with `--fail-on` threshold in CI/CD pipelines |
| **DevOps / platform engineers** | Understand the compliance implications of your infrastructure before the auditors arrive |

---

## Scan modes

`k8s-eu-audit` supports three scan modes:

| Mode | What it scans | Use case |
|------|--------------|----------|
| `kubernetes` | Kubernetes cluster only (default) | CI/CD gates, developer workstations |
| `host` | Local OS only (Linux/macOS/Windows) | Standalone server assessment |
| `hybrid` | Kubernetes cluster + host OS | Full infrastructure audit |

```bash
# Kubernetes only (default)
k8s-eu-audit scan --framework nis2

# Host OS only
k8s-eu-audit scan --framework nis2 --mode host

# Full stack: K8s + host
sudo k8s-eu-audit scan --framework nis2 --mode hybrid
```

> **Note on Linux host scanning:** Lynis requires root privileges for most checks. Use `sudo` when running in `host` or `hybrid` mode on Linux.

---

## Frameworks supported

| Framework | Controls | Status |
|-----------|----------|--------|
| **NIS2 Article 21** | 10 requirements (21.2a–j) — K8s + Linux + macOS + Windows | ✓ Available |
| **DORA ICT Risk** | 14 controls across 5 pillars — K8s + Linux + macOS + Windows | ✓ Available |
| **CIS Kubernetes Benchmark** | Via kube-bench (native) | ✓ Available |
| NIS2 national transpositions (DE, LU, FR) | BSI, CSSF, ANSSI variations | 🔒 Pro |
| DORA RTS technical standards | Regulatory Technical Standards detail | 🔒 Pro |

---

## Installation

### Homebrew (macOS/Linux)

```bash
brew install LetzCodeLuxembourg/tap/k8s-eu-audit
```

### Binary (all platforms)

Download the latest release from [GitHub Releases](https://github.com/LetzCodeLuxembourg/k8s-eu-audit/releases).

```bash
# Linux amd64
curl -L https://github.com/LetzCodeLuxembourg/k8s-eu-audit/releases/latest/download/k8s-eu-audit_linux_amd64.tar.gz | tar xz
sudo mv k8s-eu-audit /usr/local/bin/
```

### Docker

```bash
docker run --rm \
  -v ~/.kube/config:/root/.kube/config:ro \
  ghcr.io/LetzCodeLuxembourg/k8s-eu-audit:latest \
  scan --framework nis2
```

### From source

```bash
go install github.com/LetzCodeLuxembourg/k8s-eu-audit/cmd/k8s-eu-audit@latest
```

### External scanners (optional)

`k8s-eu-audit` orchestrates open-source scanners. Install any combination — the tool works with whatever is available.

**Kubernetes scanners:**

```bash
# Kubescape
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash

# Trivy
brew install trivy   # or see https://aquasecurity.github.io/trivy/

# kube-bench — see https://github.com/aquasecurity/kube-bench#installation
```

**Host scanners:**

```bash
# Lynis — Linux VM hardening (requires root for full results)
apt install lynis       # Ubuntu/Debian
yum install lynis       # RHEL/CentOS
brew install lynis      # macOS (limited checks)
```

> **macOS and Windows scanners** use only built-in OS tools — no external dependencies. On macOS: `fdesetup`, `csrutil`, `spctl`, `socketfilterfw`. On Windows: PowerShell with `Get-BitLockerVolume`, `Get-NetFirewallProfile`, `auditpol`, etc.

> **Graceful degradation:** `k8s-eu-audit` never fails because a scanner is missing. Missing scanner = SKIP, never ERROR.

---

## Usage

### Basic scan

```bash
# Scan Kubernetes cluster against NIS2 Article 21
k8s-eu-audit scan --framework nis2

# Scan against DORA ICT Risk (all 14 controls, 5 pillars)
k8s-eu-audit scan --framework dora

# Both frameworks in one run
k8s-eu-audit scan --framework nis2,dora
```

### Host and hybrid scanning

```bash
# Scan local host only (Linux/macOS/Windows)
k8s-eu-audit scan --framework nis2 --mode host

# Full stack: Kubernetes + host OS
sudo k8s-eu-audit scan --framework dora --mode hybrid

# Remote Linux VM via SSH
k8s-eu-audit scan --framework nis2 --mode host \
  --ssh-host user@192.168.1.10 \
  --ssh-key ~/.ssh/id_rsa
```

### Output formats

```bash
# Terminal table (default)
k8s-eu-audit scan --framework nis2

# HTML report — open in browser, share with auditors
k8s-eu-audit scan --framework nis2 --output report.html

# Markdown — for wikis, Confluence, documentation
k8s-eu-audit scan --framework nis2 --format markdown --output report.md

# JSON — for dashboards, integrations, custom tooling
k8s-eu-audit scan --framework nis2 --format json --output results.json
```

### CI/CD integration

```bash
# Exit code 1 if compliance score < 70%
k8s-eu-audit scan --framework nis2 --fail-on 70
```

```yaml
# .github/workflows/compliance.yaml
- name: NIS2 Compliance Check
  run: k8s-eu-audit scan --framework nis2 --fail-on 70

- name: DORA Compliance Check
  run: k8s-eu-audit scan --framework dora --fail-on 75
```

### Scope control

```bash
# Specific Kubernetes namespace
k8s-eu-audit scan --framework nis2 --namespace production

# Custom kubeconfig
k8s-eu-audit scan --framework nis2 --kubeconfig ~/.kube/prod-config
```

### Discovery

```bash
k8s-eu-audit list frameworks
k8s-eu-audit list controls --framework dora
k8s-eu-audit list scanners
k8s-eu-audit version
```

---

## How it works

```
┌─────────────────────────────────────────────────────────────────┐
│  OUTPUT LAYER                                                   │
│  Terminal table  │  HTML  │  Markdown  │  JSON                  │
└────────────────────────────┬────────────────────────────────────┘
                              │
┌─────────────────────────────┴──────────────────────────────────┐
│  k8s-eu-audit ENGINE                                           │
│  ┌───────────────┐  ┌───────────────┐  ┌──────────────────┐    │
│  │  NIS2 Mapper  │  │  DORA Mapper  │  │ Score Calculator │    │
│  └───────────────┘  └───────────────┘  └──────────────────┘    │
│  ┌───────────────────────────────────────────────────────┐      │
│  │  Scanner Orchestrator                                 │      │
│  │  Normalises · Merges · Deduplicates findings          │      │
│  └───────────────────────────────────────────────────────┘      │
└─────────────┬─────────────────────┬──────────────┬─────────────┘
              │                     │              │
   ┌──────────┴───────┐  ┌──────────┴──────┐  ┌───┴─────────────┐
   │  KUBERNETES      │  │  LINUX VM        │  │  macOS/Windows  │
   │                  │  │                  │  │                 │
   │  Kubescape       │  │  Lynis           │  │  Built-in OS    │
   │  Trivy           │  │  (SSH, firewall, │  │  commands only  │
   │  kube-bench      │  │   auditd, MFA,   │  │  No deps needed │
   │                  │  │   kernel, USB)   │  │                 │
   └──────────────────┘  └──────────────────┘  └─────────────────┘
```

### Scoring

```
Control score = (PASS findings / total findings) × 100

PASS   ≥ 80%   control satisfied
WARN   ≥ 50%   partial compliance, action recommended
FAIL   < 50%   control violated, remediation required
SKIP   no data scanner not installed or not applicable
```

Overall score: weighted average — CRITICAL × 3, HIGH × 2, MEDIUM × 1, LOW × 0.5.

---

## NIS2 Article 21 mapping

See [`internal/mapping/nis2.yaml`](internal/mapping/nis2.yaml).

| Article | Requirement | K8s | Linux | macOS | Windows |
|---------|-------------|-----|-------|-------|---------|
| 21.2(a) | Risk analysis & IS policies | Pod security, capabilities | ASLR, dmesg, kernel | SIP | UAC |
| 21.2(b) | Incident handling | K8s audit logging | auditd, syslog | OpenBSM | Security audit policy |
| 21.2(c) | Business continuity | PDB, replica counts | — | — | — |
| 21.2(d) | Supply chain security | Image registries, tags | — | Gatekeeper | Defender AV |
| 21.2(e) | Network & IS security | NetworkPolicy, etcd | Firewall, encryption | FileVault, App Firewall | BitLocker, Firewall, SMBv1 |
| 21.2(f) | Vulnerability handling | CVE counts, image freshness | Updates, packages | Pending updates | Windows Update, Defender |
| 21.2(g) | Effectiveness assessment | CIS benchmark, RBAC | AIDE/Tripwire | — | — |
| 21.2(h) | Cyber hygiene & training | RBAC, cluster-admin | USB, password policy | — | Password policy |
| 21.2(i) | Access control | Anonymous auth, RBAC | — | — | — |
| 21.2(j) | MFA & authentication | Anonymous access, RBAC | SSH hardening, PAM MFA | Screen lock, SSH | RDP+NLA, screen lock |

---

## DORA ICT Risk mapping

DORA applies to ~22,000 EU financial entities from January 2025. In Luxembourg supervised by CSSF (circulars 25/880–25/883). See [`internal/mapping/dora.yaml`](internal/mapping/dora.yaml).

**14 controls across 5 pillars:**

| Control | Article | What it verifies |
|---------|---------|-----------------|
| `dora-rm-1` | Art. 5–7 | Governance: workload security + firewall on all hosts |
| `dora-rm-2` | Art. 8–9 | Asset protection: NetworkPolicy + disk encryption |
| `dora-rm-3` | Art. 10 | Anomaly detection: K8s audit + auditd + Windows Security audit |
| `dora-rm-4` | Art. 11–12 | Business continuity: PDB + multi-replica (RTO/RPO) |
| `dora-rm-5` | Art. 13–14 | Training indicators: RBAC hygiene + password policies |
| `dora-inc-1` | Art. 17–18 | Detection & reporting: audit trail for CSSF SERIMA (4h/24h/1mo) |
| `dora-inc-2` | Art. 19–20 | Response & containment: network segmentation + recovery |
| `dora-test-1` | Art. 24–25 | Resilience testing: patching + Defender + file integrity |
| `dora-test-2` | Art. 26 | TLPT prerequisites: audit trail for red team evidence |
| `dora-tpp-1` | Art. 28–30 | Supply chain: trusted registries + Gatekeeper + Register of Information |
| `dora-tpp-2` | Art. 31–36 | Contractual: minimal privileges for external workloads + NLA |
| `dora-tpp-3` | Art. 37–44 | CTPP oversight: HA + portability indicators |
| `dora-share-1` | Art. 45–56 | Information sharing: egress control + encryption |
| **`dora-auth-1`** | **Art. 9(2)** | **MFA (CSSF priority): SSH + PAM MFA + RDP NLA + screen lock everywhere** |

> `dora-auth-1` is the most comprehensive control. A single missing PAM MFA module (`LYNIS-AUTH-003`) immediately flags non-compliance with DORA Art. 9(2) and CSSF circular 22/806.

---

## Host scanner reference

### Linux — Lynis

| Check ID | Verifies | Maps to |
|----------|---------|---------|
| `LYNIS-SSH-001/002/003` | Root login, Protocol 2, key-only auth | 21.2(j) / dora-auth-1 |
| `LYNIS-FW-001/002` | Firewall installed and active | 21.2(e) / dora-rm-1 |
| `LYNIS-LOG-001/002/003` | syslog + auditd + log rotation | 21.2(b) / dora-rm-3 |
| `LYNIS-ENC-001` | Encryption tools installed | 21.2(e) / dora-rm-2 |
| `LYNIS-UPD-001/002` | Updates applied, no vulnerable packages | 21.2(f) / dora-test-1 |
| `LYNIS-AUTH-001/002/003` | Password expiry, length, **PAM MFA module** | 21.2(j) / dora-auth-1 |
| `LYNIS-INT-001` | File integrity (AIDE/Tripwire) | 21.2(g) / dora-test-1 |
| `LYNIS-KERN-001–004` | ASLR, dmesg, rp_filter, ICMP redirects | 21.2(a) / dora-rm-1 |
| `LYNIS-USB-001` | USB storage disabled | 21.2(h) / dora-rm-5 |

### macOS — built-in tools only

| Check ID | Verifies | Maps to |
|----------|---------|---------|
| `MACOS-FV-001` | FileVault encryption | 21.2(e) / dora-rm-2 |
| `MACOS-FW-001/002` | App Firewall + stealth mode | 21.2(e) / dora-rm-1 |
| `MACOS-SIP-001` | System Integrity Protection | 21.2(a) / dora-rm-1 |
| `MACOS-GK-001` | Gatekeeper (signed software) | 21.2(d) / dora-tpp-1 |
| `MACOS-UPD-001` | No pending security updates | 21.2(f) / dora-test-1 |
| `MACOS-SCR-001` | Screen lock with immediate password | 21.2(j) / dora-auth-1 |
| `MACOS-SSH-001/002` | Remote Login / SSH root disabled | 21.2(j) / dora-auth-1 |
| `MACOS-SHR-001/002/003` | Screen/File/Remote Management sharing off | 21.2(e) / dora-share-1 |
| `MACOS-LOG-001` | OpenBSM audit configured | 21.2(b) / dora-inc-1 |

### Windows — PowerShell only

| Check ID | Verifies | Maps to |
|----------|---------|---------|
| `WIN-BL-001` | BitLocker on system drive | 21.2(e) / dora-rm-2 |
| `WIN-FW-001/002/003` | Defender Firewall — all profiles | 21.2(e) / dora-rm-1 |
| `WIN-AV-001/002` | Defender enabled + definitions current | 21.2(f) / dora-tpp-1 |
| `WIN-UPD-001/002` | Windows Update service + auto-update | 21.2(f) / dora-test-1 |
| `WIN-AUD-001/002/003` | Logon + privilege audit + log size >100MB | 21.2(b) / dora-inc-1 |
| `WIN-PWD-001/002` | Password expiry + minimum length | 21.2(j) / dora-auth-1 |
| `WIN-RDP-001/002` | RDP disabled or requires NLA | 21.2(j) / dora-auth-1 |
| `WIN-UAC-001` | User Account Control enabled | 21.2(a) / dora-rm-1 |
| `WIN-SCR-001` | Screen lock with password | 21.2(j) / dora-auth-1 |
| `WIN-SMB-001` | SMBv1 disabled (EternalBlue mitigation) | 21.2(e) / dora-rm-2 |

---

## Design principles

1. **Read-only** — never modifies any cluster resource, host file, or registry key
2. **Graceful degradation** — missing scanner = SKIP, never ERROR
3. **Offline capable** — all framework mappings embedded in binary at build time
4. **Auditor-first** — reports structured by regulatory article, readable without K8s knowledge
5. **Fast** — full hybrid scan completes in under 90 seconds
6. **CI/CD ready** — `--fail-on` threshold, exit codes 0 (pass) / 1 (fail)
7. **Extensible** — new framework = new YAML file, zero code changes
8. **Zero telemetry** — no phone-home, no analytics, no data leaves your infrastructure
9. **EU-native** — Luxembourg-based, EU data residency, Apache 2.0

---

## Roadmap

**v0.1.0** (current)
- [x] NIS2 Article 21 — full mapping, K8s + Linux + macOS + Windows
- [x] DORA ICT Risk — 14 controls, 5 pillars, all host layers
- [x] Kubescape + Trivy + kube-bench + Lynis orchestration
- [x] macOS scanner (built-in tools)
- [x] Windows scanner (PowerShell)
- [x] Scan modes: `kubernetes` / `host` / `hybrid`
- [x] Terminal, HTML, Markdown, JSON output
- [x] CI/CD `--fail-on` mode

**v0.2.0** (planned)
- [ ] SSH remote host scanning (`--ssh-host user@server`)
- [ ] DORA RTS (Regulatory Technical Standards) detail mapping
- [ ] Multi-cluster aggregation
- [ ] Trend report: delta between scans

**v0.3.0** (planned)
- [ ] NIS2 national transpositions: DE (BSI), LU (CSSF), BE, FR (ANSSI)
- [ ] PDF audit-ready report
- [ ] Scheduled scans with Slack/Teams alerting
- [ ] CRA (Cyber Resilience Act) — in force December 2027

See [GitHub Issues](https://github.com/LetzCodeLuxembourg/k8s-eu-audit/issues) to vote on features.

---

## Contributing

Most welcome:

- **Framework mappings** — corrections to NIS2/DORA control mappings with regulatory reference
- **Scanner integrations** — Wazuh, OpenSCAP, Falco adapters
- **National transpositions** — DE, FR, NL, PL country-specific NIS2 interpretations
- **Bug reports** — scanner output parsing edge cases

```bash
git clone https://github.com/LetzCodeLuxembourg/k8s-eu-audit
cd k8s-eu-audit
make dev-setup
make test
make test-violations   # non-compliance detection tests
make build
```

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

---

## About

Built by [Łukasz Ozimek](https://linkedin.com/in/lukaszozimek1) — [Letz Code S.A.R.L.](https://letzcode.io), Luxembourg.

6 years managing 300+ Kubernetes clusters at the European Commission. Direct experience with CSSF (Luxembourg financial regulator), Mastercard, and regulated-sector infrastructure at scale. Security Clearance: Top Secret (NATO, ESA, EU).

This tool exists because I kept seeing the same gap: security teams had great scanning tools, compliance teams had great GRC platforms, and nobody had anything that connected the two in the language EU regulators actually use — across the full infrastructure stack, not just Kubernetes.

**Questions or want to discuss your NIS2/DORA gap assessment?**
→ [lo@letzcode.io](mailto:lo@letzcode.io)
→ [LinkedIn](https://linkedin.com/in/lukaszozimek1)
→ [GitHub Issues](https://github.com/letzcode/k8s-eu-audit/issues)

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

The framework mapping files (`internal/mapping/*.yaml`) are also Apache 2.0. Use, modify, redistribute freely with attribution.

---

*`k8s-eu-audit` is not affiliated with ENISA, the European Commission, CSSF, or any regulatory body. Results are a technical assessment and do not constitute a formal compliance certification or legal opinion. Always validate with a qualified compliance professional before relying on results for regulatory purposes.*
