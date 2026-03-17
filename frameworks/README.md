# Framework Mappings

This directory is informational. The actual YAML files consumed by the binary
are embedded directly from `internal/mapping/nis2.yaml` and `internal/mapping/dora.yaml`.

## Adding a new framework

1. Create `internal/mapping/<id>.yaml` following the schema of existing files.
2. Add `//go:embed <id>.yaml` and register it in `internal/mapping/loader.go`.
3. Run `k8s-eu-audit list frameworks` — it will appear automatically.
4. No changes to scanner or scoring code required.

## Mapped check ID prefixes

| Prefix | Scanner | Example |
|--------|---------|---------|
| `C-XXXX` | Kubescape | `C-0004` |
| `KSV` | Trivy misconfig | `KSV001` |
| `"N.N.N"` | kube-bench CIS | `"1.2.19"` |
| `VULN_*` | Trivy CVE counts | `VULN_CRITICAL` |
| `OVERALL_*` | Synthetic aggregates | `OVERALL_CIS_SCORE` |

## Disclaimer

These mappings represent a reasonable technical interpretation of regulatory
requirements as they apply to Kubernetes infrastructure. They are not legal
advice. Always validate with a qualified compliance professional.
