# Contributing to k8s-eu-audit

## What we need most

- **Framework mapping corrections** — If a NIS2 or DORA control is mapped
  incorrectly, open an issue with a link to the regulatory text.
- **New scanner integrations** — Implement the `Scanner` interface in `internal/scanner/`.
- **National NIS2 transpositions** — Country-specific YAML mappings (DE, FR, NL…).
- **Bug reports** — Especially edge cases in scanner JSON output parsing.

## Development setup

```bash
git clone https://github.com/letzcode/k8s-eu-audit
cd k8s-eu-audit
make dev-setup
make build
make test
```

## Pull request guidelines

- One feature or fix per PR.
- Add or update tests for any changed behaviour.
- Run `make lint` and `make test` before opening a PR.
- For mapping changes, include a reference to the regulatory text (EUR-Lex, ENISA).

## Code of conduct

Be constructive. Focus on technical arguments.
