package model

// Framework defines a regulatory compliance framework (NIS2, DORA, …).
// Loaded from YAML files embedded in the binary.
type Framework struct {
	ID       string    `yaml:"id"`
	Name     string    `yaml:"name"`
	Version  string    `yaml:"version"`
	Controls []Control `yaml:"controls"`
}

// Control is one regulatory requirement mapped to concrete K8s scanner checks.
type Control struct {
	ID           string   `yaml:"id"`            // e.g. "art21-2-a"
	Article      string   `yaml:"article"`       // e.g. "21.2(a)"
	Name         string   `yaml:"name"`
	Description  string   `yaml:"description"`
	Severity     string   `yaml:"severity"`      // CRITICAL | HIGH | MEDIUM | LOW
	MappedChecks []string `yaml:"mapped_checks"` // Scanner-native control IDs
	Remediation  string   `yaml:"remediation"`
}
