package scanner

import "github.com/letzcode/k8s-eu-audit/internal/model"

// Scanner is the interface every external scanner adapter must implement.
type Scanner interface {
	Name() string
	Available() bool
	Run(opts RunOptions) ([]model.Finding, error)
}

// RunOptions carries execution parameters from the CLI to each scanner.
type RunOptions struct {
	Kubeconfig string
	Namespace  string
}
