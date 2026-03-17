package scanner

import "github.com/letzcode/k8s-eu-audit/internal/model"

// Scanner is the interface every external scanner adapter must implement.
type Scanner interface {
	// Name returns the scanner identifier (e.g. "kubescape").
	Name() string

	// Available reports whether the scanner binary is found in PATH.
	Available() bool

	// Run executes the scanner and returns normalised findings.
	Run(opts RunOptions) ([]model.Finding, error)
}

// ScanMode controls which layers of infrastructure are scanned.
type ScanMode string

const (
	// ModeKubernetes scans only Kubernetes cluster resources (default).
	ModeKubernetes ScanMode = "kubernetes"

	// ModeHost scans only the local host OS (Linux/macOS/Windows).
	ModeHost ScanMode = "host"

	// ModeHybrid scans both Kubernetes cluster and local host OS.
	ModeHybrid ScanMode = "hybrid"
)

// RunOptions carries execution parameters from the CLI to each scanner.
type RunOptions struct {
	// Kubernetes options
	Kubeconfig string
	Namespace  string

	// Host scanning options
	Mode ScanMode // "kubernetes" | "host" | "hybrid"

	// SSH options — if set, host scan runs on a remote machine
	SSHHost string // "user@192.168.1.10"
	SSHKey  string // path to private key, defaults to ~/.ssh/id_rsa
}

// IsHostScan returns true when the options request host-level scanning.
func (o RunOptions) IsHostScan() bool {
	return o.Mode == ModeHost || o.Mode == ModeHybrid
}

// IsK8sScan returns true when the options request Kubernetes scanning.
func (o RunOptions) IsK8sScan() bool {
	return o.Mode == "" || o.Mode == ModeKubernetes || o.Mode == ModeHybrid
}
