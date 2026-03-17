package main

import (
	"os"

	"github.com/letzcode/k8s-eu-audit/internal/cli"
)

func main() {
	if err := cli.NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
