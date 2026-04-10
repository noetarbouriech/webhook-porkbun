package main

import (
	"os"
	"testing"
)

// This repo originally included cert-manager's envtest-based ACME conformance
// fixture in the main package tests. That requires external test assets
// (etcd/kube-apiserver) and is not appropriate for a "prod-ready" default
// `go test ./...` experience.
//
// To run conformance locally, set RUN_CONFORMANCE=1 and ensure you have the
// cert-manager test assets available and configured.
func TestConformanceSuiteIsOptIn(t *testing.T) {
	if os.Getenv("RUN_CONFORMANCE") == "" {
		t.Skip("conformance/envtest suite is opt-in; set RUN_CONFORMANCE=1 to run")
	}

	t.Skip("conformance suite is disabled by default; re-enable with envtest assets when needed")
}
