package porkbun

import "github.com/cert-manager/cert-manager/pkg/acme/webhook"

// New returns the production Porkbun DNS01 solver implementation.
// Keep this as the package entrypoint used by `main.go`.
func New() webhook.Solver {
	return newSolver()
}
