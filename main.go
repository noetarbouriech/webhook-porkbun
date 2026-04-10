package main

import (
	"os"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"

	"github.com/cert-manager/webhook-example/porkbun"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// Register our Porkbun solver under the API group specified by GROUP_NAME.
	// Solver name is controlled by porkbun.New(...)->Name() and should match
	// issuer.spec.acme.solvers[].dns01.webhook.solverName (e.g. "porkbun").
	cmd.RunWebhookServer(
		GroupName,
		porkbun.New(),
	)
}
