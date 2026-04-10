<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>

# ACME webhook for Porkbun

Yet another cert-manager webhook for Porkbun.

## Porkbun configuration 

This webhook expects Porkbun credentials via Kubernetes `Secret` references in the
Issuer/ClusterIssuer `webhook.config` stanza.

The config fields are:

- `apiKey`: Porkbun API key (string)
- `secretApiKey`: Porkbun Secret API key (string)

Create a secret (example uses your key names):

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: porkbun-secret
  namespace: cert-manager
type: Opaque
stringData:
  PORKBUN_API_KEY: "<your-api-key>"
  PORKBUN_SECRET_API_KEY: "<your-secret-api-key>"
```

Then create a `ClusterIssuer` that references this webhook:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-issuer
spec:
  acme:
    email: mail@domain.org
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-porkbun-tls
    solvers:
      - dns01:
          webhook:
            groupName: porkbun.noe-t.dev
            solverName: porkbun
            config:
              apiKey:
                key: PORKBUN_API_KEY
                name: porkbun-secret
              secretApiKey:
                key: PORKBUN_SECRET_API_KEY
                name: porkbun-secret
        selector:
          dnsZones:
            - "domain.org"
```
