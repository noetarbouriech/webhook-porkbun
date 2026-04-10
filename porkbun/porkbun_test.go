package porkbun

import (
	"testing"

	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func TestSolver_Name(t *testing.T) {
	s := newSolver().(*solver)
	if got, want := s.Name(), SolverName; got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}
}

func TestLoadConfig_Valid(t *testing.T) {
	s := newSolver().(*solver)

	raw := []byte(`{
		"apiKey": {"name":"porkbun-secret","key":"PORKBUN_API_KEY"},
		"secretApiKey": {"name":"porkbun-secret","key":"PORKBUN_SECRET_API_KEY"}
	}`)

	cfg, err := s.loadConfig(&extapi.JSON{Raw: raw})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cfg.APIKey.Name != "porkbun-secret" || cfg.APIKey.Key != "PORKBUN_API_KEY" {
		t.Fatalf("apiKey parsed wrong: %#v", cfg.APIKey)
	}
	if cfg.SecretAPIKey.Name != "porkbun-secret" || cfg.SecretAPIKey.Key != "PORKBUN_SECRET_API_KEY" {
		t.Fatalf("secretApiKey parsed wrong: %#v", cfg.SecretAPIKey)
	}
}

func TestLoadConfig_Missing(t *testing.T) {
	s := newSolver().(*solver)

	_, err := s.loadConfig(nil)
	if err == nil {
		t.Fatalf("expected error for missing config, got nil")
	}
}

func TestLoadConfig_MissingFields(t *testing.T) {
	s := newSolver().(*solver)

	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "missing apiKey",
			raw:  `{"secretApiKey":{"name":"porkbun-secret","key":"PORKBUN_SECRET_API_KEY"}}`,
		},
		{
			name: "missing secretApiKey",
			raw:  `{"apiKey":{"name":"porkbun-secret","key":"PORKBUN_API_KEY"}}`,
		},
		{
			name: "empty apiKey name",
			raw:  `{"apiKey":{"name":"","key":"PORKBUN_API_KEY"},"secretApiKey":{"name":"porkbun-secret","key":"PORKBUN_SECRET_API_KEY"}}`,
		},
		{
			name: "empty apiKey key",
			raw:  `{"apiKey":{"name":"porkbun-secret","key":""},"secretApiKey":{"name":"porkbun-secret","key":"PORKBUN_SECRET_API_KEY"}}`,
		},
		{
			name: "empty secretApiKey name",
			raw:  `{"apiKey":{"name":"porkbun-secret","key":"PORKBUN_API_KEY"},"secretApiKey":{"name":"","key":"PORKBUN_SECRET_API_KEY"}}`,
		},
		{
			name: "empty secretApiKey key",
			raw:  `{"apiKey":{"name":"porkbun-secret","key":"PORKBUN_API_KEY"},"secretApiKey":{"name":"porkbun-secret","key":""}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.loadConfig(&extapi.JSON{Raw: []byte(tc.raw)})
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestRecordNameFromChallenge(t *testing.T) {
	cases := []struct {
		name   string
		ch     *acme.ChallengeRequest
		wantZ  string
		wantN  string
		wantEr bool
	}{
		{
			name: "basic _acme-challenge",
			ch: &acme.ChallengeRequest{
				ResolvedZone: "noe-t.dev.",
				ResolvedFQDN: "_acme-challenge.noe-t.dev.",
			},
			wantZ: "noe-t.dev",
			wantN: "_acme-challenge",
		},
		{
			name: "with subdomain",
			ch: &acme.ChallengeRequest{
				ResolvedZone: "noe-t.dev.",
				ResolvedFQDN: "_acme-challenge.sub.noe-t.dev.",
			},
			wantZ: "noe-t.dev",
			wantN: "_acme-challenge.sub",
		},
		{
			name: "zone without trailing dot",
			ch: &acme.ChallengeRequest{
				ResolvedZone: "noe-t.dev",
				ResolvedFQDN: "_acme-challenge.noe-t.dev.",
			},
			wantZ: "noe-t.dev",
			wantN: "_acme-challenge",
		},
		{
			name: "fqdn without trailing dot",
			ch: &acme.ChallengeRequest{
				ResolvedZone: "noe-t.dev.",
				ResolvedFQDN: "_acme-challenge.noe-t.dev",
			},
			wantZ: "noe-t.dev",
			wantN: "_acme-challenge",
		},
		{
			name: "missing zone",
			ch: &acme.ChallengeRequest{
				ResolvedZone: "",
				ResolvedFQDN: "_acme-challenge.noe-t.dev.",
			},
			wantEr: true,
		},
		{
			name: "missing fqdn",
			ch: &acme.ChallengeRequest{
				ResolvedZone: "noe-t.dev.",
				ResolvedFQDN: "",
			},
			wantEr: true,
		},
		{
			name: "fqdn not in zone",
			ch: &acme.ChallengeRequest{
				ResolvedZone: "noe-t.dev.",
				ResolvedFQDN: "_acme-challenge.example.com.",
			},
			wantEr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			z, n, err := recordNameFromChallenge(tc.ch)
			if tc.wantEr {
				if err == nil {
					t.Fatalf("expected error, got nil (zone=%q name=%q)", z, n)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if z != tc.wantZ || n != tc.wantN {
				t.Fatalf("got (zone=%q name=%q), want (zone=%q name=%q)", z, n, tc.wantZ, tc.wantN)
			}
		})
	}
}

func TestNormalizeRecordName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		zone string
		want string
	}{
		{
			name: "relative stays relative",
			in:   "_acme-challenge.sub",
			zone: "noe-t.dev",
			want: "_acme-challenge.sub",
		},
		{
			name: "fqdn gets stripped",
			in:   "_acme-challenge.sub.noe-t.dev.",
			zone: "noe-t.dev.",
			want: "_acme-challenge.sub",
		},
		{
			name: "apex becomes @",
			in:   "noe-t.dev.",
			zone: "noe-t.dev.",
			want: "@",
		},
		{
			name: "empty stays empty",
			in:   "",
			zone: "noe-t.dev",
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeRecordName(tc.in, tc.zone)
			if got != tc.want {
				t.Fatalf("normalizeRecordName(%q,%q)=%q want %q", tc.in, tc.zone, got, tc.want)
			}
		})
	}
}

func TestConfigJSONMatchesYourClusterIssuerExample(t *testing.T) {
	// This test encodes the exact config shape you showed:
	// config:
	//   apiKey:
	//     key: PORKBUN_API_KEY
	//     name: porkbun-secret
	//   secretApiKey:
	//     key: PORKBUN_SECRET_API_KEY
	//     name: porkbun-secret
	s := newSolver().(*solver)

	cfgJSON := []byte(`{
		"apiKey":{"key":"PORKBUN_API_KEY","name":"porkbun-secret"},
		"secretApiKey":{"key":"PORKBUN_SECRET_API_KEY","name":"porkbun-secret"}
	}`)

	cfg, err := s.loadConfig(&extapi.JSON{Raw: cfgJSON})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cfg.APIKey.LocalObjectReference.Name != "porkbun-secret" || cfg.APIKey.Key != "PORKBUN_API_KEY" {
		t.Fatalf("apiKey mismatch: %#v", cfg.APIKey)
	}
	if cfg.SecretAPIKey.LocalObjectReference.Name != "porkbun-secret" || cfg.SecretAPIKey.Key != "PORKBUN_SECRET_API_KEY" {
		t.Fatalf("secretApiKey mismatch: %#v", cfg.SecretAPIKey)
	}
}
