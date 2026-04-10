package porkbun

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

// SolverName is the value you reference in:
// issuer.spec.acme.solvers[].dns01.webhook.solverName
const SolverName = "porkbun"

// DefaultAPIBase is the default Porkbun API base URL.
const DefaultAPIBase = "https://porkbun.com/api/json/v3"

// solver implements webhook.Solver for Porkbun.
type solver struct {
	clientMu sync.Mutex
	k8s      kubernetes.Interface
	http     *http.Client
	apiBase  string
}

// newSolver constructs the Porkbun solver implementation.
// The package-level New() entrypoint lives in `porkbun.go`.
func newSolver() webhook.Solver {
	return &solver{
		http: &http.Client{
			Timeout: 15 * time.Second,
		},
		apiBase: DefaultAPIBase,
	}
}

func logf(format string, args ...any) {
	fmt.Printf("[porkbun] "+format+"\n", args...)
}

// Name returns the solver name used in the Issuer/ClusterIssuer config.
func (s *solver) Name() string {
	return SolverName
}

type config struct {
	APIKey v1.SecretKeySelector `json:"apiKey"`
	// This is Porkbun's "secret API key" (not the same as the API key).
	SecretAPIKey v1.SecretKeySelector `json:"secretApiKey"`
	// Optional override; keep empty for default.
	APIBase string `json:"apiBase,omitempty"`
}

func (s *solver) Initialize(kubeClientConfig *rest.Config, _ <-chan struct{}) error {
	// cert-manager may pass nil in some unit tests
	if kubeClientConfig == nil {
		return nil
	}

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("create kubernetes client: %w", err)
	}

	s.clientMu.Lock()
	s.k8s = cl
	s.clientMu.Unlock()

	return nil
}

func (s *solver) Present(ch *acme.ChallengeRequest) error {
	cfg, err := s.loadConfig(ch.Config)
	if err != nil {
		return err
	}

	apiKey, secretKey, err := s.loadCredentials(ch.ResourceNamespace, cfg)
	if err != nil {
		return err
	}

	zone, name, err := recordNameFromChallenge(ch)
	if err != nil {
		return err
	}

	rec := porkbunCreateRecordRequest{
		APIKey:       apiKey,
		SecretAPIKey: secretKey,
		Type:         "TXT",
		Name:         name,
		Content:      ch.Key,
		TTL:          600,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	exists, err := s.txtRecordExists(ctx, apiKey, secretKey, zone, name, ch.Key)
	if err != nil {
		return err
	}
	if exists {
		logf("present: exists zone=%s name=%s", zone, name)
		return nil
	}

	if _, err := s.createRecord(ctx, zone, rec); err != nil {
		// Retry once by re-checking existence (race with another controller instance).
		existsAfter, checkErr := s.txtRecordExists(ctx, apiKey, secretKey, zone, name, ch.Key)
		if checkErr == nil && existsAfter {
			logf("present: created by another instance zone=%s name=%s", zone, name)
			return nil
		}
		return err
	}

	logf("present: created zone=%s name=%s", zone, name)
	return nil
}

func (s *solver) CleanUp(ch *acme.ChallengeRequest) error {
	cfg, err := s.loadConfig(ch.Config)
	if err != nil {
		return err
	}

	apiKey, secretKey, err := s.loadCredentials(ch.ResourceNamespace, cfg)
	if err != nil {
		return err
	}

	zone, name, err := recordNameFromChallenge(ch)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	records, err := s.listRecords(ctx, apiKey, secretKey, zone)
	if err != nil {
		return err
	}

	var toDelete []string
	for _, r := range records {
		if strings.EqualFold(r.Type, "TXT") && fqdnEq(normalizeRecordName(r.Name, zone), name) && r.Content == ch.Key {
			if r.ID != "" {
				toDelete = append(toDelete, r.ID)
			}
		}
	}

	if len(toDelete) == 0 {
		logf("cleanup: nothing to delete zone=%s name=%s", zone, name)
		return nil
	}

	for _, id := range toDelete {
		if err := s.deleteRecord(ctx, apiKey, secretKey, zone, id); err != nil {
			return err
		}
	}

	logf("cleanup: deleted %d record(s) zone=%s name=%s", len(toDelete), zone, name)
	return nil
}

func (s *solver) loadConfig(cfgJSON *extapi.JSON) (config, error) {
	cfg := config{}

	if cfgJSON == nil || len(cfgJSON.Raw) == 0 {
		return cfg, errors.New("missing solver config: expected apiKey and secretApiKey secret refs")
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("decode solver config: %w", err)
	}

	if cfg.APIKey.Key == "" || cfg.APIKey.LocalObjectReference.Name == "" {
		return cfg, errors.New("missing config.apiKey.name or config.apiKey.key")
	}
	if cfg.SecretAPIKey.Key == "" || cfg.SecretAPIKey.LocalObjectReference.Name == "" {
		return cfg, errors.New("missing config.secretApiKey.name or config.secretApiKey.key")
	}

	if cfg.APIBase != "" {
		cfg.APIBase = strings.TrimRight(cfg.APIBase, "/")
	}

	return cfg, nil
}

func (s *solver) loadCredentials(namespace string, cfg config) (apiKey string, secretKey string, err error) {
	s.clientMu.Lock()
	k8s := s.k8s
	s.clientMu.Unlock()

	if k8s == nil {
		return "", "", errors.New("kubernetes client not initialized (cannot read Secret); is the webhook running in cluster?")
	}

	sec, err := k8s.CoreV1().Secrets(namespace).Get(context.Background(), cfg.APIKey.LocalObjectReference.Name, metav1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("read secret %s/%s: %w", namespace, cfg.APIKey.LocalObjectReference.Name, err)
	}

	apiKeyBytes, ok := sec.Data[cfg.APIKey.Key]
	if !ok {
		return "", "", fmt.Errorf("secret %s/%s missing key %q", namespace, cfg.APIKey.LocalObjectReference.Name, cfg.APIKey.Key)
	}
	secretKeyBytes, ok := sec.Data[cfg.SecretAPIKey.Key]
	if !ok {
		return "", "", fmt.Errorf("secret %s/%s missing key %q", namespace, cfg.SecretAPIKey.LocalObjectReference.Name, cfg.SecretAPIKey.Key)
	}

	apiKey = strings.TrimSpace(string(apiKeyBytes))
	secretKey = strings.TrimSpace(string(secretKeyBytes))

	if apiKey == "" {
		return "", "", fmt.Errorf("secret %s/%s key %q is empty", namespace, cfg.APIKey.LocalObjectReference.Name, cfg.APIKey.Key)
	}
	if secretKey == "" {
		return "", "", fmt.Errorf("secret %s/%s key %q is empty", namespace, cfg.SecretAPIKey.LocalObjectReference.Name, cfg.SecretAPIKey.Key)
	}

	return apiKey, secretKey, nil
}

// recordNameFromChallenge computes the Porkbun "domain" (zone) and "name" (record name)
// for the TXT record needed for DNS-01.
// Porkbun API uses:
// - domain: apex zone (e.g. "noe-t.dev")
// - name: record name relative to zone or full name; we use "_acme-challenge" or "_acme-challenge.sub".
func recordNameFromChallenge(ch *acme.ChallengeRequest) (zone string, name string, err error) {
	zone = strings.TrimSuffix(strings.TrimSpace(ch.ResolvedZone), ".")
	if zone == "" {
		return "", "", errors.New("challenge missing ResolvedZone")
	}

	fqdn := strings.TrimSuffix(strings.TrimSpace(ch.ResolvedFQDN), ".")
	if fqdn == "" {
		return "", "", errors.New("challenge missing ResolvedFQDN")
	}

	// The resolved FQDN should end with the zone.
	if !strings.HasSuffix(fqdn, zone) {
		return "", "", fmt.Errorf("resolvedFQDN %q does not end with resolvedZone %q", fqdn, zone)
	}

	// Strip ".<zone>" suffix to obtain left part.
	left := strings.TrimSuffix(fqdn, zone)
	left = strings.TrimSuffix(left, ".")
	if left == "" {
		// record at apex, should not happen for dns-01, but handle anyway.
		return zone, "@", nil
	}

	// Most commonly left will be "_acme-challenge" or "_acme-challenge.<sub>".
	return zone, left, nil
}

type porkbunEnvelope struct {
	Status  string          `json:"status"`
	Message string          `json:"message"`
	Errors  []string        `json:"errors,omitempty"`
	Records []porkbunRecord `json:"records,omitempty"`
	Record  *porkbunRecord  `json:"record,omitempty"`
}

type porkbunRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     string `json:"ttl,omitempty"`
}

type porkbunAuth struct {
	APIKey       string `json:"apikey"`
	SecretAPIKey string `json:"secretapikey"`
}

type porkbunListRecordsRequest struct {
	porkbunAuth
}

type porkbunCreateRecordRequest struct {
	APIKey       string `json:"apikey"`
	SecretAPIKey string `json:"secretapikey"`
	Type         string `json:"type"`
	Name         string `json:"name"`
	Content      string `json:"content"`
	TTL          int    `json:"ttl,omitempty"`
}

type porkbunDeleteRecordRequest struct {
	porkbunAuth
	RecordID string `json:"recordid"`
}

func (s *solver) baseURL(cfg config) string {
	if cfg.APIBase != "" {
		return cfg.APIBase
	}
	return s.apiBase
}

func (s *solver) listRecords(ctx context.Context, apiKey, secretKey, zone string) ([]porkbunRecord, error) {
	reqBody := porkbunListRecordsRequest{
		porkbunAuth: porkbunAuth{APIKey: apiKey, SecretAPIKey: secretKey},
	}
	url := strings.TrimRight(s.apiBase, "/") + "/dns/retrieve/" + zone
	env, err := s.do(ctx, url, reqBody)
	if err != nil {
		return nil, err
	}
	return env.Records, nil
}

func (s *solver) createRecord(ctx context.Context, zone string, req porkbunCreateRecordRequest) (*porkbunEnvelope, error) {
	url := strings.TrimRight(s.apiBase, "/") + "/dns/create/" + zone
	return s.do(ctx, url, req)
}

func (s *solver) deleteRecord(ctx context.Context, apiKey, secretKey, zone, recordID string) error {
	url := strings.TrimRight(s.apiBase, "/") + "/dns/delete/" + zone
	req := porkbunDeleteRecordRequest{
		porkbunAuth: porkbunAuth{APIKey: apiKey, SecretAPIKey: secretKey},
		RecordID:    recordID,
	}
	_, err := s.do(ctx, url, req)
	return err
}

func (s *solver) txtRecordExists(ctx context.Context, apiKey, secretKey, zone, name, content string) (bool, error) {
	records, err := s.listRecords(ctx, apiKey, secretKey, zone)
	if err != nil {
		return false, err
	}
	for _, r := range records {
		if !strings.EqualFold(r.Type, "TXT") {
			continue
		}
		if r.Content != content {
			continue
		}
		if fqdnEq(normalizeRecordName(r.Name, zone), name) {
			return true, nil
		}
	}
	return false, nil
}

func (s *solver) do(ctx context.Context, url string, body any) (*porkbunEnvelope, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("create http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("porkbun api request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, fmt.Errorf("read porkbun api response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("porkbun api http %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	env := &porkbunEnvelope{}
	if err := json.Unmarshal(respBody, env); err != nil {
		return nil, fmt.Errorf("decode porkbun api response: %w", err)
	}

	if !strings.EqualFold(env.Status, "SUCCESS") {
		msg := strings.TrimSpace(env.Message)
		if msg == "" && len(env.Errors) > 0 {
			msg = strings.Join(env.Errors, "; ")
		}
		if msg == "" {
			msg = "unknown error"
		}
		return nil, fmt.Errorf("porkbun api error: %s", msg)
	}

	return env, nil
}

// normalizeRecordName attempts to normalize Porkbun record "name" into the same
// form we use from the challenge (relative left-hand side, e.g. "_acme-challenge.sub").
// Porkbun may return names as either relative or FQDN; this makes comparisons robust.
func normalizeRecordName(porkbunName, zone string) string {
	n := strings.TrimSuffix(strings.TrimSpace(porkbunName), ".")
	z := strings.TrimSuffix(strings.TrimSpace(zone), ".")
	if n == "" {
		return n
	}
	// If returns full name ending with zone, strip it.
	if z != "" && strings.HasSuffix(n, z) {
		left := strings.TrimSuffix(n, z)
		left = strings.TrimSuffix(left, ".")
		if left == "" {
			return "@"
		}
		return left
	}
	return n
}

func fqdnEq(a, b string) bool {
	aa := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a)), ".")
	bb := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(b)), ".")
	return aa == bb
}
