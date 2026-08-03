package provider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxResponseBytes       = 4 << 20
	maxDiagnosticErrorText = 2048
)

var diagnosticSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(bearer\s+)[a-z0-9._~+/=-]+`),
	regexp.MustCompile(`(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|passwd|secret|authorization|cookie)\s*[=:]\s*["']?)[^\s,"'\\}]+`),
	regexp.MustCompile(`(?i)(["'](?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|passwd|secret|authorization|cookie)["']\s*:\s*["'])[^"']+`),
}

type Client struct {
	endpoint        *url.URL
	organizationID  string
	token           string
	managerID       string
	managerInstance string
	userAgent       string
	http            *http.Client
	validationMu    sync.Mutex
	regoValidations map[string]RegoValidation
	planValidations map[string]PolicyPlanValidation
}

type RegoValidation struct {
	Valid               bool             `json:"valid"`
	LanguageVersion     string           `json:"languageVersion"`
	OPAVersion          string           `json:"opaVersion"`
	SourceSHA           string           `json:"sourceSha256"`
	CompilerFingerprint string           `json:"compilerFingerprint"`
	ArtifactFingerprint string           `json:"artifactFingerprint"`
	Result              *RegoMatchResult `json:"result,omitempty"`
}

type RegoMatchResult struct {
	Matched    bool   `json:"matched"`
	ReasonCode string `json:"reasonCode"`
}

type PolicyReference struct {
	Kind      string  `json:"kind"`
	ID        string  `json:"id"`
	Selector  string  `json:"selector"`
	Qualifier *string `json:"qualifier,omitempty"`
}

type PolicyCapabilities struct {
	PolicySchemaVersion       string `json:"policySchemaVersion"`
	RegoLanguageVersion       string `json:"regoLanguageVersion"`
	RegoCompilerFingerprint   string `json:"regoCompilerFingerprint"`
	TerraformPolicyProtocol   string `json:"terraformPolicyProtocol"`
	TerraformGatewayProtocol  string `json:"terraformGatewayProtocol"`
	TerraformOwnershipBinding string `json:"terraformOwnershipBinding"`
}

type PolicyPlanValidation struct {
	Valid                       bool      `json:"valid"`
	ValidationToken             string    `json:"validationToken"`
	DefinitionSHA256            string    `json:"definitionSha256"`
	ReferenceBindingFingerprint string    `json:"referenceBindingFingerprint"`
	SchemaVersion               string    `json:"schemaVersion"`
	CompilerFingerprint         string    `json:"compilerFingerprint"`
	ExpiresAt                   time.Time `json:"expiresAt"`
}

type LLMGatewayPlanValidation struct {
	Valid           bool      `json:"valid"`
	ValidationToken string    `json:"validationToken"`
	PlanSHA256      string    `json:"planSha256"`
	SchemaVersion   string    `json:"schemaVersion"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

func (c *Client) ValidateLLMGatewayPlan(ctx context.Context, payload map[string]any) (LLMGatewayPlanValidation, error) {
	var result LLMGatewayPlanValidation
	if err := c.Do(ctx, http.MethodPost, "llm-gateway/plans/validate", payload, &result); err != nil {
		return result, fmt.Errorf("authoritative LLM Gateway plan validation: %w", err)
	}
	if !result.Valid || result.ValidationToken == "" || result.SchemaVersion != "forge.terraform.llm-gateway-plan.v1" {
		return result, errors.New("Forge server returned an incomplete LLM Gateway plan binding")
	}
	return result, nil
}

func (c *Client) ValidatePolicyPlan(ctx context.Context, family string, definition, sourceRef any, expectedRevision int64) (PolicyPlanValidation, error) {
	var result PolicyPlanValidation
	body := map[string]any{"family": family, "definition": definition, "sourceRef": sourceRef, "expectedRevision": expectedRevision}
	canonical, err := json.Marshal(body)
	if err != nil {
		return result, fmt.Errorf("encode policy plan binding: %w", err)
	}
	cacheKey := fmt.Sprintf("%x", sha256.Sum256(canonical))
	c.validationMu.Lock()
	if cached, ok := c.planValidations[cacheKey]; ok && time.Until(cached.ExpiresAt) > time.Minute {
		c.validationMu.Unlock()
		return cached, nil
	}
	c.validationMu.Unlock()
	if err := c.Do(ctx, http.MethodPost, "policy-plans/validate", body, &result); err != nil {
		return result, fmt.Errorf("authoritative policy plan validation: %w", err)
	}
	if !result.Valid || result.ValidationToken == "" || result.SchemaVersion != "forge.policy.families.v1" || result.CompilerFingerprint == "" {
		return result, errors.New("Forge server returned an incomplete policy plan binding")
	}
	c.validationMu.Lock()
	c.planValidations[cacheKey] = result
	c.validationMu.Unlock()
	return result, nil
}

func (c *Client) Negotiate(ctx context.Context) (PolicyCapabilities, error) {
	var result PolicyCapabilities
	if err := c.Do(ctx, http.MethodGet, "policy-contracts/capabilities", nil, &result); err != nil {
		return result, fmt.Errorf("negotiate Forge policy contracts: %w", err)
	}
	if result.PolicySchemaVersion != "forge.policy.families.v1" || result.RegoLanguageVersion != "forge.rego.v1" || result.TerraformPolicyProtocol != "forge.terraform.policy.v1" || result.TerraformGatewayProtocol != "forge.terraform.llm-gateway-plan.v1" || result.TerraformOwnershipBinding != "service_account_principal" || result.RegoCompilerFingerprint == "" {
		return result, errors.New("Forge server does not advertise a compatible policy-as-code contract")
	}
	return result, nil
}

func (c *Client) ValidateRego(ctx context.Context, family, module string, evaluateOn ...string) (RegoValidation, error) {
	stages := append([]string(nil), evaluateOn...)
	sort.Strings(stages)
	cacheKey := family + "\x00" + strings.Join(stages, ",") + "\x00" + fmt.Sprintf("%x", sha256.Sum256([]byte(module)))
	c.validationMu.Lock()
	if cached, ok := c.regoValidations[cacheKey]; ok {
		c.validationMu.Unlock()
		return cached, nil
	}
	c.validationMu.Unlock()
	var result RegoValidation
	body := map[string]any{"family": family, "module": module}
	if len(stages) > 0 {
		body["evaluateOn"] = stages
	}
	if err := c.Do(ctx, http.MethodPost, "policy-code/rego/validate", body, &result); err != nil {
		return result, fmt.Errorf("server rejected forge.rego.v1 module: %w", err)
	}
	if !result.Valid || result.LanguageVersion != "forge.rego.v1" || result.CompilerFingerprint == "" {
		return result, errors.New("Forge server does not advertise a compatible forge.rego.v1 compiler")
	}
	c.validationMu.Lock()
	if c.regoValidations == nil {
		c.regoValidations = make(map[string]RegoValidation)
	}
	c.regoValidations[cacheKey] = result
	c.validationMu.Unlock()
	return result, nil
}

func (c *Client) EvaluateRego(ctx context.Context, family, module string, input any, evaluateOn ...string) (RegoValidation, error) {
	var result RegoValidation
	body := map[string]any{"family": family, "module": module, "input": input}
	if len(evaluateOn) > 0 {
		body["evaluateOn"] = evaluateOn
	}
	if err := c.Do(ctx, http.MethodPost, "policy-code/rego/validate", body, &result); err != nil {
		return result, fmt.Errorf("authoritative Forge Rego evaluation: %w", err)
	}
	if !result.Valid || result.Result == nil {
		return result, errors.New("Forge server returned no authoritative Rego result")
	}
	return result, nil
}

func (c *Client) ResolvePolicyReference(ctx context.Context, kind, selector, parentID, qualifier string) (PolicyReference, error) {
	query := url.Values{"kind": {kind}, "selector": {selector}}
	if parentID != "" {
		query.Set("parentId", parentID)
	}
	if qualifier != "" {
		query.Set("qualifier", qualifier)
	}
	var response struct {
		Item PolicyReference `json:"item"`
	}
	if err := c.Do(ctx, http.MethodGet, "policy-references/resolve?"+query.Encode(), nil, &response); err != nil {
		return PolicyReference{}, err
	}
	if response.Item.ID == "" {
		return PolicyReference{}, errors.New("Forge server returned an empty policy reference")
	}
	return response.Item, nil
}

// APIError preserves the status code so resources can distinguish remote
// deletion and authority conflicts without parsing error strings.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string { return fmt.Sprintf("Forge API %d: %s", e.StatusCode, e.Message) }

func IsNotFound(err error) bool {
	var apiError *APIError
	return errors.As(err, &apiError) && apiError.StatusCode == http.StatusNotFound
}

func NewClient(endpoint, organizationID, token, managerID, managerInstance, userAgent string, timeout time.Duration) (*Client, error) {
	parsed, err := url.Parse(strings.TrimRight(endpoint, "/"))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("endpoint must be an absolute HTTP(S) URL")
	}
	if parsed.Scheme != "https" && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" {
		return nil, errors.New("endpoint must use HTTPS except for localhost")
	}
	if organizationID == "" || token == "" || managerID == "" || managerInstance == "" {
		return nil, errors.New("organization_id, api_token, manager_id, and manager_instance are required; copy organization_id from the Console URL, provide api_token via FORGE_API_TOKEN or the sensitive provider field, and choose stable manager_id and manager_instance labels for this Terraform workspace")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Client{endpoint: parsed, organizationID: organizationID, token: token, managerID: managerID, managerInstance: managerInstance, userAgent: userAgent, http: &http.Client{Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}, regoValidations: make(map[string]RegoValidation), planValidations: make(map[string]PolicyPlanValidation)}, nil
}

func (c *Client) Do(ctx context.Context, method, path string, requestBody, responseBody any) error {
	var requestBytes []byte
	if requestBody != nil {
		raw, err := json.Marshal(requestBody)
		if err != nil {
			return err
		}
		requestBytes = raw
	}
	target := *c.endpoint
	relative, err := url.Parse(strings.TrimLeft(path, "/"))
	if err != nil || relative.IsAbs() || relative.Host != "" || relative.Fragment != "" {
		return errors.New("Forge API path is invalid")
	}
	target.Path = strings.TrimRight(target.Path, "/") + "/api/headless/v1/organizations/" + url.PathEscape(c.organizationID) + "/" + relative.Path
	target.RawQuery = relative.RawQuery
	var response *http.Response
	idempotencyKey := ""
	if isMutation(method) {
		idempotencyKey, err = newIdempotencyKey()
		if err != nil {
			return err
		}
	}
	for attempt := 0; attempt < 4; attempt++ {
		var body io.Reader
		if requestBytes != nil {
			body = bytes.NewReader(requestBytes)
		}
		req, requestErr := http.NewRequestWithContext(ctx, method, target.String(), body)
		if requestErr != nil {
			return requestErr
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", c.userAgent)
		req.Header.Set("X-Forge-Terraform-Manager", c.managerID)
		req.Header.Set("X-Forge-Terraform-Instance", c.managerInstance)
		if idempotencyKey != "" {
			req.Header.Set("Idempotency-Key", idempotencyKey)
			req.Header.Set("X-Forge-Reason", "terraform policy reconciliation")
			req.Header.Set("X-Forge-Confirm", "true")
		}
		response, err = c.http.Do(req)
		if err != nil {
			if !retryableRequest(method, path) || attempt == 3 || ctx.Err() != nil {
				return err
			}
			if waitErr := waitForRetry(ctx, attempt, ""); waitErr != nil {
				return waitErr
			}
			continue
		}
		if !retryableRequest(method, path) || (response.StatusCode != http.StatusTooManyRequests && response.StatusCode < 500) || attempt == 3 {
			break
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes+1))
		response.Body.Close()
		if waitErr := waitForRetry(ctx, attempt, response.Header.Get("Retry-After")); waitErr != nil {
			return waitErr
		}
	}
	if response == nil {
		return errors.New("Forge API request produced no response")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxResponseBytes {
		return errors.New("Forge response exceeds 4 MiB")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var envelope struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &envelope)
		if envelope.Error == "" {
			envelope.Error = envelope.Message
		}
		if envelope.Error == "" {
			envelope.Error = http.StatusText(response.StatusCode)
		}
		return &APIError{StatusCode: response.StatusCode, Message: sanitizeDiagnostic(envelope.Error, c.token)}
	}
	if responseBody != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, responseBody); err != nil {
			return fmt.Errorf("decode Forge response: %w", err)
		}
	}
	return nil
}

// sanitizeDiagnostic treats remote error text as hostile and potentially
// sensitive. It removes credentials, control characters, and unbounded tails
// before the text can enter Terraform diagnostics or logs.
func sanitizeDiagnostic(message string, knownSecrets ...string) string {
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f) {
			return r
		}
		return ' '
	}, message)
	for _, secret := range knownSecrets {
		if secret != "" {
			clean = strings.ReplaceAll(clean, secret, "[REDACTED]")
		}
	}
	for _, pattern := range diagnosticSecretPatterns {
		clean = pattern.ReplaceAllString(clean, `${1}[REDACTED]`)
	}
	clean = strings.TrimSpace(clean)
	if clean == "" {
		clean = "request failed"
	}
	if len(clean) > maxDiagnosticErrorText {
		clean = clean[:maxDiagnosticErrorText] + "…"
	}
	return clean
}

func isMutation(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
}

func newIdempotencyKey() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate idempotency key: %w", err)
	}
	return fmt.Sprintf("tf-%x", value[:]), nil
}

func retryableRequest(method, path string) bool {
	clean := strings.TrimLeft(path, "/")
	idempotentCreate := map[string]bool{"content-policies": true, "access-policies": true, "skill-acls": true}
	return method == http.MethodGet || method == http.MethodPut || method == http.MethodDelete || (method == http.MethodPost && (strings.HasPrefix(clean, "policy-authority/") || clean == "policy-code/rego/validate" || clean == "policy-plans/validate" || idempotentCreate[clean]))
}

func waitForRetry(ctx context.Context, attempt int, retryAfter string) error {
	delay := time.Duration(100*(1<<attempt)) * time.Millisecond
	if parsed, err := time.ParseDuration(strings.TrimSpace(retryAfter) + "s"); err == nil && parsed > 0 && parsed <= 2*time.Second {
		delay = parsed
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
