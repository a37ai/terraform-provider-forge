package provider

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientAddsScopedTerraformHeadersAndDecodes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/headless/v1/organizations/org/content-policies" || r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("X-Forge-Terraform-Manager") != "manager" || r.Header.Get("X-Forge-Terraform-Instance") != "workspace" {
			t.Errorf("request: %s headers=%v", r.URL.Path, r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "org", "secret", "manager", "workspace", "test", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		OK bool `json:"ok"`
	}
	if err := client.Do(context.Background(), http.MethodGet, "content-policies", nil, &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK {
		t.Fatal("response not decoded")
	}
}

func TestClientSeparatesPathAndQueryForRevisionBoundDeletes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/headless/v1/organizations/org.query/content-policies/policy.one" {
			t.Fatalf("path contains query material: %q", r.URL.Path)
		}
		if r.URL.Query().Get("expectedRevision") != "42" {
			t.Fatalf("expectedRevision query=%q", r.URL.RawQuery)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "org.query", "token", "manager", "instance", "test", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Do(context.Background(), http.MethodDelete, "content-policies/policy.one?expectedRevision=42", nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestClientNeverFollowsRedirectsWithAutomationCredentials(t *testing.T) {
	var redirected bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Forge-Terraform-Manager") != "" {
			t.Fatal("automation credentials reached redirect target")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/capture", http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client, err := NewClient(source.URL, "org", "secret-token", "manager", "instance", "test", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Do(context.Background(), http.MethodGet, "policy-contracts/capabilities", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("expected redirect response to fail closed, got %v", err)
	}
	if redirected {
		t.Fatal("client followed a redirect")
	}
}

func TestClientRejectsEndpointCredentialsQueryAndFragment(t *testing.T) {
	for _, endpoint := range []string{"https://user:pass@example.com", "https://example.com?tenant=other", "https://example.com#fragment"} {
		if _, err := NewClient(endpoint, "org", "token", "manager", "instance", "test", time.Second); err == nil {
			t.Fatalf("accepted unsafe endpoint %q", endpoint)
		}
	}
}

func TestClientRetriesOnlyIdempotentRequestsAndClassifiesNotFound(t *testing.T) {
	var attempts atomic.Int32
	var idempotencyKey atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Idempotency-Key")
		if key == "" || r.Header.Get("X-Forge-Confirm") != "true" || r.Header.Get("X-Forge-Reason") == "" {
			t.Errorf("mutation safety headers missing: %v", r.Header)
		}
		if first := idempotencyKey.Load(); first == nil {
			idempotencyKey.Store(key)
		} else if first.(string) != key {
			t.Errorf("retry changed idempotency key: %q != %q", key, first)
		}
		current := attempts.Add(1)
		if current < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "org", "token", "manager", "instance", "test", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Do(context.Background(), http.MethodPut, "content-policies/p", map[string]any{"x": 1}, nil); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("attempts=%d", attempts.Load())
	}
	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer notFound.Close()
	client, _ = NewClient(notFound.URL, "org", "token", "manager", "instance", "test", time.Second)
	if err = client.Do(context.Background(), http.MethodGet, "content-policies/missing", nil, nil); !IsNotFound(err) {
		t.Fatalf("not classified: %v", err)
	}
}

func TestClientBoundsResponsesAndHonorsCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxResponseBytes+1)))
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "org", "token", "manager", "instance", "test", time.Second)
	if err := client.Do(context.Background(), http.MethodGet, "content-policies", nil, nil); err == nil || !strings.Contains(err.Error(), "4 MiB") {
		t.Fatalf("err=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.Do(ctx, http.MethodGet, "content-policies", nil, nil); err == nil {
		t.Fatal("expected cancellation")
	}
}

func TestClientRetriesOnlyExplicitlyIdempotentPosts(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "org", "token", "manager", "instance", "test", 3*time.Second)
	_ = client.Do(context.Background(), http.MethodPost, "content-policies", map[string]any{}, nil)
	if attempts.Load() != 4 {
		t.Fatalf("idempotent policy create attempts=%d", attempts.Load())
	}
	attempts.Store(0)
	_ = client.Do(context.Background(), http.MethodPost, "resource-policies", map[string]any{}, nil)
	if attempts.Load() != 4 {
		t.Fatalf("idempotent Resource policy create attempts=%d", attempts.Load())
	}
	attempts.Store(0)
	_ = client.Do(context.Background(), http.MethodPost, "policy-authority/p/claim", map[string]any{}, nil)
	if attempts.Load() != 4 {
		t.Fatalf("authority POST attempts=%d", attempts.Load())
	}
	attempts.Store(0)
	_ = client.Do(context.Background(), http.MethodPost, "resources/res_1/credentials", map[string]any{"secret": "write-only"}, nil)
	if attempts.Load() != 4 {
		t.Fatalf("Resource credential create attempts=%d", attempts.Load())
	}
	attempts.Store(0)
	_ = client.Do(context.Background(), http.MethodPost, "unrelated-action", map[string]any{}, nil)
	if attempts.Load() != 1 {
		t.Fatalf("non-idempotent POST attempts=%d", attempts.Load())
	}
}

func TestClientValidationAndBoundedErrors(t *testing.T) {
	if _, err := NewClient("http://example.com", "org", "token", "manager", "instance", "test", time.Second); err == nil {
		t.Fatal("expected HTTPS validation")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = fmt.Fprint(w, `{"error":"revision conflict"}`)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "org", "secret", "manager", "workspace", "test", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Do(context.Background(), http.MethodGet, "content-policies", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "revision conflict") {
		t.Fatalf("err=%v", err)
	}
}

func TestClientRedactsAndBoundsHostileAPIErrors(t *testing.T) {
	const configuredToken = "configured-super-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Bearer upstream-token api_key=key-value password: hunter2 secret=\"fixture-secret\" configured-super-secret\n" + strings.Repeat("x", maxDiagnosticErrorText+200)})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "org", configuredToken, "manager", "instance", "test", time.Second)
	err := client.Do(context.Background(), http.MethodGet, "content-policies", nil, nil)
	if err == nil {
		t.Fatal("expected API error")
	}
	got := err.Error()
	for _, secret := range []string{"upstream-token", "key-value", "hunter2", "fixture-secret", configuredToken} {
		if strings.Contains(got, secret) {
			t.Fatalf("diagnostic leaked %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "[REDACTED]") || len(got) > maxDiagnosticErrorText+64 {
		t.Fatalf("diagnostic was not redacted and bounded: len=%d value=%q", len(got), got)
	}
}

func TestSanitizeDiagnosticHandlesJSONAndControlCharacters(t *testing.T) {
	got := sanitizeDiagnostic("{\"access_token\":\"abc123\",\"cookie\":\"sid=xyz\"}\x00\x1b")
	if strings.Contains(got, "abc123") || strings.Contains(got, "sid=xyz") || strings.ContainsRune(got, '\x00') || strings.ContainsRune(got, '\x1b') {
		t.Fatalf("unsafe diagnostic: %q", got)
	}
}

func TestClientNegotiatesPolicyContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/headless/v1/organizations/org/policy-contracts/capabilities" {
			t.Fatalf("unexpected negotiation request: %s %s", r.Method, r.URL.Path)
		}
		_, _ = fmt.Fprint(w, `{"policySchemaVersion":"forge.policy.families.v1","regoLanguageVersion":"forge.rego.v1","regoCompilerFingerprint":"fingerprint","terraformPolicyProtocol":"forge.terraform.policy.v1","terraformGatewayProtocol":"forge.terraform.llm-gateway-plan.v1","terraformOwnershipBinding":"service_account_principal"}`)
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "org", "token", "manager", "instance", "test", time.Second)
	if _, err := client.Negotiate(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestClientRejectsIncompatiblePolicyContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"policySchemaVersion":"forge.policy.families.v2"}`)
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "org", "token", "manager", "instance", "test", time.Second)
	if _, err := client.Negotiate(context.Background()); err == nil {
		t.Fatal("incompatible server was accepted")
	}
}

func TestClientPreservesControlPlaneMessageErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = fmt.Fprint(w, `{"message":"canonical Access validation failed"}`)
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "org", "token", "manager", "instance", "test", time.Second)
	var response map[string]any
	err := client.Do(context.Background(), http.MethodGet, "access-policies", nil, &response)
	if err == nil || !strings.Contains(err.Error(), "canonical Access validation failed") {
		t.Fatalf("error=%v", err)
	}
}

func TestClientCachesAuthoritativeRegoValidationBySource(t *testing.T) {
	var requests atomic.Int32
	module := "package forge.content\nmatch := {\"matched\": false}"
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(module)))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"valid": true, "languageVersion": "forge.rego.v1", "compilerFingerprint": "compiler", "sourceSha256": digest})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "org", "token", "manager", "instance", "test", time.Second)
	for range 3 {
		if _, err := client.ValidateRego(context.Background(), "content", module); err != nil {
			t.Fatal(err)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("validation requests=%d, want 1", requests.Load())
	}
}

func TestClientRequestsAuthoritativePolicyPlanBinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/headless/v1/organizations/org/policy-plans/validate" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request["family"] != "content" || request["expectedRevision"] != float64(7) || request["definition"] == nil || request["sourceRef"] == nil {
			t.Fatalf("incomplete plan request: %#v", request)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"valid": true, "validationToken": "signed-token", "definitionSha256": strings.Repeat("a", 64), "referenceBindingFingerprint": strings.Repeat("b", 64), "schemaVersion": "forge.policy.families.v1", "compilerFingerprint": "compiler"})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "org", "token", "manager", "instance", "test", time.Second)
	result, err := client.ValidatePolicyPlan(context.Background(), "content", map[string]any{"id": "p"}, map[string]any{"tool": "terraform"}, 7)
	if err != nil || result.ValidationToken != "signed-token" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestClientRefreshesExpiringPolicyPlanBinding(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"valid": true, "validationToken": fmt.Sprintf("token-%d", requests), "schemaVersion": "forge.policy.families.v1",
			"compilerFingerprint": "compiler", "expiresAt": time.Now().Add(30 * time.Second),
		})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "org", "token", "manager", "instance", "test", time.Second)
	for range 2 {
		if _, err := client.ValidatePolicyPlan(context.Background(), "content", map[string]any{"id": "p"}, map[string]any{}, 1); err != nil {
			t.Fatal(err)
		}
	}
	if requests != 2 {
		t.Fatalf("expiring plan binding requests=%d, want 2", requests)
	}
}

func TestClientReusesStablePolicyPlanBinding(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"valid": true, "validationToken": "stable", "schemaVersion": "forge.policy.families.v1",
			"compilerFingerprint": "compiler", "expiresAt": time.Now().Add(10 * time.Minute),
		})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "org", "token", "manager", "instance", "test", time.Second)
	for range 2 {
		if _, err := client.ValidatePolicyPlan(context.Background(), "content", map[string]any{"id": "p"}, map[string]any{}, 1); err != nil {
			t.Fatal(err)
		}
	}
	if requests != 1 {
		t.Fatalf("stable plan binding requests=%d, want 1", requests)
	}
}
