package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientResolvesExactPolicyReference(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/headless/v1/organizations/org/policy-references/resolve" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		query := r.URL.Query()
		if query.Get("kind") != "mcp_tool" || query.Get("selector") != "create issue" || query.Get("parentId") != "server/one" || query.Get("qualifier") != "catalog" {
			t.Fatalf("query = %v", query)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"item": map[string]any{"kind": "mcp_tool", "id": "tool.one", "selector": "create issue"}})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "org", "token", "manager", "instance", "test", time.Second)
	item, err := client.ResolvePolicyReference(context.Background(), "mcp_tool", "create issue", "server/one", "catalog")
	if err != nil || item.ID != "tool.one" {
		t.Fatalf("resolution = %#v, %v", item, err)
	}
}

func TestClientUsesAuthoritativeRegoEvaluationResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil || body["input"] == nil {
			t.Fatalf("invalid evaluation request")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"valid": true, "artifactFingerprint": "artifact", "result": map[string]any{"matched": true, "reasonCode": "sensitive_prompt"},
		})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "org", "token", "manager", "instance", "test", time.Second)
	result, err := client.EvaluateRego(context.Background(), "content", "package forge.content", map[string]any{"stage": "prompt"})
	if err != nil || result.Result == nil || !result.Result.Matched || result.Result.ReasonCode != "sensitive_prompt" {
		t.Fatalf("evaluation = %#v, %v", result, err)
	}
	if err := assertRegoMatch(false, result.Result.Matched); err == nil {
		t.Fatal("mismatched expected result was accepted")
	}
}
