package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestGatewayBudgetTerraformPreservesAllowancesAndVersion(t *testing.T) {
	var saved llmGatewayBudgetAPI
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/headless/v1/organizations/org.test/llm-gateway/budgets") {
			t.Errorf("wrong scope: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{"budgets": []llmGatewayBudgetAPI{saved}})
			return
		}
		if r.Header.Get("Idempotency-Key") == "" || r.Header.Get("X-Forge-Confirm") != "true" {
			t.Error("unguarded mutation")
		}
		var body llmGatewayBudgetAPI
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if calls > 0 {
			if body.UpdatedAt != saved.UpdatedAt || string(body.Metadata["allowance"]) != string(saved.Metadata["allowance"]) {
				t.Error("lost version or administrator allowance")
			}
			if body.Amount == nil || *body.Amount != 200 {
				t.Error("updated normal limit missing")
			}
		}
		calls++
		body.ID = "budget.test"
		body.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		saved = body
		_ = json.NewEncoder(w).Encode(map[string]any{"budget": body})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "org.test", "test-token", "manager", "test", "test", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resource := llmGatewayBudgetResource{client: client}
	model := llmGatewayBudgetModel{SubjectKind: types.StringValue("group"), SubjectID: types.StringValue("engineering"), Window: types.StringValue("monthly"), Amount: types.Float64Value(100), MemberDefault: types.Float64Value(10)}
	var d diag.Diagnostics
	resource.save(context.Background(), &model, &d)
	if d.HasError() || model.ID.ValueString() != "budget.test" {
		t.Fatalf("create: %v %+v", d, model)
	}
	saved.Metadata["allowance"] = json.RawMessage(`{"amountUsd":5,"windowStart":"2026-11-01T00:00:00Z"}`)
	model.Amount = types.Float64Value(200)
	resource.save(context.Background(), &model, &d)
	if d.HasError() || calls != 2 {
		t.Fatalf("update: %v calls=%d", d, calls)
	}
}
