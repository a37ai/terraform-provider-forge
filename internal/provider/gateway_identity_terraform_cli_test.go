package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestTerraformCLIGatewayIdentityLifecycle(t *testing.T) {
	terraform := strings.TrimSpace(os.Getenv("FORGE_TERRAFORM_CLI"))
	if terraform == "" {
		t.Skip("set FORGE_TERRAFORM_CLI to a Terraform or OpenTofu executable")
	}
	var mu sync.Mutex
	var account map[string]any
	var override map[string]any
	var assignment map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(r.URL.Path, "/api/headless/v1/organizations/org.gateway/")
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && path == "policy-contracts/capabilities":
			_, _ = w.Write([]byte(`{"policySchemaVersion":"forge.policy.families.v1","regoLanguageVersion":"forge.rego.v1","regoCompilerFingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","terraformPolicyProtocol":"forge.terraform.policy.v1","terraformGatewayProtocol":"forge.terraform.llm-gateway-plan.v1","terraformOwnershipBinding":"service_account_principal"}`))
		case r.Method == http.MethodGet && path == "llm-gateway":
			accounts := []any{}
			if account != nil {
				accounts = append(accounts, account)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"providers": []any{}, "accessProfiles": []any{}, "routes": []any{}, "serviceAccounts": accounts})
		case r.Method == http.MethodPost && path == "llm-gateway/service-accounts":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			body["id"] = "lgwsa_tf"
			body["state"] = "active"
			account = body
			_ = json.NewEncoder(w).Encode(map[string]any{"serviceAccount": account})
		case r.Method == http.MethodPost && path == "llm-gateway/service-accounts/lgwsa_tf/disable":
			account = nil
			_ = json.NewEncoder(w).Encode(map[string]any{"serviceAccount": map[string]any{"id": "lgwsa_tf", "state": "disabled"}})
		case r.Method == http.MethodGet && path == "llm-gateway/managed-developer":
			items := []any{}
			if override != nil {
				items = append(items, override)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"overrides": items})
		case r.Method == http.MethodPut && path == "llm-gateway/managed-developer/overrides/service_account/lgwsa_tf":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			override = map[string]any{"targetKind": "service_account", "targetId": "lgwsa_tf", "accessProfileId": body["accessProfileId"], "budget": body["budget"]}
			_ = json.NewEncoder(w).Encode(override)
		case r.Method == http.MethodDelete && path == "llm-gateway/managed-developer/overrides/service_account/lgwsa_tf":
			override = nil
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && path == "devices/device_linux/gateway-identity":
			assignment = map[string]any{"deviceId": "device_linux", "resolution": "explicit", "subjectKind": "service_account", "subjectId": "lgwsa_tf", "managedPrincipalId": "mdp_tf", "revision": int64(1)}
			_ = json.NewEncoder(w).Encode(assignment)
		case r.Method == http.MethodGet && path == "devices/device_linux/gateway-identity":
			if assignment == nil {
				http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(assignment)
		case r.Method == http.MethodDelete && path == "devices/device_linux/gateway-identity":
			assignment = nil
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, fmt.Sprintf(`{"error":"unexpected %s %s"}`, r.Method, path), http.StatusNotFound)
		}
	}))
	defer server.Close()
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	providerBinary := filepath.Join(binDir, "terraform-provider-forge")
	runAcceptanceCommand(t, "go", []string{"build", "-o", providerBinary, "./tools/terraform-provider-forge"}, repositoryRoot(t), nil)
	rc := filepath.Join(root, "terraform.rc")
	if err := os.WriteFile(rc, []byte(fmt.Sprintf("provider_installation {\n  dev_overrides {\n    \"a37ai/forge\" = %q\n  }\n  direct {}\n}\n", binDir)), 0o600); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(root, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	hcl := fmt.Sprintf(`terraform {
  required_providers {
    forge = { source = "a37ai/forge" }
  }
}
provider "forge" {
  endpoint=%q
  organization_id="org.gateway"
  api_token="acceptance-token"
  manager_id="gateway"
  manager_instance="acceptance"
}
resource "forge_llm_gateway_service_account" "test" {
  name="Build bot"
  owner_kind="app_integration"
  owner_id="integration_1"
  environment="production"
}
resource "forge_llm_gateway_managed_access_override" "test" {
  target_kind="service_account"
  target_id=forge_llm_gateway_service_account.test.id
  access_profile_id="profile_1"
  budget_window="monthly"
  total_token_limit=100000
}
resource "forge_device_gateway_identity_assignment" "test" {
  device_id="device_linux"
  service_account_id=forge_llm_gateway_service_account.test.id
}
`, server.URL)
	if err := os.WriteFile(filepath.Join(work, "main.tf"), []byte(hcl), 0o600); err != nil {
		t.Fatal(err)
	}
	env := []string{"TF_CLI_CONFIG_FILE=" + rc, "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1"}
	applyOutput := runAcceptanceCommand(t, terraform, []string{"apply", "-auto-approve", "-input=false", "-no-color"}, work, env)
	t.Logf("Terraform apply proof:\n%s", applyOutput)
	if output := runAcceptanceCommand(t, terraform, []string{"plan", "-detailed-exitcode", "-input=false", "-no-color"}, work, env); !strings.Contains(output, "No changes") {
		t.Fatalf("no-op plan was not stable:\n%s", output)
	} else {
		t.Logf("Terraform no-op plan proof:\n%s", output)
	}
	destroyOutput := runAcceptanceCommand(t, terraform, []string{"destroy", "-auto-approve", "-input=false", "-no-color"}, work, env)
	t.Logf("Terraform destroy proof:\n%s", destroyOutput)
	mu.Lock()
	defer mu.Unlock()
	if account != nil || override != nil || assignment != nil {
		t.Fatalf("destroy left state account=%v override=%v assignment=%v", account, override, assignment)
	}
}
