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

// TestTerraformCLIResourceCredentialLifecycle proves the write-only contract
// through Terraform's real provider protocol. Release CI supplies every
// supported Terraform binary through FORGE_TERRAFORM_CLI.
func TestTerraformCLIResourceCredentialLifecycle(t *testing.T) {
	terraform := strings.TrimSpace(os.Getenv("FORGE_TERRAFORM_CLI"))
	if terraform == "" {
		t.Skip("set FORGE_TERRAFORM_CLI to a Terraform 1.11+ executable")
	}

	var mu sync.Mutex
	resourceExists, credentialExists := false, false
	credentialSecret, credentialName := "", ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(request.URL.Path, "/api/headless/v1/organizations/org.resources/")
		switch {
		case request.Method == http.MethodGet && path == "policy-contracts/capabilities":
			_, _ = w.Write([]byte(`{"policySchemaVersion":"forge.policy.families.v1","regoLanguageVersion":"forge.rego.v1","regoCompilerFingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","terraformPolicyProtocol":"forge.terraform.policy.v1","terraformGatewayProtocol":"forge.terraform.llm-gateway-plan.v1","terraformOwnershipBinding":"service_account_principal"}`))
		case request.Method == http.MethodPost && path == "resources":
			resourceExists = true
			writeAcceptanceResource(w)
		case request.Method == http.MethodGet && path == "resources/res_1":
			if !resourceExists {
				http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
				return
			}
			writeAcceptanceResource(w)
		case request.Method == http.MethodDelete && path == "resources/res_1":
			resourceExists = false
			w.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodPost && path == "resources/res_1/credentials":
			var body struct {
				Name   string `json:"name"`
				Secret string `json:"secret"`
			}
			_ = json.NewDecoder(request.Body).Decode(&body)
			if body.Secret == "" {
				http.Error(w, `{"error":"secret required"}`, http.StatusBadRequest)
				return
			}
			mu.Lock()
			credentialExists, credentialSecret, credentialName = true, body.Secret, body.Name
			mu.Unlock()
			writeAcceptanceCredential(w, credentialName)
		case request.Method == http.MethodGet && path == "resources/res_1/credentials/cred_1":
			mu.Lock()
			exists, name := credentialExists, credentialName
			mu.Unlock()
			if !exists {
				http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
				return
			}
			writeAcceptanceCredential(w, name)
		case request.Method == http.MethodPut && path == "resources/res_1/credentials/cred_1":
			var body struct {
				Name   string `json:"name"`
				Secret string `json:"secret"`
			}
			_ = json.NewDecoder(request.Body).Decode(&body)
			mu.Lock()
			credentialName = body.Name
			if body.Secret != "" {
				credentialSecret = body.Secret
			}
			mu.Unlock()
			writeAcceptanceCredential(w, body.Name)
		case request.Method == http.MethodDelete && path == "resources/res_1/credentials/cred_1":
			mu.Lock()
			credentialExists = false
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, fmt.Sprintf(`{"error":"unexpected %s %s"}`, request.Method, path), http.StatusNotFound)
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
	writeConfig := func(version int) {
		hcl := fmt.Sprintf(`terraform {
  required_version = ">= 1.11.0"
  required_providers { forge = { source = "a37ai/forge" } }
}
variable "database_password" {
  type = string
  sensitive = true
  ephemeral = true
}
provider "forge" {
  endpoint = %q
  organization_id = "org.resources"
  api_token = "acceptance-token"
  manager_id = "resource-repository"
  manager_instance = "acceptance"
}
resource "forge_resource" "database" {
  name = "Production PostgreSQL"
  protocol = "postgres"
  upstream_host = "db.internal.example"
  upstream_port = 5432
}
resource "forge_resource_credential" "database" {
  resource_id = forge_resource.database.id
  name = "Application account"
  kind = "username_password"
  username = "forge_app"
  secret = var.database_password
  secret_version = %d
  default = true
}
`, server.URL, version)
		if err := os.WriteFile(filepath.Join(work, "main.tf"), []byte(hcl), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	baseEnv := []string{"TF_CLI_CONFIG_FILE=" + rc, "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1"}
	planPath := filepath.Join(work, "reviewed.tfplan")
	writeConfig(1)
	env := append(baseEnv, "TF_VAR_database_password=first-super-secret")
	runAcceptanceCommand(t, terraform, []string{"plan", "-out=" + planPath, "-input=false", "-no-color"}, work, env)
	assertTerraformOutputOmits(t, runAcceptanceCommand(t, terraform, []string{"show", "-json", planPath}, work, env), "first-super-secret", "secretId", "secretRef")
	runAcceptanceCommand(t, terraform, []string{"apply", "-input=false", "-no-color", planPath}, work, env)
	assertTerraformStateOmits(t, terraform, work, env, "first-super-secret", "secretId", "secretRef")
	writeConfig(2)
	env = append(baseEnv, "TF_VAR_database_password=second-super-secret")
	runAcceptanceCommand(t, terraform, []string{"plan", "-out=" + planPath, "-input=false", "-no-color"}, work, env)
	assertTerraformOutputOmits(t, runAcceptanceCommand(t, terraform, []string{"show", "-json", planPath}, work, env), "first-super-secret", "second-super-secret", "secretId", "secretRef")
	runAcceptanceCommand(t, terraform, []string{"apply", "-input=false", "-no-color", planPath}, work, env)
	assertTerraformStateOmits(t, terraform, work, env, "first-super-secret", "second-super-secret", "secretId", "secretRef")
	mu.Lock()
	if credentialSecret != "second-super-secret" {
		t.Fatalf("credential did not rotate: %q", credentialSecret)
	}
	mu.Unlock()
	if output := runAcceptanceCommand(t, terraform, []string{"plan", "-detailed-exitcode", "-input=false", "-no-color"}, work, env); !strings.Contains(output, "No changes") {
		t.Fatalf("credential lifecycle did not converge:\n%s", output)
	}
	writeConfig(1)
	runAcceptanceCommand(t, terraform, []string{"state", "rm", "forge_resource_credential.database"}, work, env)
	runAcceptanceCommand(t, terraform, []string{"import", "-input=false", "forge_resource_credential.database", "res_1/cred_1"}, work, env)
	assertTerraformStateOmits(t, terraform, work, env, "first-super-secret", "second-super-secret", "secretId", "secretRef")
	if output := runAcceptanceCommand(t, terraform, []string{"plan", "-detailed-exitcode", "-input=false", "-no-color"}, work, env); !strings.Contains(output, "No changes") {
		t.Fatalf("imported credential did not converge:\n%s", output)
	}
}

func writeAcceptanceResource(w http.ResponseWriter) {
	_, _ = w.Write([]byte(`{"id":"res_1","organizationId":"org.resources","name":"Production PostgreSQL","protocol":"postgres","upstreamHost":"db.internal.example","upstreamPort":5432,"upstreamTls":true,"enabled":true,"transparentRouting":false,"managementMode":"terraform","managerId":"resource-repository","managerInstance":"acceptance"}`))
}

func writeAcceptanceCredential(w http.ResponseWriter, name string) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id": "cred_1", "organizationId": "org.resources", "resourceId": "res_1", "name": name,
		"kind": "username_password", "username": "forge_app", "default": true,
		"assignedTo":     map[string]any{"users": []string{}, "groups": []string{}, "serviceAccounts": []string{}},
		"managementMode": "terraform", "managerId": "resource-repository", "managerInstance": "acceptance",
	})
}

func assertTerraformStateOmits(t *testing.T, terraform, work string, env []string, forbidden ...string) {
	t.Helper()
	assertTerraformOutputOmits(t, runAcceptanceCommand(t, terraform, []string{"state", "pull"}, work, env), forbidden...)
}

func assertTerraformOutputOmits(t *testing.T, output string, forbidden ...string) {
	t.Helper()
	for _, value := range forbidden {
		if strings.Contains(output, value) {
			t.Fatalf("Terraform artifact contains forbidden credential material %q", value)
		}
	}
}
