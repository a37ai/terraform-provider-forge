package provider

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type acceptanceStoredPolicy struct {
	Definition map[string]any
	SourceRef  map[string]any
	Revision   int64
}

// TestTerraformCLIFullLifecycle drives the real Terraform binary and provider
// protocol. It is opt-in so ordinary Go tests remain portable; GA/release CI
// sets FORGE_TERRAFORM_CLI to every supported Terraform/OpenTofu binary.
func TestTerraformCLIFullLifecycle(t *testing.T) {
	terraform := strings.TrimSpace(os.Getenv("FORGE_TERRAFORM_CLI"))
	if terraform == "" {
		t.Skip("set FORGE_TERRAFORM_CLI to a Terraform or OpenTofu executable")
	}
	if _, err := os.Stat(terraform); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var policy *acceptanceStoredPolicy
	var tombstoneRevision int64
	var planCalls, writes, deletes int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer acceptance-token" || r.Header.Get("X-Forge-Terraform-Manager") != "ga-repository" || r.Header.Get("X-Forge-Terraform-Instance") != "acceptance" {
			http.Error(w, `{"error":"missing scoped Terraform identity"}`, http.StatusForbidden)
			return
		}
		base := "/api/headless/v1/organizations/org.acceptance/"
		path := strings.TrimPrefix(r.URL.Path, base)
		switch {
		case r.Method == http.MethodGet && path == "policy-contracts/capabilities":
			_, _ = w.Write([]byte(`{"policySchemaVersion":"forge.policy.families.v1","regoLanguageVersion":"forge.rego.v1","regoCompilerFingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","terraformPolicyProtocol":"forge.terraform.policy.v1","terraformOwnershipBinding":"service_account_principal"}`))
		case r.Method == http.MethodPost && path == "policy-plans/validate":
			var body struct {
				Definition       map[string]any `json:"definition"`
				SourceRef        map[string]any `json:"sourceRef"`
				ExpectedRevision int64          `json:"expectedRevision"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				http.Error(w, `{"error":"invalid plan"}`, http.StatusBadRequest)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if (policy == nil && body.ExpectedRevision != 0) || (policy != nil && body.ExpectedRevision != policy.Revision) {
				http.Error(w, `{"error":"stale revision"}`, http.StatusConflict)
				return
			}
			planCalls++
			_, _ = w.Write([]byte(`{"valid":true,"validationToken":"plan-stable","schemaVersion":"forge.policy.families.v1","compilerFingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
		case (r.Method == http.MethodPost && path == "content-policies") || (r.Method == http.MethodPut && path == "content-policies/acceptance-policy"):
			var body struct {
				Definition       map[string]any `json:"definition"`
				SourceRef        map[string]any `json:"sourceRef"`
				ExpectedRevision int64          `json:"expectedRevision"`
				ValidationToken  string         `json:"validationToken"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !strings.HasPrefix(body.ValidationToken, "plan-") {
				http.Error(w, `{"error":"missing authoritative plan binding"}`, http.StatusConflict)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if (policy == nil && body.ExpectedRevision != 0) || (policy != nil && body.ExpectedRevision != policy.Revision) {
				http.Error(w, `{"error":"stale apply"}`, http.StatusConflict)
				return
			}
			revision := int64(1)
			if policy != nil {
				revision = policy.Revision + 1
			} else if tombstoneRevision > 0 {
				revision = tombstoneRevision + 1
			}
			policy = &acceptanceStoredPolicy{Definition: body.Definition, SourceRef: body.SourceRef, Revision: revision}
			writes++
			writeAcceptancePolicy(w, policy)
		case r.Method == http.MethodGet && path == "content-policies/acceptance-policy":
			mu.Lock()
			defer mu.Unlock()
			if policy == nil {
				http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
				return
			}
			writeAcceptancePolicy(w, policy)
		case r.Method == http.MethodDelete && strings.HasPrefix(path, "content-policies/acceptance-policy"):
			mu.Lock()
			if policy != nil {
				tombstoneRevision = policy.Revision
			}
			policy = nil
			deletes++
			mu.Unlock()
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
	writeConfig := func(description string) {
		hcl := fmt.Sprintf(`terraform {
  required_providers {
    forge = { source = "a37ai/forge" }
  }
}
provider "forge" {
  endpoint = %q
  organization_id = "org.acceptance"
  api_token = "acceptance-token"
  manager_id = "ga-repository"
  manager_instance = "acceptance"
}
resource "forge_content_policy" "test" {
  id = "acceptance-policy"
  name = "Acceptance policy"
  description = %q
  evaluate_on = ["prompt"]
  action = "block"
  conditions = { field = "request.prompt", op = "contains", value = "secret" }
}
`, server.URL, description)
		if err := os.WriteFile(filepath.Join(work, "main.tf"), []byte(hcl), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env := []string{"TF_CLI_CONFIG_FILE=" + rc, "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1"}
	writeConfig("revision one")
	planPath := filepath.Join(work, "reviewed.tfplan")
	runAcceptanceCommand(t, terraform, []string{"plan", "-out=" + planPath, "-input=false", "-no-color"}, work, env)
	runAcceptanceCommand(t, terraform, []string{"apply", "-input=false", "-no-color", planPath}, work, env)
	if output := runAcceptanceCommand(t, terraform, []string{"plan", "-detailed-exitcode", "-input=false", "-no-color"}, work, env); !strings.Contains(output, "No changes") {
		t.Fatalf("no-op plan was not stable:\n%s", output)
	}
	writeConfig("revision two")
	runAcceptanceCommand(t, terraform, []string{"plan", "-out=" + planPath, "-input=false", "-no-color"}, work, env)
	runAcceptanceCommand(t, terraform, []string{"apply", "-input=false", "-no-color", planPath}, work, env)
	runAcceptanceCommand(t, terraform, []string{"destroy", "-auto-approve", "-input=false", "-no-color"}, work, env)
	// A safe destroy is a tombstone. Reapplying from the same authenticated
	// workspace recovers it as a forward revision instead of reusing identity or
	// losing history.
	runAcceptanceCommand(t, terraform, []string{"apply", "-auto-approve", "-input=false", "-no-color"}, work, env)
	if output := runAcceptanceCommand(t, terraform, []string{"plan", "-detailed-exitcode", "-input=false", "-no-color"}, work, env); !strings.Contains(output, "No changes") {
		t.Fatalf("recovered no-op plan was not stable:\n%s", output)
	}
	runAcceptanceCommand(t, terraform, []string{"destroy", "-auto-approve", "-input=false", "-no-color"}, work, env)

	mu.Lock()
	defer mu.Unlock()
	if policy != nil || writes != 3 || deletes != 2 || planCalls < 3 || tombstoneRevision != 3 {
		t.Fatalf("lifecycle counts policy=%v plans=%d writes=%d deletes=%d", policy != nil, planCalls, writes, deletes)
	}
}

// TestTerraformCLIAllPolicySchemas asks the real Terraform planner to expand,
// validate, and protocol-encode every public policy resource. This is stronger
// than parsing HCL: it catches provider schema drift, null/unknown mistakes, and
// cross-field validation regressions before any API mutation can occur.
func TestTerraformCLIAllPolicySchemas(t *testing.T) {
	terraform := strings.TrimSpace(os.Getenv("FORGE_TERRAFORM_CLI"))
	if terraform == "" {
		t.Skip("set FORGE_TERRAFORM_CLI to a Terraform or OpenTofu executable")
	}
	var mu sync.Mutex
	stored := map[string]*acceptanceStoredPolicy{}
	var gatewayProfile map[string]any
	var gatewayRoutes []any
	writes, deletes := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(r.URL.Path, "/api/headless/v1/organizations/org.enterprise/")
		switch {
		case r.Method == http.MethodGet && path == "policy-contracts/capabilities":
			_, _ = w.Write([]byte(`{"policySchemaVersion":"forge.policy.families.v1","regoLanguageVersion":"forge.rego.v1","regoCompilerFingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","terraformPolicyProtocol":"forge.terraform.policy.v1","terraformOwnershipBinding":"service_account_principal"}`))
		case r.Method == http.MethodPost && path == "policy-code/rego/validate":
			var body struct {
				Module string `json:"module"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, `{"error":"invalid Rego request"}`, http.StatusBadRequest)
				return
			}
			digest := sha256.Sum256([]byte(body.Module))
			_, _ = fmt.Fprintf(w, `{"valid":true,"languageVersion":"forge.rego.v1","sourceSha256":"%x","compilerFingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","diagnostics":[]}`, digest)
		case r.Method == http.MethodPost && path == "policy-plans/validate":
			_, _ = w.Write([]byte(`{"valid":true,"validationToken":"all-policy-schemas-plan-token","schemaVersion":"forge.policy.families.v1","compilerFingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
		case r.Method == http.MethodPost && path == "llm-gateway/access-profiles/save":
			var body struct {
				Profile map[string]any `json:"profile"`
				Routes  []any          `json:"routes"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, `{"error":"invalid gateway profile"}`, http.StatusBadRequest)
				return
			}
			if len(body.Profile["policyHooks"].([]any)) != 3 || len(body.Routes) != 1 || len(body.Routes[0].(map[string]any)["policyHooks"].([]any)) != 3 {
				http.Error(w, fmt.Sprintf(`{"error":"gateway hooks were not preserved","profile":%q,"routes":%q}`, body.Profile, body.Routes), http.StatusBadRequest)
				return
			}
			mu.Lock()
			gatewayProfile = body.Profile
			gatewayProfile["version"] = float64(1)
			gatewayRoutes = body.Routes
			for index, rawRoute := range gatewayRoutes {
				route, _ := rawRoute.(map[string]any)
				if route["providerName"] != "Test OpenAI" {
					http.Error(w, `{"error":"provider name was not preserved"}`, http.StatusBadRequest)
					mu.Unlock()
					return
				}
				delete(route, "providerName")
				route["providerId"] = "lgwp_test"
				route["id"] = fmt.Sprintf("lgwr_test_%d", index)
				route["accessProfileId"] = gatewayProfile["id"]
			}
			writes++
			response := map[string]any{"accessProfile": gatewayProfile, "routes": gatewayRoutes}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(response)
		case r.Method == http.MethodGet && path == "llm-gateway":
			mu.Lock()
			response := map[string]any{"providers": []any{map[string]any{"id": "lgwp_test", "displayName": "Test OpenAI"}}, "accessProfiles": []any{}, "routes": []any{}}
			if gatewayProfile != nil {
				response = map[string]any{"providers": []any{map[string]any{"id": "lgwp_test", "displayName": "Test OpenAI"}}, "accessProfiles": []any{gatewayProfile}, "routes": gatewayRoutes}
			}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(response)
		case r.Method == http.MethodDelete && strings.HasPrefix(path, "llm-gateway/access-profiles/"):
			mu.Lock()
			gatewayProfile, gatewayRoutes = nil, nil
			deletes++
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case isAcceptancePolicyPath(path):
			handleAcceptancePolicyCRUD(w, r, path, &mu, stored, &writes, &deletes)
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
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "tools/terraform-provider-forge/testdata/cli/main.tf"))
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.ReplaceAll(string(raw), "http://127.0.0.1:18080", server.URL))
	work := filepath.Join(root, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "main.tf"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	env := []string{"TF_CLI_CONFIG_FILE=" + rc, "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1"}
	planPath := filepath.Join(work, "all-schemas.tfplan")
	runAcceptanceCommand(t, terraform, []string{"plan", "-out=" + planPath, "-input=false", "-no-color"}, work, env)
	runAcceptanceCommand(t, terraform, []string{"apply", "-input=false", "-no-color", planPath}, work, env)
	if output := runAcceptanceCommand(t, terraform, []string{"plan", "-detailed-exitcode", "-input=false", "-no-color"}, work, env); !strings.Contains(output, "No changes") {
		t.Fatalf("all-resource no-op plan was not stable:\n%s", output)
	}
	runAcceptanceCommand(t, terraform, []string{"destroy", "-auto-approve", "-input=false", "-no-color"}, work, env)
	mu.Lock()
	defer mu.Unlock()
	if len(stored) != 0 || gatewayProfile != nil || writes != 16 || deletes != 16 {
		t.Fatalf("all-resource lifecycle stores=%d writes=%d deletes=%d", len(stored), writes, deletes)
	}
}

func isAcceptancePolicyPath(path string) bool {
	for _, collection := range []string{"content-policies", "access-policies", "skill-acls"} {
		if path == collection || strings.HasPrefix(path, collection+"/") {
			return true
		}
	}
	return false
}

func handleAcceptancePolicyCRUD(w http.ResponseWriter, r *http.Request, path string, mu *sync.Mutex, stored map[string]*acceptanceStoredPolicy, writes, deletes *int) {
	parts := strings.Split(path, "/")
	collection := parts[0]
	key := path
	if r.Method == http.MethodPost && len(parts) == 1 || r.Method == http.MethodPut && len(parts) == 2 {
		var body struct {
			Definition       map[string]any `json:"definition"`
			SourceRef        map[string]any `json:"sourceRef"`
			ExpectedRevision int64          `json:"expectedRevision"`
			ValidationToken  string         `json:"validationToken"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ValidationToken == "" {
			http.Error(w, `{"error":"invalid mutation"}`, http.StatusBadRequest)
			return
		}
		id, _ := body.Definition["id"].(string)
		key = collection + "/" + id
		mu.Lock()
		defer mu.Unlock()
		current := stored[key]
		if current == nil && body.ExpectedRevision != 0 || current != nil && body.ExpectedRevision != current.Revision {
			http.Error(w, `{"error":"stale revision"}`, http.StatusConflict)
			return
		}
		revision := int64(1)
		if current != nil {
			revision = current.Revision + 1
		}
		stored[key] = &acceptanceStoredPolicy{Definition: body.Definition, SourceRef: body.SourceRef, Revision: revision}
		*writes++
		writeAcceptancePolicyForCollection(w, collection, stored[key])
		return
	}
	if len(parts) != 2 {
		http.Error(w, `{"error":"invalid resource path"}`, http.StatusNotFound)
		return
	}
	mu.Lock()
	defer mu.Unlock()
	current := stored[key]
	switch r.Method {
	case http.MethodGet:
		if current == nil {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		writeAcceptancePolicyForCollection(w, collection, current)
	case http.MethodDelete:
		if r.URL.Query().Get("expectedRevision") == "" {
			http.Error(w, `{"error":"expectedRevision is required"}`, http.StatusBadRequest)
			return
		}
		delete(stored, key)
		*deletes++
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func writeAcceptancePolicyForCollection(w http.ResponseWriter, collection string, policy *acceptanceStoredPolicy) {
	family := map[string]string{"content-policies": "content", "access-policies": "access", "skill-acls": "skill_acl"}[collection]
	raw, _ := json.Marshal(policy.Definition)
	id, _ := policy.Definition["id"].(string)
	_ = json.NewEncoder(w).Encode(map[string]any{"item": map[string]any{
		"id": id, "family": family, "currentRevision": policy.Revision,
		"definitionSha256": fmt.Sprintf("%x", sha256.Sum256(raw)), "definition": policy.Definition,
		"sourceRef": policy.SourceRef, "managementMode": "terraform",
		"managerId": "security-policy-repository", "managerInstance": "production",
	}})
}

func writeAcceptancePolicy(w http.ResponseWriter, policy *acceptanceStoredPolicy) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"item": map[string]any{
			"id":               "acceptance-policy",
			"family":           "content",
			"currentRevision":  policy.Revision,
			"definitionSha256": fmt.Sprintf("%064x", policy.Revision),
			"definition":       policy.Definition,
			"sourceRef":        policy.SourceRef,
			"managementMode":   "terraform",
			"managerId":        "ga-repository",
			"managerInstance":  "acceptance",
		},
	})
}

func runAcceptanceCommand(t *testing.T, name string, args []string, dir string, extraEnv []string) string {
	t.Helper()
	command := exec.Command(name, args...)
	command.Dir = dir
	command.Env = append(os.Environ(), extraEnv...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, output)
	}
	return string(output)
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}
