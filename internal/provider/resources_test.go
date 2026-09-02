package provider

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestLLMGatewayPlanExpectedVersion(t *testing.T) {
	claims, err := json.Marshal(map[string]any{"expectedVersion": 17})
	if err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(claims) + ".signature"
	if got, err := llmGatewayPlanExpectedVersion(token); err != nil || got != 17 {
		t.Fatalf("llmGatewayPlanExpectedVersion() = %d, %v", got, err)
	}
	if _, err := llmGatewayPlanExpectedVersion("not-a-plan-token"); err == nil {
		t.Fatal("invalid plan token was accepted")
	}
}

func testClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/headless/v1/organizations/org.test/policy-plans/validate" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"valid": true, "validationToken": "test-plan-token", "schemaVersion": "forge.policy.families.v1",
				"compilerFingerprint": "compiler", "expiresAt": time.Now().Add(10 * time.Minute),
			})
			return
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(server.URL, "org.test", "secret", "workspace", "instance", "test", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestTerraformExamplesParse(t *testing.T) {
	matches, err := filepath.Glob("../../examples/**/*.tf")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		matches, _ = filepath.Glob("../../examples/*/*.tf")
	}
	if len(matches) == 0 {
		t.Fatal("no Terraform examples")
	}
	parser := hclparse.NewParser()
	for _, name := range matches {
		if _, diagnostics := parser.ParseHCLFile(name); diagnostics.HasErrors() {
			t.Errorf("%s: %s", name, diagnostics.Error())
		}
	}
}

func TestPolicySchemasExposeOnlyTheirFamilySurface(t *testing.T) {
	for family, forbidden := range map[string][]string{
		"content": {"severity", "enforcement_surfaces", "runtime", "notification", "approval_mode", "remediation", "devices", "enforced_by", "remediation_action", "remediation_target"},
		"access":  {"service_accounts", "evaluate_on", "agents", "products", "custom_fields", "message", "auto_approve_on_request", "redaction_strategy", "redaction_pattern", "filter_path", "remediation_action", "remediation_target"},
	} {
		policyResource := &regoPolicyResource{family: family}
		var response resource.SchemaResponse
		policyResource.Schema(context.Background(), resource.SchemaRequest{}, &response)
		for _, name := range forbidden {
			if _, exists := response.Schema.Attributes[name]; exists {
				t.Errorf("%s schema exposes %s", family, name)
			}
		}
	}
}

func TestPolicyPlanPayloadComparisonNormalizesTerraformNumbers(t *testing.T) {
	configured := map[string]any{"runtime": map[string]any{"detectionLatencyMs": json.Number("750"), "confidenceThreshold": json.Number("0.95")}}
	refreshed := map[string]any{"runtime": map[string]any{"detectionLatencyMs": float64(750), "confidenceThreshold": 0.95}}
	if policyPlanPayloadChanged(configured, map[string]any{}, refreshed, map[string]any{}) {
		t.Fatal("equivalent Terraform and JSON number representations caused false policy drift")
	}
}

func emptySet() types.Set { return types.SetValueMust(types.StringType, nil) }
func stringSet(values ...string) types.Set {
	items := make([]attr.Value, 0, len(values))
	for _, value := range values {
		items = append(items, types.StringValue(value))
	}
	return types.SetValueMust(types.StringType, items)
}
func stringMap(values map[string]string) types.Map {
	items := make(map[string]attr.Value, len(values))
	for key, value := range values {
		items[key] = types.StringValue(value)
	}
	return types.MapValueMust(types.StringType, items)
}

func testDynamic(t *testing.T, value any) types.Dynamic {
	t.Helper()
	var diagnostics diag.Diagnostics
	result := dynamicFromGo(value, &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("dynamic value diagnostics: %v", diagnostics)
	}
	return result
}

func TestContentRegoResourceLowersReadableReferencesAndPinsDigest(t *testing.T) {
	var body map[string]any
	module := "package forge.content\nmatch := {\"matched\": true}"
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(module)))
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forge-Terraform-Manager") != "workspace" {
			t.Error("missing manager binding")
		}
		if r.URL.Path == "/api/headless/v1/organizations/org.test/policy-code/rego/validate" {
			_ = json.NewEncoder(w).Encode(map[string]any{"valid": true, "languageVersion": "forge.rego.v1", "compilerFingerprint": "compiler", "sourceSha256": digest})
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"item": map[string]any{"id": "p", "currentRevision": 1, "definitionSha256": "server", "definition": body["definition"], "sourceRef": body["sourceRef"]}})
	})
	resource := &regoPolicyResource{client: client, family: "content", path: "content-policies"}
	m := regoPolicyModel{ID: types.StringValue("p"), Name: types.StringValue("Readable"), Enabled: types.BoolValue(true), Users: stringSet("alice@example.com"), UserDirectoryIDs: stringMap(map[string]string{"alice@example.com": "directory-primary"}), Groups: stringSet("Finance"), GroupDirectoryIDs: types.MapNull(types.StringType), ServiceAccounts: emptySet(), Agents: emptySet(), Products: emptySet(), EvaluateOn: types.ListValueMust(types.StringType, []attr.Value{types.StringValue("pre_tool")}), Action: types.StringValue("block"), Module: types.StringValue(module), Devices: emptySet()}
	var d diag.Diagnostics
	resource.apply(context.Background(), m, 0, &d, func(v regoPolicyModel) { m = v })
	if d.HasError() {
		t.Fatalf("diagnostics=%v", d)
	}
	if m.ModuleSHA.ValueString() == "" || m.CurrentRevision.ValueInt64() != 1 {
		t.Fatalf("state=%+v", m)
	}
	definition := body["definition"].(map[string]any)
	scope := definition["appliesTo"].(map[string]any)
	if scope["users"].([]any)[0] != "alice@example.com" {
		t.Fatalf("body=%+v", body)
	}
	sourceRef := body["sourceRef"].(map[string]any)
	sourceUsers := sourceRef["selectors"].(map[string]any)["appliesTo"].(map[string]any)["users"].([]any)
	qualified := sourceUsers[0].(map[string]any)
	if qualified["name"] != "alice@example.com" || qualified["directoryId"] != "directory-primary" {
		t.Fatalf("qualified source selector=%+v", qualified)
	}
}

func TestPolicyApplyUsesReviewedPlanValidationToken(t *testing.T) {
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/headless/v1/organizations/org.test/policy-plans/validate" {
			t.Fatalf("apply revalidated policy plan instead of using the reviewed plan token")
		}
		if r.Method != http.MethodPut || r.URL.Path != "/api/headless/v1/organizations/org.test/content-policies/p" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["validationToken"] != "reviewed-plan-token" {
			t.Fatalf("validationToken=%v, want reviewed plan token", body["validationToken"])
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"item": map[string]any{"id": "p", "currentRevision": 2, "definitionSha256": "server", "definition": body["definition"], "sourceRef": body["sourceRef"]}})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "org.test", "secret", "workspace", "instance", "test", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resource := &regoPolicyResource{client: client, family: "content", path: "content-policies"}
	var diagnostics diag.Diagnostics
	m := regoPolicyModel{
		ID:                    types.StringValue("p"),
		Name:                  types.StringValue("Reviewed token"),
		Description:           types.StringValue("Updated by a saved Terraform plan."),
		Enabled:               types.BoolValue(true),
		AcknowledgeBroadScope: types.BoolValue(true),
		Users:                 emptySet(),
		Groups:                emptySet(),
		ServiceAccounts:       emptySet(),
		Agents:                emptySet(),
		Products:              emptySet(),
		UseCases:              emptySet(),
		ComplianceFrameworks:  emptySet(),
		Labels:                emptySet(),
		UserDirectoryIDs:      types.MapNull(types.StringType),
		GroupDirectoryIDs:     types.MapNull(types.StringType),
		EvaluateOn:            types.ListValueMust(types.StringType, []attr.Value{types.StringValue("prompt")}),
		Action:                types.StringValue("block"),
		Conditions:            dynamicFromGo(map[string]any{"field": "request.prompt", "op": "contains", "value": "secret"}, &diagnostics),
		CurrentRevision:       types.Int64Value(1),
		ValidationToken:       types.StringValue("reviewed-plan-token"),
	}
	resource.apply(context.Background(), m, 1, &diagnostics, func(value regoPolicyModel) { m = value })
	if diagnostics.HasError() {
		t.Fatalf("diagnostics=%v", diagnostics)
	}
	if m.CurrentRevision.ValueInt64() != 2 {
		t.Fatalf("current revision=%d, want 2", m.CurrentRevision.ValueInt64())
	}
}

func TestQualifiedSelectorRejectsQualifierForUnlistedName(t *testing.T) {
	var diagnostics diag.Diagnostics
	_ = qualifiedSelectorValues(context.Background(), stringSet("alice@example.com"), stringMap(map[string]string{"bob@example.com": "directory-primary"}), "user", &diagnostics)
	if !diagnostics.HasError() {
		t.Fatal("qualifier for an unlisted selector must fail")
	}
}

func TestLLMGatewayTerraformResourceUsesCanonicalAccessProfileRoutePlan(t *testing.T) {
	providers := []llmGatewayProviderAPI{{ID: "provider.openai", Name: "OpenAI"}}
	var diagnostics diag.Diagnostics
	routes, diagnostics := types.ListValueFrom(context.Background(), routeObjectType(), []llmGatewayRoutePlanModel{{
		ID: types.StringValue("route.primary"), Provider: types.StringValue("OpenAI"), Name: types.StringValue("Primary"),
		RequestedModelPattern: types.StringValue("gpt-*"), UpstreamModel: types.StringValue("gpt-5"), APISurface: types.StringValue("openai_responses"),
		Strategy: types.StringValue("fixed"), RoutePriority: types.Int64Value(1), TrafficPercentage: types.Int64Value(100), RolloutState: types.StringValue("enforce"),
		EnforcementMode: types.StringValue("enforce"), PolicyHooks: stringSet("prompt", "pre_tool_use"), ToolDenyBehavior: types.StringValue("hard_block"), ConfigJSON: types.StringValue(`{"timeoutSeconds":30}`),
	}})
	if diagnostics.HasError() {
		t.Fatalf("route model diagnostics=%v", diagnostics)
	}
	model := llmGatewayAccessProfileModel{ID: types.StringValue("profile.engineering"), Name: types.StringValue("Engineering"), Description: types.StringValue("Engineering gateway access"), State: types.StringValue("active"), EnforcementMode: types.StringValue("enforce"), ModelPatterns: stringSet("gpt-5"), DataClasses: stringSet("internal"), PolicyHooks: stringSet("prompt"), Routes: routes}
	var d diag.Diagnostics
	body := (&llmGatewayAccessProfileResource{}).payload(context.Background(), model, providers, &d)
	if d.HasError() {
		t.Fatalf("payload diagnostics=%v", d)
	}
	profile := body["profile"].(map[string]any)
	if profile["id"] != "profile.engineering" || object(profile["modelSelectors"])["modelPatterns"].([]string)[0] != "gpt-5" {
		t.Fatalf("profile=%+v", profile)
	}
	if _, exists := profile["subjectBindings"]; exists {
		t.Fatalf("retired subject bindings were emitted: %+v", profile)
	}
	route := body["routes"].([]map[string]any)[0]
	if route["providerId"] != "provider.openai" || route["trafficPercentage"] != int64(100) || route["apiSurface"] != "openai_responses" || object(route["config"])["timeoutSeconds"] != float64(30) {
		t.Fatalf("route=%+v", route)
	}
}

func TestLLMGatewayTerraformResourceRejectsMissingAndAmbiguousProviders(t *testing.T) {
	routes, buildDiagnostics := types.ListValueFrom(context.Background(), routeObjectType(), []llmGatewayRoutePlanModel{{
		Provider: types.StringValue("OpenAI"), Name: types.StringValue("Primary"), RequestedModelPattern: types.StringValue("gpt-*"), APISurface: types.StringValue("openai_responses"), PolicyHooks: types.SetNull(types.StringType),
	}})
	if buildDiagnostics.HasError() {
		t.Fatalf("route diagnostics=%v", buildDiagnostics)
	}
	model := llmGatewayAccessProfileModel{
		ModelPatterns: types.SetNull(types.StringType), Routes: routes,
	}
	var diagnostics diag.Diagnostics
	_ = (&llmGatewayAccessProfileResource{}).payload(context.Background(), model, nil, &diagnostics)
	if !diagnostics.HasError() {
		t.Fatal("missing provider must fail")
	}
	diagnostics = nil
	providers := []llmGatewayProviderAPI{{ID: "one", Name: "OpenAI"}, {ID: "two", Name: "OpenAI"}}
	_ = (&llmGatewayAccessProfileResource{}).payload(context.Background(), model, providers, &diagnostics)
	if !diagnostics.HasError() {
		t.Fatal("ambiguous provider must fail")
	}
}

func TestLLMGatewayRefreshPreservesOmittedSelectorsAndExactRouteConfig(t *testing.T) {
	priorRoutes, diagnostics := types.ListValueFrom(context.Background(), routeObjectType(), []llmGatewayRoutePlanModel{
		{ID: types.StringNull(), Provider: types.StringValue("OpenAI"), Name: types.StringValue("Primary"), RequestedModelPattern: types.StringValue("gpt-*"), UpstreamModel: types.StringValue("gpt-5"), APISurface: types.StringValue("openai_responses"), PolicyHooks: types.SetNull(types.StringType), ConfigJSON: types.StringNull()},
		{ID: types.StringValue("route.secondary"), Provider: types.StringValue("OpenAI"), Name: types.StringValue("Secondary"), RequestedModelPattern: types.StringValue("gpt-4*"), UpstreamModel: types.StringValue("gpt-4.1"), APISurface: types.StringValue("openai_responses"), PolicyHooks: types.SetNull(types.StringType), ConfigJSON: types.StringValue("{}")},
	})
	if diagnostics.HasError() {
		t.Fatalf("route model diagnostics=%v", diagnostics)
	}
	model := llmGatewayAccessProfileModel{Routes: priorRoutes}
	profile := llmGatewayAccessProfileAPI{ID: "profile", Name: "Profile", State: "active", EnforcementMode: "enforce", ModelSelectors: json.RawMessage("{}")}
	routes := []llmGatewayRouteAPI{
		{ID: "route.primary", ProviderID: "provider", Name: "Primary", RequestedModelPattern: "gpt-*", UpstreamModel: "gpt-5", APISurface: "openai_responses", Config: json.RawMessage("{}")},
		{ID: "route.secondary", ProviderID: "provider", Name: "Secondary", RequestedModelPattern: "gpt-4*", UpstreamModel: "gpt-4.1", APISurface: "openai_responses", Config: json.RawMessage("{}")},
	}
	var refreshDiagnostics diag.Diagnostics
	(&llmGatewayAccessProfileResource{}).refreshModel(context.Background(), &model, profile, routes, []llmGatewayProviderAPI{{ID: "provider", Name: "OpenAI"}}, &refreshDiagnostics)
	if refreshDiagnostics.HasError() {
		t.Fatalf("refresh diagnostics=%v", refreshDiagnostics)
	}
	var refreshed []llmGatewayRoutePlanModel
	refreshDiagnostics.Append(model.Routes.ElementsAs(context.Background(), &refreshed, false)...)
	if len(refreshed) != 2 || !refreshed[0].ConfigJSON.IsNull() || refreshed[1].ConfigJSON.ValueString() != "{}" {
		t.Fatalf("route config state was not matched exactly: %+v", refreshed)
	}
}

func TestEverySubjectResourcePreservesDirectoryQualifiers(t *testing.T) {
	users := stringSet("alex@example.com")
	groups := stringSet("Finance")
	userDirectories := stringMap(map[string]string{"alex@example.com": "directory-primary"})
	groupDirectories := stringMap(map[string]string{"Finance": "directory-primary"})
	assertQualified := func(t *testing.T, sourceRef map[string]any, scopeKey string) {
		t.Helper()
		scope := object(object(sourceRef["selectors"])[scopeKey])
		for key, name := range map[string]string{"users": "alex@example.com", "groups": "Finance"} {
			values, ok := scope[key].([]any)
			if !ok || len(values) != 1 {
				t.Fatalf("%s selectors=%+v", key, scope[key])
			}
			qualified := object(values[0])
			if qualified["name"] != name || qualified["directoryId"] != "directory-primary" {
				t.Fatalf("%s selector=%+v", key, qualified)
			}
		}
	}

	var diagnostics diag.Diagnostics
	_, skillRef := (&skillACLResource{}).build(context.Background(), skillACLModel{
		ID: types.StringValue("skill"), Skill: types.StringValue("deploy"), Enabled: types.BoolValue(true),
		Users: users, UserDirectoryIDs: userDirectories, Groups: groups, GroupDirectoryIDs: groupDirectories, Effect: types.StringValue("allow"),
	}, &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("skill diagnostics=%v", diagnostics)
	}
	assertQualified(t, skillRef, "subjects")

	diagnostics = nil
	_, mcpRef := (&mcpACLResource{}).build(context.Background(), mcpACLModel{
		ID: types.StringValue("mcp"), Name: types.StringValue("MCP"), Enabled: types.BoolValue(true), Server: types.StringValue("github"), Tools: emptySet(),
		Users: users, UserDirectoryIDs: userDirectories, Groups: groups, GroupDirectoryIDs: groupDirectories, Effect: types.StringValue("allow"),
	}, &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("mcp diagnostics=%v", diagnostics)
	}
	assertQualified(t, mcpRef, "appliesTo")
}

func TestPolicyResourcesPreserveAllCanonicalMetadataAndExceptions(t *testing.T) {
	model := regoPolicyModel{
		ID: types.StringValue("complete-access"), Name: types.StringValue("Complete access"),
		Description: types.StringValue("Description"), Rationale: types.StringValue("Rationale"), Enabled: types.BoolValue(true),
		UseCases: stringSet("Organizational Access"), ComplianceFrameworks: stringSet("NIST"), Labels: stringSet("owner:security"),
		Users: stringSet("alice@example.com"), Groups: emptySet(), UserDirectoryIDs: stringMap(nil), GroupDirectoryIDs: stringMap(nil),
		Devices: stringSet("Finance MacBook"), ServiceAccounts: emptySet(), Agents: emptySet(), Products: emptySet(),
		Action: types.StringValue("block"), Conditions: testDynamic(t, map[string]any{"field": "device.platform", "op": "eq", "value": "darwin"}),
		Except:     testDynamic(t, map[string]any{"field": "identity.user_id", "op": "eq", "value": "break-glass@example.com"}),
		Exceptions: testDynamic(t, []any{map[string]any{"id": "exception:finance", "reason": "Approved finance workflow", "expiresAt": "2026-09-01T00:00:00Z", "conditions": map[string]any{"field": "identity.group_ids", "op": "contains", "value": "finance"}}}),
		EnforcedBy: stringSet("CrowdStrike Falcon"), EvaluateOn: types.ListNull(types.StringType), Module: types.StringNull(),
		Message: types.StringNull(), RemediationAction: types.StringNull(), RemediationTarget: types.StringNull(),
	}
	resource := &regoPolicyResource{family: "access", path: "access-policies"}
	var diagnostics diag.Diagnostics
	definition, sourceRef := resource.buildMutation(context.Background(), model, false, &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("diagnostics=%v", diagnostics)
	}
	if definition["rationale"] != "Rationale" || definition["description"] != "Description" {
		t.Fatalf("metadata=%+v", definition)
	}
	if got := definition["useCases"].([]string); len(got) != 1 || got[0] != "Organizational Access" {
		t.Fatalf("useCases=%v", got)
	}
	legacyException := object(definition["except"])
	if legacyException["field"] != "identity.user_id" || legacyException["op"] != "eq" || legacyException["value"] != "break-glass@example.com" {
		t.Fatalf("except=%+v", definition["except"])
	}
	exceptions := definition["exceptions"].([]any)
	if len(exceptions) != 1 {
		t.Fatalf("exceptions=%+v", definition["exceptions"])
	}
	exception := object(exceptions[0])
	exceptionConditions := object(exception["conditions"])
	if exception["id"] != "exception:finance" ||
		exception["reason"] != "Approved finance workflow" ||
		exception["expiresAt"] != "2026-09-01T00:00:00Z" ||
		exceptionConditions["field"] != "identity.group_ids" ||
		exceptionConditions["op"] != "contains" ||
		exceptionConditions["value"] != "finance" {
		t.Fatalf("exceptions=%+v", definition["exceptions"])
	}
	if got := definition["enforcedBy"].([]string); len(got) != 1 || got[0] != "CrowdStrike Falcon" {
		t.Fatalf("enforcedBy=%v", got)
	}
	selectors := object(sourceRef["selectors"])
	if got := selectors["enforcedBy"].([]string); len(got) != 1 || got[0] != "CrowdStrike Falcon" {
		t.Fatalf("source selectors=%+v", selectors)
	}
	var flattened regoPolicyModel
	resource.flatten(context.Background(), policyAPIItem{Definition: definition}, &flattened, &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("flatten diagnostics=%v", diagnostics)
	}
	roundTrippedLegacy, err := terraformDynamicToGo(flattened.Except)
	if err != nil {
		t.Fatalf("round-tripped except=%+v err=%v", roundTrippedLegacy, err)
	}
	roundTrippedLegacyException := object(roundTrippedLegacy)
	if roundTrippedLegacyException["field"] != "identity.user_id" || roundTrippedLegacyException["op"] != "eq" || roundTrippedLegacyException["value"] != "break-glass@example.com" {
		t.Fatalf("round-tripped except=%+v", roundTrippedLegacy)
	}
	roundTripped, err := terraformDynamicToGo(flattened.Exceptions)
	if err != nil {
		t.Fatalf("round-tripped exceptions=%+v err=%v", roundTripped, err)
	}
	roundTrippedExceptions := roundTripped.([]any)
	if len(roundTrippedExceptions) != 1 {
		t.Fatalf("round-tripped exceptions=%+v", roundTripped)
	}
	roundTrippedException := object(roundTrippedExceptions[0])
	roundTrippedConditions := object(roundTrippedException["conditions"])
	if roundTrippedException["id"] != "exception:finance" ||
		roundTrippedException["reason"] != "Approved finance workflow" ||
		roundTrippedException["expiresAt"] != "2026-09-01T00:00:00Z" ||
		roundTrippedConditions["field"] != "identity.group_ids" ||
		roundTrippedConditions["op"] != "contains" ||
		roundTrippedConditions["value"] != "finance" {
		t.Fatalf("round-tripped exceptions=%+v", roundTripped)
	}
}

func TestAccessRegoResourceOmitsUnsupportedServiceAccountsAndMapsNotification(t *testing.T) {
	var body map[string]any
	var diagnostics diag.Diagnostics
	module := "package forge.access\nmatch := {\"matched\": true}"
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(module)))
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/headless/v1/organizations/org.test/policy-code/rego/validate" {
			_ = json.NewEncoder(w).Encode(map[string]any{"valid": true, "languageVersion": "forge.rego.v1", "compilerFingerprint": "compiler", "sourceSha256": digest})
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"item": map[string]any{"id": "access-a", "currentRevision": 1, "definitionSha256": "server", "definition": body["definition"], "sourceRef": body["sourceRef"]}})
	})
	m := regoPolicyModel{
		ID: types.StringValue("access-a"), Name: types.StringValue("Access A"), Enabled: types.BoolValue(true),
		Users: stringSet("alice@example.com"), Groups: emptySet(), Devices: stringSet("macbook-a"),
		ServiceAccounts: types.SetNull(types.StringType), Agents: types.SetNull(types.StringType), Products: types.SetNull(types.StringType),
		EvaluateOn: types.ListNull(types.StringType), Action: types.StringValue("block"),
		Severity: types.StringValue("high"), AcknowledgeBroadScope: types.BoolValue(false), EnforcementSurfaces: stringSet("inline_hook"),
		Notification: dynamicFromGo(map[string]any{"message": "Use the approved product", "notifyUser": true}, &diagnostics),
		Module:       types.StringValue(module),
	}
	resource := &regoPolicyResource{client: client, family: "access", path: "access-policies"}
	resource.apply(context.Background(), m, 0, &diagnostics, func(regoPolicyModel) {})
	if diagnostics.HasError() {
		t.Fatalf("diagnostics=%v", diagnostics)
	}
	definition := body["definition"].(map[string]any)
	scope := definition["appliesTo"].(map[string]any)
	if _, exists := scope["serviceAccounts"]; exists {
		t.Fatalf("access scope included unsupported serviceAccounts: %+v", scope)
	}
	if object(definition["notification"])["message"] != "Use the approved product" {
		t.Fatalf("access notification was lost: %+v", definition)
	}
	if got, ok := definition["enforcementSurfaces"].([]any); !ok || len(got) != 1 || got[0] != "inline_hook" {
		t.Fatalf("access enforcement surfaces were lost: %+v", definition)
	}
}

func TestAccessTerraformResourcePreservesRuntimeApprovalAndRemediation(t *testing.T) {
	var diagnostics diag.Diagnostics
	model := regoPolicyModel{
		ID: types.StringValue("approval-route"), Name: types.StringValue("Approval route"), Enabled: types.BoolValue(true),
		Users: stringSet("alice@example.com"), Groups: emptySet(), Devices: emptySet(),
		UserDirectoryIDs: stringMap(nil), GroupDirectoryIDs: stringMap(nil),
		ServiceAccounts: emptySet(), Agents: emptySet(), Products: emptySet(), EvaluateOn: types.ListNull(types.StringType),
		UseCases: emptySet(), ComplianceFrameworks: emptySet(), Labels: stringSet("owner:security"),
		Action: types.StringValue("require_approval"), ApprovalMode: types.StringValue("self_serve"),
		Severity: types.StringValue("critical"), AcknowledgeBroadScope: types.BoolValue(false),
		EnforcementSurfaces: stringSet("endpoint_route"), EnforcedBy: emptySet(),
		Conditions: testDynamic(t, map[string]any{"field": "route.posture", "op": "eq", "value": "managed_route"}), Module: types.StringNull(),
		Runtime: dynamicFromGo(map[string]any{
			"candidateMode": "enhanced_runtime_hold", "detectionMode": "enhanced_runtime_detection",
			"detectionLatencyMs": float64(400), "timeoutBehavior": "policy_action", "failBehavior": "fail_closed", "confidenceThreshold": 0.9,
		}, &diagnostics),
		Notification: dynamicFromGo(map[string]any{
			"message": "Confirm this route", "notifyUser": true, "adminAudience": "security_admins", "acknowledgement": "mandatory_when_disruptive", "exceptionRequest": "available_when_future_policy_blocks",
		}, &diagnostics),
		Remediation: dynamicFromGo(map[string]any{
			"triggerPhase": "approval_response", "applyWhenClassification": "known_ai",
			"actions": []any{map[string]any{"surface": "desktop_process", "action": "forceTerminate", "target": "process.1"}},
		}, &diagnostics),
		Except: types.DynamicNull(), CustomFields: types.DynamicNull(),
	}
	resource := &regoPolicyResource{family: "access", path: "access-policies"}
	definition, _ := resource.buildMutation(context.Background(), model, false, &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("diagnostics=%v", diagnostics)
	}
	if object(definition["approval"])["mode"] != "self_serve" || object(definition["runtime"])["failBehavior"] != "fail_closed" {
		t.Fatalf("approval/runtime=%+v", definition)
	}
	if object(definition["notification"])["exceptionRequest"] != "available_when_future_policy_blocks" {
		t.Fatalf("notification=%+v", definition["notification"])
	}
	remediation := object(definition["remediation"])
	if remediation["triggerPhase"] != "approval_response" || len(remediation["actions"].([]any)) != 1 {
		t.Fatalf("remediation=%+v", remediation)
	}
}

func TestContentPolicySupportsCanonicalNativeConditionsWithoutRego(t *testing.T) {
	var body map[string]any
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/headless/v1/organizations/org.test/policy-code/rego/validate" {
			t.Fatal("native policy unexpectedly invoked Rego validation")
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"item": map[string]any{"currentRevision": 1, "definitionSha256": "native", "definition": body["definition"], "sourceRef": body["sourceRef"]}})
	})
	m := regoPolicyModel{
		ID: types.StringValue("native"), Name: types.StringValue("Native"), Enabled: types.BoolValue(true),
		Users: emptySet(), Groups: stringSet("Finance"), ServiceAccounts: emptySet(), Agents: emptySet(), Products: emptySet(), Devices: emptySet(),
		EvaluateOn: types.ListValueMust(types.StringType, []attr.Value{types.StringValue("pre_tool")}), Action: types.StringValue("block"),
		Module: types.StringNull(), Conditions: testDynamic(t, map[string]any{"all": []any{map[string]any{"field": "tool.id", "op": "eq", "value": "customer.export"}}}),
	}
	var diagnostics diag.Diagnostics
	resource := &regoPolicyResource{client: client, family: "content", path: "content-policies"}
	resource.apply(context.Background(), m, 0, &diagnostics, func(value regoPolicyModel) { m = value })
	if diagnostics.HasError() {
		t.Fatalf("native policy diagnostics: %v", diagnostics)
	}
	definition := body["definition"].(map[string]any)
	if definition["conditions"] == nil || definition["logic"] != nil || !m.ModuleSHA.IsNull() {
		t.Fatalf("native policy lowering/state is wrong: body=%+v state=%+v", body, m)
	}
}

func TestNonEmptyReferenceCollectionsOmitUnsetProperties(t *testing.T) {
	var requests []map[string]any
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		requests = append(requests, body)
		_ = json.NewEncoder(w).Encode(map[string]any{"item": map[string]any{"currentRevision": 1, "definitionSha256": "sha"}})
	})
	skill := &skillACLResource{client: client}
	sm := skillACLModel{ID: types.StringValue("s"), Skill: types.StringValue("deploy"), Enabled: types.BoolValue(true), Users: emptySet(), Groups: stringSet("Finance"), Effect: types.StringValue("allow")}
	var sd diag.Diagnostics
	skill.apply(context.Background(), sm, 0, &sd, func(skillACLModel) {})
	if sd.HasError() {
		t.Fatalf("skill: %v", sd)
	}
	skillDef := requests[0]["definition"].(map[string]any)
	subjects := skillDef["subjects"].(map[string]any)
	if _, ok := subjects["users"]; ok {
		t.Fatalf("empty users serialized: %+v", subjects)
	}
}

func TestRegoPolicyRefreshUsesReadableSelectorsAndRemoteDefinition(t *testing.T) {
	module := "package forge.content\nmatch := {\"matched\": false}"
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(module)))
	item := policyAPIItem{
		CurrentRevision: 7,
		DefinitionSHA:   "remote-sha",
		Definition: map[string]any{
			"id": "content.finance", "name": "Remote name", "enabled": false,
			"appliesTo":  map[string]any{"users": []any{"usr_internal"}, "groups": []any{"grp_internal"}},
			"evaluateOn": []any{"prompt"}, "action": "block",
			"logic": map[string]any{"module": module, "moduleSha256": digest},
		},
		SourceRef: map[string]any{"selectors": map[string]any{"appliesTo": map[string]any{"users": []any{"alice@example.com"}, "groups": []any{"Finance"}}}},
	}
	var model regoPolicyModel
	var diagnostics diag.Diagnostics
	resource := &regoPolicyResource{family: "content"}
	resource.flatten(context.Background(), item, &model, &diagnostics)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	var users, groups []string
	diagnostics.Append(model.Users.ElementsAs(context.Background(), &users, false)...)
	diagnostics.Append(model.Groups.ElementsAs(context.Background(), &groups, false)...)
	if model.Name.ValueString() != "Remote name" || model.Enabled.ValueBool() || model.CurrentRevision.ValueInt64() != 7 || model.DefinitionSHA.ValueString() != "remote-sha" {
		t.Fatalf("remote drift was not flattened: %+v", model)
	}
	if fmt.Sprint(users) != "[alice@example.com]" || fmt.Sprint(groups) != "[Finance]" {
		t.Fatalf("readable selectors were lost: users=%v groups=%v", users, groups)
	}
	if model.Module.ValueString() != module || model.ModuleSHA.ValueString() != digest {
		t.Fatalf("rego source identity was not refreshed: %+v", model)
	}
}

func TestPolicyAuthorityVerificationRejectsOtherManagers(t *testing.T) {
	client := &Client{managerID: "workspace-a", managerInstance: "instance-a"}
	for _, item := range []policyAPIItem{
		{},
		{ManagementMode: "forge"},
		{ManagementMode: "terraform", ManagerID: "workspace-b", ManagerInstance: "instance-a"},
		{ManagementMode: "terraform", ManagerID: "workspace-a", ManagerInstance: "instance-b"},
	} {
		if err := item.verifyAuthority(client); err == nil {
			t.Fatalf("expected authority conflict for %+v", item)
		}
	}
	if err := (policyAPIItem{ManagementMode: "terraform", ManagerID: "workspace-a", ManagerInstance: "instance-a"}).verifyAuthority(client); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyAuthorityImportPinsObservedRevision(t *testing.T) {
	m := policyAuthorityModel{ExpectedRevision: types.Int64Null()}
	managerID, managerInstance := "workspace-a", "instance-a"
	m.set(struct {
		ID              string  `json:"id"`
		CurrentRevision int64   `json:"currentRevision"`
		ManagementMode  string  `json:"managementMode"`
		ManagerID       *string `json:"managerId"`
		ManagerInstance *string `json:"managerInstance"`
	}{ID: "policy-a", CurrentRevision: 7, ManagementMode: "terraform", ManagerID: &managerID, ManagerInstance: &managerInstance})
	if m.ExpectedRevision.ValueInt64() != 7 || m.CurrentRevision.ValueInt64() != 7 {
		t.Fatalf("imported authority state did not pin revision: %+v", m)
	}
}

func TestConditionValuesFindsNestedMCPSelectors(t *testing.T) {
	node := map[string]any{"all": []any{
		map[string]any{"field": "mcp.server_id", "op": "eq", "value": "server.internal"},
		map[string]any{"any": []any{map[string]any{"field": "mcp.tool_id", "op": "in", "value": []any{"tool.a", "tool.b"}}}},
	}}
	if got := conditionValues(node, "mcp.server_id"); fmt.Sprint(got) != "[server.internal]" {
		t.Fatalf("servers=%v", got)
	}
	if got := conditionValues(node, "mcp.tool_id"); fmt.Sprint(got) != "[tool.a tool.b]" {
		t.Fatalf("tools=%v", got)
	}
}

func TestRegoPolicyConfigValidationCoversEnumsAndActionSpecificShapes(t *testing.T) {
	null := func(action string) regoPolicyModel {
		return regoPolicyModel{
			Action: types.StringValue(action), EvaluateOn: types.ListValueMust(types.StringType, []attr.Value{types.StringValue("prompt")}),
			Module: types.StringValue("package forge.content\nmatch := {\"matched\": false}"), Conditions: types.DynamicNull(),
			RedactionReplacement: types.StringNull(), RedactionStrategy: types.StringNull(), RedactionPaths: types.SetNull(types.StringType),
			RedactionKeepStart: types.Int64Null(), RedactionKeepEnd: types.Int64Null(), RedactionMask: types.StringNull(), RedactionSaltRef: types.StringNull(), RedactionFakeSubtype: types.StringNull(),
			FilterCollectionPath: types.StringNull(), FilterPath: types.StringNull(), FilterOperator: types.StringNull(), FilterValue: types.DynamicNull(), FilterOnUnavailable: types.StringNull(),
			RemediationAction: types.StringNull(), RemediationTarget: types.StringNull(),
		}
	}
	constant := null("redact")
	if got := validateRegoPolicyConfig(context.Background(), "content", constant); len(got) == 0 {
		t.Fatal("constant redaction without replacement must fail")
	}
	constant.RedactionReplacement = types.StringValue("[REDACTED]")
	constant.RedactionSaltRef = types.StringValue("wrong-strategy")
	if got := validateRegoPolicyConfig(context.Background(), "content", constant); len(got) == 0 {
		t.Fatal("constant redaction with hash-only attributes must fail")
	}
	hash := null("redact")
	hash.RedactionStrategy = types.StringValue("hash")
	hash.RedactionReplacement = types.StringValue("wrong-strategy")
	if got := validateRegoPolicyConfig(context.Background(), "content", hash); len(got) == 0 {
		t.Fatal("hash redaction with constant-only attributes must fail")
	}
	partial := null("redact")
	partial.RedactionStrategy = types.StringValue("partial")
	partial.RedactionKeepStart = types.Int64Value(2)
	partial.RedactionPaths = stringSet("$.credentials[0]")
	if got := validateRegoPolicyConfig(context.Background(), "content", partial); len(got) != 0 {
		t.Fatalf("valid partial redaction: %v", got)
	}
	partial.RedactionApplyTo = types.StringValue("matches")
	if got := validateRegoPolicyConfig(context.Background(), "content", partial); len(got) == 0 {
		t.Fatal("match-only redaction without a pattern must fail")
	}
	partial.RedactionPattern = types.StringValue("secret-[0-9]+")
	if got := validateRegoPolicyConfig(context.Background(), "content", partial); len(got) != 0 {
		t.Fatalf("valid match-only redaction: %v", got)
	}
	invalidPath := partial
	invalidPath.RedactionPaths = stringSet("$..secret")
	if got := validateRegoPolicyConfig(context.Background(), "content", invalidPath); len(got) == 0 {
		t.Fatal("recursive JSON path must fail")
	}
	filter := null("filter")
	if got := validateRegoPolicyConfig(context.Background(), "content", filter); len(got) == 0 {
		t.Fatal("incomplete filter must fail")
	}
	access := null("block")
	access.EvaluateOn = types.ListNull(types.StringType)
	access.RemediationAction = types.StringValue("inventedAction")
	if got := validateRegoPolicyConfig(context.Background(), "access", access); len(got) == 0 {
		t.Fatal("unknown remediation enum must fail")
	}
	contentApproval := null("block")
	contentApproval.AutoApprove = types.BoolValue(true)
	if got := validateRegoPolicyConfig(context.Background(), "content", contentApproval); len(got) == 0 {
		t.Fatal("approval configuration on a block policy must fail")
	}
	accessApproval := null("block")
	accessApproval.EvaluateOn = types.ListNull(types.StringType)
	accessApproval.ApprovalMode = types.StringValue("self_serve")
	if got := validateRegoPolicyConfig(context.Background(), "access", accessApproval); len(got) == 0 {
		t.Fatal("approval mode on a block policy must fail")
	}
}

func TestSkillACLBuildSupportsEveryoneAndRejectsMixedSubjects(t *testing.T) {
	resource := &skillACLResource{}
	model := skillACLModel{ID: types.StringValue("skill.everyone"), Skill: types.StringValue("deploy"), Enabled: types.BoolValue(true), Everyone: types.BoolValue(true), Users: stringSet(), Groups: stringSet(), UserDirectoryIDs: stringMap(nil), GroupDirectoryIDs: stringMap(nil), Effect: types.StringValue("allow")}
	var diagnostics diag.Diagnostics
	definition, _ := resource.build(context.Background(), model, &diagnostics)
	if diagnostics.HasError() || !boolFrom(object(definition["subjects"])["everyone"]) {
		t.Fatalf("everyone ACL failed: definition=%+v diagnostics=%v", definition, diagnostics)
	}
	model.Users = stringSet("alice@example.com")
	diagnostics = nil
	resource.build(context.Background(), model, &diagnostics)
	if !diagnostics.HasError() {
		t.Fatal("everyone combined with users must fail")
	}
}

func TestDynamicFilterValueRoundTripsTypedJSON(t *testing.T) {
	for name, input := range map[string]any{
		"string":  "restricted",
		"boolean": true,
		"number":  float64(42.5),
		"array":   []any{"restricted", float64(3), false},
		"object":  map[string]any{"classification": "restricted", "score": float64(9)},
	} {
		t.Run(name, func(t *testing.T) {
			var diagnostics diag.Diagnostics
			dynamic := dynamicFromGo(input, &diagnostics)
			if diagnostics.HasError() {
				t.Fatal(diagnostics)
			}
			got, err := terraformDynamicToGo(dynamic)
			if err != nil {
				t.Fatal(err)
			}
			left, _ := json.Marshal(input)
			right, _ := json.Marshal(got)
			if string(left) != string(right) {
				t.Fatalf("round trip: %s != %s", left, right)
			}
		})
	}
}
