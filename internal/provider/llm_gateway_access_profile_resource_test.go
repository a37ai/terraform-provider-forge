package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestLLMGatewayAccessProfilePayloadCaptureMode(t *testing.T) {
	ctx := context.Background()
	routes, routeDiagnostics := types.ListValueFrom(ctx, routeObjectType(), []llmGatewayRoutePlanModel{{
		Provider: types.StringValue("OpenAI"), Name: types.StringValue("Chat"),
		RequestedModelPattern: types.StringValue("gpt-4o-mini"), UpstreamModel: types.StringValue("gpt-4o-mini"),
		APISurface: types.StringValue("openai_chat_completions"), PolicyHooks: types.SetNull(types.StringType),
	}})
	if routeDiagnostics.HasError() {
		t.Fatal(routeDiagnostics)
	}
	resource := &llmGatewayAccessProfileResource{}
	model := llmGatewayAccessProfileModel{Routes: routes, FallbackRules: types.ListNull(fallbackRuleObjectType())}
	providers := []llmGatewayProviderAPI{{ID: "provider-1", Name: "OpenAI"}}
	for _, mode := range []types.String{types.StringNull(), types.StringUnknown(), types.StringValue("usage_only")} {
		model.CaptureMode = mode
		var diagnostics diag.Diagnostics
		payload := resource.payload(ctx, model, providers, &diagnostics)
		if diagnostics.HasError() {
			t.Fatal(diagnostics)
		}
		profile := payload["profile"].(map[string]any)
		value, present := profile["captureMode"]
		if mode.IsNull() || mode.IsUnknown() {
			if present {
				t.Fatalf("omitted capture mode became %v", value)
			}
		} else if value != mode.ValueString() {
			t.Fatalf("capture mode = %v, want %s", value, mode.ValueString())
		}
	}
}

func TestLLMGatewayPolicyHooksRejectResponse(t *testing.T) {
	var schemaResponse resource.SchemaResponse
	(&llmGatewayAccessProfileResource{}).Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
	profileHooks := schemaResponse.Schema.Attributes["policy_hooks"].(schema.SetAttribute)
	route := schemaResponse.Schema.Blocks["route"].(schema.ListNestedBlock)
	routeHooks := route.NestedObject.Attributes["policy_hooks"].(schema.SetAttribute)

	for _, name := range []string{"enforcement_mode", "rollout_state"} {
		if _, ok := schemaResponse.Schema.Attributes[name]; ok {
			t.Errorf("profile exposes removed field %s", name)
		}
		if _, ok := route.NestedObject.Attributes[name]; ok {
			t.Errorf("route exposes removed field %s", name)
		}
	}
	for scope, hooks := range map[string]schema.SetAttribute{"profile": profileHooks, "route": routeHooks} {
		if !hooks.Optional || !hooks.Computed {
			t.Errorf("%s policy_hooks must accept server defaults", scope)
		}
		if strings.Contains(hooks.Description, "response") {
			t.Errorf("%s policy_hooks description advertises unsupported response hook: %q", scope, hooks.Description)
		}
		for _, test := range []struct {
			name    string
			values  types.Set
			wantErr bool
		}{
			{name: "supported hooks", values: stringSet("prompt", "pre_tool_use", "post_tool_use")},
			{name: "response", values: stringSet("response"), wantErr: true},
		} {
			t.Run(scope+"/"+test.name, func(t *testing.T) {
				request := validator.SetRequest{
					Path:           path.Root("policy_hooks"),
					PathExpression: path.MatchRoot("policy_hooks"),
					ConfigValue:    test.values,
				}
				var response validator.SetResponse
				for _, hookValidator := range hooks.Validators {
					hookValidator.ValidateSet(context.Background(), request, &response)
				}
				if response.Diagnostics.HasError() != test.wantErr {
					t.Fatalf("diagnostics=%v, want error=%t", response.Diagnostics, test.wantErr)
				}
			})
		}
	}
}

func TestLLMGatewayRouteStrategiesMatchTierModel(t *testing.T) {
	var schemaResponse resource.SchemaResponse
	(&llmGatewayAccessProfileResource{}).Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
	route := schemaResponse.Schema.Blocks["route"].(schema.ListNestedBlock)
	strategy := route.NestedObject.Attributes["strategy"].(schema.StringAttribute)

	for _, test := range []struct {
		value   string
		wantErr bool
	}{
		{value: "fixed"},
		{value: "weighted"},
		{value: "policy"},
		{value: "cost"},
		{value: "latency"},
		{value: "fallback", wantErr: true},
		{value: "quality", wantErr: true},
	} {
		t.Run(test.value, func(t *testing.T) {
			request := validator.StringRequest{ConfigValue: types.StringValue(test.value)}
			var response validator.StringResponse
			for _, strategyValidator := range strategy.Validators {
				strategyValidator.ValidateString(context.Background(), request, &response)
			}
			if response.Diagnostics.HasError() != test.wantErr {
				t.Fatalf("diagnostics=%v, want error=%t", response.Diagnostics, test.wantErr)
			}
		})
	}
}

func TestLLMGatewayPlanValidatesEquivalentNetworkEditAfterImport(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/llm-gateway"):
			_, _ = w.Write([]byte(`{"providers":[{"id":"provider_test","displayName":"Test OpenAI"}]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/llm-gateway/plans/validate"):
			_, _ = w.Write([]byte(`{"valid":true,"validationToken":"fresh-validation","schemaVersion":"forge.terraform.llm-gateway-plan.v1"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(server.URL, "org_test", "test-token", "test-manager", "test-instance", "test", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	gateway := &llmGatewayAccessProfileResource{client: client}
	var schemaResponse resource.SchemaResponse
	gateway.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
	routes, diagnostics := types.ListValueFrom(ctx, routeObjectType(), []llmGatewayRoutePlanModel{{
		Provider: types.StringValue("Test OpenAI"), Name: types.StringValue("Primary"),
		RequestedModelPattern: types.StringValue("gpt-*"), APISurface: types.StringValue("openai_chat_completions"),
		PolicyHooks: types.SetNull(types.StringType),
	}})
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	model := llmGatewayAccessProfileModel{
		ID: types.StringValue("profile_test"), Name: types.StringValue("Profile"), Routes: routes,
		Version: types.Int64Value(1), AllowedClientNetworks: stringSet("203.0.113.10/32"),
		ModelPatterns: types.SetNull(types.StringType), DataClasses: types.SetNull(types.StringType),
		PolicyHooks: types.SetNull(types.StringType), FallbackRules: types.ListNull(fallbackRuleObjectType()),
	}
	state := tfsdk.State{Schema: schemaResponse.Schema}
	if diagnostics := state.Set(ctx, &model); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	model.AllowedClientNetworks = stringSet("203.0.113.10")
	plan := tfsdk.Plan{Schema: schemaResponse.Schema}
	if diagnostics := plan.Set(ctx, &model); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	response := resource.ModifyPlanResponse{Plan: plan}
	gateway.ModifyPlan(ctx, resource.ModifyPlanRequest{
		State: state, Plan: plan, Config: tfsdk.Config{Schema: schemaResponse.Schema, Raw: plan.Raw},
	}, &response)
	if response.Diagnostics.HasError() {
		t.Fatal(response.Diagnostics)
	}
	var token types.String
	if diagnostics := response.Plan.GetAttribute(ctx, path.Root("validation_token"), &token); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if token.ValueString() != "fresh-validation" {
		t.Fatal("equivalent network edit after import did not receive a validation token")
	}
}
