package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestLLMGatewayAccessProfilePayloadPreservesOrderedFailoverRule(t *testing.T) {
	ctx := context.Background()
	routeIDs, ds := types.ListValueFrom(ctx, types.StringType, []string{"backup-b", "backup-a"})
	if ds.HasError() {
		t.Fatalf("route IDs: %v", ds)
	}
	rules, ds := types.ListValueFrom(ctx, fallbackRuleObjectType(), []llmGatewayFallbackRulePlanModel{{Reason: types.StringValue("provider_context_limit"), RouteIDs: routeIDs}})
	if ds.HasError() {
		t.Fatalf("rules: %v", ds)
	}
	routes, ds := types.ListValueFrom(ctx, routeObjectType(), []llmGatewayRoutePlanModel{})
	if ds.HasError() {
		t.Fatalf("routes: %v", ds)
	}
	model := llmGatewayAccessProfileModel{ID: types.StringValue("profile"), Name: types.StringValue("Profile"), FallbackRules: rules, Routes: routes,
		ModelPatterns: types.SetNull(types.StringType), DataClasses: types.SetNull(types.StringType), PolicyHooks: types.SetNull(types.StringType)}
	var diagnostics diag.Diagnostics
	payload := (&llmGatewayAccessProfileResource{}).payload(ctx, model, nil, &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("payload diagnostics: %v", diagnostics)
	}
	profile := payload["profile"].(map[string]any)
	rule := profile["failoverRules"].([]map[string]any)[0]
	ids := rule["routeIds"].([]string)
	if ids[0] != "backup-b" || ids[1] != "backup-a" {
		t.Fatalf("route order = %v", ids)
	}
}
