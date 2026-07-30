package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestLLMGatewayPolicyHooksRejectResponse(t *testing.T) {
	var schemaResponse resource.SchemaResponse
	(&llmGatewayAccessProfileResource{}).Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
	profileHooks := schemaResponse.Schema.Attributes["policy_hooks"].(schema.SetAttribute)
	route := schemaResponse.Schema.Blocks["route"].(schema.ListNestedBlock)
	routeHooks := route.NestedObject.Attributes["policy_hooks"].(schema.SetAttribute)

	for scope, hooks := range map[string]schema.SetAttribute{"profile": profileHooks, "route": routeHooks} {
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
