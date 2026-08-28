package provider

import (
	"context"
	"os"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const defaultForgeEndpoint = "https://api.forge.ai"

type forgeProvider struct{ version string }

type providerModel struct {
	Endpoint        types.String `tfsdk:"endpoint"`
	OrganizationID  types.String `tfsdk:"organization_id"`
	APIToken        types.String `tfsdk:"api_token"`
	ManagerID       types.String `tfsdk:"manager_id"`
	ManagerInstance types.String `tfsdk:"manager_instance"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider { return &forgeProvider{version: version} }
}

func (p *forgeProvider) Metadata(_ context.Context, _ provider.MetadataRequest, response *provider.MetadataResponse) {
	response.TypeName = "forge"
	response.Version = p.version
}

func (p *forgeProvider) Schema(_ context.Context, _ provider.SchemaRequest, response *provider.SchemaResponse) {
	required := []validator.String{stringvalidator.LengthAtLeast(1)}
	response.Schema = schema.Schema{Attributes: map[string]schema.Attribute{
		"endpoint":         schema.StringAttribute{Optional: true, Description: "Forge control-plane endpoint."},
		"organization_id":  schema.StringAttribute{Required: true, Validators: required},
		"api_token":        schema.StringAttribute{Optional: true, Sensitive: true, Validators: required},
		"manager_id":       schema.StringAttribute{Required: true, Validators: required},
		"manager_instance": schema.StringAttribute{Required: true, Validators: required},
	}}
}

func (p *forgeProvider) Configure(ctx context.Context, request provider.ConfigureRequest, response *provider.ConfigureResponse) {
	var config providerModel
	response.Diagnostics.Append(request.Config.Get(ctx, &config)...)
	if response.Diagnostics.HasError() {
		return
	}
	endpoint := resolveForgeEndpoint(config.Endpoint.ValueString())
	token := config.APIToken.ValueString()
	if token == "" {
		token = os.Getenv("FORGE_API_TOKEN")
	}
	client, err := NewClient(endpoint, config.OrganizationID.ValueString(), token, config.ManagerID.ValueString(), config.ManagerInstance.ValueString(), "terraform-provider-forge/"+p.version, 30*time.Second)
	if err != nil {
		response.Diagnostics.Append(diag.NewErrorDiagnostic("Invalid Forge provider configuration", err.Error()))
		return
	}
	if _, err := client.Negotiate(ctx); err != nil {
		response.Diagnostics.Append(diag.NewErrorDiagnostic("Incompatible Forge policy API", err.Error()))
		return
	}
	response.ResourceData = client
	response.DataSourceData = client
}

func (p *forgeProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{newContentPolicyResource, newAccessPolicyResource, newLLMGatewayAccessProfileResource, newLLMGatewayServiceAccountResource, newLLMGatewayManagedAccessOverrideResource, newDeviceGatewayIdentityAssignmentResource, newMCPACLResource, newSkillACLResource, newPolicyAuthorityResource}
}
func (p *forgeProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		newUserDataSource, newGroupDataSource, newAgentDataSource, newAIProductDataSource,
		newIntegrationDataSource, newMCPServerDataSource, newMCPToolDataSource, newSkillDataSource,
		newGatewayProviderDataSource, newRegoTestDataSource,
	}
}

func resolveForgeEndpoint(configured string) string {
	if configured != "" {
		return configured
	}
	if endpoint := os.Getenv("FORGE_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return defaultForgeEndpoint
}
