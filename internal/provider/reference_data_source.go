package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type referenceDataSource struct {
	client   *Client
	typeName string
	kind     string
	parented bool
}

type referenceDataSourceModel struct {
	ID        types.String `tfsdk:"id"`
	Selector  types.String `tfsdk:"selector"`
	Qualifier types.String `tfsdk:"qualifier"`
}

type parentedReferenceDataSourceModel struct {
	ID        types.String `tfsdk:"id"`
	Selector  types.String `tfsdk:"selector"`
	Qualifier types.String `tfsdk:"qualifier"`
	ParentID  types.String `tfsdk:"parent_id"`
}

func newReferenceDataSource(typeName, kind string) datasource.DataSource {
	return &referenceDataSource{typeName: typeName, kind: kind}
}

func newUserDataSource() datasource.DataSource  { return newReferenceDataSource("user", "user") }
func newGroupDataSource() datasource.DataSource { return newReferenceDataSource("group", "group") }
func newAgentDataSource() datasource.DataSource { return newReferenceDataSource("agent", "agent") }
func newAIProductDataSource() datasource.DataSource {
	return newReferenceDataSource("ai_product", "ai_product")
}
func newIntegrationDataSource() datasource.DataSource {
	return newReferenceDataSource("integration", "integration")
}
func newMCPServerDataSource() datasource.DataSource {
	return newReferenceDataSource("mcp_server", "mcp_server")
}
func newMCPToolDataSource() datasource.DataSource {
	return &referenceDataSource{typeName: "mcp_tool", kind: "mcp_tool", parented: true}
}
func newSkillDataSource() datasource.DataSource { return newReferenceDataSource("skill", "skill") }
func newGatewayProviderDataSource() datasource.DataSource {
	return newReferenceDataSource("gateway_provider", "gateway_provider")
}

func (d *referenceDataSource) Metadata(_ context.Context, request datasource.MetadataRequest, response *datasource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_" + d.typeName
}

func (d *referenceDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, response *datasource.SchemaResponse) {
	attributes := map[string]schema.Attribute{
		"id":        schema.StringAttribute{Computed: true, Description: "Exact Forge object ID."},
		"selector":  schema.StringAttribute{Required: true, Description: "Exact customer-visible name, key, email, or existing ID."},
		"qualifier": schema.StringAttribute{Optional: true, Computed: true, Description: "Exact disambiguator when the selector is not unique."},
	}
	if d.parented {
		attributes["parent_id"] = schema.StringAttribute{Required: true, Description: "Resolved parent MCP server ID."}
	}
	response.Schema = schema.Schema{Description: "Resolve one exact Forge policy reference.", Attributes: attributes}
}

func (d *referenceDataSource) Configure(_ context.Context, request datasource.ConfigureRequest, response *datasource.ConfigureResponse) {
	if request.ProviderData == nil {
		return
	}
	client, ok := request.ProviderData.(*Client)
	if !ok {
		response.Diagnostics.AddError("Unexpected provider data", "Forge client not configured")
		return
	}
	d.client = client
}

func (d *referenceDataSource) Read(ctx context.Context, request datasource.ReadRequest, response *datasource.ReadResponse) {
	if d.parented {
		var model parentedReferenceDataSourceModel
		response.Diagnostics.Append(request.Config.Get(ctx, &model)...)
		if response.Diagnostics.HasError() {
			return
		}
		item, err := d.client.ResolvePolicyReference(ctx, d.kind, model.Selector.ValueString(), model.ParentID.ValueString(), model.Qualifier.ValueString())
		if err != nil {
			response.Diagnostics.AddError("Resolve Forge policy reference", err.Error())
			return
		}
		model.ID = types.StringValue(item.ID)
		model.Qualifier = types.StringPointerValue(item.Qualifier)
		response.Diagnostics.Append(response.State.Set(ctx, &model)...)
		return
	}
	var model referenceDataSourceModel
	response.Diagnostics.Append(request.Config.Get(ctx, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := d.client.ResolvePolicyReference(ctx, d.kind, model.Selector.ValueString(), "", model.Qualifier.ValueString())
	if err != nil {
		response.Diagnostics.AddError("Resolve Forge policy reference", err.Error())
		return
	}
	model.ID = types.StringValue(item.ID)
	model.Qualifier = types.StringPointerValue(item.Qualifier)
	response.Diagnostics.Append(response.State.Set(ctx, &model)...)
}

var _ datasource.DataSourceWithConfigure = (*referenceDataSource)(nil)
