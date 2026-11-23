package provider

import (
	"context"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type mcpServerClientNetworksResource struct{ client *Client }

type mcpServerClientNetworksModel struct {
	ServerID              types.String `tfsdk:"server_id"`
	AllowedClientNetworks types.Set    `tfsdk:"allowed_client_networks"`
}

type mcpServerClientNetworksAPI struct {
	AllowedClientNetworks        []string `json:"allowedClientNetworks"`
	AllowedClientNetworksManaged bool     `json:"allowedClientNetworksManaged"`
}

func newMCPServerClientNetworksResource() resource.Resource {
	return &mcpServerClientNetworksResource{}
}

func (r *mcpServerClientNetworksResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_mcp_server_client_networks"
}

func (r *mcpServerClientNetworksResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = schema.Schema{
		Description: "Manage the allowed client networks of an existing Forge MCP Registry server.",
		Attributes: map[string]schema.Attribute{
			"server_id": schema.StringAttribute{
				Required:      true,
				Description:   "The ID of an existing MCP Registry server in the provider organization.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"allowed_client_networks": schema.SetAttribute{
				Required:    true,
				ElementType: types.StringType,
				Description: "Allowed IP addresses or CIDR ranges. An empty set clears the network restriction.",
				Validators:  []validator.Set{allowedClientNetworksValidator{}},
			},
		},
	}
}

func (r *mcpServerClientNetworksResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	if request.ProviderData == nil {
		return
	}
	client, ok := request.ProviderData.(*Client)
	if !ok {
		response.Diagnostics.AddError("Unexpected provider data", "Forge client not configured")
		return
	}
	r.client = client
}

func (r *mcpServerClientNetworksResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var model mcpServerClientNetworksModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &model)...)
	r.apply(ctx, &model, &response.Diagnostics)
	if !response.Diagnostics.HasError() {
		response.Diagnostics.Append(response.State.Set(ctx, &model)...)
	}
}

func (r *mcpServerClientNetworksResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var model mcpServerClientNetworksModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &model)...)
	r.apply(ctx, &model, &response.Diagnostics)
	if !response.Diagnostics.HasError() {
		response.Diagnostics.Append(response.State.Set(ctx, &model)...)
	}
}

func (r *mcpServerClientNetworksResource) apply(ctx context.Context, model *mcpServerClientNetworksModel, diagnostics *diag.Diagnostics) {
	networks, parseDiagnostics := normalizedAllowedClientNetworks(ctx, model.AllowedClientNetworks, path.Root("allowed_client_networks"))
	diagnostics.Append(parseDiagnostics...)
	if diagnostics.HasError() {
		return
	}
	if networks == nil {
		diagnostics.AddAttributeError(path.Root("allowed_client_networks"), "Unknown client networks", "The list of allowed client networks must be known when applying the resource.")
		return
	}

	var result mcpServerClientNetworksAPI
	body := map[string][]string{"allowedClientNetworks": networks}
	if err := r.client.Do(ctx, http.MethodPut, model.apiPath(), body, &result); err != nil {
		diagnostics.AddError("Save Forge MCP server client networks", err.Error())
		return
	}
	if !result.AllowedClientNetworksManaged {
		diagnostics.AddError("Save Forge MCP server client networks", "Forge did not report Terraform ownership of the network setting.")
		return
	}
	model.AllowedClientNetworks = allowedClientNetworksState(ctx, model.AllowedClientNetworks, result.AllowedClientNetworks, diagnostics)
}

func (r *mcpServerClientNetworksResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var model mcpServerClientNetworksModel
	response.Diagnostics.Append(request.State.Get(ctx, &model)...)
	if response.Diagnostics.HasError() {
		return
	}

	var result mcpServerClientNetworksAPI
	err := r.client.Do(ctx, http.MethodGet, model.apiPath(), nil, &result)
	if IsNotFound(err) {
		response.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Read Forge MCP server client networks", err.Error())
		return
	}
	if !result.AllowedClientNetworksManaged {
		response.State.RemoveResource(ctx)
		return
	}
	model.AllowedClientNetworks = allowedClientNetworksState(ctx, model.AllowedClientNetworks, result.AllowedClientNetworks, &response.Diagnostics)
	response.Diagnostics.Append(response.State.Set(ctx, &model)...)
}

func (r *mcpServerClientNetworksResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var model mcpServerClientNetworksModel
	response.Diagnostics.Append(request.State.Get(ctx, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	if err := r.client.Do(ctx, http.MethodDelete, model.apiPath(), nil, nil); err != nil && !IsNotFound(err) {
		response.Diagnostics.AddError("Release Terraform management of Forge MCP server client networks", err.Error())
	}
}

func (r *mcpServerClientNetworksResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("server_id"), request, response)
}

func (model mcpServerClientNetworksModel) apiPath() string {
	return "mcp-registry/" + url.PathEscape(model.ServerID.ValueString()) + "/allowed-client-networks"
}

var _ resource.ResourceWithConfigure = (*mcpServerClientNetworksResource)(nil)
var _ resource.ResourceWithImportState = (*mcpServerClientNetworksResource)(nil)
