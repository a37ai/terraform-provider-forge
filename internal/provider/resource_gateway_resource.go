package provider

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type resourceGatewayResource struct{ client *Client }

type resourceGatewayModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Hostname        types.String `tfsdk:"hostname"`
	Enabled         types.Bool   `tfsdk:"enabled"`
	ManagementMode  types.String `tfsdk:"management_mode"`
	ManagerID       types.String `tfsdk:"manager_id"`
	ManagerInstance types.String `tfsdk:"manager_instance"`
}

type resourceGatewayAPI struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	Hostname        string  `json:"hostname"`
	Enabled         bool    `json:"enabled"`
	ManagementMode  string  `json:"managementMode"`
	ManagerID       *string `json:"managerId"`
	ManagerInstance *string `json:"managerInstance"`
}

func newResourceGatewayResource() resource.Resource { return &resourceGatewayResource{} }

func (r *resourceGatewayResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_resource_gateway"
}

func (r *resourceGatewayResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = schema.Schema{
		Description: "A customer-deployed Forge gateway that carries direct and automatic access to assigned Resources.",
		Attributes: map[string]schema.Attribute{
			"id":               schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":             schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.LengthBetween(1, 128)}},
			"hostname":         schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.LengthBetween(3, 253)}, Description: "DNS hostname clients use to reach this Resource Gateway."},
			"enabled":          schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"management_mode":  schema.StringAttribute{Computed: true, Description: "Where this Resource Gateway is managed."},
			"manager_id":       schema.StringAttribute{Computed: true, Description: "Terraform manager that owns this Resource Gateway."},
			"manager_instance": schema.StringAttribute{Computed: true, Description: "Terraform workspace that owns this Resource Gateway."},
		},
	}
}

func (r *resourceGatewayResource) Configure(_ context.Context, request resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if request.ProviderData != nil {
		r.client, _ = request.ProviderData.(*Client)
	}
}

func (r *resourceGatewayResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var model resourceGatewayModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	var result resourceGatewayAPI
	if err := r.client.Do(ctx, http.MethodPost, "resource-gateways", resourceGatewayPayload(model), &result); err != nil {
		response.Diagnostics.AddError("Create Forge Resource Gateway", err.Error())
		return
	}
	if err := verifyResourceGatewayAuthority(r.client, result); err != nil {
		response.Diagnostics.AddError("Forge Resource Gateway authority conflict", err.Error())
		return
	}
	refreshResourceGatewayModel(&model, result)
	response.Diagnostics.Append(response.State.Set(ctx, &model)...)
}

func (r *resourceGatewayResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var model resourceGatewayModel
	response.Diagnostics.Append(request.State.Get(ctx, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	var result resourceGatewayAPI
	err := r.client.Do(ctx, http.MethodGet, "resource-gateways/"+url.PathEscape(model.ID.ValueString()), nil, &result)
	if IsNotFound(err) {
		response.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Read Forge Resource Gateway", err.Error())
		return
	}
	if err := verifyResourceGatewayAuthority(r.client, result); err != nil {
		response.Diagnostics.AddError("Forge Resource Gateway authority conflict", err.Error())
		return
	}
	refreshResourceGatewayModel(&model, result)
	response.Diagnostics.Append(response.State.Set(ctx, &model)...)
}

func (r *resourceGatewayResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var model resourceGatewayModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	var result resourceGatewayAPI
	if err := r.client.Do(ctx, http.MethodPut, "resource-gateways/"+url.PathEscape(model.ID.ValueString()), resourceGatewayPayload(model), &result); err != nil {
		response.Diagnostics.AddError("Update Forge Resource Gateway", err.Error())
		return
	}
	if err := verifyResourceGatewayAuthority(r.client, result); err != nil {
		response.Diagnostics.AddError("Forge Resource Gateway authority conflict", err.Error())
		return
	}
	refreshResourceGatewayModel(&model, result)
	response.Diagnostics.Append(response.State.Set(ctx, &model)...)
}

func (r *resourceGatewayResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var model resourceGatewayModel
	response.Diagnostics.Append(request.State.Get(ctx, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	if err := r.client.Do(ctx, http.MethodDelete, "resource-gateways/"+url.PathEscape(model.ID.ValueString()), nil, nil); err != nil && !IsNotFound(err) {
		response.Diagnostics.AddError("Delete Forge Resource Gateway", err.Error())
	}
}

func (r *resourceGatewayResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}

func resourceGatewayPayload(model resourceGatewayModel) map[string]any {
	return map[string]any{"name": model.Name.ValueString(), "hostname": model.Hostname.ValueString(), "enabled": model.Enabled.ValueBool()}
}

func refreshResourceGatewayModel(model *resourceGatewayModel, result resourceGatewayAPI) {
	model.ID = types.StringValue(result.ID)
	model.Name = types.StringValue(result.Name)
	model.Hostname = types.StringValue(result.Hostname)
	model.Enabled = types.BoolValue(result.Enabled)
	model.ManagementMode = types.StringValue(result.ManagementMode)
	model.ManagerID = nullableTerraformString(result.ManagerID)
	model.ManagerInstance = nullableTerraformString(result.ManagerInstance)
}

func nullableTerraformString(value *string) types.String {
	if value == nil || *value == "" {
		return types.StringNull()
	}
	return types.StringValue(*value)
}

func verifyResourceGatewayAuthority(client *Client, result resourceGatewayAPI) error {
	if result.ManagementMode != "terraform" {
		return errors.New("the object is not managed by Terraform")
	}
	if result.ManagerID == nil || *result.ManagerID != client.managerID || result.ManagerInstance == nil || *result.ManagerInstance != client.managerInstance {
		return errors.New("the object belongs to a different Terraform manager or workspace")
	}
	return nil
}

var _ resource.ResourceWithConfigure = (*resourceGatewayResource)(nil)
var _ resource.ResourceWithImportState = (*resourceGatewayResource)(nil)
