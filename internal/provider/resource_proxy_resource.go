package provider

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
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

type resourceProxyResource struct{ client *Client }

type resourceProxyModel struct {
	ID                 types.String `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	Protocol           types.String `tfsdk:"protocol"`
	UpstreamHost       types.String `tfsdk:"upstream_host"`
	UpstreamPort       types.Int64  `tfsdk:"upstream_port"`
	Enabled            types.Bool   `tfsdk:"enabled"`
	TransparentRouting types.Bool   `tfsdk:"transparent_routing"`
	UpstreamTLS        types.Bool   `tfsdk:"upstream_tls"`
	UpstreamCAPEM      types.String `tfsdk:"upstream_ca_pem"`
	ManagementMode     types.String `tfsdk:"management_mode"`
	ManagerID          types.String `tfsdk:"manager_id"`
	ManagerInstance    types.String `tfsdk:"manager_instance"`
}

type resourceProxyAPI struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Protocol           string `json:"protocol"`
	UpstreamHost       string `json:"upstreamHost"`
	UpstreamPort       int64  `json:"upstreamPort"`
	Enabled            bool   `json:"enabled"`
	TransparentRouting bool   `json:"transparentRouting"`
	UpstreamTLS        bool   `json:"upstreamTls"`
	UpstreamCAPEM      string `json:"upstreamCaPem"`
	ManagementMode     string `json:"managementMode"`
	ManagerID          string `json:"managerId"`
	ManagerInstance    string `json:"managerInstance"`
}

func newResourceProxyResource() resource.Resource { return &resourceProxyResource{} }

func (r *resourceProxyResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_resource"
}

func (r *resourceProxyResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = schema.Schema{
		Description: "An HTTP or PostgreSQL destination governed by Forge Access Policies.",
		Attributes: map[string]schema.Attribute{
			"id":                  schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":                schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.LengthBetween(1, 128)}},
			"protocol":            schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.OneOf("http", "postgres")}},
			"upstream_host":       schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.LengthBetween(3, 253)}},
			"upstream_port":       schema.Int64Attribute{Required: true, Validators: []validator.Int64{int64validator.Between(1, 65535)}},
			"upstream_tls":        schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true), Description: "Encrypt and verify the connection from Forge to the destination."},
			"upstream_ca_pem":     schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.LengthAtMost(65536)}, Description: "Public CA certificate PEM used to verify a destination with a private certificate. Omit to use system trust roots."},
			"enabled":             schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"transparent_routing": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), Description: "Automatically route matching managed-device traffic through Forge."},
			"management_mode":     schema.StringAttribute{Computed: true, Description: "Where this Resource is managed."},
			"manager_id":          schema.StringAttribute{Computed: true, Description: "Terraform manager that owns this Resource."},
			"manager_instance":    schema.StringAttribute{Computed: true, Description: "Terraform workspace that owns this Resource."},
		},
	}
}

func (r *resourceProxyResource) ValidateConfig(ctx context.Context, request resource.ValidateConfigRequest, response *resource.ValidateConfigResponse) {
	var model resourceProxyModel
	response.Diagnostics.Append(request.Config.Get(ctx, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	if err := validateResourceUpstreamCA(model); err != nil {
		response.Diagnostics.AddAttributeError(path.Root("upstream_ca_pem"), "Invalid upstream CA certificate", err.Error())
	}
}

func validateResourceUpstreamCA(model resourceProxyModel) error {
	if !model.Protocol.IsNull() && !model.Protocol.IsUnknown() && model.Protocol.ValueString() == "postgres" && !model.UpstreamTLS.IsNull() && !model.UpstreamTLS.IsUnknown() && !model.UpstreamTLS.ValueBool() {
		return errors.New("PostgreSQL Resources require upstream_tls = true")
	}
	if model.UpstreamCAPEM.IsNull() || model.UpstreamCAPEM.IsUnknown() {
		return nil
	}
	pem := model.UpstreamCAPEM.ValueString()
	if strings.TrimSpace(pem) != pem {
		return errors.New("remove surrounding whitespace, for example with trimspace(file(\"private-ca.pem\"))")
	}
	if !model.UpstreamTLS.IsNull() && !model.UpstreamTLS.IsUnknown() && !model.UpstreamTLS.ValueBool() && pem != "" {
		return errors.New("upstream_ca_pem can be set only when upstream_tls is true")
	}
	return nil
}

func (r *resourceProxyResource) Configure(_ context.Context, request resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if request.ProviderData != nil {
		r.client, _ = request.ProviderData.(*Client)
	}
}

func (r *resourceProxyResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var model resourceProxyModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	var result resourceProxyAPI
	if err := r.client.Do(ctx, http.MethodPost, "resources", resourceProxyPayload(model), &result); err != nil {
		response.Diagnostics.AddError("Create Forge resource", err.Error())
		return
	}
	if err := verifyResourceAuthority(r.client, result.ManagementMode, result.ManagerID, result.ManagerInstance); err != nil {
		response.Diagnostics.AddError("Forge resource authority conflict", err.Error())
		return
	}
	refreshResourceProxyModel(&model, result)
	response.Diagnostics.Append(response.State.Set(ctx, &model)...)
}

func (r *resourceProxyResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var model resourceProxyModel
	response.Diagnostics.Append(request.State.Get(ctx, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	var result resourceProxyAPI
	err := r.client.Do(ctx, http.MethodGet, "resources/"+url.PathEscape(model.ID.ValueString()), nil, &result)
	if IsNotFound(err) {
		response.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Read Forge resource", err.Error())
		return
	}
	if err := verifyResourceAuthority(r.client, result.ManagementMode, result.ManagerID, result.ManagerInstance); err != nil {
		response.Diagnostics.AddError("Forge resource authority conflict", err.Error())
		return
	}
	refreshResourceProxyModel(&model, result)
	response.Diagnostics.Append(response.State.Set(ctx, &model)...)
}

func (r *resourceProxyResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var model resourceProxyModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	var result resourceProxyAPI
	err := r.client.Do(ctx, http.MethodPut, "resources/"+url.PathEscape(model.ID.ValueString()), resourceProxyPayload(model), &result)
	if err != nil {
		response.Diagnostics.AddError("Update Forge resource", err.Error())
		return
	}
	if err := verifyResourceAuthority(r.client, result.ManagementMode, result.ManagerID, result.ManagerInstance); err != nil {
		response.Diagnostics.AddError("Forge resource authority conflict", err.Error())
		return
	}
	refreshResourceProxyModel(&model, result)
	response.Diagnostics.Append(response.State.Set(ctx, &model)...)
}

func (r *resourceProxyResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var model resourceProxyModel
	response.Diagnostics.Append(request.State.Get(ctx, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	err := r.client.Do(ctx, http.MethodDelete, "resources/"+url.PathEscape(model.ID.ValueString()), nil, nil)
	if err != nil && !IsNotFound(err) {
		response.Diagnostics.AddError("Delete Forge resource", err.Error())
	}
}

func (r *resourceProxyResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}

func resourceProxyPayload(model resourceProxyModel) map[string]any {
	return map[string]any{
		"name": model.Name.ValueString(), "protocol": model.Protocol.ValueString(),
		"upstreamHost": model.UpstreamHost.ValueString(), "upstreamPort": model.UpstreamPort.ValueInt64(),
		"upstreamTls": model.UpstreamTLS.ValueBool(), "upstreamCaPem": model.UpstreamCAPEM.ValueString(), "enabled": model.Enabled.ValueBool(), "transparentRouting": model.TransparentRouting.ValueBool(),
	}
}

func refreshResourceProxyModel(model *resourceProxyModel, result resourceProxyAPI) {
	model.ID = types.StringValue(result.ID)
	model.Name = types.StringValue(result.Name)
	model.Protocol = types.StringValue(result.Protocol)
	model.UpstreamHost = types.StringValue(result.UpstreamHost)
	model.UpstreamPort = types.Int64Value(result.UpstreamPort)
	model.UpstreamTLS = types.BoolValue(result.UpstreamTLS)
	if result.UpstreamCAPEM == "" {
		model.UpstreamCAPEM = types.StringNull()
	} else {
		model.UpstreamCAPEM = types.StringValue(result.UpstreamCAPEM)
	}
	model.Enabled = types.BoolValue(result.Enabled)
	model.TransparentRouting = types.BoolValue(result.TransparentRouting)
	model.ManagementMode = types.StringValue(result.ManagementMode)
	model.ManagerID = types.StringValue(result.ManagerID)
	model.ManagerInstance = types.StringValue(result.ManagerInstance)
}

func verifyResourceAuthority(client *Client, mode, managerID, managerInstance string) error {
	if mode != "terraform" {
		return errors.New("the object is not managed by Terraform")
	}
	if managerID != client.managerID || managerInstance != client.managerInstance {
		return errors.New("the object belongs to a different Terraform manager or workspace")
	}
	return nil
}

var _ resource.ResourceWithConfigure = (*resourceProxyResource)(nil)
var _ resource.ResourceWithValidateConfig = (*resourceProxyResource)(nil)
var _ resource.ResourceWithImportState = (*resourceProxyResource)(nil)
