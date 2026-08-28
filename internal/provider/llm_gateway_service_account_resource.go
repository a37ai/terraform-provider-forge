package provider

import (
	"context"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type llmGatewayServiceAccountResource struct{ client *Client }
type llmGatewayServiceAccountModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	OwnerKind   types.String `tfsdk:"owner_kind"`
	OwnerID     types.String `tfsdk:"owner_id"`
	Environment types.String `tfsdk:"environment"`
	State       types.String `tfsdk:"state"`
}
type llmGatewayServiceAccountResponse struct {
	ServiceAccount llmGatewayServiceAccountAPI `json:"serviceAccount"`
}

func newLLMGatewayServiceAccountResource() resource.Resource {
	return &llmGatewayServiceAccountResource{}
}
func (r *llmGatewayServiceAccountResource) Metadata(_ context.Context, q resource.MetadataRequest, p *resource.MetadataResponse) {
	p.TypeName = q.ProviderTypeName + "_llm_gateway_service_account"
}
func (r *llmGatewayServiceAccountResource) Schema(_ context.Context, _ resource.SchemaRequest, p *resource.SchemaResponse) {
	p.Schema = schema.Schema{Attributes: map[string]schema.Attribute{
		"id":   schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		"name": schema.StringAttribute{Required: true}, "description": schema.StringAttribute{Optional: true},
		"owner_kind": schema.StringAttribute{Required: true}, "owner_id": schema.StringAttribute{Required: true},
		"environment": schema.StringAttribute{Optional: true, Computed: true}, "state": schema.StringAttribute{Computed: true},
	}}
}
func (r *llmGatewayServiceAccountResource) Configure(_ context.Context, q resource.ConfigureRequest, p *resource.ConfigureResponse) {
	if q.ProviderData != nil {
		r.client, _ = q.ProviderData.(*Client)
	}
}
func (r *llmGatewayServiceAccountResource) Create(ctx context.Context, q resource.CreateRequest, p *resource.CreateResponse) {
	var m llmGatewayServiceAccountModel
	p.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	r.save(ctx, &m, &p.Diagnostics)
	if !p.Diagnostics.HasError() {
		p.Diagnostics.Append(p.State.Set(ctx, &m)...)
	}
}
func (r *llmGatewayServiceAccountResource) Update(ctx context.Context, q resource.UpdateRequest, p *resource.UpdateResponse) {
	var m llmGatewayServiceAccountModel
	p.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	r.save(ctx, &m, &p.Diagnostics)
	if !p.Diagnostics.HasError() {
		p.Diagnostics.Append(p.State.Set(ctx, &m)...)
	}
}
func (r *llmGatewayServiceAccountResource) save(ctx context.Context, m *llmGatewayServiceAccountModel, d *diag.Diagnostics) {
	if d.HasError() {
		return
	}
	body := map[string]any{"name": m.Name.ValueString(), "description": m.Description.ValueString(), "ownerKind": m.OwnerKind.ValueString(), "ownerId": m.OwnerID.ValueString(), "environment": m.Environment.ValueString()}
	if !m.ID.IsNull() && !m.ID.IsUnknown() {
		body["id"] = m.ID.ValueString()
	}
	var out llmGatewayServiceAccountResponse
	if err := r.client.Do(ctx, http.MethodPost, "llm-gateway/service-accounts", body, &out); err != nil {
		d.AddError("Save Forge LLM Gateway service account", err.Error())
		return
	}
	r.refresh(m, out.ServiceAccount)
}
func (r *llmGatewayServiceAccountResource) Read(ctx context.Context, q resource.ReadRequest, p *resource.ReadResponse) {
	var m llmGatewayServiceAccountModel
	p.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if p.Diagnostics.HasError() {
		return
	}
	var summary llmGatewaySummary
	if err := r.client.Do(ctx, http.MethodGet, "llm-gateway", nil, &summary); err != nil {
		p.Diagnostics.AddError("Read Forge LLM Gateway service account", err.Error())
		return
	}
	for _, a := range summary.ServiceAccounts {
		if a.ID == m.ID.ValueString() && a.State == "active" {
			r.refresh(&m, a)
			p.Diagnostics.Append(p.State.Set(ctx, &m)...)
			return
		}
	}
	p.State.RemoveResource(ctx)
}
func (r *llmGatewayServiceAccountResource) Delete(ctx context.Context, q resource.DeleteRequest, p *resource.DeleteResponse) {
	var m llmGatewayServiceAccountModel
	p.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if p.Diagnostics.HasError() {
		return
	}
	err := r.client.Do(ctx, http.MethodPost, "llm-gateway/service-accounts/"+url.PathEscape(m.ID.ValueString())+"/disable", map[string]any{}, nil)
	if err != nil && !IsNotFound(err) {
		p.Diagnostics.AddError("Delete Forge LLM Gateway service account", err.Error())
	}
}
func (r *llmGatewayServiceAccountResource) refresh(m *llmGatewayServiceAccountModel, a llmGatewayServiceAccountAPI) {
	description := optionalString(a.Description)
	if a.Description == "" && m.Description.IsNull() {
		description = types.StringNull()
	}
	m.ID = types.StringValue(a.ID)
	m.Name = types.StringValue(a.Name)
	m.Description = description
	m.OwnerKind = types.StringValue(a.OwnerKind)
	m.OwnerID = types.StringValue(a.OwnerID)
	m.Environment = types.StringValue(a.Environment)
	m.State = types.StringValue(a.State)
}

var _ resource.ResourceWithConfigure = (*llmGatewayServiceAccountResource)(nil)
