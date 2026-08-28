package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type llmGatewayManagedAccessOverrideResource struct{ client *Client }
type llmGatewayManagedAccessOverrideModel struct {
	ID              types.String  `tfsdk:"id"`
	TargetKind      types.String  `tfsdk:"target_kind"`
	TargetID        types.String  `tfsdk:"target_id"`
	AccessProfileID types.String  `tfsdk:"access_profile_id"`
	BudgetWindow    types.String  `tfsdk:"budget_window"`
	AmountUSD       types.Float64 `tfsdk:"amount_usd"`
	TotalTokenLimit types.Int64   `tfsdk:"total_token_limit"`
}
type managedAccessOverrideAPI struct {
	TargetKind      string `json:"targetKind"`
	TargetID        string `json:"targetId"`
	AccessProfileID string `json:"accessProfileId"`
	Budget          struct {
		BudgetWindow    string   `json:"budgetWindow"`
		AmountUSD       *float64 `json:"amountUsd"`
		TotalTokenLimit *int64   `json:"totalTokenLimit"`
	} `json:"budget"`
}
type managedAccessStatusAPI struct {
	Overrides []managedAccessOverrideAPI `json:"overrides"`
}

func newLLMGatewayManagedAccessOverrideResource() resource.Resource {
	return &llmGatewayManagedAccessOverrideResource{}
}
func (r *llmGatewayManagedAccessOverrideResource) Metadata(_ context.Context, q resource.MetadataRequest, p *resource.MetadataResponse) {
	p.TypeName = q.ProviderTypeName + "_llm_gateway_managed_access_override"
}
func (r *llmGatewayManagedAccessOverrideResource) Schema(_ context.Context, _ resource.SchemaRequest, p *resource.SchemaResponse) {
	p.Schema = schema.Schema{Attributes: map[string]schema.Attribute{
		"id":                schema.StringAttribute{Computed: true},
		"target_kind":       schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.OneOf("user", "group", "service_account")}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"target_id":         schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"access_profile_id": schema.StringAttribute{Required: true}, "budget_window": schema.StringAttribute{Required: true},
		"amount_usd": schema.Float64Attribute{Optional: true}, "total_token_limit": schema.Int64Attribute{Optional: true},
	}}
}
func (r *llmGatewayManagedAccessOverrideResource) Configure(_ context.Context, q resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if q.ProviderData != nil {
		r.client, _ = q.ProviderData.(*Client)
	}
}
func (r *llmGatewayManagedAccessOverrideResource) Create(ctx context.Context, q resource.CreateRequest, p *resource.CreateResponse) {
	var m llmGatewayManagedAccessOverrideModel
	p.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	r.save(ctx, &m, &p.Diagnostics)
	if !p.Diagnostics.HasError() {
		p.Diagnostics.Append(p.State.Set(ctx, &m)...)
	}
}
func (r *llmGatewayManagedAccessOverrideResource) Update(ctx context.Context, q resource.UpdateRequest, p *resource.UpdateResponse) {
	var m llmGatewayManagedAccessOverrideModel
	p.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	r.save(ctx, &m, &p.Diagnostics)
	if !p.Diagnostics.HasError() {
		p.Diagnostics.Append(p.State.Set(ctx, &m)...)
	}
}
func (r *llmGatewayManagedAccessOverrideResource) save(ctx context.Context, m *llmGatewayManagedAccessOverrideModel, d *diag.Diagnostics) {
	if d.HasError() {
		return
	}
	budget := map[string]any{"budgetWindow": m.BudgetWindow.ValueString()}
	if !m.AmountUSD.IsNull() {
		budget["amountUsd"] = m.AmountUSD.ValueFloat64()
	}
	if !m.TotalTokenLimit.IsNull() {
		budget["totalTokenLimit"] = m.TotalTokenLimit.ValueInt64()
	}
	body := map[string]any{"accessProfileId": m.AccessProfileID.ValueString(), "budget": budget}
	path := "llm-gateway/managed-developer/overrides/" + url.PathEscape(m.TargetKind.ValueString()) + "/" + url.PathEscape(m.TargetID.ValueString())
	var out managedAccessOverrideAPI
	if err := r.client.Do(ctx, http.MethodPut, path, body, &out); err != nil {
		d.AddError("Save Forge LLM Gateway managed access override", err.Error())
		return
	}
	r.refresh(m, out)
}
func (r *llmGatewayManagedAccessOverrideResource) Read(ctx context.Context, q resource.ReadRequest, p *resource.ReadResponse) {
	var m llmGatewayManagedAccessOverrideModel
	p.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if p.Diagnostics.HasError() {
		return
	}
	var out managedAccessStatusAPI
	if err := r.client.Do(ctx, http.MethodGet, "llm-gateway/managed-developer", nil, &out); err != nil {
		p.Diagnostics.AddError("Read Forge LLM Gateway managed access override", err.Error())
		return
	}
	for _, o := range out.Overrides {
		if o.TargetKind == m.TargetKind.ValueString() && o.TargetID == m.TargetID.ValueString() {
			r.refresh(&m, o)
			p.Diagnostics.Append(p.State.Set(ctx, &m)...)
			return
		}
	}
	p.State.RemoveResource(ctx)
}
func (r *llmGatewayManagedAccessOverrideResource) Delete(ctx context.Context, q resource.DeleteRequest, p *resource.DeleteResponse) {
	var m llmGatewayManagedAccessOverrideModel
	p.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if p.Diagnostics.HasError() {
		return
	}
	path := "llm-gateway/managed-developer/overrides/" + url.PathEscape(m.TargetKind.ValueString()) + "/" + url.PathEscape(m.TargetID.ValueString())
	if err := r.client.Do(ctx, http.MethodDelete, path, nil, nil); err != nil && !IsNotFound(err) {
		p.Diagnostics.AddError("Delete Forge LLM Gateway managed access override", err.Error())
	}
}
func (r *llmGatewayManagedAccessOverrideResource) refresh(m *llmGatewayManagedAccessOverrideModel, o managedAccessOverrideAPI) {
	m.ID = types.StringValue(fmt.Sprintf("%s:%s", o.TargetKind, o.TargetID))
	m.TargetKind = types.StringValue(o.TargetKind)
	m.TargetID = types.StringValue(o.TargetID)
	m.AccessProfileID = types.StringValue(o.AccessProfileID)
	m.BudgetWindow = types.StringValue(o.Budget.BudgetWindow)
	m.AmountUSD = types.Float64PointerValue(o.Budget.AmountUSD)
	m.TotalTokenLimit = types.Int64PointerValue(o.Budget.TotalTokenLimit)
}

var _ resource.ResourceWithConfigure = (*llmGatewayManagedAccessOverrideResource)(nil)
