package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

type llmGatewayManagedAccessOverrideResource struct{ client *Client }
type llmGatewayManagedAccessOverrideModel struct {
	HostedDefault   types.Bool   `tfsdk:"hosted_default"`
	ID              types.String `tfsdk:"id"`
	TargetKind      types.String `tfsdk:"target_kind"`
	TargetID        types.String `tfsdk:"target_id"`
	AccessProfileID types.String `tfsdk:"access_profile_id"`
}
type managedAccessOverrideAPI struct {
	HostedDefault   bool   `json:"hostedDefault"`
	TargetKind      string `json:"targetKind"`
	TargetID        string `json:"targetId"`
	AccessProfileID string `json:"accessProfileId"`
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
	p.Schema = schema.Schema{Version: 1, Attributes: map[string]schema.Attribute{
		"id":                schema.StringAttribute{Computed: true},
		"target_kind":       schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.OneOf("user", "group", "service_account")}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"target_id":         schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"hosted_default":    schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false)},
		"access_profile_id": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
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
	body := map[string]any{"hostedDefault": m.HostedDefault.ValueBool(), "accessProfileId": m.AccessProfileID.ValueString()}
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
		if o.TargetKind == m.TargetKind.ValueString() && o.TargetID == m.TargetID.ValueString() && o.AccessProfileID == m.AccessProfileID.ValueString() {
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
	if err := r.client.Do(ctx, http.MethodDelete, path+"?accessProfileId="+url.QueryEscape(m.AccessProfileID.ValueString()), nil, nil); err != nil && !IsNotFound(err) {
		p.Diagnostics.AddError("Delete Forge LLM Gateway managed access override", err.Error())
	}
}
func (r *llmGatewayManagedAccessOverrideResource) refresh(m *llmGatewayManagedAccessOverrideModel, o managedAccessOverrideAPI) {
	m.ID = types.StringValue(fmt.Sprintf("%s:%s:%s", o.TargetKind, o.TargetID, o.AccessProfileID))
	m.TargetKind = types.StringValue(o.TargetKind)
	m.TargetID = types.StringValue(o.TargetID)
	m.AccessProfileID = types.StringValue(o.AccessProfileID)
	m.HostedDefault = types.BoolValue(o.HostedDefault)
}

var _ resource.ResourceWithConfigure = (*llmGatewayManagedAccessOverrideResource)(nil)

// UpgradeState removes obsolete budget fields from Terraform state without
// deleting or changing the remote budgets they previously configured.
func (r *llmGatewayManagedAccessOverrideResource) UpgradeState(context.Context) map[int64]resource.StateUpgrader {
	return map[int64]resource.StateUpgrader{0: {StateUpgrader: func(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
		var values map[string]json.RawMessage
		if err := json.Unmarshal(req.RawState.JSON, &values); err != nil {
			resp.Diagnostics.AddError("Upgrade access assignment state", err.Error())
			return
		}
		for _, key := range []string{"budget_window", "amount_usd", "total_token_limit", "alert_threshold_percent"} {
			delete(values, key)
		}
		raw, err := json.Marshal(values)
		if err != nil {
			resp.Diagnostics.AddError("Upgrade access assignment state", err.Error())
			return
		}
		var current resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &current)
		value, err := (&tfprotov6.RawState{JSON: raw}).Unmarshal(current.Schema.Type().TerraformType(ctx))
		if err != nil {
			resp.Diagnostics.AddError("Upgrade access assignment state", err.Error())
			return
		}
		resp.State.Raw = value
		resp.State.Schema = current.Schema
	}}}
}
