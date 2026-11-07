package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type llmGatewayBudgetResource struct{ client *Client }
type llmGatewayBudgetModel struct {
	ID              types.String  `tfsdk:"id"`
	AccessProfileID types.String  `tfsdk:"access_profile_id"`
	TokenID         types.String  `tfsdk:"token_id"`
	SubjectKind     types.String  `tfsdk:"subject_kind"`
	SubjectID       types.String  `tfsdk:"subject_id"`
	Window          types.String  `tfsdk:"budget_window"`
	Amount          types.Float64 `tfsdk:"amount_usd"`
	Input           types.Int64   `tfsdk:"input_token_limit"`
	Output          types.Int64   `tfsdk:"output_token_limit"`
	Total           types.Int64   `tfsdk:"total_token_limit"`
	MemberDefault   types.Float64 `tfsdk:"member_limit_usd"`
	MemberLimits    types.Map     `tfsdk:"member_limits_usd"`
}
type llmGatewayBudgetAPI struct {
	ID              string                     `json:"id,omitempty"`
	AccessProfileID *string                    `json:"accessProfileId,omitempty"`
	TokenID         *string                    `json:"tokenId,omitempty"`
	SubjectKind     *string                    `json:"subjectKind,omitempty"`
	SubjectID       *string                    `json:"subjectId,omitempty"`
	Window          string                     `json:"budgetWindow"`
	Amount          *float64                   `json:"amountUsd,omitempty"`
	Input           *int64                     `json:"inputTokenLimit,omitempty"`
	Output          *int64                     `json:"outputTokenLimit,omitempty"`
	Total           *int64                     `json:"totalTokenLimit,omitempty"`
	Metadata        map[string]json.RawMessage `json:"metadata"`
	State           string                     `json:"state"`
	UpdatedAt       string                     `json:"updatedAt,omitempty"`
}

func newLLMGatewayBudgetResource() resource.Resource { return &llmGatewayBudgetResource{} }

func (r *llmGatewayBudgetResource) ImportState(ctx context.Context, q resource.ImportStateRequest, p *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), q, p)
}
func (r *llmGatewayBudgetResource) Metadata(_ context.Context, q resource.MetadataRequest, p *resource.MetadataResponse) {
	p.TypeName = q.ProviderTypeName + "_llm_gateway_budget"
}
func (r *llmGatewayBudgetResource) Schema(_ context.Context, _ resource.SchemaRequest, p *resource.SchemaResponse) {
	target := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Optional: true, Description: description, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}}
	}
	p.Schema = schema.Schema{Description: "Independent cumulative gateway budget. Temporary allowances are preserved; deletion disables the cap without deleting usage.", Attributes: map[string]schema.Attribute{
		"id":                schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		"access_profile_id": target("Optional profile filter; omission covers all profiles."),
		"token_id":          target("Optional gateway key ID."), "subject_kind": target("user, group, or service_account."), "subject_id": target("Directory subject ID."),
		"budget_window": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}, Description: "daily, weekly, monthly, rolling_24h, rolling_7d, or rolling_30d."},
		"amount_usd":    schema.Float64Attribute{Optional: true}, "input_token_limit": schema.Int64Attribute{Optional: true}, "output_token_limit": schema.Int64Attribute{Optional: true}, "total_token_limit": schema.Int64Attribute{Optional: true},
		"member_limit_usd":  schema.Float64Attribute{Optional: true, Description: "Per-user default for a group USD budget."},
		"member_limits_usd": schema.MapAttribute{Optional: true, ElementType: types.Float64Type, Description: "User IDs mapped to replacement per-member USD limits."},
	}}
}
func (r *llmGatewayBudgetResource) Configure(_ context.Context, q resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if q.ProviderData != nil {
		r.client, _ = q.ProviderData.(*Client)
	}
}
func (r *llmGatewayBudgetResource) Create(ctx context.Context, q resource.CreateRequest, p *resource.CreateResponse) {
	var m llmGatewayBudgetModel
	p.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	r.save(ctx, &m, &p.Diagnostics)
	if !p.Diagnostics.HasError() {
		p.Diagnostics.Append(p.State.Set(ctx, &m)...)
	}
}
func (r *llmGatewayBudgetResource) Update(ctx context.Context, q resource.UpdateRequest, p *resource.UpdateResponse) {
	var m llmGatewayBudgetModel
	p.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	r.save(ctx, &m, &p.Diagnostics)
	if !p.Diagnostics.HasError() {
		p.Diagnostics.Append(p.State.Set(ctx, &m)...)
	}
}
func (r *llmGatewayBudgetResource) lookup(ctx context.Context, id string) (*llmGatewayBudgetAPI, error) {
	var out struct {
		Budgets []llmGatewayBudgetAPI `json:"budgets"`
	}
	if err := r.client.Do(ctx, http.MethodGet, "llm-gateway/budgets", nil, &out); err != nil {
		return nil, err
	}
	for _, b := range out.Budgets {
		if b.ID == id {
			return &b, nil
		}
	}
	return nil, nil
}
func (r *llmGatewayBudgetResource) save(ctx context.Context, m *llmGatewayBudgetModel, d *diag.Diagnostics) {
	if d.HasError() {
		return
	}
	body := llmGatewayBudgetAPI{AccessProfileID: budgetString(m.AccessProfileID), TokenID: budgetString(m.TokenID), SubjectKind: budgetString(m.SubjectKind), SubjectID: budgetString(m.SubjectID), Window: m.Window.ValueString(), Amount: budgetFloat(m.Amount), Input: budgetInt(m.Input), Output: budgetInt(m.Output), Total: budgetInt(m.Total), State: "active", Metadata: map[string]json.RawMessage{}}
	path, method := "llm-gateway/budgets", http.MethodPost
	if !m.ID.IsNull() && !m.ID.IsUnknown() && m.ID.ValueString() != "" {
		existing, err := r.lookup(ctx, m.ID.ValueString())
		if err != nil || existing == nil {
			d.AddError("Read Forge budget before update", fmt.Sprintf("Budget no longer exists or could not be read: %v", err))
			return
		}
		body.UpdatedAt = existing.UpdatedAt
		body.Metadata = existing.Metadata
		path += "/" + url.PathEscape(m.ID.ValueString())
		method = http.MethodPut
	}
	if body.Metadata == nil {
		body.Metadata = map[string]json.RawMessage{}
	}
	delete(body.Metadata, "memberLimitUsd")
	delete(body.Metadata, "memberLimitsUsd")
	if !m.MemberDefault.IsNull() && !m.MemberDefault.IsUnknown() {
		body.Metadata["memberLimitUsd"], _ = json.Marshal(m.MemberDefault.ValueFloat64())
	}
	if !m.MemberLimits.IsNull() && !m.MemberLimits.IsUnknown() {
		var limits map[string]float64
		d.Append(m.MemberLimits.ElementsAs(ctx, &limits, false)...)
		if d.HasError() {
			return
		}
		body.Metadata["memberLimitsUsd"], _ = json.Marshal(limits)
	}
	var out struct {
		Budget llmGatewayBudgetAPI `json:"budget"`
	}
	if err := r.client.Do(ctx, method, path, body, &out); err != nil {
		d.AddError("Save Forge budget", err.Error())
		return
	}
	m.ID = types.StringValue(out.Budget.ID)
}
func (r *llmGatewayBudgetResource) Read(ctx context.Context, q resource.ReadRequest, p *resource.ReadResponse) {
	var m llmGatewayBudgetModel
	p.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if p.Diagnostics.HasError() {
		return
	}
	b, err := r.lookup(ctx, m.ID.ValueString())
	if err != nil {
		p.Diagnostics.AddError("Read Forge budget", err.Error())
		return
	}
	if b == nil || b.State == "disabled" {
		p.State.RemoveResource(ctx)
		return
	}
	m.AccessProfileID = types.StringPointerValue(b.AccessProfileID)
	m.TokenID = types.StringPointerValue(b.TokenID)
	m.SubjectKind = types.StringPointerValue(b.SubjectKind)
	m.SubjectID = types.StringPointerValue(b.SubjectID)
	m.Window = types.StringValue(b.Window)
	m.Amount = types.Float64PointerValue(b.Amount)
	m.Input = types.Int64PointerValue(b.Input)
	m.Output = types.Int64PointerValue(b.Output)
	m.Total = types.Int64PointerValue(b.Total)
	m.MemberDefault = types.Float64Null()
	m.MemberLimits = types.MapNull(types.Float64Type)
	if raw := b.Metadata["memberLimitUsd"]; len(raw) > 0 {
		var n float64
		if err := json.Unmarshal(raw, &n); err != nil {
			p.Diagnostics.AddError("Read member default", err.Error())
			return
		}
		m.MemberDefault = types.Float64Value(n)
	}
	if raw := b.Metadata["memberLimitsUsd"]; len(raw) > 0 {
		var limits map[string]float64
		if err := json.Unmarshal(raw, &limits); err != nil {
			p.Diagnostics.AddError("Read member exceptions", err.Error())
			return
		}
		var d diag.Diagnostics
		m.MemberLimits, d = types.MapValueFrom(ctx, types.Float64Type, limits)
		p.Diagnostics.Append(d...)
	}
	p.Diagnostics.Append(p.State.Set(ctx, &m)...)
}
func (r *llmGatewayBudgetResource) Delete(ctx context.Context, q resource.DeleteRequest, p *resource.DeleteResponse) {
	var m llmGatewayBudgetModel
	p.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if p.Diagnostics.HasError() {
		return
	}
	b, err := r.lookup(ctx, m.ID.ValueString())
	if err != nil {
		p.Diagnostics.AddError("Read Forge budget", err.Error())
		return
	}
	if b == nil {
		return
	}
	budgetID := b.ID
	b.ID = ""
	b.State = "disabled"
	var out any
	if err := r.client.Do(ctx, http.MethodPut, "llm-gateway/budgets/"+url.PathEscape(budgetID), b, &out); err != nil {
		p.Diagnostics.AddError("Disable Forge budget", err.Error())
	}
}
func budgetString(v types.String) *string {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	s := v.ValueString()
	return &s
}
func budgetFloat(v types.Float64) *float64 {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	s := v.ValueFloat64()
	return &s
}
func budgetInt(v types.Int64) *int64 {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	s := v.ValueInt64()
	return &s
}

var _ resource.ResourceWithConfigure = (*llmGatewayBudgetResource)(nil)
