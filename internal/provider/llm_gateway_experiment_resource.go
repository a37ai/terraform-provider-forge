package provider

import (
	"context"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type llmGatewayExperimentResource struct{ client *Client }
type llmGatewayExperimentModel struct {
	ID               types.String  `tfsdk:"id"`
	AccessProfileID  types.String  `tfsdk:"access_profile_id"`
	CandidateRouteID types.String  `tfsdk:"candidate_route_id"`
	JudgeRouteID     types.String  `tfsdk:"judge_route_id"`
	Name             types.String  `tfsdk:"name"`
	Mode             types.String  `tfsdk:"mode"`
	SamplePercent    types.Int64   `tfsdk:"sample_percent"`
	SpendCapUSD      types.Float64 `tfsdk:"spend_cap_usd"`
	EndAt            types.String  `tfsdk:"end_at"`
	State            types.String  `tfsdk:"state"`
}
type llmGatewayExperimentAPI struct {
	ID               string    `json:"id"`
	AccessProfileID  string    `json:"accessProfileId"`
	CandidateRouteID string    `json:"candidateRouteId"`
	JudgeRouteID     *string   `json:"judgeRouteId,omitempty"`
	Name             string    `json:"name"`
	Mode             string    `json:"mode"`
	SamplePercent    int64     `json:"samplePercent"`
	SpendCapUSD      float64   `json:"spendCapUsd"`
	EndAt            time.Time `json:"endAt"`
	State            string    `json:"state"`
}
type llmGatewayExperimentsAPI struct {
	Experiments []llmGatewayExperimentAPI `json:"experiments"`
}

func newLLMGatewayExperimentResource() resource.Resource { return &llmGatewayExperimentResource{} }
func (r *llmGatewayExperimentResource) Metadata(_ context.Context, q resource.MetadataRequest, p *resource.MetadataResponse) {
	p.TypeName = q.ProviderTypeName + "_llm_gateway_experiment"
}
func (r *llmGatewayExperimentResource) Schema(_ context.Context, _ resource.SchemaRequest, p *resource.SchemaResponse) {
	p.Schema = schema.Schema{Description: "Mirrors sampled AI Gateway requests to a candidate destination without changing the live response.", Attributes: map[string]schema.Attribute{
		"id":                 schema.StringAttribute{Computed: true},
		"access_profile_id":  schema.StringAttribute{Required: true},
		"candidate_route_id": schema.StringAttribute{Required: true},
		"judge_route_id":     schema.StringAttribute{Optional: true, Description: "Required for compare mode"},
		"name":               schema.StringAttribute{Required: true},
		"mode":               schema.StringAttribute{Required: true, Description: "mirror or compare"},
		"sample_percent":     schema.Int64Attribute{Required: true},
		"spend_cap_usd":      schema.Float64Attribute{Required: true},
		"end_at":             schema.StringAttribute{Required: true, Description: "RFC3339 end time"},
		"state":              schema.StringAttribute{Required: true, Description: "active, paused, or stopped"},
	}}
}
func (r *llmGatewayExperimentResource) Configure(_ context.Context, q resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if q.ProviderData != nil {
		r.client, _ = q.ProviderData.(*Client)
	}
}
func (r *llmGatewayExperimentResource) Create(ctx context.Context, q resource.CreateRequest, p *resource.CreateResponse) {
	var m llmGatewayExperimentModel
	p.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	r.save(ctx, &m, &p.Diagnostics)
	if !p.Diagnostics.HasError() {
		p.Diagnostics.Append(p.State.Set(ctx, &m)...)
	}
}
func (r *llmGatewayExperimentResource) Update(ctx context.Context, q resource.UpdateRequest, p *resource.UpdateResponse) {
	var m llmGatewayExperimentModel
	p.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	r.save(ctx, &m, &p.Diagnostics)
	if !p.Diagnostics.HasError() {
		p.Diagnostics.Append(p.State.Set(ctx, &m)...)
	}
}
func (r *llmGatewayExperimentResource) save(ctx context.Context, m *llmGatewayExperimentModel, d *diag.Diagnostics) {
	if d.HasError() {
		return
	}
	if m.Mode.ValueString() != "mirror" && m.Mode.ValueString() != "compare" {
		d.AddError("Invalid experiment mode", "Use mirror or compare.")
		return
	}
	if m.Mode.ValueString() == "compare" && (m.JudgeRouteID.IsNull() || m.JudgeRouteID.ValueString() == "") {
		d.AddError("Missing judge route", "Compare mode requires judge_route_id.")
		return
	}
	if m.SamplePercent.ValueInt64() < 1 || m.SamplePercent.ValueInt64() > 100 || m.SpendCapUSD.ValueFloat64() <= 0 {
		d.AddError("Invalid experiment limits", "sample_percent must be 1–100 and spend_cap_usd must be positive.")
		return
	}
	endAt, err := time.Parse(time.RFC3339, m.EndAt.ValueString())
	if err != nil {
		d.AddError("Invalid end_at", err.Error())
		return
	}
	var judgeRouteID *string
	if !m.JudgeRouteID.IsNull() && !m.JudgeRouteID.IsUnknown() {
		value := m.JudgeRouteID.ValueString()
		judgeRouteID = &value
	}
	body := llmGatewayExperimentAPI{ID: m.ID.ValueString(), AccessProfileID: m.AccessProfileID.ValueString(), CandidateRouteID: m.CandidateRouteID.ValueString(), JudgeRouteID: judgeRouteID, Name: m.Name.ValueString(), Mode: m.Mode.ValueString(), SamplePercent: m.SamplePercent.ValueInt64(), SpendCapUSD: m.SpendCapUSD.ValueFloat64(), EndAt: endAt, State: m.State.ValueString()}
	var out llmGatewayExperimentAPI
	if err := r.client.Do(ctx, http.MethodPost, "llm-gateway/experiments", body, &out); err != nil {
		d.AddError("Save Forge LLM Gateway experiment", err.Error())
		return
	}
	r.refresh(m, out)
}
func (r *llmGatewayExperimentResource) Read(ctx context.Context, q resource.ReadRequest, p *resource.ReadResponse) {
	var m llmGatewayExperimentModel
	p.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if p.Diagnostics.HasError() {
		return
	}
	var out llmGatewayExperimentsAPI
	if err := r.client.Do(ctx, http.MethodGet, "llm-gateway/experiments", nil, &out); err != nil {
		p.Diagnostics.AddError("Read Forge LLM Gateway experiment", err.Error())
		return
	}
	for _, item := range out.Experiments {
		if item.ID == m.ID.ValueString() {
			r.refresh(&m, item)
			p.Diagnostics.Append(p.State.Set(ctx, &m)...)
			return
		}
	}
	p.State.RemoveResource(ctx)
}
func (r *llmGatewayExperimentResource) Delete(ctx context.Context, q resource.DeleteRequest, p *resource.DeleteResponse) {
	var m llmGatewayExperimentModel
	p.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if p.Diagnostics.HasError() {
		return
	}
	m.State = types.StringValue("stopped")
	r.save(ctx, &m, &p.Diagnostics)
}
func (r *llmGatewayExperimentResource) refresh(m *llmGatewayExperimentModel, item llmGatewayExperimentAPI) {
	m.ID = types.StringValue(item.ID)
	m.AccessProfileID = types.StringValue(item.AccessProfileID)
	m.CandidateRouteID = types.StringValue(item.CandidateRouteID)
	if item.JudgeRouteID != nil {
		m.JudgeRouteID = types.StringValue(*item.JudgeRouteID)
	} else {
		m.JudgeRouteID = types.StringNull()
	}
	m.Name = types.StringValue(item.Name)
	m.Mode = types.StringValue(item.Mode)
	m.SamplePercent = types.Int64Value(item.SamplePercent)
	m.SpendCapUSD = types.Float64Value(item.SpendCapUSD)
	endAt := item.EndAt.Format(time.RFC3339)
	if original, err := time.Parse(time.RFC3339, m.EndAt.ValueString()); err == nil && original.Equal(item.EndAt) {
		endAt = m.EndAt.ValueString()
	}
	m.EndAt = types.StringValue(endAt)
	m.State = types.StringValue(item.State)
}

var _ resource.ResourceWithConfigure = (*llmGatewayExperimentResource)(nil)
