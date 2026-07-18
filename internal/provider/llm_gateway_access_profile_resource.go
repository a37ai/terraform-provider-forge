package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type llmGatewayAccessProfileResource struct{ client *Client }

type llmGatewayAccessProfileModel struct {
	ID                  types.String `tfsdk:"id"`
	Name                types.String `tfsdk:"name"`
	Description         types.String `tfsdk:"description"`
	State               types.String `tfsdk:"state"`
	EnforcementMode     types.String `tfsdk:"enforcement_mode"`
	SubjectBindingsJSON types.String `tfsdk:"subject_bindings_json"`
	ModelSelectorsJSON  types.String `tfsdk:"model_selectors_json"`
	DataClasses         types.Set    `tfsdk:"data_classes"`
	PolicyHooks         types.Set    `tfsdk:"policy_hooks"`
	Routes              types.List   `tfsdk:"route"`
	Version             types.Int64  `tfsdk:"version"`
}

type llmGatewayRoutePlanModel struct {
	ID                    types.String `tfsdk:"id"`
	Provider              types.String `tfsdk:"provider"`
	Name                  types.String `tfsdk:"name"`
	RequestedModelPattern types.String `tfsdk:"requested_model_pattern"`
	UpstreamModel         types.String `tfsdk:"upstream_model"`
	APISurface            types.String `tfsdk:"api_surface"`
	Strategy              types.String `tfsdk:"strategy"`
	RoutePriority         types.Int64  `tfsdk:"route_priority"`
	Weight                types.Int64  `tfsdk:"weight"`
	RolloutState          types.String `tfsdk:"rollout_state"`
	EnforcementMode       types.String `tfsdk:"enforcement_mode"`
	PolicyHooks           types.Set    `tfsdk:"policy_hooks"`
	ToolDenyBehavior      types.String `tfsdk:"tool_deny_behavior"`
	ConfigJSON            types.String `tfsdk:"config_json"`
}

type llmGatewaySummary struct {
	Providers      []llmGatewayProviderAPI      `json:"providers"`
	AccessProfiles []llmGatewayAccessProfileAPI `json:"accessProfiles"`
	Routes         []llmGatewayRouteAPI         `json:"routes"`
}
type llmGatewayProviderAPI struct {
	ID   string `json:"id"`
	Name string `json:"displayName"`
}
type llmGatewayRoutePlanResponse struct {
	AccessProfile llmGatewayAccessProfileAPI `json:"accessProfile"`
	Routes        []llmGatewayRouteAPI       `json:"routes"`
}
type llmGatewayAccessProfileAPI struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	State           string          `json:"state"`
	EnforcementMode string          `json:"enforcementMode"`
	SubjectBindings json.RawMessage `json:"subjectBindings"`
	ModelSelectors  json.RawMessage `json:"modelSelectors"`
	DataClasses     []string        `json:"dataClasses"`
	PolicyHooks     []string        `json:"policyHooks"`
	Version         int64           `json:"version"`
}
type llmGatewayRouteAPI struct {
	ID                    string          `json:"id"`
	AccessProfileID       string          `json:"accessProfileId"`
	ProviderID            string          `json:"providerId"`
	Name                  string          `json:"name"`
	RequestedModelPattern string          `json:"requestedModelPattern"`
	UpstreamModel         string          `json:"upstreamModel"`
	APISurface            string          `json:"apiSurface"`
	Strategy              string          `json:"strategy"`
	RolloutState          string          `json:"rolloutState"`
	EnforcementMode       string          `json:"enforcementMode"`
	ToolDenyBehavior      string          `json:"toolDenyBehavior"`
	RoutePriority         int64           `json:"routePriority"`
	Weight                int64           `json:"weight"`
	PolicyHooks           []string        `json:"policyHooks"`
	Config                json.RawMessage `json:"config"`
}

func newLLMGatewayAccessProfileResource() resource.Resource {
	return &llmGatewayAccessProfileResource{}
}
func (r *llmGatewayAccessProfileResource) Metadata(_ context.Context, q resource.MetadataRequest, p *resource.MetadataResponse) {
	p.TypeName = q.ProviderTypeName + "_llm_gateway_access_profile"
}
func (r *llmGatewayAccessProfileResource) Schema(_ context.Context, _ resource.SchemaRequest, p *resource.SchemaResponse) {
	hooks := func(description string) schema.SetAttribute {
		return schema.SetAttribute{Optional: true, Description: description, ElementType: types.StringType, Validators: []validator.Set{setvalidator.ValueStringsAre(stringvalidator.OneOf("prompt", "pre_tool_use", "post_tool_use", "response"))}}
	}
	p.Schema = schema.Schema{Description: "A Forge LLM Gateway access profile and its atomic provider route plan. This is the same durable object used by the staging gateway runtime and console.", Attributes: map[string]schema.Attribute{
		"id":   schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"name": schema.StringAttribute{Required: true}, "description": schema.StringAttribute{Optional: true},
		"state":                 schema.StringAttribute{Optional: true, Computed: true, Description: "Lifecycle state: draft, active, disabled, or archived.", Validators: []validator.String{stringvalidator.OneOf("draft", "active", "disabled", "archived")}},
		"enforcement_mode":      schema.StringAttribute{Optional: true, Computed: true, Description: "Policy behavior: monitor records decisions, simulate returns simulated outcomes, enforce changes traffic, and break_glass bypasses enforcement while retaining audit evidence.", Validators: []validator.String{stringvalidator.OneOf("monitor", "simulate", "enforce", "break_glass")}},
		"subject_bindings_json": schema.StringAttribute{Optional: true, Description: "JSON array using the gateway runtime's native subject binding schema."},
		"model_selectors_json":  schema.StringAttribute{Optional: true, Description: "JSON object using the gateway runtime's native model selector schema."},
		"data_classes":          schema.SetAttribute{Optional: true, Computed: true, ElementType: types.StringType, Validators: []validator.Set{setvalidator.SizeAtMost(256)}},
		"policy_hooks":          hooks("Gateway stages evaluated for this profile: prompt, pre_tool_use, post_tool_use, and response."), "version": schema.Int64Attribute{Computed: true},
	}, Blocks: map[string]schema.Block{
		"route": schema.ListNestedBlock{Validators: []validator.List{listvalidator.SizeAtLeast(1)}, NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Optional: true, Computed: true}, "provider": schema.StringAttribute{Required: true, Description: "Exact provider name configured in Forge. Forge resolves the name to its canonical internal ID and rejects missing or ambiguous matches."}, "name": schema.StringAttribute{Required: true},
			"requested_model_pattern": schema.StringAttribute{Required: true}, "upstream_model": schema.StringAttribute{Optional: true},
			"api_surface": schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.OneOf(
				"openai_chat_completions", "openai_responses", "anthropic_messages", "openai_completions",
				"openai_embeddings", "openai_images", "openai_audio", "openai_models", "openai_files",
				"openai_batches", "openai_fine_tuning", "openai_moderations", "openai_realtime", "rerank",
				"provider_passthrough", "bedrock_converse", "gemini_generate_content", "custom",
			)}},
			"strategy":       schema.StringAttribute{Optional: true, Computed: true, Description: "Route selection strategy: fixed, fallback, weighted, policy, cost, latency, or quality.", Validators: []validator.String{stringvalidator.OneOf("fixed", "fallback", "weighted", "policy", "cost", "latency", "quality")}},
			"route_priority": schema.Int64Attribute{Optional: true, Computed: true}, "weight": schema.Int64Attribute{Optional: true, Computed: true},
			"rollout_state":    schema.StringAttribute{Optional: true, Computed: true, Description: "Route rollout state: draft, monitor, simulate, enforce, paused, or archived.", Validators: []validator.String{stringvalidator.OneOf("draft", "monitor", "simulate", "enforce", "paused", "archived")}},
			"enforcement_mode": schema.StringAttribute{Optional: true, Computed: true, Description: "Route policy behavior: monitor, simulate, enforce, or break_glass.", Validators: []validator.String{stringvalidator.OneOf("monitor", "simulate", "enforce", "break_glass")}},
			"policy_hooks":     hooks("Gateway stages evaluated on this route: prompt, pre_tool_use, post_tool_use, and response."), "tool_deny_behavior": schema.StringAttribute{Optional: true, Computed: true, Description: "Denied tool behavior: hard_block rejects the request; rewrite_refusal returns a refusal-shaped result.", Validators: []validator.String{stringvalidator.OneOf("hard_block", "rewrite_refusal")}},
			"config_json": schema.StringAttribute{Optional: true, Description: "JSON object passed to the native gateway route config."},
		}}},
	}}
}
func (r *llmGatewayAccessProfileResource) Configure(_ context.Context, q resource.ConfigureRequest, p *resource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	client, ok := q.ProviderData.(*Client)
	if !ok {
		p.Diagnostics.AddError("Unexpected provider data", "Forge client not configured")
		return
	}
	r.client = client
}
func (r *llmGatewayAccessProfileResource) Create(ctx context.Context, q resource.CreateRequest, p *resource.CreateResponse) {
	r.apply(ctx, q.Plan, &p.Diagnostics, func(model llmGatewayAccessProfileModel) { p.Diagnostics.Append(p.State.Set(ctx, &model)...) })
}
func (r *llmGatewayAccessProfileResource) Update(ctx context.Context, q resource.UpdateRequest, p *resource.UpdateResponse) {
	r.apply(ctx, q.Plan, &p.Diagnostics, func(model llmGatewayAccessProfileModel) { p.Diagnostics.Append(p.State.Set(ctx, &model)...) })
}
func (r *llmGatewayAccessProfileResource) apply(ctx context.Context, plan interface {
	Get(context.Context, any) diag.Diagnostics
}, diagnostics *diag.Diagnostics, save func(llmGatewayAccessProfileModel)) {
	var model llmGatewayAccessProfileModel
	diagnostics.Append(plan.Get(ctx, &model)...)
	if diagnostics.HasError() {
		return
	}
	body := r.payload(ctx, model, diagnostics)
	if diagnostics.HasError() {
		return
	}
	var response llmGatewayRoutePlanResponse
	if err := r.client.Do(ctx, http.MethodPost, "llm-gateway/access-profiles/save", body, &response); err != nil {
		diagnostics.AddError("Save Forge LLM Gateway access profile", err.Error())
		return
	}
	var summary llmGatewaySummary
	if err := r.client.Do(ctx, http.MethodGet, "llm-gateway", nil, &summary); err != nil {
		diagnostics.AddError("Refresh Forge LLM Gateway provider references", err.Error())
		return
	}
	r.refreshModel(ctx, &model, response.AccessProfile, response.Routes, summary.Providers, diagnostics)
	if !diagnostics.HasError() {
		save(model)
	}
}
func (r *llmGatewayAccessProfileResource) payload(ctx context.Context, model llmGatewayAccessProfileModel, diagnostics *diag.Diagnostics) map[string]any {
	selectors := map[string]any{}
	if !model.ModelSelectorsJSON.IsNull() && strings.TrimSpace(model.ModelSelectorsJSON.ValueString()) != "" {
		if err := json.Unmarshal([]byte(model.ModelSelectorsJSON.ValueString()), &selectors); err != nil {
			diagnostics.AddError("Invalid model_selectors_json", err.Error())
		}
	}
	bindings := []any{}
	if !model.SubjectBindingsJSON.IsNull() && strings.TrimSpace(model.SubjectBindingsJSON.ValueString()) != "" {
		if err := json.Unmarshal([]byte(model.SubjectBindingsJSON.ValueString()), &bindings); err != nil {
			diagnostics.AddError("Invalid subject_bindings_json", err.Error())
		}
	}
	var dataClasses, hooks []string
	if !model.DataClasses.IsNull() && !model.DataClasses.IsUnknown() {
		diagnostics.Append(model.DataClasses.ElementsAs(ctx, &dataClasses, false)...)
	}
	if !model.PolicyHooks.IsNull() && !model.PolicyHooks.IsUnknown() {
		diagnostics.Append(model.PolicyHooks.ElementsAs(ctx, &hooks, false)...)
	}
	var routeModels []llmGatewayRoutePlanModel
	diagnostics.Append(model.Routes.ElementsAs(ctx, &routeModels, false)...)
	routes := make([]map[string]any, 0, len(routeModels))
	for i, route := range routeModels {
		config := map[string]any{}
		if !route.ConfigJSON.IsNull() && strings.TrimSpace(route.ConfigJSON.ValueString()) != "" {
			if err := json.Unmarshal([]byte(route.ConfigJSON.ValueString()), &config); err != nil {
				diagnostics.AddError(fmt.Sprintf("Invalid route[%d].config_json", i), err.Error())
				continue
			}
		}
		var routeHooks []string
		if !route.PolicyHooks.IsNull() && !route.PolicyHooks.IsUnknown() {
			diagnostics.Append(route.PolicyHooks.ElementsAs(ctx, &routeHooks, false)...)
		}
		item := map[string]any{"providerName": route.Provider.ValueString(), "name": route.Name.ValueString(), "requestedModelPattern": route.RequestedModelPattern.ValueString(), "apiSurface": route.APISurface.ValueString(), "config": config}
		for key, value := range map[string]types.String{"id": route.ID, "upstreamModel": route.UpstreamModel, "strategy": route.Strategy, "rolloutState": route.RolloutState, "enforcementMode": route.EnforcementMode, "toolDenyBehavior": route.ToolDenyBehavior} {
			if !value.IsNull() && !value.IsUnknown() && value.ValueString() != "" {
				item[key] = value.ValueString()
			}
		}
		if !route.RoutePriority.IsNull() && !route.RoutePriority.IsUnknown() {
			item["routePriority"] = route.RoutePriority.ValueInt64()
		}
		if !route.Weight.IsNull() && !route.Weight.IsUnknown() {
			item["weight"] = route.Weight.ValueInt64()
		}
		if len(routeHooks) > 0 {
			item["policyHooks"] = routeHooks
		}
		routes = append(routes, item)
	}
	profile := map[string]any{"id": model.ID.ValueString(), "name": model.Name.ValueString(), "subjectBindings": bindings, "modelSelectors": selectors, "dataClasses": dataClasses, "policyHooks": hooks}
	for key, value := range map[string]types.String{"description": model.Description, "state": model.State, "enforcementMode": model.EnforcementMode} {
		if !value.IsNull() && !value.IsUnknown() && value.ValueString() != "" {
			profile[key] = value.ValueString()
		}
	}
	return map[string]any{"profile": profile, "routes": routes}
}
func (r *llmGatewayAccessProfileResource) Read(ctx context.Context, q resource.ReadRequest, p *resource.ReadResponse) {
	var model llmGatewayAccessProfileModel
	p.Diagnostics.Append(q.State.Get(ctx, &model)...)
	if p.Diagnostics.HasError() {
		return
	}
	var summary llmGatewaySummary
	if err := r.client.Do(ctx, http.MethodGet, "llm-gateway", nil, &summary); err != nil {
		p.Diagnostics.AddError("Read Forge LLM Gateway access profile", err.Error())
		return
	}
	for _, profile := range summary.AccessProfiles {
		if profile.ID != model.ID.ValueString() {
			continue
		}
		routes := make([]llmGatewayRouteAPI, 0)
		for _, route := range summary.Routes {
			if route.AccessProfileID == profile.ID {
				routes = append(routes, route)
			}
		}
		r.refreshModel(ctx, &model, profile, routes, summary.Providers, &p.Diagnostics)
		if !p.Diagnostics.HasError() {
			p.Diagnostics.Append(p.State.Set(ctx, &model)...)
		}
		return
	}
	p.State.RemoveResource(ctx)
}
func (r *llmGatewayAccessProfileResource) refreshModel(ctx context.Context, model *llmGatewayAccessProfileModel, profile llmGatewayAccessProfileAPI, routes []llmGatewayRouteAPI, providers []llmGatewayProviderAPI, diagnostics *diag.Diagnostics) {
	model.ID, model.Name = types.StringValue(profile.ID), types.StringValue(profile.Name)
	model.Description, model.State, model.EnforcementMode = optionalString(profile.Description), types.StringValue(profile.State), types.StringValue(profile.EnforcementMode)
	bindings := strings.TrimSpace(string(profile.SubjectBindings))
	if bindings == "" || bindings == "null" || (bindings == "[]" && (model.SubjectBindingsJSON.IsNull() || model.SubjectBindingsJSON.IsUnknown())) {
		if model.SubjectBindingsJSON.IsNull() || model.SubjectBindingsJSON.IsUnknown() {
			model.SubjectBindingsJSON = types.StringNull()
		} else {
			model.SubjectBindingsJSON = types.StringValue("[]")
		}
	} else {
		model.SubjectBindingsJSON = types.StringValue(bindings)
	}
	selectors := strings.TrimSpace(string(profile.ModelSelectors))
	if selectors == "" || selectors == "null" {
		if model.ModelSelectorsJSON.IsNull() || model.ModelSelectorsJSON.IsUnknown() {
			model.ModelSelectorsJSON = types.StringNull()
		} else {
			model.ModelSelectorsJSON = types.StringValue("{}")
		}
	} else {
		model.ModelSelectorsJSON = types.StringValue(selectors)
	}
	model.Version = types.Int64Value(profile.Version)
	model.DataClasses, model.PolicyHooks = setStringState(ctx, profile.DataClasses, diagnostics), setStringState(ctx, profile.PolicyHooks, diagnostics)
	var priorRoutes []llmGatewayRoutePlanModel
	if !model.Routes.IsNull() && !model.Routes.IsUnknown() {
		diagnostics.Append(model.Routes.ElementsAs(ctx, &priorRoutes, false)...)
	}
	items := make([]llmGatewayRoutePlanModel, 0, len(routes))
	for _, route := range routes {
		providerName := ""
		for _, provider := range providers {
			if provider.ID == route.ProviderID {
				providerName = provider.Name
				break
			}
		}
		if providerName == "" {
			diagnostics.AddError("Resolve Forge LLM Gateway provider", fmt.Sprintf("provider ID %q is unavailable in the organization summary", route.ProviderID))
			continue
		}
		config := strings.TrimSpace(string(route.Config))
		configState := types.StringValue(config)
		if config == "" || config == "null" || config == "{}" {
			configState = types.StringValue("{}")
			for _, prior := range priorRoutes {
				if prior.Provider.ValueString() == providerName && prior.APISurface.ValueString() == route.APISurface && (prior.ConfigJSON.IsNull() || prior.ConfigJSON.IsUnknown()) {
					configState = types.StringNull()
					break
				}
			}
		}
		items = append(items, llmGatewayRoutePlanModel{ID: optionalString(route.ID), Provider: types.StringValue(providerName), Name: types.StringValue(route.Name), RequestedModelPattern: types.StringValue(route.RequestedModelPattern), UpstreamModel: optionalString(route.UpstreamModel), APISurface: types.StringValue(route.APISurface), Strategy: types.StringValue(route.Strategy), RoutePriority: types.Int64Value(route.RoutePriority), Weight: types.Int64Value(route.Weight), RolloutState: types.StringValue(route.RolloutState), EnforcementMode: types.StringValue(route.EnforcementMode), PolicyHooks: setStringState(ctx, route.PolicyHooks, diagnostics), ToolDenyBehavior: types.StringValue(route.ToolDenyBehavior), ConfigJSON: configState})
	}
	value, ds := types.ListValueFrom(ctx, routeObjectType(), items)
	diagnostics.Append(ds...)
	model.Routes = value
}
func routeObjectType() types.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{"id": types.StringType, "provider": types.StringType, "name": types.StringType, "requested_model_pattern": types.StringType, "upstream_model": types.StringType, "api_surface": types.StringType, "strategy": types.StringType, "route_priority": types.Int64Type, "weight": types.Int64Type, "rollout_state": types.StringType, "enforcement_mode": types.StringType, "policy_hooks": types.SetType{ElemType: types.StringType}, "tool_deny_behavior": types.StringType, "config_json": types.StringType}}
}
func (r *llmGatewayAccessProfileResource) Delete(ctx context.Context, q resource.DeleteRequest, p *resource.DeleteResponse) {
	var model llmGatewayAccessProfileModel
	p.Diagnostics.Append(q.State.Get(ctx, &model)...)
	if p.Diagnostics.HasError() {
		return
	}
	if err := r.client.Do(ctx, http.MethodDelete, "llm-gateway/access-profiles/"+url.PathEscape(model.ID.ValueString()), nil, nil); err != nil && !IsNotFound(err) {
		p.Diagnostics.AddError("Delete Forge LLM Gateway access profile", err.Error())
	}
}
func (r *llmGatewayAccessProfileResource) ImportState(ctx context.Context, q resource.ImportStateRequest, p *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), q, p)
}

var _ resource.ResourceWithConfigure = (*llmGatewayAccessProfileResource)(nil)
var _ resource.ResourceWithImportState = (*llmGatewayAccessProfileResource)(nil)
