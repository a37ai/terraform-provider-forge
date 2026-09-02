package provider

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type mcpACLResource struct{ client *Client }
type mcpACLModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Enabled           types.Bool   `tfsdk:"enabled"`
	Server            types.String `tfsdk:"server"`
	Tools             types.Set    `tfsdk:"tools"`
	Users             types.Set    `tfsdk:"users"`
	UserDirectoryIDs  types.Map    `tfsdk:"user_directory_ids"`
	Groups            types.Set    `tfsdk:"groups"`
	GroupDirectoryIDs types.Map    `tfsdk:"group_directory_ids"`
	Effect            types.String `tfsdk:"effect"`
	CurrentRevision   types.Int64  `tfsdk:"current_revision"`
	DefinitionSHA     types.String `tfsdk:"definition_sha256"`
	ValidationToken   types.String `tfsdk:"validation_token"`
}

func newMCPACLResource() resource.Resource { return &mcpACLResource{} }
func (r *mcpACLResource) Metadata(_ context.Context, q resource.MetadataRequest, p *resource.MetadataResponse) {
	p.TypeName = q.ProviderTypeName + "_mcp_acl"
}
func (r *mcpACLResource) Schema(_ context.Context, _ resource.SchemaRequest, p *resource.SchemaResponse) {
	set := func(required bool) schema.SetAttribute {
		return schema.SetAttribute{Required: required, Optional: !required, ElementType: types.StringType, Validators: []validator.Set{setvalidator.SizeBetween(1, 256)}}
	}
	p.Schema = schema.Schema{Description: "An MCP server/tool ACL lowered to the canonical ContentPolicy family.", Attributes: map[string]schema.Attribute{"id": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}}, "name": schema.StringAttribute{Required: true}, "enabled": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)}, "server": schema.StringAttribute{Required: true, Description: "Exact MCP server name or slug."}, "tools": set(false), "users": optionalSubjectSetAttribute("Exact user emails."), "user_directory_ids": directoryQualifierAttribute("user"), "groups": optionalSubjectSetAttribute("Exact group names."), "group_directory_ids": directoryQualifierAttribute("group"), "effect": schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.OneOf(canonicalSkillEffects...)}}, "current_revision": schema.Int64Attribute{Computed: true}, "definition_sha256": schema.StringAttribute{Computed: true}, "validation_token": schema.StringAttribute{Computed: true, Sensitive: true}}}
}
func (r *mcpACLResource) Configure(_ context.Context, q resource.ConfigureRequest, p *resource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	c, ok := q.ProviderData.(*Client)
	if !ok {
		p.Diagnostics.AddError("Unexpected provider data", "Forge client not configured")
		return
	}
	r.client = c
}
func (r *mcpACLResource) ModifyPlan(ctx context.Context, q resource.ModifyPlanRequest, p *resource.ModifyPlanResponse) {
	if q.Plan.Raw.IsNull() || r.client == nil {
		return
	}
	var m, prior mcpACLModel
	p.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if p.Diagnostics.HasError() || (!m.ValidationToken.IsNull() && !m.ValidationToken.IsUnknown() && m.ValidationToken.ValueString() != "") {
		return
	}
	revision := m.CurrentRevision.ValueInt64()
	if !q.State.Raw.IsNull() {
		p.Diagnostics.Append(q.State.Get(ctx, &prior)...)
		if m.CurrentRevision.IsUnknown() {
			revision = prior.CurrentRevision.ValueInt64()
		}
	}
	definition, sourceRef := r.build(ctx, m, &p.Diagnostics)
	if p.Diagnostics.HasError() {
		return
	}
	if !q.State.Raw.IsNull() {
		priorDefinition, priorSourceRef := r.build(ctx, prior, &p.Diagnostics)
		if p.Diagnostics.HasError() {
			return
		}
		if !policyPlanPayloadChanged(definition, sourceRef, priorDefinition, priorSourceRef) {
			p.Diagnostics.Append(p.Plan.SetAttribute(ctx, path.Root("validation_token"), prior.ValidationToken.ValueString())...)
			p.Diagnostics.Append(p.Plan.SetAttribute(ctx, path.Root("current_revision"), prior.CurrentRevision.ValueInt64())...)
			p.Diagnostics.Append(p.Plan.SetAttribute(ctx, path.Root("definition_sha256"), prior.DefinitionSHA.ValueString())...)
			return
		}
	}
	validation, err := r.client.ValidatePolicyPlan(ctx, "content", definition, sourceRef, revision)
	if err != nil {
		p.Diagnostics.AddError("Forge MCP ACL plan validation failed", err.Error())
		return
	}
	p.Diagnostics.Append(p.Plan.SetAttribute(ctx, path.Root("validation_token"), validation.ValidationToken)...)
}
func (r *mcpACLResource) Create(ctx context.Context, q resource.CreateRequest, p *resource.CreateResponse) {
	var m mcpACLModel
	p.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if !p.Diagnostics.HasError() {
		r.apply(ctx, m, 0, &p.Diagnostics, func(v mcpACLModel) { p.Diagnostics.Append(p.State.Set(ctx, &v)...) })
	}
}
func (r *mcpACLResource) Update(ctx context.Context, q resource.UpdateRequest, p *resource.UpdateResponse) {
	var m, o mcpACLModel
	p.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	p.Diagnostics.Append(q.State.Get(ctx, &o)...)
	if !p.Diagnostics.HasError() {
		r.apply(ctx, m, o.CurrentRevision.ValueInt64(), &p.Diagnostics, func(v mcpACLModel) { p.Diagnostics.Append(p.State.Set(ctx, &v)...) })
	}
}
func (r *mcpACLResource) Read(ctx context.Context, q resource.ReadRequest, p *resource.ReadResponse) {
	var m mcpACLModel
	p.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if p.Diagnostics.HasError() {
		return
	}
	var e struct {
		Item policyAPIItem `json:"item"`
	}
	err := r.client.Do(ctx, http.MethodGet, "content-policies/"+url.PathEscape(m.ID.ValueString()), nil, &e)
	if IsNotFound(err) {
		p.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		p.Diagnostics.AddError("Read Forge MCP ACL", err.Error())
		return
	}
	if err := e.Item.verifyAuthority(r.client); err != nil {
		p.Diagnostics.AddError("Forge MCP ACL authority conflict", err.Error())
		return
	}
	definition, selectors := e.Item.Definition, selectorObject(e.Item)
	scope, scopeSelectors := object(definition["appliesTo"]), object(selectors["appliesTo"])
	m.ID, m.Name = types.StringValue(stringFrom(definition["id"])), types.StringValue(stringFrom(definition["name"]))
	m.Enabled = types.BoolValue(boolFrom(definition["enabled"]))
	m.Users, m.UserDirectoryIDs = qualifiedSelectorState(ctx, selected(scopeSelectors, scope, "users"), &p.Diagnostics)
	m.Groups, m.GroupDirectoryIDs = qualifiedSelectorState(ctx, selected(scopeSelectors, scope, "groups"), &p.Diagnostics)
	server, tools := stringFrom(selectors["server"]), selectors["tools"]
	if server == "" {
		conditions := object(definition["conditions"])
		servers := conditionValues(conditions, "mcp.server_id")
		if len(servers) > 0 {
			server = servers[0]
		}
		if tools == nil {
			values := conditionValues(conditions, "mcp.tool_id")
			if len(values) > 0 {
				items := make([]any, len(values))
				for i := range values {
					items[i] = values[i]
				}
				tools = items
			}
		}
	}
	m.Server = types.StringValue(server)
	m.Tools = setStringState(ctx, tools, &p.Diagnostics)
	m.Effect = types.StringValue(stringFrom(definition["action"]))
	m.CurrentRevision = types.Int64Value(e.Item.CurrentRevision)
	m.DefinitionSHA = types.StringValue(e.Item.DefinitionSHA)
	p.Diagnostics.Append(p.State.Set(ctx, &m)...)
}
func (r *mcpACLResource) Delete(ctx context.Context, q resource.DeleteRequest, p *resource.DeleteResponse) {
	var m mcpACLModel
	p.Diagnostics.Append(q.State.Get(ctx, &m)...)
	target := "content-policies/" + url.PathEscape(m.ID.ValueString()) + "?expectedRevision=" + strconv.FormatInt(m.CurrentRevision.ValueInt64(), 10)
	if err := r.client.Do(ctx, http.MethodDelete, target, nil, nil); err != nil && !IsNotFound(err) {
		p.Diagnostics.AddError("Destroy Forge MCP ACL", err.Error())
	}
}
func (r *mcpACLResource) ImportState(ctx context.Context, q resource.ImportStateRequest, p *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), q, p)
	p.Diagnostics.Append(p.State.SetAttribute(ctx, path.Root("validation_token"), "")...)
}
func (r *mcpACLResource) apply(ctx context.Context, m mcpACLModel, rev int64, d *diag.Diagnostics, save func(mcpACLModel)) {
	def, sourceRef := r.build(ctx, m, d)
	if d.HasError() {
		return
	}
	validationToken := m.ValidationToken.ValueString()
	if validationToken == "" {
		validation, err := r.client.ValidatePolicyPlan(ctx, "content", def, sourceRef, rev)
		if err != nil {
			d.AddError("Refresh Forge MCP ACL plan validation", err.Error())
			return
		}
		validationToken = validation.ValidationToken
	}
	body := map[string]any{"definition": def, "expectedRevision": rev, "sourceRef": sourceRef, "validationToken": validationToken}
	method, target := http.MethodPost, "content-policies"
	if rev > 0 {
		method, target = http.MethodPut, target+"/"+url.PathEscape(m.ID.ValueString())
	}
	var e struct {
		Item policyAPIItem `json:"item"`
	}
	if err := r.client.Do(ctx, method, target, body, &e); err != nil {
		d.AddError("Apply Forge MCP ACL", err.Error())
		return
	}
	m.CurrentRevision, m.DefinitionSHA = types.Int64Value(e.Item.CurrentRevision), types.StringValue(e.Item.DefinitionSHA)
	save(m)
}
func (r *mcpACLResource) build(ctx context.Context, m mcpACLModel, d *diag.Diagnostics) (map[string]any, map[string]any) {
	var users, groups, tools []string
	d.Append(m.Users.ElementsAs(ctx, &users, false)...)
	d.Append(m.Groups.ElementsAs(ctx, &groups, false)...)
	d.Append(m.Tools.ElementsAs(ctx, &tools, false)...)
	if d.HasError() {
		return nil, nil
	}
	if len(users)+len(groups) == 0 {
		d.AddError("Empty MCP ACL subjects", "At least one user or group is required")
		return nil, nil
	}
	userSelectors := qualifiedSelectorValues(ctx, m.Users, m.UserDirectoryIDs, "user", d)
	groupSelectors := qualifiedSelectorValues(ctx, m.Groups, m.GroupDirectoryIDs, "group", d)
	if d.HasError() {
		return nil, nil
	}
	conditions := []any{map[string]any{"field": "mcp.server_id", "op": "eq", "value": m.Server.ValueString()}}
	if len(tools) > 0 {
		conditions = append(conditions, map[string]any{"field": "mcp.tool_id", "op": "in", "value": tools})
	}
	def := map[string]any{"id": m.ID.ValueString(), "name": m.Name.ValueString(), "enabled": m.Enabled.ValueBool(), "appliesTo": map[string]any{"users": users, "groups": groups}, "evaluateOn": []string{"pre_tool"}, "conditions": map[string]any{"all": conditions}, "action": m.Effect.ValueString()}
	return def, map[string]any{"tool": "terraform", "resource": "forge_mcp_acl." + m.ID.ValueString(), "selectors": map[string]any{"server": m.Server.ValueString(), "tools": tools, "appliesTo": nonemptyMap(map[string]any{"users": userSelectors, "groups": groupSelectors})}}
}

var _ resource.ResourceWithConfigure = (*mcpACLResource)(nil)
var _ resource.ResourceWithImportState = (*mcpACLResource)(nil)
var _ resource.ResourceWithModifyPlan = (*mcpACLResource)(nil)
