package provider

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

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

type skillACLResource struct{ client *Client }
type skillACLModel struct {
	ID                types.String `tfsdk:"id"`
	Skill             types.String `tfsdk:"skill"`
	Enabled           types.Bool   `tfsdk:"enabled"`
	Users             types.Set    `tfsdk:"users"`
	UserDirectoryIDs  types.Map    `tfsdk:"user_directory_ids"`
	Groups            types.Set    `tfsdk:"groups"`
	GroupDirectoryIDs types.Map    `tfsdk:"group_directory_ids"`
	Effect            types.String `tfsdk:"effect"`
	CurrentRevision   types.Int64  `tfsdk:"current_revision"`
	DefinitionSHA     types.String `tfsdk:"definition_sha256"`
	ValidationToken   types.String `tfsdk:"validation_token"`
}
type policyAPIItem struct {
	ID              string         `json:"id"`
	CurrentRevision int64          `json:"currentRevision"`
	DefinitionSHA   string         `json:"definitionSha256"`
	Definition      map[string]any `json:"definition"`
	ManagementMode  string         `json:"managementMode"`
	ManagerID       string         `json:"managerId"`
	ManagerInstance string         `json:"managerInstance"`
	SourceRef       map[string]any `json:"sourceRef"`
}

func newSkillACLResource() resource.Resource { return &skillACLResource{} }
func (r *skillACLResource) Metadata(_ context.Context, q resource.MetadataRequest, p *resource.MetadataResponse) {
	p.TypeName = q.ProviderTypeName + "_skill_acl"
}
func (r *skillACLResource) Schema(_ context.Context, _ resource.SchemaRequest, p *resource.SchemaResponse) {
	nonempty := []validator.String{stringvalidator.LengthAtLeast(1)}
	p.Schema = schema.Schema{Description: "A Forge skill access-control policy.", Attributes: map[string]schema.Attribute{
		"id": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}, Validators: nonempty}, "skill": schema.StringAttribute{Required: true, Description: "Exact skill name or slug.", Validators: nonempty},
		"enabled": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)}, "users": optionalSubjectSetAttribute("Exact user emails."), "user_directory_ids": directoryQualifierAttribute("user"),
		"groups": optionalSubjectSetAttribute("Exact group names."), "group_directory_ids": directoryQualifierAttribute("group"), "effect": schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.OneOf(canonicalSkillEffects...)}},
		"current_revision": schema.Int64Attribute{Computed: true}, "definition_sha256": schema.StringAttribute{Computed: true}, "validation_token": schema.StringAttribute{Computed: true, Sensitive: true},
	}}
}
func (r *skillACLResource) Configure(_ context.Context, q resource.ConfigureRequest, p *resource.ConfigureResponse) {
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
func (r *skillACLResource) ModifyPlan(ctx context.Context, q resource.ModifyPlanRequest, p *resource.ModifyPlanResponse) {
	if q.Plan.Raw.IsNull() || r.client == nil {
		return
	}
	var m, prior skillACLModel
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
	validation, err := r.client.ValidatePolicyPlan(ctx, "skill_acl", definition, sourceRef, revision)
	if err != nil {
		p.Diagnostics.AddError("Forge skill ACL plan validation failed", err.Error())
		return
	}
	p.Diagnostics.Append(p.Plan.SetAttribute(ctx, path.Root("validation_token"), validation.ValidationToken)...)
}
func (r *skillACLResource) Create(ctx context.Context, q resource.CreateRequest, p *resource.CreateResponse) {
	var m skillACLModel
	p.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if p.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, m, 0, &p.Diagnostics, func(v skillACLModel) { p.Diagnostics.Append(p.State.Set(ctx, &v)...) })
}
func (r *skillACLResource) Update(ctx context.Context, q resource.UpdateRequest, p *resource.UpdateResponse) {
	var m, o skillACLModel
	p.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	p.Diagnostics.Append(q.State.Get(ctx, &o)...)
	if p.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, m, o.CurrentRevision.ValueInt64(), &p.Diagnostics, func(v skillACLModel) { p.Diagnostics.Append(p.State.Set(ctx, &v)...) })
}
func (r *skillACLResource) Read(ctx context.Context, q resource.ReadRequest, p *resource.ReadResponse) {
	var m skillACLModel
	p.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if p.Diagnostics.HasError() {
		return
	}
	var e struct {
		Item policyAPIItem `json:"item"`
	}
	if err := r.client.Do(ctx, http.MethodGet, "skill-acls/"+url.PathEscape(m.ID.ValueString()), nil, &e); err != nil {
		if IsNotFound(err) {
			p.State.RemoveResource(ctx)
			return
		}
		p.Diagnostics.AddError("Read Forge skill ACL", err.Error())
		return
	}
	if err := e.Item.verifyAuthority(r.client); err != nil {
		p.Diagnostics.AddError("Forge skill ACL authority conflict", err.Error())
		return
	}
	definition, selectors := e.Item.Definition, selectorObject(e.Item)
	subjects, subjectSelectors := object(definition["subjects"]), object(selectors["subjects"])
	m.ID = types.StringValue(stringFrom(definition["id"]))
	m.Skill = types.StringValue(stringFrom(selected(selectors, definition, "skillId")))
	m.Enabled = types.BoolValue(boolFrom(definition["enabled"]))
	m.Users, m.UserDirectoryIDs = qualifiedSelectorState(ctx, selected(subjectSelectors, subjects, "users"), &p.Diagnostics)
	m.Groups, m.GroupDirectoryIDs = qualifiedSelectorState(ctx, selected(subjectSelectors, subjects, "groups"), &p.Diagnostics)
	m.Effect = types.StringValue(stringFrom(definition["effect"]))
	m.CurrentRevision = types.Int64Value(e.Item.CurrentRevision)
	m.DefinitionSHA = types.StringValue(e.Item.DefinitionSHA)
	p.Diagnostics.Append(p.State.Set(ctx, &m)...)
}
func (r *skillACLResource) Delete(ctx context.Context, q resource.DeleteRequest, p *resource.DeleteResponse) {
	var m skillACLModel
	p.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if p.Diagnostics.HasError() {
		return
	}
	target := "skill-acls/" + url.PathEscape(m.ID.ValueString()) + "?expectedRevision=" + strconv.FormatInt(m.CurrentRevision.ValueInt64(), 10)
	if err := r.client.Do(ctx, http.MethodDelete, target, nil, nil); err != nil && !IsNotFound(err) {
		p.Diagnostics.AddError("Destroy Forge skill ACL", err.Error())
	}
}
func (r *skillACLResource) ImportState(ctx context.Context, q resource.ImportStateRequest, p *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), q, p)
	p.Diagnostics.Append(p.State.SetAttribute(ctx, path.Root("validation_token"), "")...)
}
func (r *skillACLResource) apply(ctx context.Context, m skillACLModel, rev int64, d *diag.Diagnostics, save func(skillACLModel)) {
	definition, sourceRef := r.build(ctx, m, d)
	if d.HasError() {
		return
	}
	body := map[string]any{"definition": definition, "expectedRevision": rev, "sourceRef": sourceRef, "validationToken": m.ValidationToken.ValueString()}
	method, target := http.MethodPost, "skill-acls"
	if rev > 0 {
		method, target = http.MethodPut, target+"/"+url.PathEscape(m.ID.ValueString())
	}
	var e struct {
		Item policyAPIItem `json:"item"`
	}
	if err := r.client.Do(ctx, method, target, body, &e); err != nil {
		d.AddError("Apply Forge skill ACL", err.Error())
		return
	}
	m.CurrentRevision, m.DefinitionSHA = types.Int64Value(e.Item.CurrentRevision), types.StringValue(e.Item.DefinitionSHA)
	save(m)
}
func (r *skillACLResource) build(ctx context.Context, m skillACLModel, d *diag.Diagnostics) (map[string]any, map[string]any) {
	var users, groups []string
	d.Append(m.Users.ElementsAs(ctx, &users, false)...)
	d.Append(m.Groups.ElementsAs(ctx, &groups, false)...)
	if d.HasError() {
		return nil, nil
	}
	if len(users)+len(groups) == 0 {
		d.AddError("Empty skill ACL subjects", "At least one user or group is required")
		return nil, nil
	}
	userSelectors := qualifiedSelectorValues(ctx, m.Users, m.UserDirectoryIDs, "user", d)
	groupSelectors := qualifiedSelectorValues(ctx, m.Groups, m.GroupDirectoryIDs, "group", d)
	if d.HasError() {
		return nil, nil
	}
	subjects := map[string]any{}
	if len(users) > 0 {
		subjects["users"] = users
	}
	if len(groups) > 0 {
		subjects["groups"] = groups
	}
	definition := map[string]any{"id": m.ID.ValueString(), "skillId": m.Skill.ValueString(), "enabled": m.Enabled.ValueBool(), "subjects": subjects, "effect": m.Effect.ValueString()}
	return definition, map[string]any{"tool": "terraform", "resource": "forge_skill_acl." + m.ID.ValueString(), "selectors": map[string]any{"skillId": m.Skill.ValueString(), "subjects": nonemptyMap(map[string]any{"users": userSelectors, "groups": groupSelectors})}}
}

var _ resource.ResourceWithConfigure = (*skillACLResource)(nil)
var _ resource.ResourceWithImportState = (*skillACLResource)(nil)
var _ resource.ResourceWithModifyPlan = (*skillACLResource)(nil)
