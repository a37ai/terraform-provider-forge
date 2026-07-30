package provider

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]*$`)

type regoPolicyResource struct {
	client *Client
	family string
	path   string
}

type regoPolicyModel struct {
	ID                    types.String  `tfsdk:"id"`
	Name                  types.String  `tfsdk:"name"`
	Description           types.String  `tfsdk:"description"`
	Rationale             types.String  `tfsdk:"rationale"`
	UseCases              types.Set     `tfsdk:"use_cases"`
	ComplianceFrameworks  types.Set     `tfsdk:"compliance_frameworks"`
	Labels                types.Set     `tfsdk:"labels"`
	Enabled               types.Bool    `tfsdk:"enabled"`
	Severity              types.String  `tfsdk:"severity"`
	AcknowledgeBroadScope types.Bool    `tfsdk:"acknowledge_broad_scope"`
	EnforcementSurfaces   types.Set     `tfsdk:"enforcement_surfaces"`
	Runtime               types.Dynamic `tfsdk:"runtime"`
	Notification          types.Dynamic `tfsdk:"notification"`
	ApprovalMode          types.String  `tfsdk:"approval_mode"`
	Remediation           types.Dynamic `tfsdk:"remediation"`
	Users                 types.Set     `tfsdk:"users"`
	Groups                types.Set     `tfsdk:"groups"`
	UserDirectoryIDs      types.Map     `tfsdk:"user_directory_ids"`
	GroupDirectoryIDs     types.Map     `tfsdk:"group_directory_ids"`
	ServiceAccounts       types.Set     `tfsdk:"service_accounts"`
	Devices               types.Set     `tfsdk:"devices"`
	Agents                types.Set     `tfsdk:"agents"`
	Products              types.Set     `tfsdk:"products"`
	EvaluateOn            types.List    `tfsdk:"evaluate_on"`
	Action                types.String  `tfsdk:"action"`
	Message               types.String  `tfsdk:"message"`
	AutoApprove           types.Bool    `tfsdk:"auto_approve_on_request"`
	RedactionReplacement  types.String  `tfsdk:"redaction_replacement"`
	RedactionStrategy     types.String  `tfsdk:"redaction_strategy"`
	RedactionPaths        types.Set     `tfsdk:"redaction_paths"`
	RedactionKeepStart    types.Int64   `tfsdk:"redaction_keep_start"`
	RedactionKeepEnd      types.Int64   `tfsdk:"redaction_keep_end"`
	RedactionMask         types.String  `tfsdk:"redaction_mask_character"`
	RedactionSaltRef      types.String  `tfsdk:"redaction_salt_ref"`
	RedactionFakeSubtype  types.String  `tfsdk:"redaction_fake_subtype"`
	FilterCollectionPath  types.String  `tfsdk:"filter_collection_path"`
	FilterPath            types.String  `tfsdk:"filter_path"`
	FilterOperator        types.String  `tfsdk:"filter_operator"`
	FilterValue           types.Dynamic `tfsdk:"filter_value"`
	FilterOnUnavailable   types.String  `tfsdk:"filter_on_unavailable"`
	RemediationAction     types.String  `tfsdk:"remediation_action"`
	RemediationTarget     types.String  `tfsdk:"remediation_target"`
	Module                types.String  `tfsdk:"module"`
	Conditions            types.Dynamic `tfsdk:"conditions"`
	CustomFields          types.Dynamic `tfsdk:"custom_fields"`
	Except                types.Dynamic `tfsdk:"except"`
	EnforcedBy            types.Set     `tfsdk:"enforced_by"`
	CurrentRevision       types.Int64   `tfsdk:"current_revision"`
	DefinitionSHA         types.String  `tfsdk:"definition_sha256"`
	ValidationToken       types.String  `tfsdk:"validation_token"`
	ModuleSHA             types.String  `tfsdk:"module_sha256"`
}

func newContentPolicyResource() resource.Resource {
	return &regoPolicyResource{family: "content", path: "content-policies"}
}

func newAccessPolicyResource() resource.Resource {
	return &regoPolicyResource{family: "access", path: "access-policies"}
}

func (r *regoPolicyResource) Metadata(_ context.Context, q resource.MetadataRequest, p *resource.MetadataResponse) {
	p.TypeName = q.ProviderTypeName + "_" + r.family + "_policy"
}

func (r *regoPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, p *resource.SchemaResponse) {
	nonempty := []validator.String{stringvalidator.LengthBetween(1, 4096)}
	attrs := map[string]schema.Attribute{
		"id":                      schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}, Validators: []validator.String{stringvalidator.LengthBetween(1, 256), stringvalidator.RegexMatches(identifierPattern, "must be a Forge policy identifier")}},
		"name":                    schema.StringAttribute{Required: true, Validators: nonempty},
		"description":             schema.StringAttribute{Optional: true, Validators: nonempty},
		"rationale":               schema.StringAttribute{Optional: true, Validators: nonempty},
		"use_cases":               schema.SetAttribute{Optional: true, Computed: true, Default: setdefault.StaticValue(types.SetValueMust(types.StringType, nil)), ElementType: types.StringType, Validators: []validator.Set{setvalidator.SizeAtMost(9), setvalidator.ValueStringsAre(stringvalidator.OneOf(canonicalPolicyUseCases...))}},
		"compliance_frameworks":   schema.SetAttribute{Optional: true, Computed: true, Default: setdefault.StaticValue(types.SetValueMust(types.StringType, nil)), ElementType: types.StringType, Validators: []validator.Set{setvalidator.SizeAtMost(8), setvalidator.ValueStringsAre(stringvalidator.OneOf(canonicalComplianceFrameworks...))}},
		"labels":                  schema.SetAttribute{Optional: true, Computed: true, Default: setdefault.StaticValue(types.SetValueMust(types.StringType, nil)), ElementType: types.StringType, Validators: []validator.Set{setvalidator.SizeAtMost(256)}},
		"enabled":                 schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
		"users":                   schema.SetAttribute{Optional: true, Computed: true, Default: setdefault.StaticValue(types.SetValueMust(types.StringType, nil)), ElementType: types.StringType, Validators: []validator.Set{setvalidator.SizeAtMost(256)}},
		"groups":                  schema.SetAttribute{Optional: true, Computed: true, Default: setdefault.StaticValue(types.SetValueMust(types.StringType, nil)), ElementType: types.StringType, Validators: []validator.Set{setvalidator.SizeAtMost(256)}},
		"user_directory_ids":      schema.MapAttribute{Optional: true, Computed: true, Default: mapdefault.StaticValue(types.MapValueMust(types.StringType, nil)), ElementType: types.StringType, Validators: []validator.Map{mapvalidator.SizeAtMost(256)}, Description: "Optional map from a configured user email to a Forge directory ID, used only to disambiguate duplicate exact matches."},
		"group_directory_ids":     schema.MapAttribute{Optional: true, Computed: true, Default: mapdefault.StaticValue(types.MapValueMust(types.StringType, nil)), ElementType: types.StringType, Validators: []validator.Map{mapvalidator.SizeAtMost(256)}, Description: "Optional map from a configured group name to a Forge directory ID, used only to disambiguate duplicate exact matches."},
		"service_accounts":        schema.SetAttribute{Optional: true, Computed: true, Default: setdefault.StaticValue(types.SetValueMust(types.StringType, nil)), ElementType: types.StringType, Validators: []validator.Set{setvalidator.SizeAtMost(256)}},
		"module":                  schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.LengthBetween(1, 256<<10)}, Description: "A forge.rego.v1 module. Set exactly one of module or conditions."},
		"conditions":              schema.DynamicAttribute{Optional: true, Description: "A native HCL condition object using field/op/value leaves; all, any, and not; and Content-only stateful operators. Set exactly one of conditions or module."},
		"custom_fields":           schema.DynamicAttribute{Optional: true, Description: "Immutable typed descriptors for registered nested tool.input fields used by native content-policy conditions."},
		"except":                  schema.DynamicAttribute{Optional: true, Description: "A canonical native HCL condition tree. A matching exception suppresses this policy after its primary match succeeds."},
		"action":                  schema.StringAttribute{Required: true},
		"message":                 schema.StringAttribute{Optional: true, Validators: nonempty},
		"auto_approve_on_request": schema.BoolAttribute{Optional: true},
		"redaction_replacement":   schema.StringAttribute{Optional: true},
		"redaction_strategy":      schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.OneOf(canonicalRedactionStrategies...)}},
		"redaction_paths":         schema.SetAttribute{Optional: true, ElementType: types.StringType, Validators: []validator.Set{setvalidator.SizeBetween(1, 64)}},
		"redaction_keep_start":    schema.Int64Attribute{Optional: true}, "redaction_keep_end": schema.Int64Attribute{Optional: true},
		"redaction_mask_character": schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.LengthBetween(1, 1)}},
		"redaction_salt_ref":       schema.StringAttribute{Optional: true}, "redaction_fake_subtype": schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.OneOf(canonicalFakeSubtypes...)}},
		"filter_collection_path": schema.StringAttribute{Optional: true}, "filter_path": schema.StringAttribute{Optional: true},
		"filter_operator": schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.OneOf(canonicalFilterOperators...)}},
		"filter_value":    schema.DynamicAttribute{Optional: true, Description: "Typed scalar, collection, or object compared by the filter."}, "filter_on_unavailable": schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.OneOf(canonicalFilterUnavailableActions...)}},
		"remediation_action": schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.OneOf(canonicalAccessRemediationActions...)}},
		"remediation_target": schema.StringAttribute{Optional: true},
		"current_revision":   schema.Int64Attribute{Computed: true},
		"definition_sha256":  schema.StringAttribute{Computed: true},
		"validation_token":   schema.StringAttribute{Computed: true, Sensitive: true, Description: "Short-lived server plan binding. Managed internally by the provider and never authored."},
		"module_sha256":      schema.StringAttribute{Computed: true},
	}
	if r.family == "content" {
		attrs["severity"] = schema.StringAttribute{Computed: true}
		attrs["acknowledge_broad_scope"] = schema.BoolAttribute{Computed: true}
		attrs["enforcement_surfaces"] = schema.SetAttribute{Computed: true, ElementType: types.StringType}
		attrs["runtime"] = schema.DynamicAttribute{Computed: true}
		attrs["notification"] = schema.DynamicAttribute{Computed: true}
		attrs["approval_mode"] = schema.StringAttribute{Computed: true}
		attrs["remediation"] = schema.DynamicAttribute{Computed: true}
		attrs["evaluate_on"] = schema.ListAttribute{Required: true, ElementType: types.StringType, Validators: []validator.List{listvalidator.SizeBetween(1, 4), listvalidator.ValueStringsAre(stringvalidator.OneOf(canonicalContentEvaluationPoints...))}}
		attrs["agents"] = schema.SetAttribute{Optional: true, Computed: true, Default: setdefault.StaticValue(types.SetValueMust(types.StringType, nil)), ElementType: types.StringType, Validators: []validator.Set{setvalidator.SizeAtMost(256)}}
		attrs["products"] = schema.SetAttribute{Optional: true, Computed: true, Default: setdefault.StaticValue(types.SetValueMust(types.StringType, nil)), ElementType: types.StringType, Validators: []validator.Set{setvalidator.SizeAtMost(256)}}
		attrs["devices"] = schema.SetAttribute{Computed: true, ElementType: types.StringType, PlanModifiers: []planmodifier.Set{setplanmodifier.UseStateForUnknown()}}
		attrs["enforced_by"] = schema.SetAttribute{Computed: true, ElementType: types.StringType}
		attrs["action"] = schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.OneOf(canonicalContentActions...)}}
	} else {
		attrs["severity"] = schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("medium"), Validators: []validator.String{stringvalidator.OneOf(canonicalAccessSeverities...)}}
		attrs["acknowledge_broad_scope"] = schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), Description: "Required before enabling a broad disruptive Access policy."}
		attrs["enforcement_surfaces"] = schema.SetAttribute{Required: true, ElementType: types.StringType, Validators: []validator.Set{setvalidator.SizeBetween(1, 3), setvalidator.ValueStringsAre(stringvalidator.OneOf(canonicalAccessEnforcementSurfaces...))}, Description: "Exact execution surfaces: inline_hook, endpoint_route, or provider."}
		attrs["runtime"] = schema.DynamicAttribute{Optional: true, Description: "Canonical Access runtime object: candidateMode, detectionMode, detectionLatencyMs, timeoutBehavior, failBehavior, and confidenceThreshold."}
		attrs["notification"] = schema.DynamicAttribute{Optional: true, Description: "Canonical structured Access notification object."}
		attrs["approval_mode"] = schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("admin_approval"), Validators: []validator.String{stringvalidator.OneOf(canonicalAccessApprovalModes...)}}
		attrs["remediation"] = schema.DynamicAttribute{Optional: true, Description: "Canonical Access remediation object with triggerPhase, applyWhenClassification, and one or more actions."}
		attrs["message"] = schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}}
		attrs["auto_approve_on_request"] = schema.BoolAttribute{Computed: true, PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()}}
		attrs["remediation_action"] = schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}}
		attrs["remediation_target"] = schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}}
		attrs["service_accounts"] = schema.SetAttribute{Computed: true, ElementType: types.StringType, PlanModifiers: []planmodifier.Set{setplanmodifier.UseStateForUnknown()}}
		attrs["devices"] = schema.SetAttribute{Optional: true, Computed: true, Default: setdefault.StaticValue(types.SetValueMust(types.StringType, nil)), ElementType: types.StringType, Validators: []validator.Set{setvalidator.SizeAtMost(256)}}
		attrs["evaluate_on"] = schema.ListAttribute{Computed: true, ElementType: types.StringType, PlanModifiers: []planmodifier.List{listplanmodifier.UseStateForUnknown()}}
		attrs["agents"] = schema.SetAttribute{Computed: true, ElementType: types.StringType, PlanModifiers: []planmodifier.Set{setplanmodifier.UseStateForUnknown()}}
		attrs["products"] = schema.SetAttribute{Computed: true, ElementType: types.StringType, PlanModifiers: []planmodifier.Set{setplanmodifier.UseStateForUnknown()}}
		attrs["enforced_by"] = schema.SetAttribute{Optional: true, Computed: true, Default: setdefault.StaticValue(types.SetValueMust(types.StringType, nil)), ElementType: types.StringType, Validators: []validator.Set{setvalidator.SizeAtMost(256)}, Description: "Exact integration names. Forge resolves them authoritatively and errors on missing or ambiguous matches."}
		attrs["action"] = schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.OneOf(canonicalAccessActions...)}}
	}
	p.Schema = schema.Schema{Description: "A Forge " + r.family + " policy using forge.rego.v1 match logic.", Attributes: attrs}
}

func (r *regoPolicyResource) Configure(_ context.Context, q resource.ConfigureRequest, p *resource.ConfigureResponse) {
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

func (r *regoPolicyResource) ModifyPlan(ctx context.Context, request resource.ModifyPlanRequest, response *resource.ModifyPlanResponse) {
	if request.Plan.Raw.IsNull() || r.client == nil {
		return
	}
	var model regoPolicyModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	if !model.ValidationToken.IsNull() && !model.ValidationToken.IsUnknown() && model.ValidationToken.ValueString() != "" {
		return
	}
	revision := model.CurrentRevision.ValueInt64()
	var prior regoPolicyModel
	if !request.State.Raw.IsNull() {
		response.Diagnostics.Append(request.State.Get(ctx, &prior)...)
		if model.CurrentRevision.IsUnknown() {
			revision = prior.CurrentRevision.ValueInt64()
		}
	}
	definition, sourceRef := r.buildMutation(ctx, model, false, &response.Diagnostics)
	if response.Diagnostics.HasError() {
		return
	}
	if !request.State.Raw.IsNull() {
		priorDefinition, priorSourceRef := r.buildMutation(ctx, prior, false, &response.Diagnostics)
		if response.Diagnostics.HasError() {
			return
		}
		if !policyPlanPayloadChanged(definition, sourceRef, priorDefinition, priorSourceRef) {
			response.Diagnostics.Append(response.Plan.SetAttribute(ctx, path.Root("validation_token"), prior.ValidationToken.ValueString())...)
			response.Diagnostics.Append(response.Plan.SetAttribute(ctx, path.Root("current_revision"), prior.CurrentRevision.ValueInt64())...)
			response.Diagnostics.Append(response.Plan.SetAttribute(ctx, path.Root("definition_sha256"), prior.DefinitionSHA.ValueString())...)
			response.Diagnostics.Append(response.Plan.SetAttribute(ctx, path.Root("module_sha256"), prior.ModuleSHA)...)
			return
		}
	}
	validation, err := r.client.ValidatePolicyPlan(ctx, r.family, definition, sourceRef, revision)
	if err != nil {
		response.Diagnostics.AddError("Forge Rego plan validation failed", err.Error())
		return
	}
	response.Diagnostics.Append(response.Plan.SetAttribute(ctx, path.Root("validation_token"), validation.ValidationToken)...)
}

func (r *regoPolicyResource) Create(ctx context.Context, q resource.CreateRequest, p *resource.CreateResponse) {
	var m regoPolicyModel
	p.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if !p.Diagnostics.HasError() {
		r.apply(ctx, m, 0, &p.Diagnostics, func(v regoPolicyModel) { p.Diagnostics.Append(p.State.Set(ctx, &v)...) })
	}
}

func (r *regoPolicyResource) Update(ctx context.Context, q resource.UpdateRequest, p *resource.UpdateResponse) {
	var m, prior regoPolicyModel
	p.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	p.Diagnostics.Append(q.State.Get(ctx, &prior)...)
	if !p.Diagnostics.HasError() {
		r.apply(ctx, m, prior.CurrentRevision.ValueInt64(), &p.Diagnostics, func(v regoPolicyModel) { p.Diagnostics.Append(p.State.Set(ctx, &v)...) })
	}
}

func (r *regoPolicyResource) Read(ctx context.Context, q resource.ReadRequest, p *resource.ReadResponse) {
	var m regoPolicyModel
	p.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if p.Diagnostics.HasError() {
		return
	}
	var envelope struct {
		Item policyAPIItem `json:"item"`
	}
	err := r.client.Do(ctx, http.MethodGet, r.path+"/"+url.PathEscape(m.ID.ValueString()), nil, &envelope)
	if IsNotFound(err) {
		p.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		p.Diagnostics.AddError("Read Forge policy", err.Error())
		return
	}
	if err := envelope.Item.verifyAuthority(r.client); err != nil {
		p.Diagnostics.AddError("Forge policy authority conflict", err.Error())
		return
	}
	r.flatten(ctx, envelope.Item, &m, &p.Diagnostics)
	p.Diagnostics.Append(p.State.Set(ctx, &m)...)
}

func (r *regoPolicyResource) flatten(ctx context.Context, item policyAPIItem, m *regoPolicyModel, diagnostics *diag.Diagnostics) {
	definition, selectors := item.Definition, selectorObject(item)
	scope, scopeSelectors := object(definition["appliesTo"]), object(selectors["appliesTo"])
	configuredDevices := m.Devices
	m.Devices, m.Agents, m.Products = types.SetNull(types.StringType), types.SetNull(types.StringType), types.SetNull(types.StringType)
	m.EvaluateOn = types.ListNull(types.StringType)
	m.RedactionPaths = types.SetNull(types.StringType)
	m.RedactionReplacement, m.RedactionStrategy = types.StringNull(), types.StringNull()
	m.RedactionKeepStart, m.RedactionKeepEnd = types.Int64Null(), types.Int64Null()
	m.RedactionMask, m.RedactionSaltRef, m.RedactionFakeSubtype = types.StringNull(), types.StringNull(), types.StringNull()
	m.FilterCollectionPath, m.FilterPath, m.FilterOperator = types.StringNull(), types.StringNull(), types.StringNull()
	m.FilterValue, m.FilterOnUnavailable = types.DynamicNull(), types.StringNull()
	m.RemediationAction, m.RemediationTarget = types.StringNull(), types.StringNull()
	m.Severity, m.ApprovalMode = types.StringNull(), types.StringNull()
	m.AcknowledgeBroadScope = types.BoolNull()
	m.EnforcementSurfaces = types.SetNull(types.StringType)
	m.Runtime, m.Notification, m.Remediation = types.DynamicNull(), types.DynamicNull(), types.DynamicNull()
	m.Rationale = optionalString(definition["rationale"])
	m.UseCases = setStringStateDefaultEmpty(ctx, definition["useCases"], diagnostics)
	m.ComplianceFrameworks = setStringStateDefaultEmpty(ctx, definition["complianceFrameworks"], diagnostics)
	m.Labels = setStringStateDefaultEmpty(ctx, definition["labels"], diagnostics)
	m.Except = types.DynamicNull()
	if exception := definition["except"]; exception != nil {
		m.Except = dynamicFromGo(exception, diagnostics)
	}
	m.ID = types.StringValue(stringFrom(definition["id"]))
	m.Name = types.StringValue(stringFrom(definition["name"]))
	m.Description = optionalString(definition["description"])
	m.Enabled = types.BoolValue(boolFrom(definition["enabled"]))
	m.Users, m.UserDirectoryIDs = qualifiedSelectorState(ctx, selected(scopeSelectors, scope, "users"), diagnostics)
	m.Groups, m.GroupDirectoryIDs = qualifiedSelectorState(ctx, selected(scopeSelectors, scope, "groups"), diagnostics)
	m.ServiceAccounts = types.SetNull(types.StringType)
	m.Action = types.StringValue(stringFrom(definition["action"]))
	m.Message = types.StringNull()
	logic := object(definition["logic"])
	m.Module, m.ModuleSHA, m.Conditions, m.CustomFields = types.StringNull(), types.StringNull(), types.DynamicNull(), types.DynamicNull()
	if logic != nil {
		m.Module = types.StringValue(stringFrom(logic["module"]))
		m.ModuleSHA = types.StringValue(stringFrom(logic["moduleSha256"]))
	} else if conditions := definition["conditions"]; conditions != nil {
		m.Conditions = dynamicFromGo(conditions, diagnostics)
	}
	if customFields := definition["customFields"]; customFields != nil {
		m.CustomFields = dynamicFromGo(customFields, diagnostics)
	}
	m.AutoApprove = types.BoolNull()
	if r.family == "content" {
		m.Message = optionalString(definition["message"])
		if approval := object(definition["approval"]); approval != nil {
			m.AutoApprove = types.BoolValue(boolFrom(approval["autoApproveOnRequest"]))
		}
		m.ServiceAccounts = setStringStateDefaultEmpty(ctx, selected(scopeSelectors, scope, "serviceAccounts"), diagnostics)
		m.EvaluateOn = listStringState(ctx, definition["evaluateOn"], diagnostics)
		m.Agents = setStringStateDefaultEmpty(ctx, selected(scopeSelectors, scope, "agents"), diagnostics)
		m.Products = setStringStateDefaultEmpty(ctx, selected(scopeSelectors, scope, "products"), diagnostics)
		m.EnforcedBy = types.SetNull(types.StringType)
		redaction := object(definition["redaction"])
		m.RedactionStrategy = optionalString(redaction["strategy"])
		m.RedactionReplacement = optionalString(redaction["replacement"])
		m.RedactionPaths = setStringState(ctx, redaction["paths"], diagnostics)
		m.RedactionKeepStart = optionalInt64(redaction["keepStart"])
		m.RedactionKeepEnd = optionalInt64(redaction["keepEnd"])
		m.RedactionMask = optionalString(redaction["maskCharacter"])
		m.RedactionSaltRef = optionalString(redaction["saltRef"])
		m.RedactionFakeSubtype = optionalString(redaction["subtype"])
		filter := object(definition["filter"])
		removeWhere := object(filter["removeWhere"])
		m.FilterCollectionPath = optionalString(filter["collectionPath"])
		m.FilterPath = optionalString(removeWhere["path"])
		m.FilterOperator = optionalString(removeWhere["op"])
		m.FilterValue = dynamicFromGo(removeWhere["value"], diagnostics)
		m.FilterOnUnavailable = optionalString(filter["onUnavailable"])
	} else {
		m.Severity = types.StringValue(firstNonEmptyTerraformString(stringFrom(definition["severity"]), "medium"))
		m.AcknowledgeBroadScope = types.BoolValue(boolFrom(definition["acknowledgeBroadScope"]))
		m.EnforcementSurfaces = setStringState(ctx, definition["enforcementSurfaces"], diagnostics)
		m.Runtime = dynamicFromGo(definition["runtime"], diagnostics)
		m.Notification = dynamicFromGo(definition["notification"], diagnostics)
		m.Remediation = dynamicFromGo(definition["remediation"], diagnostics)
		m.ApprovalMode = types.StringValue("admin_approval")
		if approval := object(definition["approval"]); approval != nil && stringFrom(approval["mode"]) != "" {
			m.ApprovalMode = types.StringValue(stringFrom(approval["mode"]))
		}
		m.Devices = setStringStatePreserveConfiguredNull(ctx, selected(scopeSelectors, scope, "devices"), configuredDevices, diagnostics)
		m.EnforcedBy = setStringStateDefaultEmpty(ctx, selected(selectors, definition, "enforcedBy"), diagnostics)
		remediation := object(definition["remediation"])
		_ = remediation
	}
	m.CurrentRevision = types.Int64Value(item.CurrentRevision)
	m.DefinitionSHA = types.StringValue(item.DefinitionSHA)
}

func (r *regoPolicyResource) Delete(ctx context.Context, q resource.DeleteRequest, p *resource.DeleteResponse) {
	var m regoPolicyModel
	p.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if p.Diagnostics.HasError() {
		return
	}
	target := r.path + "/" + url.PathEscape(m.ID.ValueString()) + "?expectedRevision=" + strconv.FormatInt(m.CurrentRevision.ValueInt64(), 10)
	if err := r.client.Do(ctx, http.MethodDelete, target, nil, nil); err != nil && !IsNotFound(err) {
		p.Diagnostics.AddError("Destroy Forge policy", err.Error())
	}
}

func (r *regoPolicyResource) ImportState(ctx context.Context, q resource.ImportStateRequest, p *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), q, p)
	// Imported resources have no prior plan binding. Persist the provider's
	// empty sentinel so the first plan can converge without a computed
	// null-to-empty update.
	p.Diagnostics.Append(p.State.SetAttribute(ctx, path.Root("validation_token"), "")...)
}

func (r *regoPolicyResource) apply(ctx context.Context, m regoPolicyModel, revision int64, diagnostics *diag.Diagnostics, save func(regoPolicyModel)) {
	definition, sourceRef := r.buildMutation(ctx, m, true, diagnostics)
	if diagnostics.HasError() {
		return
	}
	body := map[string]any{"definition": definition, "expectedRevision": revision, "sourceRef": sourceRef, "validationToken": m.ValidationToken.ValueString()}
	method, target := http.MethodPost, r.path
	if revision > 0 {
		method, target = http.MethodPut, target+"/"+url.PathEscape(m.ID.ValueString())
	}
	var envelope struct {
		Item policyAPIItem `json:"item"`
	}
	if err := r.client.Do(ctx, method, target, body, &envelope); err != nil {
		diagnostics.AddError("Apply Forge policy", err.Error())
		return
	}
	// Persist the server's canonical definition rather than the planned model.
	// Besides reflecting server normalization immediately, this resolves every
	// family-inapplicable computed attribute to a known null before returning
	// state to Terraform/OpenTofu.
	r.flatten(ctx, envelope.Item, &m, diagnostics)
	if diagnostics.HasError() {
		return
	}
	save(m)
}

func (r *regoPolicyResource) buildMutation(ctx context.Context, m regoPolicyModel, validateRego bool, diagnostics *diag.Diagnostics) (map[string]any, map[string]any) {
	toStrings := func(set types.Set) []string {
		out := make([]string, 0)
		if set.IsNull() || set.IsUnknown() || set.ElementType(ctx) == nil {
			return out
		}
		diagnostics.Append(set.ElementsAs(ctx, &out, false)...)
		return out
	}
	userSelectors := qualifiedSelectorValues(ctx, m.Users, m.UserDirectoryIDs, "user", diagnostics)
	groupSelectors := qualifiedSelectorValues(ctx, m.Groups, m.GroupDirectoryIDs, "group", diagnostics)
	users, groups := toStrings(m.Users), toStrings(m.Groups)
	useCases, frameworks, labels := toStrings(m.UseCases), toStrings(m.ComplianceFrameworks), toStrings(m.Labels)
	if diagnostics.HasError() {
		return nil, nil
	}
	var serviceAccounts []string
	if r.family == "content" {
		serviceAccounts = toStrings(m.ServiceAccounts)
	}
	module := m.Module.ValueString()
	var evaluationPoints []string
	if r.family == "content" {
		diagnostics.Append(m.EvaluateOn.ElementsAs(ctx, &evaluationPoints, false)...)
	}
	moduleSet := module != ""
	conditionsSet := !m.Conditions.IsNull() && !m.Conditions.IsUnderlyingValueNull()
	if moduleSet == conditionsSet {
		diagnostics.AddError("Select one policy language", "Set exactly one of module or conditions.")
		return nil, nil
	}
	scope := map[string]any{"users": users, "groups": groups}
	definition := map[string]any{"id": m.ID.ValueString(), "name": m.Name.ValueString(), "enabled": m.Enabled.ValueBool(), "appliesTo": scope, "action": m.Action.ValueString()}
	customFields, customFieldTypes, customFieldsErr := customFieldsFromTerraform(m.CustomFields, r.family)
	if customFieldsErr != nil {
		diagnostics.AddError("Invalid custom fields", customFieldsErr.Error())
		return nil, nil
	}
	if len(customFields) > 0 {
		definition["customFields"] = customFields
	}
	if module != "" {
		digest := fmt.Sprintf("%x", sha256.Sum256([]byte(module)))
		if validateRego {
			validation, validationErr := r.client.ValidateRego(ctx, r.family, module, evaluationPoints...)
			if validationErr != nil {
				diagnostics.AddError("Validate Forge Rego policy", validationErr.Error())
				return nil, nil
			}
			if validation.SourceSHA != digest {
				diagnostics.AddError("Forge Rego digest mismatch", "Authoritative server validation returned a different source digest.")
				return nil, nil
			}
		}
		definition["logic"] = map[string]any{"kind": "rego", "languageVersion": "forge.rego.v1", "entrypoint": "data.forge." + r.family + ".match", "module": module, "moduleSha256": digest}
	} else {
		conditions, err := nativeConditionsFromTerraform(m.Conditions, r.family, customFieldTypes)
		if err != nil {
			diagnostics.AddError("Invalid native conditions", err.Error())
			return nil, nil
		}
		definition["conditions"] = conditions
	}
	if !m.Description.IsNull() {
		definition["description"] = m.Description.ValueString()
	}
	if !m.Rationale.IsNull() {
		definition["rationale"] = m.Rationale.ValueString()
	}
	if len(useCases) > 0 {
		definition["useCases"] = useCases
	}
	if len(frameworks) > 0 {
		definition["complianceFrameworks"] = frameworks
	}
	if len(labels) > 0 {
		definition["labels"] = labels
	}
	if !m.Except.IsNull() && !m.Except.IsUnknown() && m.Except.UnderlyingValue() != nil && !m.Except.IsUnderlyingValueNull() {
		exception, err := nativeConditionsFromTerraform(m.Except, r.family, customFieldTypes)
		if err != nil {
			diagnostics.AddError("Invalid native exception", err.Error())
			return nil, nil
		}
		definition["except"] = exception
	}
	if r.family == "content" {
		scope["serviceAccounts"] = serviceAccounts
		definition["evaluateOn"] = evaluationPoints
		scope["agents"] = toStrings(m.Agents)
		scope["products"] = toStrings(m.Products)
		if m.Action.ValueString() == "redact" {
			strategy := m.RedactionStrategy.ValueString()
			if strategy == "" {
				strategy = "constant"
			}
			redaction := map[string]any{"strategy": strategy}
			paths := toStrings(m.RedactionPaths)
			if len(paths) > 0 {
				redaction["paths"] = paths
			}
			if !m.RedactionReplacement.IsNull() {
				redaction["replacement"] = m.RedactionReplacement.ValueString()
			}
			if !m.RedactionKeepStart.IsNull() {
				redaction["keepStart"] = m.RedactionKeepStart.ValueInt64()
			}
			if !m.RedactionKeepEnd.IsNull() {
				redaction["keepEnd"] = m.RedactionKeepEnd.ValueInt64()
			}
			if !m.RedactionMask.IsNull() {
				redaction["maskCharacter"] = m.RedactionMask.ValueString()
			}
			if !m.RedactionSaltRef.IsNull() {
				redaction["saltRef"] = m.RedactionSaltRef.ValueString()
			}
			if !m.RedactionFakeSubtype.IsNull() {
				redaction["subtype"] = m.RedactionFakeSubtype.ValueString()
			}
			definition["redaction"] = redaction
		}
		if m.Action.ValueString() == "filter" {
			filterValue, valueErr := terraformDynamicToGo(m.FilterValue)
			if valueErr != nil {
				diagnostics.AddError("Invalid filter value", valueErr.Error())
				return nil, nil
			}
			definition["filter"] = map[string]any{"collectionPath": m.FilterCollectionPath.ValueString(), "removeWhere": map[string]any{"path": m.FilterPath.ValueString(), "op": m.FilterOperator.ValueString(), "value": filterValue}, "onUnavailable": m.FilterOnUnavailable.ValueString()}
		}
		if !m.Message.IsNull() {
			definition["message"] = m.Message.ValueString()
		}
	} else {
		scope["devices"] = toStrings(m.Devices)
		definition["severity"] = firstNonEmptyTerraformString(m.Severity.ValueString(), "medium")
		definition["acknowledgeBroadScope"] = m.AcknowledgeBroadScope.ValueBool()
		definition["enforcementSurfaces"] = toStrings(m.EnforcementSurfaces)
		enforcedBy := toStrings(m.EnforcedBy)
		if len(enforcedBy) > 0 {
			definition["enforcedBy"] = enforcedBy
		}
		if value, valueErr := optionalTerraformDynamicObject(m.Runtime); valueErr != nil {
			diagnostics.AddError("Invalid Access runtime", valueErr.Error())
			return nil, nil
		} else if value != nil {
			definition["runtime"] = value
		}
		if value, valueErr := optionalTerraformDynamicObject(m.Notification); valueErr != nil {
			diagnostics.AddError("Invalid Access notification", valueErr.Error())
			return nil, nil
		} else if value != nil {
			definition["notification"] = value
		}
		if value, valueErr := optionalTerraformDynamicObject(m.Remediation); valueErr != nil {
			diagnostics.AddError("Invalid Access remediation", valueErr.Error())
			return nil, nil
		} else if value != nil {
			definition["remediation"] = value
		}
	}
	if m.Action.ValueString() == "require_approval" {
		if r.family == "access" {
			definition["approval"] = map[string]any{"mode": firstNonEmptyTerraformString(m.ApprovalMode.ValueString(), "admin_approval")}
		} else {
			definition["approval"] = map[string]any{"autoApproveOnRequest": m.AutoApprove.ValueBool()}
		}
	}
	if diagnostics.HasError() {
		return nil, nil
	}
	scopeSelectors := nonemptyMap(map[string]any{"users": userSelectors, "groups": groupSelectors})
	if r.family == "content" {
		scopeSelectors["serviceAccounts"] = serviceAccounts
		scopeSelectors["agents"] = toStrings(m.Agents)
		scopeSelectors["products"] = toStrings(m.Products)
		scopeSelectors = nonemptyMap(scopeSelectors)
	} else {
		scopeSelectors["devices"] = toStrings(m.Devices)
		scopeSelectors = nonemptyMap(scopeSelectors)
	}
	selectors := map[string]any{"appliesTo": scopeSelectors}
	if r.family == "access" {
		selectors["enforcedBy"] = toStrings(m.EnforcedBy)
	}
	return definition, map[string]any{"tool": "terraform", "resource": "forge_" + r.family + "_policy." + m.ID.ValueString(), "selectors": nonemptyMap(selectors)}
}

func optionalTerraformDynamicObject(value types.Dynamic) (any, error) {
	return terraformDynamicToGo(value)
}

func firstNonEmptyTerraformString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

var _ resource.ResourceWithConfigure = (*regoPolicyResource)(nil)
var _ resource.ResourceWithImportState = (*regoPolicyResource)(nil)
var _ resource.ResourceWithModifyPlan = (*regoPolicyResource)(nil)
