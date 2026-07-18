package provider

import (
	"context"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type policyAuthorityResource struct{ client *Client }
type policyAuthorityModel struct {
	ID               types.String `tfsdk:"id"`
	PolicyID         types.String `tfsdk:"policy_id"`
	ExpectedRevision types.Int64  `tfsdk:"expected_revision"`
	CurrentRevision  types.Int64  `tfsdk:"current_revision"`
	ManagementMode   types.String `tfsdk:"management_mode"`
	ManagerID        types.String `tfsdk:"manager_id"`
	ManagerInstance  types.String `tfsdk:"manager_instance"`
}

func newPolicyAuthorityResource() resource.Resource { return &policyAuthorityResource{} }
func (r *policyAuthorityResource) Metadata(_ context.Context, q resource.MetadataRequest, p *resource.MetadataResponse) {
	p.TypeName = q.ProviderTypeName + "_policy_authority"
}
func (r *policyAuthorityResource) Schema(_ context.Context, _ resource.SchemaRequest, p *resource.SchemaResponse) {
	p.Schema = schema.Schema{Description: "Explicitly adopt an existing Forge-managed policy into this Terraform manager; destroy releases it.", Attributes: map[string]schema.Attribute{"id": schema.StringAttribute{Computed: true}, "policy_id": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}}, "expected_revision": schema.Int64Attribute{Required: true, PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()}}, "current_revision": schema.Int64Attribute{Computed: true}, "management_mode": schema.StringAttribute{Computed: true}, "manager_id": schema.StringAttribute{Computed: true}, "manager_instance": schema.StringAttribute{Computed: true}}}
}
func (r *policyAuthorityResource) Configure(_ context.Context, q resource.ConfigureRequest, p *resource.ConfigureResponse) {
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
func (r *policyAuthorityResource) Create(ctx context.Context, q resource.CreateRequest, p *resource.CreateResponse) {
	var m policyAuthorityModel
	p.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if p.Diagnostics.HasError() {
		return
	}
	var e authorityEnvelope
	body := map[string]any{"expectedRevision": m.ExpectedRevision.ValueInt64(), "managerId": r.client.managerID, "managerInstance": r.client.managerInstance}
	if err := r.client.Do(ctx, http.MethodPost, "policy-authority/"+url.PathEscape(m.PolicyID.ValueString())+"/claim", body, &e); err != nil {
		p.Diagnostics.AddError("Adopt Forge policy", err.Error())
		return
	}
	m.set(e.Item)
	p.Diagnostics.Append(p.State.Set(ctx, &m)...)
}
func (r *policyAuthorityResource) Read(ctx context.Context, q resource.ReadRequest, p *resource.ReadResponse) {
	var m policyAuthorityModel
	p.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if p.Diagnostics.HasError() {
		return
	}
	var e authorityEnvelope
	err := r.client.Do(ctx, http.MethodGet, "policy-authority/"+url.PathEscape(m.PolicyID.ValueString()), nil, &e)
	if IsNotFound(err) {
		p.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		p.Diagnostics.AddError("Read Forge policy authority", err.Error())
		return
	}
	if e.Item.ManagementMode != "terraform" || e.Item.ManagerID == nil || *e.Item.ManagerID != r.client.managerID || e.Item.ManagerInstance == nil || *e.Item.ManagerInstance != r.client.managerInstance {
		p.Diagnostics.AddError("Lost Forge policy authority", "The policy is no longer bound to this Terraform manager; explicit recovery or transfer is required.")
		return
	}
	m.set(e.Item)
	p.Diagnostics.Append(p.State.Set(ctx, &m)...)
}
func (r *policyAuthorityResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
}
func (r *policyAuthorityResource) Delete(ctx context.Context, q resource.DeleteRequest, p *resource.DeleteResponse) {
	var m policyAuthorityModel
	p.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if p.Diagnostics.HasError() {
		return
	}
	body := map[string]any{"expectedRevision": m.CurrentRevision.ValueInt64()}
	if err := r.client.Do(ctx, http.MethodPost, "policy-authority/"+url.PathEscape(m.PolicyID.ValueString())+"/release", body, nil); err != nil && !IsNotFound(err) {
		p.Diagnostics.AddError("Release Forge policy authority", err.Error())
	}
}
func (r *policyAuthorityResource) ImportState(ctx context.Context, q resource.ImportStateRequest, p *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("policy_id"), q, p)
	p.Diagnostics.Append(p.State.SetAttribute(ctx, path.Root("id"), q.ID)...)
}

type authorityEnvelope struct {
	Item struct {
		ID              string  `json:"id"`
		CurrentRevision int64   `json:"currentRevision"`
		ManagementMode  string  `json:"managementMode"`
		ManagerID       *string `json:"managerId"`
		ManagerInstance *string `json:"managerInstance"`
	} `json:"item"`
}

func (m *policyAuthorityModel) set(item struct {
	ID              string  `json:"id"`
	CurrentRevision int64   `json:"currentRevision"`
	ManagementMode  string  `json:"managementMode"`
	ManagerID       *string `json:"managerId"`
	ManagerInstance *string `json:"managerInstance"`
}) {
	m.ID = types.StringValue(item.ID)
	m.PolicyID = types.StringValue(item.ID)
	m.CurrentRevision = types.Int64Value(item.CurrentRevision)
	// Import has no configuration from which to recover expected_revision. Pin it
	// to the revision observed on the first refresh so the imported authority
	// resource has complete, stable state. Configured resources retain the
	// revision the operator explicitly approved when claiming authority.
	if m.ExpectedRevision.IsNull() || m.ExpectedRevision.IsUnknown() {
		m.ExpectedRevision = types.Int64Value(item.CurrentRevision)
	}
	m.ManagementMode = types.StringValue(item.ManagementMode)
	m.ManagerID = types.StringPointerValue(item.ManagerID)
	m.ManagerInstance = types.StringPointerValue(item.ManagerInstance)
}

var _ resource.ResourceWithConfigure = (*policyAuthorityResource)(nil)
var _ resource.ResourceWithImportState = (*policyAuthorityResource)(nil)
