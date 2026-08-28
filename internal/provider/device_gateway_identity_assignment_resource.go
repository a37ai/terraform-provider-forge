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

type deviceGatewayIdentityAssignmentResource struct{ client *Client }
type deviceGatewayIdentityAssignmentModel struct {
	ID                 types.String `tfsdk:"id"`
	DeviceID           types.String `tfsdk:"device_id"`
	ServiceAccountID   types.String `tfsdk:"service_account_id"`
	ManagedPrincipalID types.String `tfsdk:"managed_principal_id"`
	Revision           types.Int64  `tfsdk:"revision"`
}
type deviceGatewayIdentityAPI struct {
	DeviceID           string `json:"deviceId"`
	Resolution         string `json:"resolution"`
	SubjectKind        string `json:"subjectKind"`
	SubjectID          string `json:"subjectId"`
	ManagedPrincipalID string `json:"managedPrincipalId"`
	Revision           int64  `json:"revision"`
}

func newDeviceGatewayIdentityAssignmentResource() resource.Resource {
	return &deviceGatewayIdentityAssignmentResource{}
}
func (r *deviceGatewayIdentityAssignmentResource) Metadata(_ context.Context, q resource.MetadataRequest, p *resource.MetadataResponse) {
	p.TypeName = q.ProviderTypeName + "_device_gateway_identity_assignment"
}
func (r *deviceGatewayIdentityAssignmentResource) Schema(_ context.Context, _ resource.SchemaRequest, p *resource.SchemaResponse) {
	p.Schema = schema.Schema{Attributes: map[string]schema.Attribute{"id": schema.StringAttribute{Computed: true}, "device_id": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}}, "service_account_id": schema.StringAttribute{Required: true}, "managed_principal_id": schema.StringAttribute{Computed: true}, "revision": schema.Int64Attribute{Computed: true}}}
}
func (r *deviceGatewayIdentityAssignmentResource) Configure(_ context.Context, q resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if q.ProviderData != nil {
		r.client, _ = q.ProviderData.(*Client)
	}
}
func (r *deviceGatewayIdentityAssignmentResource) Create(ctx context.Context, q resource.CreateRequest, p *resource.CreateResponse) {
	var m deviceGatewayIdentityAssignmentModel
	p.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	r.save(ctx, &m, &p.Diagnostics)
	if !p.Diagnostics.HasError() {
		p.Diagnostics.Append(p.State.Set(ctx, &m)...)
	}
}
func (r *deviceGatewayIdentityAssignmentResource) Update(ctx context.Context, q resource.UpdateRequest, p *resource.UpdateResponse) {
	var m deviceGatewayIdentityAssignmentModel
	p.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	r.save(ctx, &m, &p.Diagnostics)
	if !p.Diagnostics.HasError() {
		p.Diagnostics.Append(p.State.Set(ctx, &m)...)
	}
}
func (r *deviceGatewayIdentityAssignmentResource) save(ctx context.Context, m *deviceGatewayIdentityAssignmentModel, d *diag.Diagnostics) {
	if d.HasError() {
		return
	}
	var out deviceGatewayIdentityAPI
	path := "devices/" + url.PathEscape(m.DeviceID.ValueString()) + "/gateway-identity"
	if err := r.client.Do(ctx, http.MethodPut, path, map[string]any{"serviceAccountId": m.ServiceAccountID.ValueString(), "source": "terraform"}, &out); err != nil {
		d.AddError("Save Forge device Gateway identity assignment", err.Error())
		return
	}
	r.refresh(m, out)
}
func (r *deviceGatewayIdentityAssignmentResource) Read(ctx context.Context, q resource.ReadRequest, p *resource.ReadResponse) {
	var m deviceGatewayIdentityAssignmentModel
	p.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if p.Diagnostics.HasError() {
		return
	}
	var out deviceGatewayIdentityAPI
	err := r.client.Do(ctx, http.MethodGet, "devices/"+url.PathEscape(m.DeviceID.ValueString())+"/gateway-identity", nil, &out)
	if IsNotFound(err) {
		p.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		p.Diagnostics.AddError("Read Forge device Gateway identity assignment", err.Error())
		return
	}
	if out.Resolution != "explicit" {
		p.State.RemoveResource(ctx)
		return
	}
	r.refresh(&m, out)
	p.Diagnostics.Append(p.State.Set(ctx, &m)...)
}
func (r *deviceGatewayIdentityAssignmentResource) Delete(ctx context.Context, q resource.DeleteRequest, p *resource.DeleteResponse) {
	var m deviceGatewayIdentityAssignmentModel
	p.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if p.Diagnostics.HasError() {
		return
	}
	err := r.client.Do(ctx, http.MethodDelete, "devices/"+url.PathEscape(m.DeviceID.ValueString())+"/gateway-identity", nil, nil)
	if err != nil && !IsNotFound(err) {
		p.Diagnostics.AddError("Delete Forge device Gateway identity assignment", err.Error())
	}
}
func (r *deviceGatewayIdentityAssignmentResource) refresh(m *deviceGatewayIdentityAssignmentModel, out deviceGatewayIdentityAPI) {
	m.ID = types.StringValue(out.DeviceID)
	m.DeviceID = types.StringValue(out.DeviceID)
	m.ServiceAccountID = types.StringValue(out.SubjectID)
	m.ManagedPrincipalID = types.StringValue(out.ManagedPrincipalID)
	m.Revision = types.Int64Value(out.Revision)
}

var _ resource.ResourceWithConfigure = (*deviceGatewayIdentityAssignmentResource)(nil)
