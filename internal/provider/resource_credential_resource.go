package provider

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type resourceCredentialResource struct{ client *Client }

type resourceCredentialModel struct {
	ID                 types.String `tfsdk:"id"`
	ResourceID         types.String `tfsdk:"resource_id"`
	Name               types.String `tfsdk:"name"`
	Kind               types.String `tfsdk:"kind"`
	Username           types.String `tfsdk:"username"`
	HeaderName         types.String `tfsdk:"header_name"`
	AWSRegion          types.String `tfsdk:"aws_region"`
	AWSRoleARN         types.String `tfsdk:"aws_role_arn"`
	OAuthTokenEndpoint types.String `tfsdk:"oauth_token_endpoint"`
	OAuthClientID      types.String `tfsdk:"oauth_client_id"`
	OAuthScopes        types.Set    `tfsdk:"oauth_scopes"`
	OAuthAudience      types.String `tfsdk:"oauth_audience"`
	Secret             types.String `tfsdk:"secret"`
	SecretVersion      types.Int64  `tfsdk:"secret_version"`
	Default            types.Bool   `tfsdk:"default"`
	Users              types.Set    `tfsdk:"users"`
	Groups             types.Set    `tfsdk:"groups"`
	ServiceAccounts    types.Set    `tfsdk:"service_accounts"`
	ManagementMode     types.String `tfsdk:"management_mode"`
	ManagerID          types.String `tfsdk:"manager_id"`
	ManagerInstance    types.String `tfsdk:"manager_instance"`
}

type resourceCredentialAssignmentsAPI struct {
	Users           []string `json:"users"`
	Groups          []string `json:"groups"`
	ServiceAccounts []string `json:"serviceAccounts"`
}

type resourceCredentialAPI struct {
	ID              string                               `json:"id"`
	ResourceID      string                               `json:"resourceId"`
	Name            string                               `json:"name"`
	Kind            string                               `json:"kind"`
	Username        *string                              `json:"username"`
	HeaderName      *string                              `json:"headerName"`
	Authentication  *resourceCredentialAuthenticationAPI `json:"authentication"`
	Default         bool                                 `json:"default"`
	AssignedTo      resourceCredentialAssignmentsAPI     `json:"assignedTo"`
	ManagementMode  string                               `json:"managementMode"`
	ManagerID       string                               `json:"managerId"`
	ManagerInstance string                               `json:"managerInstance"`
}

type resourceCredentialAuthenticationAPI struct {
	Region        string   `json:"region,omitempty"`
	RoleARN       string   `json:"roleArn,omitempty"`
	TokenEndpoint string   `json:"tokenEndpoint,omitempty"`
	ClientID      string   `json:"clientId,omitempty"`
	Scopes        []string `json:"scopes,omitempty"`
	Audience      string   `json:"audience,omitempty"`
}

func newResourceCredentialResource() resource.Resource { return &resourceCredentialResource{} }

func (r *resourceCredentialResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_resource_credential"
}

func (r *resourceCredentialResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	emptyStrings := types.SetValueMust(types.StringType, nil)
	assignments := func(description string) schema.SetAttribute {
		return schema.SetAttribute{
			Optional: true, Computed: true, Default: setdefault.StaticValue(emptyStrings),
			ElementType: types.StringType, Description: description,
			Validators: []validator.Set{setvalidator.SizeAtMost(256)},
		}
	}
	response.Schema = schema.Schema{
		Description: "A credential Forge uses to connect to one Resource.",
		Attributes: map[string]schema.Attribute{
			"id":                   schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"resource_id":          schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}, Description: "Resource that uses this credential."},
			"name":                 schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.LengthBetween(1, 128)}},
			"kind":                 schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.OneOf("username_password", "bearer_token", "header", "aws_rds_iam", "oauth2_client_credentials", "oauth2_token_exchange")}, Description: "Authentication method: username/password or RDS IAM for PostgreSQL and MySQL, username/password for Redis, and bearer token, header, OAuth client credentials, or OAuth token exchange for HTTP."},
			"username":             schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.LengthBetween(1, 256)}, Description: "Destination username for username_password or aws_rds_iam."},
			"header_name":          schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.LengthBetween(1, 256)}, Description: "Destination header name for header credentials."},
			"aws_region":           schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.LengthBetween(1, 32)}, Description: "AWS Region of the RDS or Aurora database. Uses the Resource Gateway's AWS identity."},
			"aws_role_arn":         schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.LengthBetween(1, 2048)}, Description: "Exact IAM role the Resource Gateway assumes before generating a temporary database password."},
			"oauth_token_endpoint": schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.LengthBetween(1, 2048)}, Description: "HTTPS endpoint that issues temporary access tokens."},
			"oauth_client_id":      schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.LengthBetween(1, 1024)}, Description: "OAuth client ID. Required for client credentials and optional for token exchange."},
			"oauth_scopes":         schema.SetAttribute{Optional: true, ElementType: types.StringType, Validators: []validator.Set{setvalidator.SizeAtMost(64)}, Description: "OAuth scopes requested for the Resource."},
			"oauth_audience":       schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.LengthBetween(1, 2048)}, Description: "Optional OAuth audience for the Resource."},
			"secret":               schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "Credential secret for username_password, bearer_token, header, or oauth2_client_credentials. Required when creating or increasing secret_version for those methods; use an ephemeral variable to keep it out of saved plans and state."},
			"secret_version":       schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(1), Validators: []validator.Int64{int64validator.AtLeast(1)}, Description: "For stored-secret methods, increase this value and provide secret to rotate the credential."},
			"default":              schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), Description: "Use when no identity-specific credential is assigned."},
			"users":                assignments("User IDs assigned to this credential."),
			"groups":               assignments("Group IDs assigned to this credential."),
			"service_accounts":     assignments("Service account IDs assigned to this credential."),
			"management_mode":      schema.StringAttribute{Computed: true, Description: "Where this credential is managed."},
			"manager_id":           schema.StringAttribute{Computed: true, Description: "Terraform manager that owns this credential."},
			"manager_instance":     schema.StringAttribute{Computed: true, Description: "Terraform workspace that owns this credential."},
		},
	}
}

func (r *resourceCredentialResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	if request.ProviderData == nil {
		return
	}
	client, ok := request.ProviderData.(*Client)
	if !ok {
		response.Diagnostics.AddError("Unexpected provider data", "Forge client not configured")
		return
	}
	r.client = client
}

func (r *resourceCredentialResource) ValidateConfig(ctx context.Context, request resource.ValidateConfigRequest, response *resource.ValidateConfigResponse) {
	var model resourceCredentialModel
	response.Diagnostics.Append(request.Config.Get(ctx, &model)...)
	if response.Diagnostics.HasError() || model.Kind.IsNull() || model.Kind.IsUnknown() {
		return
	}
	usernameSet := knownNonEmpty(model.Username)
	headerSet := knownNonEmpty(model.HeaderName)
	regionSet := knownNonEmpty(model.AWSRegion)
	roleSet := knownNonEmpty(model.AWSRoleARN)
	tokenEndpointSet := knownNonEmpty(model.OAuthTokenEndpoint)
	clientIDSet := knownNonEmpty(model.OAuthClientID)
	audienceSet := knownNonEmpty(model.OAuthAudience)
	scopesSet := !model.OAuthScopes.IsNull() && !model.OAuthScopes.IsUnknown() && len(model.OAuthScopes.Elements()) > 0
	switch model.Kind.ValueString() {
	case "username_password":
		if !usernameSet {
			response.Diagnostics.AddAttributeError(path.Root("username"), "Missing username", "username is required for username_password credentials")
		}
		if headerSet {
			response.Diagnostics.AddAttributeError(path.Root("header_name"), "Unexpected header name", "header_name is only valid for header credentials")
		}
	case "bearer_token":
		if usernameSet || headerSet {
			response.Diagnostics.AddAttributeError(path.Root("kind"), "Unexpected credential fields", "bearer_token credentials do not use username or header_name")
		}
	case "header":
		if !headerSet {
			response.Diagnostics.AddAttributeError(path.Root("header_name"), "Missing header name", "header_name is required for header credentials")
		}
		if usernameSet {
			response.Diagnostics.AddAttributeError(path.Root("username"), "Unexpected username", "username is only valid for username_password credentials")
		}
	case "aws_rds_iam":
		if !usernameSet || !regionSet {
			response.Diagnostics.AddAttributeError(path.Root("kind"), "Missing AWS database settings", "aws_rds_iam requires username and aws_region")
		}
		if headerSet {
			response.Diagnostics.AddAttributeError(path.Root("header_name"), "Unexpected header name", "header_name is not used for AWS database authentication")
		}
	case "oauth2_client_credentials":
		if !tokenEndpointSet || !clientIDSet {
			response.Diagnostics.AddAttributeError(path.Root("kind"), "Missing OAuth settings", "oauth2_client_credentials requires oauth_token_endpoint and oauth_client_id")
		} else if parsed, err := url.Parse(model.OAuthTokenEndpoint.ValueString()); err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || net.ParseIP(parsed.Hostname()) != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			response.Diagnostics.AddAttributeError(path.Root("oauth_token_endpoint"), "Invalid OAuth token endpoint", "oauth_token_endpoint must be an HTTPS hostname without credentials, query parameters, or a fragment")
		}
		if usernameSet || headerSet {
			response.Diagnostics.AddAttributeError(path.Root("kind"), "Unexpected credential fields", "OAuth client credentials do not use username or header_name")
		}
	case "oauth2_token_exchange":
		if !tokenEndpointSet {
			response.Diagnostics.AddAttributeError(path.Root("kind"), "Missing OAuth settings", "oauth2_token_exchange requires oauth_token_endpoint")
		} else if parsed, err := url.Parse(model.OAuthTokenEndpoint.ValueString()); err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || net.ParseIP(parsed.Hostname()) != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			response.Diagnostics.AddAttributeError(path.Root("oauth_token_endpoint"), "Invalid OAuth token endpoint", "oauth_token_endpoint must be an HTTPS hostname without credentials, query parameters, or a fragment")
		}
		if usernameSet || headerSet {
			response.Diagnostics.AddAttributeError(path.Root("kind"), "Unexpected credential fields", "OAuth token exchange does not use username or header_name")
		}
	}
	if model.Kind.ValueString() != "aws_rds_iam" && (regionSet || roleSet) {
		response.Diagnostics.AddAttributeError(path.Root("aws_region"), "Unexpected AWS settings", "aws_region and aws_role_arn are only valid with aws_rds_iam")
	}
	if model.Kind.ValueString() != "oauth2_client_credentials" && model.Kind.ValueString() != "oauth2_token_exchange" && (tokenEndpointSet || clientIDSet || scopesSet || audienceSet) {
		response.Diagnostics.AddAttributeError(path.Root("oauth_token_endpoint"), "Unexpected OAuth settings", "OAuth settings are only valid with OAuth credentials")
	}
	if !resourceCredentialRequiresSecret(model.Kind.ValueString()) && knownNonEmpty(model.Secret) {
		response.Diagnostics.AddAttributeError(path.Root("secret"), "Unexpected credential secret", "this authentication method does not store a secret")
	}
}

func (r *resourceCredentialResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var model, config resourceCredentialModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &model)...)
	response.Diagnostics.Append(request.Config.Get(ctx, &config)...)
	if response.Diagnostics.HasError() {
		return
	}
	if resourceCredentialRequiresSecret(model.Kind.ValueString()) && !knownNonEmpty(config.Secret) {
		response.Diagnostics.AddAttributeError(path.Root("secret"), "Missing credential secret", "secret is required when creating a Resource credential")
		return
	}
	var result resourceCredentialAPI
	if err := r.client.Do(ctx, http.MethodPost, resourceCredentialCollectionPath(model.ResourceID.ValueString()), resourceCredentialPayload(ctx, model, config.Secret.ValueString(), &response.Diagnostics), &result); err != nil {
		response.Diagnostics.AddError("Create Forge Resource credential", err.Error())
		return
	}
	if response.Diagnostics.HasError() {
		return
	}
	if err := verifyResourceAuthority(r.client, result.ManagementMode, result.ManagerID, result.ManagerInstance); err != nil {
		response.Diagnostics.AddError("Forge Resource credential authority conflict", err.Error())
		return
	}
	refreshResourceCredentialModel(ctx, &model, result, &response.Diagnostics)
	response.Diagnostics.Append(response.State.Set(ctx, &model)...)
}

func (r *resourceCredentialResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var model resourceCredentialModel
	response.Diagnostics.Append(request.State.Get(ctx, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	var result resourceCredentialAPI
	err := r.client.Do(ctx, http.MethodGet, resourceCredentialItemPath(model.ResourceID.ValueString(), model.ID.ValueString()), nil, &result)
	if IsNotFound(err) {
		response.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Read Forge Resource credential", err.Error())
		return
	}
	if err := verifyResourceAuthority(r.client, result.ManagementMode, result.ManagerID, result.ManagerInstance); err != nil {
		response.Diagnostics.AddError("Forge Resource credential authority conflict", err.Error())
		return
	}
	refreshResourceCredentialModel(ctx, &model, result, &response.Diagnostics)
	response.Diagnostics.Append(response.State.Set(ctx, &model)...)
}

func (r *resourceCredentialResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var model, prior, config resourceCredentialModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &model)...)
	response.Diagnostics.Append(request.State.Get(ctx, &prior)...)
	response.Diagnostics.Append(request.Config.Get(ctx, &config)...)
	if response.Diagnostics.HasError() {
		return
	}
	secret := ""
	if !resourceCredentialRequiresSecret(prior.Kind.ValueString()) && resourceCredentialRequiresSecret(model.Kind.ValueString()) && !knownNonEmpty(config.Secret) {
		response.Diagnostics.AddAttributeError(path.Root("secret"), "Missing credential secret", "secret is required when changing to a stored credential")
		return
	}
	if resourceCredentialRequiresSecret(model.Kind.ValueString()) && model.SecretVersion.ValueInt64() < prior.SecretVersion.ValueInt64() {
		response.Diagnostics.AddAttributeError(path.Root("secret_version"), "Invalid credential version", "secret_version cannot decrease")
		return
	}
	if resourceCredentialRequiresSecret(model.Kind.ValueString()) && model.SecretVersion.ValueInt64() > prior.SecretVersion.ValueInt64() {
		if !knownNonEmpty(config.Secret) {
			response.Diagnostics.AddAttributeError(path.Root("secret"), "Missing replacement secret", "secret is required when secret_version changes")
			return
		}
		secret = config.Secret.ValueString()
	}
	if !resourceCredentialRequiresSecret(prior.Kind.ValueString()) && resourceCredentialRequiresSecret(model.Kind.ValueString()) {
		secret = config.Secret.ValueString()
	}
	var result resourceCredentialAPI
	if err := r.client.Do(ctx, http.MethodPut, resourceCredentialItemPath(model.ResourceID.ValueString(), model.ID.ValueString()), resourceCredentialPayload(ctx, model, secret, &response.Diagnostics), &result); err != nil {
		response.Diagnostics.AddError("Update Forge Resource credential", err.Error())
		return
	}
	if response.Diagnostics.HasError() {
		return
	}
	if err := verifyResourceAuthority(r.client, result.ManagementMode, result.ManagerID, result.ManagerInstance); err != nil {
		response.Diagnostics.AddError("Forge Resource credential authority conflict", err.Error())
		return
	}
	refreshResourceCredentialModel(ctx, &model, result, &response.Diagnostics)
	response.Diagnostics.Append(response.State.Set(ctx, &model)...)
}

func (r *resourceCredentialResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var model resourceCredentialModel
	response.Diagnostics.Append(request.State.Get(ctx, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	err := r.client.Do(ctx, http.MethodDelete, resourceCredentialItemPath(model.ResourceID.ValueString(), model.ID.ValueString()), nil, nil)
	if err != nil && !IsNotFound(err) {
		response.Diagnostics.AddError("Delete Forge Resource credential", err.Error())
	}
}

func (r *resourceCredentialResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resourceID, credentialID, err := parseResourceCredentialImportID(request.ID)
	if err != nil {
		response.Diagnostics.AddError("Invalid Resource credential import ID", "Use resource_id/credential_id.")
		return
	}
	response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("resource_id"), resourceID)...)
	response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("id"), credentialID)...)
}

func resourceCredentialPayload(ctx context.Context, model resourceCredentialModel, secret string, diagnostics *diag.Diagnostics) map[string]any {
	assignedTo := map[string]any{
		"users": setStrings(ctx, model.Users, diagnostics), "groups": setStrings(ctx, model.Groups, diagnostics),
		"serviceAccounts": setStrings(ctx, model.ServiceAccounts, diagnostics),
	}
	payload := map[string]any{
		"name": model.Name.ValueString(), "kind": model.Kind.ValueString(), "default": model.Default.ValueBool(), "assignedTo": assignedTo,
	}
	if knownNonEmpty(model.Username) {
		payload["username"] = model.Username.ValueString()
	}
	if knownNonEmpty(model.HeaderName) {
		payload["headerName"] = model.HeaderName.ValueString()
	}
	if model.Kind.ValueString() == "aws_rds_iam" {
		authentication := map[string]any{"region": model.AWSRegion.ValueString()}
		if knownNonEmpty(model.AWSRoleARN) {
			authentication["roleArn"] = model.AWSRoleARN.ValueString()
		}
		payload["authentication"] = authentication
	} else if model.Kind.ValueString() == "oauth2_client_credentials" || model.Kind.ValueString() == "oauth2_token_exchange" {
		authentication := map[string]any{
			"tokenEndpoint": model.OAuthTokenEndpoint.ValueString(),
			"clientId":      model.OAuthClientID.ValueString(),
			"scopes":        setStrings(ctx, model.OAuthScopes, diagnostics),
		}
		if knownNonEmpty(model.OAuthAudience) {
			authentication["audience"] = model.OAuthAudience.ValueString()
		}
		payload["authentication"] = authentication
	}
	if secret != "" {
		payload["secret"] = secret
	}
	return payload
}

func refreshResourceCredentialModel(ctx context.Context, model *resourceCredentialModel, result resourceCredentialAPI, diagnostics *diag.Diagnostics) {
	if model.SecretVersion.IsNull() || model.SecretVersion.IsUnknown() {
		model.SecretVersion = types.Int64Value(1)
	}
	model.ID = types.StringValue(result.ID)
	model.ResourceID = types.StringValue(result.ResourceID)
	model.Name = types.StringValue(result.Name)
	model.Kind = types.StringValue(result.Kind)
	model.Username = nullableString(result.Username)
	model.HeaderName = nullableString(result.HeaderName)
	if result.Authentication == nil {
		model.AWSRegion, model.AWSRoleARN = types.StringNull(), types.StringNull()
		model.OAuthTokenEndpoint, model.OAuthClientID, model.OAuthAudience = types.StringNull(), types.StringNull(), types.StringNull()
		model.OAuthScopes = types.SetNull(types.StringType)
	} else {
		model.AWSRegion = nullableNonEmptyString(result.Authentication.Region)
		if result.Authentication.RoleARN == "" {
			model.AWSRoleARN = types.StringNull()
		} else {
			model.AWSRoleARN = types.StringValue(result.Authentication.RoleARN)
		}
		model.OAuthTokenEndpoint = nullableNonEmptyString(result.Authentication.TokenEndpoint)
		model.OAuthClientID = nullableNonEmptyString(result.Authentication.ClientID)
		model.OAuthAudience = nullableNonEmptyString(result.Authentication.Audience)
		if result.Kind == "oauth2_client_credentials" || result.Kind == "oauth2_token_exchange" {
			model.OAuthScopes = stringSetValue(ctx, result.Authentication.Scopes, diagnostics)
		} else {
			model.OAuthScopes = types.SetNull(types.StringType)
		}
	}
	model.Secret = types.StringNull()
	model.Default = types.BoolValue(result.Default)
	model.Users = stringSetValue(ctx, result.AssignedTo.Users, diagnostics)
	model.Groups = stringSetValue(ctx, result.AssignedTo.Groups, diagnostics)
	model.ServiceAccounts = stringSetValue(ctx, result.AssignedTo.ServiceAccounts, diagnostics)
	model.ManagementMode = types.StringValue(result.ManagementMode)
	model.ManagerID = types.StringValue(result.ManagerID)
	model.ManagerInstance = types.StringValue(result.ManagerInstance)
}

func resourceCredentialCollectionPath(resourceID string) string {
	return "resources/" + url.PathEscape(resourceID) + "/credentials"
}

func resourceCredentialItemPath(resourceID, credentialID string) string {
	return resourceCredentialCollectionPath(resourceID) + "/" + url.PathEscape(credentialID)
}

func parseResourceCredentialImportID(value string) (string, string, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", errors.New("expected resource_id/credential_id")
	}
	return parts[0], parts[1], nil
}

func knownNonEmpty(value types.String) bool {
	return !value.IsNull() && !value.IsUnknown() && strings.TrimSpace(value.ValueString()) != ""
}

func resourceCredentialRequiresSecret(kind string) bool {
	return kind != "aws_rds_iam" && kind != "oauth2_token_exchange"
}

func nullableString(value *string) types.String {
	if value == nil {
		return types.StringNull()
	}
	return types.StringValue(*value)
}

func nullableNonEmptyString(value string) types.String {
	if value == "" {
		return types.StringNull()
	}
	return types.StringValue(value)
}

func setStrings(ctx context.Context, value types.Set, diagnostics *diag.Diagnostics) []string {
	if value.IsNull() || value.IsUnknown() {
		return []string{}
	}
	var values []string
	if diags := value.ElementsAs(ctx, &values, false); diags.HasError() {
		diagnostics.Append(diags...)
		return nil
	}
	sort.Strings(values)
	return values
}

func stringSetValue(ctx context.Context, values []string, diagnostics *diag.Diagnostics) types.Set {
	if values == nil {
		values = []string{}
	}
	sort.Strings(values)
	value, diags := types.SetValueFrom(ctx, types.StringType, values)
	if diags.HasError() {
		diagnostics.Append(diags...)
		return types.SetNull(types.StringType)
	}
	return value
}

var _ resource.ResourceWithConfigure = (*resourceCredentialResource)(nil)
var _ resource.ResourceWithValidateConfig = (*resourceCredentialResource)(nil)
var _ resource.ResourceWithImportState = (*resourceCredentialResource)(nil)
