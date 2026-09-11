package provider

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestResourceSchemaExposesOnlyImplementedProtocolsAndSafeDefaults(t *testing.T) {
	var response resource.SchemaResponse
	(&resourceProxyResource{}).Schema(context.Background(), resource.SchemaRequest{}, &response)

	protocol := response.Schema.Attributes["protocol"].(schema.StringAttribute)
	if len(protocol.Validators) != 1 {
		t.Fatalf("protocol validators=%d, want one closed enum", len(protocol.Validators))
	}
	for _, value := range []string{"http", "postgres", "mysql", "redis"} {
		var validation validator.StringResponse
		protocol.Validators[0].ValidateString(context.Background(), validator.StringRequest{ConfigValue: types.StringValue(value)}, &validation)
		if validation.Diagnostics.HasError() {
			t.Errorf("implemented protocol %q was rejected: %v", value, validation.Diagnostics)
		}
	}
	for _, name := range []string{"upstream_tls", "enabled", "transparent_routing"} {
		attribute := response.Schema.Attributes[name].(schema.BoolAttribute)
		if !attribute.Optional || !attribute.Computed || attribute.Default == nil {
			t.Errorf("%s must have a stable optional default: %#v", name, attribute)
		}
	}
	ca := response.Schema.Attributes["upstream_ca_pem"].(schema.StringAttribute)
	if !ca.Optional || ca.Sensitive || ca.WriteOnly || ca.Computed {
		t.Fatalf("private CA certificate is readable public configuration: %#v", ca)
	}

	model := resourceProxyModel{
		Name: types.StringValue("Production API"), Protocol: types.StringValue("http"),
		UpstreamHost: types.StringValue("api.example.com"), UpstreamPort: types.Int64Value(443),
		UpstreamTLS: types.BoolValue(true), UpstreamCAPEM: types.StringValue("-----BEGIN CERTIFICATE-----\npublic-ca\n-----END CERTIFICATE-----"), Enabled: types.BoolValue(true), TransparentRouting: types.BoolValue(false),
	}
	payload := resourceProxyPayload(model)
	if !reflect.DeepEqual(payload, map[string]any{
		"name": "Production API", "protocol": "http", "upstreamHost": "api.example.com", "upstreamPort": int64(443),
		"upstreamTls": true, "upstreamCaPem": "-----BEGIN CERTIFICATE-----\npublic-ca\n-----END CERTIFICATE-----", "enabled": true, "transparentRouting": false,
		"gatewayId": nil,
	}) {
		t.Fatalf("resource payload=%#v", payload)
	}
	if gateway := response.Schema.Attributes["gateway_id"].(schema.StringAttribute); !gateway.Optional || gateway.Computed {
		t.Fatalf("gateway_id must be an optional assignment: %#v", gateway)
	}
	if accessName := response.Schema.Attributes["access_name"].(schema.StringAttribute); !accessName.Computed || accessName.Optional {
		t.Fatalf("access_name must be read-only: %#v", accessName)
	}
	if err := validateResourceUpstreamCA(model); err != nil {
		t.Fatalf("valid private CA configuration was rejected: %v", err)
	}
	model.UpstreamTLS = types.BoolValue(false)
	if err := validateResourceUpstreamCA(model); err == nil {
		t.Fatal("PostgreSQL Resource was accepted without upstream encryption")
	}
	model.Protocol = types.StringValue("http")
	if err := validateResourceUpstreamCA(model); err == nil {
		t.Fatal("private CA was accepted without upstream encryption")
	}
	model.UpstreamTLS = types.BoolValue(true)
	model.UpstreamCAPEM = types.StringValue(" trailing-newline\n")
	if err := validateResourceUpstreamCA(model); err == nil {
		t.Fatal("non-stable CA whitespace was accepted")
	}
}

func TestResourceCredentialSecretIsActuallyWriteOnly(t *testing.T) {
	var response resource.SchemaResponse
	(&resourceCredentialResource{}).Schema(context.Background(), resource.SchemaRequest{}, &response)
	secret := response.Schema.Attributes["secret"].(schema.StringAttribute)
	if !secret.Optional || !secret.Sensitive || !secret.WriteOnly || secret.Computed {
		t.Fatalf("secret schema must be optional, sensitive, write-only, and not computed: %#v", secret)
	}
	if _, exists := response.Schema.Attributes["secret_id"]; exists {
		t.Fatal("internal secret reference must not be exposed in Terraform")
	}
	if _, exists := response.Schema.Attributes["secret_ref"]; exists {
		t.Fatal("internal secret reference must not be exposed in Terraform")
	}
}

func TestResourceCredentialHeaderNameMatchesAPILimit(t *testing.T) {
	var response resource.SchemaResponse
	(&resourceCredentialResource{}).Schema(context.Background(), resource.SchemaRequest{}, &response)
	header := response.Schema.Attributes["header_name"].(schema.StringAttribute)
	for _, test := range []struct {
		length  int
		wantErr bool
	}{{length: 256}, {length: 257, wantErr: true}} {
		var validation validator.StringResponse
		header.Validators[0].ValidateString(context.Background(), validator.StringRequest{ConfigValue: types.StringValue(strings.Repeat("x", test.length))}, &validation)
		if validation.Diagnostics.HasError() != test.wantErr {
			t.Fatalf("header_name length %d error=%v, wantErr=%v", test.length, validation.Diagnostics, test.wantErr)
		}
	}
}

func TestResourceCredentialPayloadOmitsSecretExceptDuringCreateOrRotation(t *testing.T) {
	model := resourceCredentialModel{
		Name: types.StringValue("Application account"), Kind: types.StringValue("username_password"),
		Username: types.StringValue("forge_app"), HeaderName: types.StringNull(), Default: types.BoolValue(true),
		Users: stringSet("usr_2", "usr_1"), Groups: emptySet(), ServiceAccounts: emptySet(),
	}
	var diagnostics diag.Diagnostics
	withoutSecret := resourceCredentialPayload(context.Background(), model, "", &diagnostics)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if _, exists := withoutSecret["secret"]; exists {
		t.Fatalf("ordinary update leaked a secret field: %#v", withoutSecret)
	}
	assigned := withoutSecret["assignedTo"].(map[string]any)
	if got := assigned["users"]; !reflect.DeepEqual(got, []string{"usr_1", "usr_2"}) {
		t.Fatalf("users=%#v", got)
	}
	withSecret := resourceCredentialPayload(context.Background(), model, "do-not-persist", &diagnostics)
	if withSecret["secret"] != "do-not-persist" {
		t.Fatalf("create/rotation payload missing write-only secret: %#v", withSecret)
	}
}

func TestResourceCredentialPayloadUsesGatewayAWSIdentityWithoutSecret(t *testing.T) {
	model := resourceCredentialModel{
		Name: types.StringValue("RDS IAM access"), Kind: types.StringValue("aws_rds_iam"),
		Username: types.StringValue("forge_app"), AWSRegion: types.StringValue("us-west-2"),
		AWSRoleARN: types.StringValue("arn:aws:iam::123456789012:role/forge-database"), Default: types.BoolValue(true),
		Users: emptySet(), Groups: emptySet(), ServiceAccounts: emptySet(),
	}
	var diagnostics diag.Diagnostics
	payload := resourceCredentialPayload(context.Background(), model, "", &diagnostics)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if _, exists := payload["secret"]; exists {
		t.Fatalf("IAM payload contains secret: %#v", payload)
	}
	authentication := payload["authentication"].(map[string]any)
	if authentication["region"] != "us-west-2" || authentication["roleArn"] != "arn:aws:iam::123456789012:role/forge-database" {
		t.Fatalf("IAM authentication=%#v", authentication)
	}
}

func TestResourceCredentialPayloadUsesOAuthClientCredentials(t *testing.T) {
	model := resourceCredentialModel{
		Name: types.StringValue("API temporary access"), Kind: types.StringValue("oauth2_client_credentials"),
		OAuthTokenEndpoint: types.StringValue("https://identity.example.com/oauth/token"), OAuthClientID: types.StringValue("agent-client"),
		OAuthScopes: stringSet("write", "read"), OAuthAudience: types.StringValue("https://api.example.com"), Default: types.BoolValue(true),
		Users: emptySet(), Groups: emptySet(), ServiceAccounts: stringSet("svc_1"),
	}
	var diagnostics diag.Diagnostics
	payload := resourceCredentialPayload(context.Background(), model, "client-secret", &diagnostics)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if payload["secret"] != "client-secret" {
		t.Fatalf("OAuth client secret missing from write-only payload: %#v", payload)
	}
	authentication := payload["authentication"].(map[string]any)
	if authentication["tokenEndpoint"] != "https://identity.example.com/oauth/token" || authentication["clientId"] != "agent-client" || authentication["audience"] != "https://api.example.com" || !reflect.DeepEqual(authentication["scopes"], []string{"read", "write"}) {
		t.Fatalf("OAuth authentication=%#v", authentication)
	}
}

func TestResourceCredentialPayloadUsesKeylessOAuthTokenExchange(t *testing.T) {
	model := resourceCredentialModel{
		Name: types.StringValue("User identity exchange"), Kind: types.StringValue("oauth2_token_exchange"),
		OAuthTokenEndpoint: types.StringValue("https://identity.example.com/oauth/token"), OAuthClientID: types.StringValue("forge-resource-client"),
		OAuthScopes: stringSet("orders.read"), OAuthAudience: types.StringValue("orders-api"), Default: types.BoolValue(true),
		Users: emptySet(), Groups: emptySet(), ServiceAccounts: emptySet(),
	}
	var diagnostics diag.Diagnostics
	payload := resourceCredentialPayload(context.Background(), model, "", &diagnostics)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if _, exists := payload["secret"]; exists {
		t.Fatalf("token exchange payload contains a secret: %#v", payload)
	}
	authentication := payload["authentication"].(map[string]any)
	if authentication["tokenEndpoint"] != "https://identity.example.com/oauth/token" || authentication["clientId"] != "forge-resource-client" || authentication["audience"] != "orders-api" || !reflect.DeepEqual(authentication["scopes"], []string{"orders.read"}) {
		t.Fatalf("token exchange authentication=%#v", authentication)
	}
}

func TestResourceCredentialRefreshCannotPlaceSecretInState(t *testing.T) {
	username := "forge_app"
	model := resourceCredentialModel{Secret: types.StringValue("must-disappear"), SecretVersion: types.Int64Value(8)}
	result := resourceCredentialAPI{
		ID: "cred_1", ResourceID: "res_1", Name: "Application account", Kind: "username_password", Username: &username,
		Default: true, AssignedTo: resourceCredentialAssignmentsAPI{Users: []string{"usr_1"}},
		ManagementMode: "terraform", ManagerID: "manager", ManagerInstance: "production",
	}
	var diagnostics diag.Diagnostics
	refreshResourceCredentialModel(context.Background(), &model, result, &diagnostics)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if !model.Secret.IsNull() || model.SecretVersion.ValueInt64() != 8 {
		t.Fatalf("refresh retained secret or lost the rotation trigger: secret=%#v version=%d", model.Secret, model.SecretVersion.ValueInt64())
	}
	imported := resourceCredentialModel{SecretVersion: types.Int64Null()}
	refreshResourceCredentialModel(context.Background(), &imported, result, &diagnostics)
	if imported.SecretVersion.ValueInt64() != 1 {
		t.Fatalf("import did not initialize the local rotation counter: %d", imported.SecretVersion.ValueInt64())
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"must-disappear", "secretId", "secretRef"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("credential read contract leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestResourceCredentialRefreshPreservesEmptyOAuthScopes(t *testing.T) {
	model := resourceCredentialModel{SecretVersion: types.Int64Value(1)}
	result := resourceCredentialAPI{
		ID: "cred_1", ResourceID: "res_1", Name: "Temporary API access", Kind: "oauth2_client_credentials",
		Authentication: &resourceCredentialAuthenticationAPI{TokenEndpoint: "https://identity.example.com/token", ClientID: "agent-client"},
		AssignedTo:     resourceCredentialAssignmentsAPI{}, ManagementMode: "terraform", ManagerID: "manager", ManagerInstance: "production",
	}
	var diagnostics diag.Diagnostics
	refreshResourceCredentialModel(context.Background(), &model, result, &diagnostics)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if model.OAuthScopes.IsNull() || model.OAuthScopes.IsUnknown() || len(model.OAuthScopes.Elements()) != 0 {
		t.Fatalf("empty OAuth scopes were not preserved as an empty set: %#v", model.OAuthScopes)
	}
}

func TestResourceCredentialImportAndAuthorityAreUnambiguous(t *testing.T) {
	resourceID, credentialID, err := parseResourceCredentialImportID("res_1/cred_1")
	if err != nil || resourceID != "res_1" || credentialID != "cred_1" {
		t.Fatalf("import=%q/%q err=%v", resourceID, credentialID, err)
	}
	for _, invalid := range []string{"", "res_1", "/cred_1", "res_1/", "res_1/cred_1/extra"} {
		if _, _, err := parseResourceCredentialImportID(invalid); err == nil {
			t.Errorf("accepted invalid import ID %q", invalid)
		}
	}
	client := &Client{managerID: "manager", managerInstance: "production"}
	if err := verifyResourceAuthority(client, "terraform", "manager", "production"); err != nil {
		t.Fatal(err)
	}
	for _, authority := range [][3]string{{"forge", "", ""}, {"terraform", "other", "production"}, {"terraform", "manager", "other"}} {
		if err := verifyResourceAuthority(client, authority[0], authority[1], authority[2]); err == nil {
			t.Errorf("accepted foreign authority %#v", authority)
		}
	}
}
