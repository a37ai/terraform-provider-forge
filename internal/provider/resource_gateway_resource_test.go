package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestResourceGatewaySchemaContainsNoDeploymentSecret(t *testing.T) {
	var response resource.SchemaResponse
	(&resourceGatewayResource{}).Schema(context.Background(), resource.SchemaRequest{}, &response)
	for _, forbidden := range []string{"token", "secret", "deployment_token", "bootstrap_token"} {
		if _, exists := response.Schema.Attributes[forbidden]; exists {
			t.Fatalf("Resource Gateway schema exposes %s", forbidden)
		}
	}
	for _, name := range []string{"name", "hostname"} {
		attribute := response.Schema.Attributes[name].(schema.StringAttribute)
		if !attribute.Required {
			t.Errorf("%s must be required", name)
		}
	}
	if enabled := response.Schema.Attributes["enabled"].(schema.BoolAttribute); !enabled.Optional || !enabled.Computed || enabled.Default == nil {
		t.Fatalf("enabled must have a stable optional default: %#v", enabled)
	}
}

func TestResourceGatewayPayloadContainsOnlyConfiguration(t *testing.T) {
	model := resourceGatewayModel{Name: types.StringValue("Production access"), Hostname: types.StringValue("resources.example.com"), Enabled: types.BoolValue(true)}
	want := map[string]any{"name": "Production access", "hostname": "resources.example.com", "enabled": true}
	if got := resourceGatewayPayload(model); !reflect.DeepEqual(got, want) {
		t.Fatalf("payload=%#v, want=%#v", got, want)
	}
}

func TestResourceGatewayCreateContractHasNoDeploymentToken(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/headless/v1/organizations/org.test/resource-gateways" {
			t.Fatalf("request=%s %s", request.Method, request.URL.Path)
		}
		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if _, exists := payload["deploymentToken"]; exists {
			t.Fatal("Terraform sent a deployment token")
		}
		manager, instance := "workspace", "instance"
		_ = json.NewEncoder(w).Encode(resourceGatewayAPI{
			ID: "rgw_1", Name: "Production access", Hostname: "resources.example.com", Enabled: true,
			ManagementMode: "terraform", ManagerID: &manager, ManagerInstance: &instance,
		})
	})
	resourceUnderTest := &resourceGatewayResource{client: client}
	model := resourceGatewayModel{Name: types.StringValue("Production access"), Hostname: types.StringValue("resources.example.com"), Enabled: types.BoolValue(true)}
	var result resourceGatewayAPI
	if err := resourceUnderTest.client.Do(context.Background(), http.MethodPost, "resource-gateways", resourceGatewayPayload(model), &result); err != nil {
		t.Fatal(err)
	}
	refreshResourceGatewayModel(&model, result)
	if model.ID.ValueString() != "rgw_1" {
		t.Fatalf("refreshed model=%+v", model)
	}
}
