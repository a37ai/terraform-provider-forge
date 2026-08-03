package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
)

func TestResolveForgeEndpoint(t *testing.T) {
	t.Setenv("FORGE_ENDPOINT", "")
	if got := resolveForgeEndpoint(""); got != "https://api.forge.ai" {
		t.Fatalf("default endpoint = %q", got)
	}

	t.Setenv("FORGE_ENDPOINT", "https://api-staging.forge.ai")
	if got := resolveForgeEndpoint(""); got != "https://api-staging.forge.ai" {
		t.Fatalf("environment endpoint = %q", got)
	}

	if got := resolveForgeEndpoint("https://api.example.test"); got != "https://api.example.test" {
		t.Fatalf("configured endpoint = %q", got)
	}
}

func TestProviderRegistersTypedDiscoveryAndRegoTestDataSources(t *testing.T) {
	provider := &forgeProvider{}
	got := map[string]bool{}
	for _, constructor := range provider.DataSources(context.Background()) {
		var metadata datasource.MetadataResponse
		constructor().Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "forge"}, &metadata)
		got[metadata.TypeName] = true
	}
	for _, name := range []string{"forge_user", "forge_group", "forge_agent", "forge_ai_product", "forge_integration", "forge_mcp_server", "forge_mcp_tool", "forge_skill", "forge_gateway_provider", "forge_rego_test"} {
		if !got[name] {
			t.Errorf("data source %s is not registered", name)
		}
	}
}
