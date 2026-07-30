package provider

import "testing"

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
