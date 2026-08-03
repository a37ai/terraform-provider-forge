terraform {
  required_version = ">= 1.8.0"

  required_providers {
    forge = {
      source  = "a37ai/forge"
      version = "0.1.0"
    }
  }
}

provider "forge" {
  organization_id  = "org.example"
  manager_id       = "policy-repository"
  manager_instance = "production"
}

resource "forge_llm_gateway_access_profile" "approved_models" {
  id               = "approved-models"
  name             = "Approved models"
  state            = "active"
  enforcement_mode = "enforce"
  model_patterns   = ["claude-sonnet", "gpt-5"]
  route {
    provider                = "OpenAI"
    name                    = "Primary OpenAI"
    requested_model_pattern = "gpt-*"
    upstream_model          = "gpt-5"
    api_surface             = "openai_chat_completions"
    rollout_state           = "enforce"
    enforcement_mode        = "enforce"
  }
}

resource "forge_mcp_acl" "github_write" {
  id     = "github-write"
  name   = "Restrict GitHub write tools"
  server = "github"
  tools  = ["create_pull_request", "merge_pull_request"]
  groups = ["Engineering"]
  effect = "allow"
}
