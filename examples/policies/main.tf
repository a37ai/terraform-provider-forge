terraform {
  required_version = ">= 1.8.0"

  required_providers {
    forge = {
      source  = "a37ai/forge"
      version = "~> 0.4.0"
    }
  }
}

provider "forge" {
  organization_id  = "org.example"
  manager_id       = "policy-repository"
  manager_instance = "production"
}

resource "forge_content_policy" "review_sensitive_prompt" {
  id          = "review-sensitive-prompt"
  name        = "Review sensitive prompts"
  evaluate_on = ["prompt"]
  action      = "flag_for_review"
  conditions = {
    field = "request.prompt"
    op    = "contains"
    value = "confidential"
  }
}

resource "forge_access_policy" "untrusted_runtime" {
  id                      = "untrusted-runtime"
  name                    = "Block an untrusted local runtime"
  action                  = "block"
  severity                = "high"
  acknowledge_broad_scope = true
  enforcement_surfaces    = ["inline_hook"]
  conditions = {
    all = [
      { field = "process.id", op = "eq", value = "runtime.local" },
      { field = "process.path", op = "starts_with", value = "/tmp/" }
    ]
  }
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
