terraform {
  required_version = ">= 1.11.0"

  required_providers {
    forge = {
      source  = "a37ai/forge"
      version = "~> 0.4.0"
    }
  }
}

variable "production_database_password" {
  type      = string
  sensitive = true
  ephemeral = true
}

variable "internal_api_token" {
  type      = string
  sensitive = true
  ephemeral = true
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

resource "forge_resource" "production_database" {
  name                = "Production PostgreSQL"
  protocol            = "postgres"
  upstream_host       = "db.internal.example"
  upstream_port       = 5432
  upstream_tls        = true
  transparent_routing = true
}

resource "forge_resource_credential" "production_database" {
  resource_id    = forge_resource.production_database.id
  name           = "Application account"
  kind           = "username_password"
  username       = "forge_app"
  secret         = var.production_database_password
  secret_version = 1
  default        = true
}

resource "forge_access_policy" "production_database_writes" {
  id                   = "production-database-writes"
  name                 = "Block production database deletes"
  action               = "block"
  severity             = "high"
  enforcement          = "enforce"
  enforcement_surfaces = ["resource_proxy"]
  resources            = [forge_resource.production_database.id]

  conditions = {
    field = "request.postgres.command"
    op    = "eq"
    value = "DELETE"
  }
}

resource "forge_resource" "internal_api" {
  name          = "Internal API"
  protocol      = "http"
  upstream_host = "api.internal.example"
  upstream_port = 443
  upstream_tls  = true
}

resource "forge_resource_credential" "internal_api" {
  resource_id    = forge_resource.internal_api.id
  name           = "API token"
  kind           = "bearer_token"
  secret         = var.internal_api_token
  secret_version = 1
  default        = true
}

resource "forge_access_policy" "monitor_internal_api_deletes" {
  id                   = "monitor-internal-api-deletes"
  name                 = "Monitor deletes to the internal API"
  action               = "block"
  enforcement          = "monitor"
  enforcement_surfaces = ["resource_proxy"]
  resources            = [forge_resource.internal_api.id]

  conditions = {
    field = "request.http.method"
    op    = "eq"
    value = "DELETE"
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
