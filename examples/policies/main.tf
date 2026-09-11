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

variable "production_cache_password" {
  type      = string
  sensitive = true
  ephemeral = true
}

provider "forge" {
  organization_id  = "org.example"
  manager_id       = "policy-repository"
  manager_instance = "production"
}

resource "forge_resource_gateway" "production" {
  name     = "Production access"
  hostname = "resources.example.com"
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
  gateway_id          = forge_resource_gateway.production.id
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

resource "forge_resource_policy" "production_database_writes" {
  id          = "production-database-writes"
  name        = "Block production database deletes"
  action      = "block"
  severity    = "high"
  enforcement = "enforce"
  resources   = [forge_resource.production_database.id]
  message     = "Production DELETE commands are not allowed."

  conditions = {
    field = "request.postgres.command"
    op    = "eq"
    value = "DELETE"
  }
}

resource "forge_resource_policy" "production_database_results" {
  id                    = "production-database-results"
  name                  = "Protect customer email results"
  action                = "redact"
  data_target           = "postgres_result"
  resources             = [forge_resource.production_database.id]
  redaction_strategy    = "constant"
  redaction_replacement = "[REDACTED]"
  redaction_paths       = ["$.email"]
  conditions            = { field = "request.postgres.tables", op = "contains", value = "customers" }
}

resource "forge_resource_policy" "approve_production_updates" {
  id            = "approve-production-updates"
  name          = "Approve production updates"
  action        = "require_approval"
  approval_mode = "admin_approval"
  resources     = [forge_resource.production_database.id]
  conditions    = { field = "request.postgres.command", op = "eq", value = "UPDATE" }
}

resource "forge_resource" "internal_api" {
  name          = "Internal API"
  protocol      = "http"
  upstream_host = "api.internal.example"
  upstream_port = 443
  upstream_tls  = true
  gateway_id    = forge_resource_gateway.production.id
}

resource "forge_resource_credential" "internal_api" {
  resource_id          = forge_resource.internal_api.id
  name                 = "User identity exchange"
  kind                 = "oauth2_token_exchange"
  oauth_token_endpoint = "https://identity.example.com/oauth/token"
  oauth_client_id      = "forge-resource-client"
  oauth_audience       = "orders-api"
  oauth_scopes         = ["orders.read"]
  default              = true
}

resource "forge_resource_policy" "monitor_internal_api_deletes" {
  id          = "monitor-internal-api-deletes"
  name        = "Monitor deletes to the internal API"
  action      = "block"
  enforcement = "monitor"
  resources   = [forge_resource.internal_api.id]

  conditions = {
    field = "request.http.method"
    op    = "eq"
    value = "DELETE"
  }
}

resource "forge_resource_policy" "filter_internal_api_response" {
  id                     = "filter-internal-api-response"
  name                   = "Hide disabled customer records"
  action                 = "filter"
  data_target            = "http_response_body"
  resources              = [forge_resource.internal_api.id]
  filter_collection_path = "$.customers"
  filter_path            = "$.status"
  filter_operator        = "eq"
  filter_value           = "disabled"
  filter_on_unavailable  = "block"

  module = <<-REGO
    package forge.resource
    match := {"matched": input.request.http.path == "/customers"}
  REGO
}

resource "forge_resource" "production_cache" {
  name                = "Production Redis"
  protocol            = "redis"
  upstream_host       = "cache.internal.example"
  upstream_port       = 6379
  upstream_tls        = true
  transparent_routing = true
  gateway_id          = forge_resource_gateway.production.id
}

resource "forge_resource_credential" "production_cache" {
  resource_id    = forge_resource.production_cache.id
  name           = "Agent cache access"
  kind           = "username_password"
  username       = "forge_agent"
  secret         = var.production_cache_password
  secret_version = 1
  default        = true
}

resource "forge_resource_policy" "approve_cache_deletes" {
  id            = "approve-cache-deletes"
  name          = "Approve cache deletes"
  action        = "require_approval"
  approval_mode = "admin_approval"
  resources     = [forge_resource.production_cache.id]
  conditions    = { field = "request.redis.command", op = "eq", value = "DEL" }
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
