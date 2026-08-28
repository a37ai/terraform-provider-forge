# forge_llm_gateway_service_account

Creates and manages an LLM Gateway service account.

```hcl
resource "forge_llm_gateway_service_account" "build" {
  name        = "Build bot"
  description = "CI inference identity"
  owner_kind  = "app_integration"
  owner_id    = "integration_ci"
  environment = "production"
}
```

`id` and `state` are computed. Destroy disables the service account.
