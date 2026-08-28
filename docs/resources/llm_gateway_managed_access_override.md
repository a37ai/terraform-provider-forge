# forge_llm_gateway_managed_access_override

Assigns an LLM Gateway access profile and budget override to a user, group, or
service account.

```hcl
resource "forge_llm_gateway_managed_access_override" "build" {
  target_kind       = "service_account"
  target_id         = forge_llm_gateway_service_account.build.id
  access_profile_id = forge_llm_gateway_access_profile.ci.id
  budget_window     = "monthly"
  total_token_limit = 1000000
}
```

At least one of `amount_usd` or `total_token_limit` must be configured.
