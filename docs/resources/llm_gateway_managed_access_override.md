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
  alert_threshold_percent = 80
}
```

At least one of `amount_usd` or `total_token_limit` must be configured.
`alert_threshold_percent` is optional. Forge sends one admin notification when
actual usage first reaches that percentage in the budget window. For rolling
windows, the alert rearms after usage falls below the threshold.
