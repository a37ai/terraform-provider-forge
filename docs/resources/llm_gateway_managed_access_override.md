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

Create one resource per target/profile pair to grant several profiles to the
same person, group or service account. `hosted_default = true` marks the
preferred profile for hosted requests without a selector. The default flag
does not expand private network credentials.

All assignments for the same target share one aggregate budget. Use identical
budget settings for those resources to avoid drift. Removing one assignment
removes only that target/profile pair and keeps the other assignments.
