# forge_llm_gateway_managed_access_override

Assigns an LLM Gateway access profile to a user, group, or service account.
Spending limits are optional and independent; configure them in Gateway → Budgets
or through the budget API.
Use `forge_llm_gateway_budget` for spending and token limits. Temporary
allowances can be granted through the Console or guarded public budget API.

```hcl
resource "forge_llm_gateway_managed_access_override" "build" {
  target_kind       = "service_account"
  target_id         = forge_llm_gateway_service_account.build.id
  access_profile_id = forge_llm_gateway_access_profile.ci.id
}
```

Create one resource per target/profile pair to grant several profiles to the
same person, group or service account. `hosted_default = true` marks the
preferred profile for hosted requests without a selector. The default flag
does not expand private network credentials.

Removing an assignment revokes only that target/profile grant. Existing budgets,
allowances and usage remain unchanged.

When upgrading an existing configuration, remove `budget_window`, `amount_usd`,
`total_token_limit` and `alert_threshold_percent` from this resource. The provider
upgrades its local state without deleting remote limits; manage those limits in
Budgets afterward.
