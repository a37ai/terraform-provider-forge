# forge_llm_gateway_budget

Manages an optional gateway spending or token limit independently of access
assignments. All matching budgets apply. Omit `access_profile_id` to share a
subject's budget across profiles and providers.

```hcl
resource "forge_llm_gateway_budget" "engineering" {
  subject_kind     = "group"
  subject_id       = "directory-group-id"
  budget_window    = "monthly"
  amount_usd       = 100
  member_limit_usd = 10
  member_limits_usd = {
    "directory-user-id" = 20
  }
}
```

Set one or more of `amount_usd`, `input_token_limit`, `output_token_limit`, and
`total_token_limit`. Alternatively set `token_id` to target a gateway key.
`budget_window` accepts `daily`, `weekly`, `monthly`, `rolling_24h`, `rolling_7d`,
and `rolling_30d`. Calendar periods reset in UTC; weeks start Monday.

`member_limit_usd` and `member_limits_usd` require a group USD budget. Named
values replace the per-member default, while the group total still applies.

Target and period changes replace the resource. Normal limit edits preserve
usage. Reads and updates preserve administrator-granted temporary allowances and
alert settings; Terraform does not regrant an allowance on every apply. Manage
allowances through the Budgets tab or the guarded public budget API. Expired
allowances are pruned on ordinary edits; current and scheduled allowances remain
protected. Period changes still replace the budget. API grants can supply
`allowanceWindowStart` from `periodStarts` to reject a reset with `409`; zero-value
removal is unaffected.

Destroy disables the limit and preserves accounting history. Concurrent edits
can return a stale-version conflict; refresh and review the plan before retrying.
The provider requires `policies:read` and `policies:write`; writes use the normal
reason, confirmation, and idempotency controls.

Import an existing budget by its budget ID:

```shell
terraform import forge_llm_gateway_budget.engineering lgwb_example
```
