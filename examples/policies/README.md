# Policy example

This example manages representative Content and Access policies, an LLM
Gateway access profile, and an MCP ACL through the published Forge provider.

Before running it:

1. Create a Forge service account with the **Terraform policy management**
   preset and export its one-time secret as `FORGE_API_TOKEN`.
2. Replace `org.example` with the organization key from the Forge Console URL.
3. Replace `OpenAI`, `github`, and `Engineering` with exact names that already
   exist in that organization. Forge deliberately fails on missing or ambiguous
   selectors.
4. Keep `manager_id` and `manager_instance` stable for the lifetime of the
   workspace.

Then run:

```sh
terraform init
terraform fmt -check
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
terraform plan -detailed-exitcode
```

The final plan should exit `0` with **No changes**. Use `terraform destroy`
only when you intend to tombstone the example policies and disable or remove
the other managed resources according to each resource's destroy semantics.
