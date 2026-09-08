# Policy example

This example manages representative Content and Access policies, HTTPS and
PostgreSQL Resources with credentials, an LLM Gateway access profile, and an
MCP ACL.

Before running it:

1. Use Terraform 1.11 or newer. The example uses an ephemeral, sensitive
   variable with a write-only attribute to keep the credential out of saved
   plans and state.
2. Create a Forge service account with the **Terraform policy management**
   preset, add `resources:read`, `resources:write`, and
   `resource_credentials:write`, then export its one-time secret as
   `FORGE_API_TOKEN`.
3. Set `TF_VAR_production_database_password` and `TF_VAR_internal_api_token`
   for the example Resources.
4. Replace `org.example` with the organization key from the Forge Console URL.
5. Replace `OpenAI`, `github`, and `Engineering` with exact names that already
   exist in that organization. Forge deliberately fails on missing or ambiguous
   selectors.
6. Keep `manager_id` and `manager_instance` stable for the lifetime of the
   workspace.

Changing a credential secret requires incrementing `secret_version`. The
secret is sent only during creation or that explicit rotation and is never
stored in Terraform plan or state.

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
