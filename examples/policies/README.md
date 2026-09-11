# Policy example

This example manages representative Content, Access, and Resource policies, a
customer-deployed Resource Gateway, HTTPS and PostgreSQL Resources with
credentials, an LLM Gateway access profile, and an MCP ACL.

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

After apply, open the Resource Gateway in Forge Console and create its one-time
Docker Compose files. Save them in the target network and run the displayed
command. The deployment credential is deliberately absent from the Terraform
schema and state.

Once the Gateway is online, authenticate each direct client with a short-lived
Resource token. The command prints only the token, so it can be passed straight
to the client without writing it to disk:

```sh
curl https://resources.example.com/health \
  --header "Proxy-Authorization: Bearer $(forge resources token 'Internal API')"

PGPASSWORD="$(forge resources token 'Production PostgreSQL')" \
  psql 'host=resources.example.com port=5432 dbname=app@production-postgresql user=forge_app sslmode=require'
```

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
