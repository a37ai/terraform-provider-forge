---
page_title: 'forge_resource_credential Resource - forge'
subcategory: ''
description: |-
  A credential Forge uses to connect to one Resource.
---

# forge_resource_credential (Resource)

A credential Forge uses to connect to one HTTP, PostgreSQL, MySQL, or Redis
Resource. Forge keeps stored credential material server-side; clients and
managed devices never receive it. The Resource must be assigned to a Resource
Gateway before the credential can be used for routed traffic.

Terraform 1.11 or newer is required. `secret` is write-only and sensitive, so
Terraform does not store its planned or state value. Supply it through a
sensitive ephemeral variable to keep the value out of saved plan configuration
too. To rotate the credential, increment `secret_version` and provide the
replacement `secret` in the same configuration change.

RDS and Aurora PostgreSQL or MySQL can instead use the Resource Gateway's AWS
workload identity. This stores no database password:

```hcl
resource "forge_resource_credential" "database_iam" {
  resource_id = forge_resource.database.id
  name        = "Application IAM access"
  kind        = "aws_rds_iam"
  username    = "forge_app"
  aws_region  = "us-west-2"
  # aws_role_arn = "arn:aws:iam::123456789012:role/forge-database"
  default     = true
}
```

Without `aws_role_arn`, the Gateway workload identity needs `rds-db:connect`
for the intended database user. With `aws_role_arn`, that role needs
`rds-db:connect`, while the Gateway identity needs `sts:AssumeRole` for the
exact role. Do not provide AWS access keys to Forge.

HTTP APIs can use OAuth 2.0 client credentials. The Gateway requests and caches
a short-lived bearer token only after Resource Policy and approval succeed:

```hcl
variable "orders_client_secret" {
  type      = string
  sensitive = true
  ephemeral = true
}

variable "orders_service_account_id" {
  type        = string
  description = "ID of an active Forge service account with resources:connect"
}

resource "forge_resource_credential" "orders_oauth" {
  resource_id          = forge_resource.orders.id
  name                 = "Orders API temporary access"
  kind                 = "oauth2_client_credentials"
  oauth_token_endpoint = "https://identity.example.com/oauth/token"
  oauth_client_id      = "orders-agent"
  oauth_scopes         = ["orders.read", "orders.write"]
  oauth_audience       = "https://orders.example.com"
  secret               = var.orders_client_secret
  service_accounts     = [var.orders_service_account_id]
}
```

The token endpoint must use HTTPS and cannot redirect, and must accept HTTP
Basic client authentication. The client secret is write-only; only the
temporary bearer token is sent to the Resource.

When the destination identity provider supports OAuth 2.0 token exchange, the
Gateway can exchange the caller's short-lived Forge Resource token without a
stored client secret:

```hcl
resource "forge_resource_credential" "orders_identity_exchange" {
  resource_id          = forge_resource.orders.id
  name                 = "Orders API user access"
  kind                 = "oauth2_token_exchange"
  oauth_token_endpoint = "https://identity.example.com/oauth/token"
  oauth_client_id      = "forge-resource-client"
  oauth_scopes         = ["orders.read"]
  oauth_audience       = "orders-api"
  default              = true
}
```

Token exchange is keyless. The identity provider must trust the Forge issuer
and Resource token audience. Tokens are cached separately per caller and only
until shortly before their reported expiry.

```hcl
variable "database_password" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "forge_resource_credential" "database" {
  resource_id    = forge_resource.database.id
  name           = "Application account"
  kind           = "username_password"
  username       = "forge_app"
  secret         = var.database_password
  secret_version = 1
  default        = true
}
```

Import uses both parent and credential IDs:

```sh
terraform import forge_resource_credential.database resource_id/credential_id
```

Import never recovers a secret and initializes `secret_version` at `1`. Leave
`secret` unset and use version `1` until the next planned rotation.

## Schema

### Required

- `kind` (String) Authentication method: `username_password` or `aws_rds_iam` for PostgreSQL and MySQL, `username_password` for Redis, and `bearer_token`, `header`, `oauth2_client_credentials`, or `oauth2_token_exchange` for HTTP.
- `name` (String)
- `resource_id` (String) Resource that uses this credential.

### Optional

- `default` (Boolean) Use when no identity-specific credential is assigned. (default: `false`)
- `aws_region` (String) AWS Region for `aws_rds_iam`. The Gateway uses its AWS workload identity.
- `aws_role_arn` (String) Optional exact IAM role the Gateway assumes for `aws_rds_iam`.
- `groups` (Set of String) Group IDs assigned to this credential.
- `header_name` (String) Destination header name for `header` credentials.
- `oauth_audience` (String) Optional audience for OAuth client credentials or token exchange.
- `oauth_client_id` (String) OAuth client ID. Required for client credentials and optional for token exchange.
- `oauth_scopes` (Set of String) Optional scopes requested for OAuth client credentials or token exchange.
- `oauth_token_endpoint` (String) HTTPS token endpoint for OAuth client credentials or token exchange.
- `secret` (String, Sensitive, Write-only) Credential secret for `username_password`, `bearer_token`, `header`, or `oauth2_client_credentials`. Required on create and when `secret_version` changes for those methods.
- `secret_version` (Number) For stored-secret methods, increase this value and provide `secret` to rotate the credential. (default: `1`)
- `service_accounts` (Set of String) Service account IDs assigned to this credential.
- `username` (String) Destination username for `username_password` or `aws_rds_iam`.
- `users` (Set of String) User IDs assigned to this credential.

### Read-Only

- `id` (String)
- `management_mode` (String) Where this credential is managed.
- `manager_id` (String) Terraform manager that owns this credential.
- `manager_instance` (String) Terraform workspace that owns this credential.
