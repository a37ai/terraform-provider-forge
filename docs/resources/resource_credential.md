---
page_title: 'forge_resource_credential Resource - forge'
subcategory: ''
description: |-
  A credential Forge uses to connect to one Resource.
---

# forge_resource_credential (Resource)

A credential Forge uses to connect to one HTTP or PostgreSQL Resource. Forge
keeps the credential server-side; clients and managed devices never receive it.

Terraform 1.11 or newer is required. `secret` is write-only and sensitive, so
Terraform does not store its planned or state value. Supply it through a
sensitive ephemeral variable to keep the value out of saved plan configuration
too. To rotate the credential, increment `secret_version` and provide the
replacement `secret` in the same configuration change.

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

- `kind` (String) Use `username_password` for PostgreSQL, or `bearer_token` or `header` for HTTP.
- `name` (String)
- `resource_id` (String) Resource that uses this credential.

### Optional

- `default` (Boolean) Use when no identity-specific credential is assigned. (default: `false`)
- `groups` (Set of String) Group IDs assigned to this credential.
- `header_name` (String) Required for `header` credentials.
- `secret` (String, Sensitive, Write-only) Required on create and when `secret_version` changes.
- `secret_version` (Number) Increase this value and provide `secret` to rotate the credential. (default: `1`)
- `service_accounts` (Set of String) Service account IDs assigned to this credential.
- `username` (String) Required for `username_password` credentials.
- `users` (Set of String) User IDs assigned to this credential.

### Read-Only

- `id` (String)
- `management_mode` (String) Where this credential is managed.
- `manager_id` (String) Terraform manager that owns this credential.
- `manager_instance` (String) Terraform workspace that owns this credential.
