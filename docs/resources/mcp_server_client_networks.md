---
page_title: 'forge_mcp_server_client_networks Resource - terraform-provider-forge'
subcategory: ''
description: |-
  Manage the allowed client networks of an existing Forge MCP Registry server.
---

# forge_mcp_server_client_networks (Resource)

Manage the allowed client networks of an existing Forge MCP Registry server.
Clients must still meet the server's access rules.

## Example

```hcl
data "forge_mcp_server" "internal_tools" {
  selector = "Internal Tools"
}

resource "forge_mcp_server_client_networks" "internal_tools" {
  server_id               = data.forge_mcp_server.internal_tools.id
  allowed_client_networks = ["203.0.113.0/24", "2001:db8:1234::/48"]
}
```

## Schema

- `server_id` (String, Required) The ID of an existing MCP Registry server. Changing it replaces the resource.
- `allowed_client_networks` (Set of String, Required) Up to 128 IPv4 or IPv6 addresses or CIDR ranges. Apply an empty set to clear the restriction.

## Ownership and import

While Terraform owns this setting, Console shows the list as read-only.
To claim an existing Console-managed restriction, apply its current list first.
Change the list in a subsequent apply.

Import an existing setting already managed by the same Terraform owner using
the MCP Registry server ID.

```shell
terraform import forge_mcp_server_client_networks.internal_tools mcri_example
```

Destroying the resource releases Terraform ownership and keeps the saved
network list in Forge. To remove the restriction, apply an empty set before
destroying the resource.
