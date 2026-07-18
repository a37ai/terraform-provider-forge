# Forge Terraform provider

The provider intentionally manages policy resources only. Identities,
integrations, products, models, routes, MCP servers, and skills are referenced
by exact human-readable names and resolved authoritatively by Forge.

```hcl
terraform {
  required_providers {
    forge = { source = "a37ai/forge" }
  }
}

provider "forge" {
  organization_id  = "org.acme"
  manager_id       = "security-platform"
  manager_instance = "production"
  # api_token may be supplied with FORGE_API_TOKEN
}

resource "forge_content_policy" "customer_export" {
  id          = "customer-export"
  name        = "Protect customer exports"
  groups      = ["Finance"]
  evaluate_on = ["pre_tool"]
  action      = "block"
  module      = <<-REGO
    package forge.content
    match := {"matched": input.tool.id == "customer.export", "reasonCode": "customer_export"}
  REGO
}

resource "forge_access_policy" "untrusted_runtime" {
  id                       = "untrusted-runtime"
  name                     = "Block an untrusted local runtime"
  action                   = "block"
  severity                 = "high"
  acknowledge_broad_scope  = true
  enforcement_surfaces     = ["inline_hook"]
  conditions = {
    all = [
      { field = "process.id", op = "eq", value = "runtime.local" },
      { field = "process.path", op = "starts_with", value = "/tmp/" }
    ]
  }
  notification = {
    message         = "An untrusted local AI runtime was blocked."
    notifyUser      = true
    adminAudience   = "security_admins"
    acknowledgement = "mandatory_when_disruptive"
    exceptionRequest = "disabled_for_future_blocks"
  }
  remediation = {
    triggerPhase = "post_block_cleanup"
    actions = [{ surface = "local_runtime", action = "quarantineRuntime" }]
  }
}

resource "forge_skill_acl" "deploy" {
  id     = "deploy-skill-finance"
  skill  = "deploy-production"
  groups = ["Finance"]
  effect = "block"
}
```

If local development state used the former provider address, update it once
before planning:

```sh
terraform state replace-provider registry.terraform.io/forge/forge registry.terraform.io/a37ai/forge
```

Resources: `forge_content_policy`, `forge_access_policy`,
`forge_llm_gateway_access_profile`, `forge_mcp_acl`, and `forge_skill_acl`.
`forge_policy_authority` is the explicit, revision-bound
adoption/release resource for an existing console-authored policy. The first two
accept exactly one `forge.rego.v1` module or a native recursive HCL
`conditions` object. The LLM gateway resource mirrors the native staging access
profile, subject-binding, model-selector, and atomic route-plan API; it does not
create a second compiled gateway policy. MCP ACLs and skill ACLs expose typed
attributes and enums.

The Rego policy resources expose typed scope sets, family action enums,
Content evaluation stages, approvals, every redaction strategy, structured
filters with dynamically typed JSON comparison values, and the complete Access
contract: enforcement surfaces, severity, broad-scope acknowledgement, runtime
posture, structured notifications, approval mode, and trigger-bound remediation
authorizations. Access policies use `approval_mode = "admin_approval"` or
`"self_serve"`; endpoint-route approval is route-scoped rather than a Forge
agent session or single invocation. Native gateway route plans and ACLs use
bounded ordered lists or unique sets as appropriate. Rego
source is always compiled by the authoritative server before a mutation.

Forge atomically binds a new policy to `manager_id`, `manager_instance`, and the
authenticated service-account principal.
Console and ordinary API mutation paths reject Terraform-managed policies, and
a different Terraform workspace cannot update or destroy them. Updates use the
last observed revision for optimistic concurrency. Destroy disables and
tombstones the policy; it does not erase history or make the policy ID reusable.
Use Terraform `prevent_destroy` for policies that require an explicit change
review before tombstoning.

The readable manager values are a coordination and drift contract, while the
server-bound service-account principal is the ownership boundary. Copying the
manager headers to another credential does not grant access. Restrict tokens
with `policies:read` and `policies:write` to trusted automation.

The provider requires HTTPS except for localhost, bounds responses to 4 MiB,
never logs the token, retries bounded idempotent reads/updates/deletes on 429 and
5xx responses, and treats a remote 404 as removal from state. Create, update,
and tombstone operations are replay-safe when a response is lost: every mutation
uses a durable idempotency key and Forge replays the exact completed response.
Refresh verifies authority and reconstructs readable selectors from bounded
source provenance while using canonical server definitions for drift. Import
sets the policy ID; authority adoption is deliberately not implicit, so a
Forge-managed policy must be explicitly claimed before import can converge.

## Development

The provider is developed in the Forge monorepo and synchronized here after
review. This repository is the public release and issue-tracking surface.
