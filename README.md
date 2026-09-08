# Forge Terraform provider

The provider manages Forge policies, Resources, Resource credentials, and
gateway configuration. Existing identities and integrations are referenced
rather than recreated.

```hcl
terraform {
  required_version = ">= 1.11.0"

  required_providers {
    forge = {
      source  = "a37ai/forge"
      version = "~> 0.4.0"
    }
  }
}

provider "forge" {
  organization_id  = "org_..."
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
    default match := {"matched": false}
    match := {"matched": input.tool.id == "customer.export", "reasonCode": "customer_export"}
  REGO
}

resource "forge_access_policy" "unapproved_ai_api" {
  id                      = "unapproved-ai-api"
  name                    = "Block unapproved AI API destination"
  action                  = "block"
  severity                = "high"
  acknowledge_broad_scope = true
  enforcement_surfaces    = ["endpoint_route"]

  conditions = {
    field = "destination.domain"
    op    = "eq"
    value = "api.deepseek.com"
  }

  notification = {
    message          = "Direct access to this AI API destination is blocked."
    notifyUser       = true
    adminAudience    = "security_admins"
    acknowledgement  = "mandatory_when_disruptive"
    exceptionRequest = "disabled_for_future_blocks"
  }
}

resource "forge_resource" "production_database" {
  name                = "Production PostgreSQL"
  protocol            = "postgres"
  upstream_host       = "db.internal.example"
  upstream_port       = 5432
  upstream_tls        = true
  # For a private CA only; omit this to use system trust roots.
  # upstream_ca_pem = trimspace(file("private-ca.pem"))
  transparent_routing = true
}

variable "production_database_password" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "forge_resource_credential" "production_database" {
  resource_id    = forge_resource.production_database.id
  name           = "Application account"
  kind           = "username_password"
  username       = "forge_app"
  secret         = var.production_database_password
  secret_version = 1
  default        = true
}

resource "forge_access_policy" "production_database_deletes" {
  id                   = "block-production-database-deletes"
  name                 = "Block production database deletes"
  enabled              = true
  action               = "block"
  severity             = "high"
  enforcement_surfaces = ["resource_proxy"]
  resources            = [forge_resource.production_database.id]
  enforcement          = "enforce"

  conditions = {
    field = "request.postgres.command"
    op    = "eq"
    value = "DELETE"
  }
}

resource "forge_skill_acl" "deploy" {
  id     = "deploy-skill-finance"
  skill  = "deploy-production"
  groups = ["Finance"]
  effect = "block"
}
```

## Credentials

Create a service account in **Forge Console → Settings → Access tokens → New
service account**. Choose **Use preset → Terraform policy management** to get
the exact `policies:read` and `policies:write` scopes, then copy the token once
when Forge displays it. Export it only in the Terraform shell:

```sh
export FORGE_API_TOKEN='paste-the-token-here'
```

When the workspace manages Resources, also grant `resources:read` and
`resources:write`. Managing Resource credentials additionally requires the
narrow `resource_credentials:write` scope; ordinary policy-management tokens
cannot write upstream secrets.

The provider connects to `https://api.forge.ai` by default. Set
`FORGE_ENDPOINT` only for a different Forge environment.

In Forge Console, switch to the organization you intend to manage and open any
organization page. Copy `organization_id` from the browser URL: for
`https://console.forge.ai/organizations/acme_logistics/policies`, use
`acme_logistics`. This is the organization URL key, not its display name.

`manager_id` and `manager_instance` are stable, user-chosen labels for the
Terraform workspace (not credentials). Keep them unchanged across runs; for
example, use `terraform-staging` and `staging`.

If local development state used the former provider address, update it once
before planning:

```sh
terraform state replace-provider registry.terraform.io/forge/forge registry.terraform.io/a37ai/forge
```

Resources: `forge_resource`, `forge_resource_credential`,
`forge_content_policy`, `forge_access_policy`,
`forge_llm_gateway_access_profile`, `forge_llm_gateway_service_account`,
`forge_llm_gateway_managed_access_override`,
`forge_device_gateway_identity_assignment`, `forge_mcp_acl`,
`forge_skill_acl`, and `forge_policy_authority`.
`forge_policy_authority` is the explicit, revision-bound
adoption/release resource for an existing console-authored policy. The first two
accept exactly one `forge.rego.v1` module or a native recursive HCL
`conditions` object. The LLM gateway resource mirrors the native access profile
and atomic route-plan API; it does not create a second compiled gateway policy.
Use `model_patterns`; route providers are selected by exact configured display
name and resolved to stable IDs by Forge. Runtime identity and profile
assignment belong to gateway keys, created after apply in **Forge Console → LLM
Gateway → Gateway keys**. Profiles do not contain subject bindings. Existing
Console profiles require `adopt_existing = true`; adoption and the first update
are one version-checked transaction. MCP ACLs and skill ACLs expose typed
attributes and enums.

Discovery data sources are `forge_user`, `forge_group`, `forge_agent`,
`forge_ai_product`, `forge_integration`, `forge_mcp_server`, `forge_mcp_tool`,
`forge_skill`, and `forge_gateway_provider`. Each resolves exactly one readable
selector and fails on missing or ambiguous results. `forge_rego_test` evaluates
a module against native HCL input through Forge's authoritative compiler for
use in `terraform test`.

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

## Apply and verify

Run the normal Terraform lifecycle from the directory containing the
configuration:

```sh
terraform init
terraform fmt -check
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
terraform plan -detailed-exitcode # exit 0 means refresh converged
```

Planning is an online operation. Forge negotiates the policy-as-code protocol,
resolves every readable selector, and validates Rego, native conditions, stages,
and enforcement surfaces before Terraform can apply a mutation. A validation
error therefore means the proposed policy is not executable on the selected
surface; correct the policy instead of bypassing the plan.

Import is supported for Resources, Resource credentials, Content policies,
Access policies, MCP ACLs, skill ACLs, LLM Gateway access profiles, and
policy-authority bindings:

```sh
terraform import forge_content_policy.example existing-policy-id
terraform import forge_resource.example existing-resource-id
terraform import forge_resource_credential.example existing-resource-id/existing-credential-id
```

`forge_resource_credential.secret` requires Terraform 1.11 or newer. It is
write-only and sensitive. Supply it through an ephemeral variable, as above,
to keep the value absent from both saved plans and state; Forge never returns it.
Increment `secret_version` and provide `secret` to rotate it. Import does not
recover the secret and initializes the local version counter at `1`; configure
a higher value only when you provide the next replacement.

The remote object must already be owned by the same Terraform manager,
manager instance, and service-account principal. Console-managed policies must
first be adopted explicitly with `forge_policy_authority`. LLM Gateway service
accounts, managed access overrides, and device identity assignments do not
support import; create them with Terraform or leave their existing lifecycle
outside Terraform.

Destroy is intentionally recoverable/auditable rather than a hard delete:
policy resources are disabled and tombstoned, LLM Gateway service accounts are
disabled, managed overrides are removed, and device identity assignments are
cleared. A tombstoned policy ID cannot be reused.

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

Organization owners can use **Break glass** from the read-only console policy
view during an incident. The console requires a 10-1,024 character reason,
creates a forward Forge-managed revision, writes a `policy_family.break_glass`
organization audit event, clears the Terraform manager binding, and unlocks
console editing. The previous Terraform state cannot silently overwrite that
revision: refresh or plan fails with an authority conflict until Terraform
explicitly claims or imports authority again through the reviewed authority
workflow.

The provider requires HTTPS except for localhost, bounds responses to 4 MiB,
never logs the token, retries bounded idempotent reads/updates/deletes on 429 and
5xx responses, and treats a remote 404 as removal from state. Create, update,
and tombstone operations are replay-safe when a response is lost: every mutation
uses a durable idempotency key and Forge replays the exact completed response.
Refresh verifies authority and reconstructs readable selectors from bounded
source provenance while using server definitions for drift. Import
sets the policy ID; authority adoption is deliberately not implicit, so a
Forge-managed policy must be explicitly claimed before import can converge.

## Development

The provider is developed in the Forge monorepo and synchronized here after
review. This repository is the public release and issue-tracking surface.
