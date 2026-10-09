---
page_title: 'forge_llm_gateway_catalog Data Source - terraform-provider-forge'
description: |-
  Discover reviewed Forge LLM Gateway models.
---

# forge_llm_gateway_catalog (Data Source)

Discover the reviewed model catalog for Terraform configuration. The catalog is a guide; model IDs in access profiles remain free-form so a newly released model can be used before the next catalog review.

```terraform
data "forge_llm_gateway_catalog" "current" {}

output "catalog_digest" {
  value = data.forge_llm_gateway_catalog.current.catalog_digest
}

output "anthropic_models" {
  value = [for model in data.forge_llm_gateway_catalog.current.models : model.id if model.provider_kind == "anthropic"]
}
```

## Schema

### Read-Only

- `id` (String) Catalog digest.
- `catalog_digest` (String) SHA-256 digest of the reviewed catalog.
- `schema_version` (String) Catalog schema version.
- `models` (List of Object) Model IDs, provider kinds, and supported API surfaces.
