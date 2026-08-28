# forge_device_gateway_identity_assignment

Assigns an active LLM Gateway service account as a device's explicit Gateway
identity. Destroy clears the assignment and restores assigned-user resolution.

```hcl
resource "forge_device_gateway_identity_assignment" "runner" {
  device_id          = "device_linux_runner"
  service_account_id = forge_llm_gateway_service_account.build.id
}
```
