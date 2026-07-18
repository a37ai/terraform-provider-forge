# Terraform Registry publishing

The provider release workflow creates the archives, manifest, checksums, and
detached GPG signature required by the Terraform Registry.

The registry publisher must add the public key in
`terraform-registry-gpg-public-key.asc` when registering the
`a37ai/terraform-provider-forge` repository. Its fingerprint is
`2EF4 C8BC 353B 0C7F 0168 8DCA 3CF0 51A2 B9B1 202C`.

After registration, pushing a semantic version tag such as `v0.1.0` publishes
a signed GitHub release that the registry can ingest.
