# Terraform Registry publishing

The provider release workflow creates the archives, manifest, checksums, and
detached GPG signature required by the Terraform Registry.

The registry publisher must add the public key in
`terraform-registry-gpg-public-key.asc` when registering the
`a37ai/terraform-provider-forge` repository. Its fingerprint is
`D9E8 DFE2 42BF 1FDF A6FD 2960 BAF3 D29A E889 5C62`.

After registration, pushing a semantic version tag such as `v0.1.0` publishes
a signed GitHub release that the registry can ingest.
