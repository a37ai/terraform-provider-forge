#!/usr/bin/env bash
set -euo pipefail
gpg --batch --yes --pinentry-mode loopback --passphrase "${GPG_PASSPHRASE}" \
  --local-user "${GPG_FINGERPRINT}" --detach-sign --output "$2" "$1"
