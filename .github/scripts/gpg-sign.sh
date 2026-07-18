#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "${GPG_PASSPHRASE}" | gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 \
  --local-user "${GPG_FINGERPRINT}" --detach-sign --output "$2" "$1"
