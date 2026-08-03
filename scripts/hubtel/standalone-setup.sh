#!/usr/bin/env bash
# Hubtel fork addition — not for upstream contribution.
#
# Provisions a standalone hubtel-projects vault on a running OpenBao server:
# no Azure, no CCI. Engineers authenticate with userpass (username = email),
# membership enforcement stays on, and creating a project automatically makes
# the creator a member.
#
# Usage:
#   BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=<admin-token> \
#     ./scripts/hubtel/standalone-setup.sh alice@hubtel.com bob@hubtel.com
#
# Each listed engineer gets a userpass account; the generated password is
# printed once. Re-running is idempotent for mounts/policy and resets the
# passwords of the listed engineers.
set -euo pipefail

BAO=${BAO:-bao}
POLICY_NAME="hubtel-projects-engineer"

if [[ -z "${BAO_ADDR:-}" || -z "${BAO_TOKEN:-}" ]]; then
  echo "BAO_ADDR and BAO_TOKEN must be set" >&2
  exit 1
fi

echo "==> Enabling auth and secrets mounts"
$BAO auth enable userpass 2>/dev/null || echo "    userpass already enabled"
$BAO secrets enable hubtel-projects 2>/dev/null || echo "    hubtel-projects already enabled"

echo "==> Configuring engine (membership enforcement on, no CCI)"
$BAO write hubtel-projects/config enforce_membership=true

echo "==> Writing engineer policy '$POLICY_NAME'"
$BAO policy write "$POLICY_NAME" - <<'EOF'
# Engineers manage projects and secrets; the engine additionally enforces
# per-project membership from the caller's identity entity.
path "hubtel-projects/projects" {
  capabilities = ["list"]
}
path "hubtel-projects/projects/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
# Engine configuration and CCI sync remain admin-only.
EOF

for email in "$@"; do
  password=$(openssl rand -base64 24)
  $BAO write "auth/userpass/users/$email" \
    password="$password" \
    token_policies="$POLICY_NAME" \
    token_ttl=8h >/dev/null
  echo "==> Engineer $email created (userpass). Password: $password"
done

cat <<'EOF'

Done. Engineers log in with:

  bao login -method=userpass username=<email>

or through AQUA:

  export OPENBAO_ADDRESS=$BAO_ADDR
  export OPENBAO_AUTH_METHOD=userpass
  aqua vault projects create --name my-service
  aqua vault secret create --project my-service --environment dev --name API_KEY --generate
EOF
