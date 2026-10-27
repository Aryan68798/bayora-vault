#!/usr/bin/env bash
# scripts/init_secrets.sh
# Generates Ed25519 keypair and HMAC secret into .secrets/ (git-ignored).
# Safe to re-run: warns before overwriting existing keys.
set -euo pipefail

SECRETS_DIR=".secrets"
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

if [[ -f "$SECRETS_DIR/ed25519_private.pem" ]]; then
    echo "WARNING: .secrets/ed25519_private.pem already exists — skipping keygen."
    echo "         Delete .secrets/ and re-run to rotate keys."
    exit 0
fi

echo "==> Generating Ed25519 keypair and HMAC secret..."

PYTHON_BIN="${PYTHON:-.venv/bin/python}"
if [[ ! -x "$PYTHON_BIN" ]] && ! command -v "$PYTHON_BIN" &>/dev/null; then
    PYTHON_BIN="python3"
fi

"$PYTHON_BIN" - <<'PYEOF'
import secrets
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

d = Path(".secrets")

priv = Ed25519PrivateKey.generate()
pub  = priv.public_key()

priv_pem = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
pub_pem = pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

(d / "ed25519_private.pem").write_bytes(priv_pem)
(d / "ed25519_public.pem").write_bytes(pub_pem)
(d / "hmac_secret").write_text(secrets.token_hex(32) + "\n")

for name in ["ed25519_private.pem", "ed25519_public.pem", "hmac_secret"]:
    (d / name).chmod(0o600)
    print(f"  .secrets/{name}")
PYEOF

echo "==> Done."
