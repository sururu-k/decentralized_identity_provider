"""分散 IdP が出した JWT を、独立した標準 Ed25519 検証器で検証する。

IdP 側の実装（自前の FROST）を一切共有していないので、RP 互換性の実証になる。

    cargo run --bin pasta_demo | python3 scripts/verify_token.py
"""
import base64, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

def b64u(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

pub_hex = token = None
for line in sys.stdin:
    if line.startswith("PUBKEY "): pub_hex = line.split()[1]
    if line.startswith("TOKEN "):  token = line.split()[1]

pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
header_b64, payload_b64, sig_b64 = token.split(".")
signing_input = f"{header_b64}.{payload_b64}".encode()

print("header :", json.dumps(json.loads(b64u(header_b64)), separators=(",", ":")))
print("payload:", json.dumps(json.loads(b64u(payload_b64)), indent=2))
print("sig len:", len(b64u(sig_b64)), "bytes")

try:
    pk.verify(b64u(sig_b64), signing_input)
    print("\n[OK] 標準 Ed25519 検証器で検証成功 (cryptography)")
except InvalidSignature:
    print("\n[NG] 検証失敗"); sys.exit(1)

# 改竄したら落ちることも確認する
tampered = json.loads(b64u(payload_b64)); tampered["sub"] = "admin"
t_b64 = base64.urlsafe_b64encode(json.dumps(tampered, separators=(",", ":")).encode()).rstrip(b"=").decode()
try:
    pk.verify(b64u(sig_b64), f"{header_b64}.{t_b64}".encode())
    print("[NG] 改竄が通ってしまった"); sys.exit(1)
except InvalidSignature:
    print("[OK] sub を admin に改竄すると検証が落ちる")

# PyNaCl でも独立に確認
import nacl.signing, nacl.exceptions
try:
    nacl.signing.VerifyKey(bytes.fromhex(pub_hex)).verify(signing_input, b64u(sig_b64))
    print("[OK] PyNaCl (libsodium) でも検証成功")
except nacl.exceptions.BadSignatureError:
    print("[NG] PyNaCl で検証失敗"); sys.exit(1)
