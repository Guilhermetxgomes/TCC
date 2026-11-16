"""
Authorization tokens (RF06): what the judge signs and how anyone holding the judge's
public key checks it.

The signed payload is canonical (crypto/canonical.py), so changing any field -- the
operator, the deadline, one camera of the scope, the budget -- invalidates the signature.

In the Busca Fechada the plate never appears in the token: the judge signs
HMAC(k_jud, plate), where k_jud is a key of the Judiciary shared only with the Auditor.
The Servidor, which sees the token, learns nothing about the plate; the Auditor can check
afterwards that the plate a declared decryption revealed is the one the order named.
Caveat: the plate space is small (~1.8e8 for LLLNNNN), so whoever holds k_jud can invert
the HMAC by brute force -- k_jud protects the plate from the Servidor, not from the Auditor.
"""
import hashlib
import hmac
from dataclasses import replace
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from crypto.canonical import encode, json_bytes
from entities.auth_token import AuthToken

TOKEN_CONTEXT = b"nemesis-token-v1"


class SigningKey:
    """An ECDSA P-256 key pair; the private half never leaves its holder."""

    def __init__(self):
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key_bytes = self._private_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
        )

    def sign(self, payload: bytes) -> bytes:
        return self._private_key.sign(payload, ec.ECDSA(hashes.SHA256()))


def verify_signature(public_key_bytes: Optional[bytes], signature: Optional[bytes], payload: bytes) -> bool:
    if not public_key_bytes or not signature:
        return False
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_bytes)
    try:
        public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def token_payload(token: AuthToken) -> bytes:
    return encode(
        TOKEN_CONTEXT, token.token_id.encode(), token.mode.encode(), token.operator_id.encode(),
        token.issued_at.encode(), token.expires_at.encode(), json_bytes(token.scope),
    )


def sign_token(token: AuthToken, key: SigningKey) -> AuthToken:
    return replace(token, signature=key.sign(token_payload(token)))


def verify_token(token: AuthToken, judge_public_key: Optional[bytes]) -> bool:
    return verify_signature(judge_public_key, token.signature, token_payload(token))


def plate_commitment(hmac_key: bytes, plate: str) -> str:
    return hmac.new(hmac_key, b"plate|" + plate.encode(), hashlib.sha256).hexdigest()
