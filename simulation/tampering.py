"""
What a dishonest Servidor operator can do to a stored record -- and what catches it.

The operator has write access to the database and, like anyone, can solve a puzzle by
brute force. Two attacks (crypto/signing.py explains the defences):

- move_attack: rewrites camera_id and captured_at of a row (a false alibi or a false
  accusation). Caught by the associated data: under the new (camera, instant) no k opens
  the ciphertext. Also caught by the signature, which covers both fields.
- forge_attack: solves the puzzle, learns K and re-encrypts another plate under the same
  c' and the same AD. AES-GCM accepts it (the tag is valid: K both encrypts and
  authenticates); only the camera's signature, which the operator cannot produce, catches it.

Each attack returns the tampered record and the list of checks a verifier would run, in
order, each with whether it detected the tampering. The checks also show what the
previous prototype (AES-GCM without AD, no signature) would have accepted.
"""
from dataclasses import replace

from cryptography.exceptions import InvalidTag

from crypto.crumpling import decrypt, derive_key, encrypt, generate_nonce
from crypto.puzzle import open_record
from crypto.signing import CameraSigner, record_ad, verify_record
from entities.record import Record


def _check(label: str, detected: bool, detail: str) -> dict:
    return {"label": label, "detected": detected, "detail": detail}


def _open(record: Record, k: int, prefix: bytes):
    try:
        return open_record(record, k, prefix)
    except InvalidTag:
        return None


def move_attack(record: Record, k: int, prefix: bytes, public_key: bytes, plate: str,
                new_camera_id: int, new_captured_at: str) -> tuple[Record, list[dict]]:
    moved = replace(record, camera_id=new_camera_id, captured_at=new_captured_at)
    checks = []

    # The previous prototype: same key, same nonce, but AES-GCM without associated data.
    key = derive_key(prefix + record.c_prime, k)
    legacy_ciphertext = encrypt(plate.encode(), key, record.nonce, None)
    legacy_plate = decrypt(legacy_ciphertext, key, record.nonce, None).decode()
    checks.append(_check(
        "Protótipo anterior (AES-GCM sem AD)", False,
        f"abriria normalmente: {legacy_plate} na câmera {new_camera_id}, {new_captured_at[11:19]}. "
        "A etiqueta não cobre câmera nem instante, então a adulteração passa e a conclusão é falsa.",
    ))

    opened = _open(moved, k, prefix)
    checks.append(_check(
        "AES-GCM com AD = (câmera, instante)", opened is None,
        "recusado (InvalidTag): mesmo com o k correto, a etiqueta não confere com a nova câmera e o novo "
        "instante. Nenhum k abre o registro adulterado." if opened is None else f"abriu: {opened}",
    ))

    signature_ok = verify_record(moved, public_key)
    checks.append(_check(
        "Assinatura da câmera", not signature_ok,
        "inválida: a câmera assinou a câmera e o instante originais." if not signature_ok else "válida",
    ))
    return moved, checks


def forge_attack(record: Record, k: int, prefix: bytes, public_key: bytes,
                 fake_plate: str) -> tuple[Record, list[dict]]:
    key = derive_key(prefix + record.c_prime, k)  # what solving the puzzle gives the operator
    nonce = generate_nonce()
    # The AD is public: the forger simply reuses it.
    forged = replace(record, nonce=nonce,
                     ciphertext=encrypt(fake_plate.encode(), key, nonce, record_ad(record.camera_id, record.captured_at)))
    checks = []

    opened = _open(forged, k, prefix)
    checks.append(_check(
        "AES-GCM com AD = (câmera, instante)", opened is None,
        f"aceito: abre com o mesmo puzzle e mostra {opened}. A etiqueta é válida porque quem tem K "
        "também gera etiquetas; o AD é público e foi reaproveitado." if opened is not None else "recusado",
    ))

    signature_ok = verify_record(forged, public_key)
    checks.append(_check(
        "Assinatura original da câmera", not signature_ok,
        "inválida: ela foi feita sobre o nonce e o texto cifrado originais." if not signature_ok else "válida",
    ))

    own = replace(forged)
    own.signature = CameraSigner().sign(own)
    own_ok = verify_record(own, public_key)
    checks.append(_check(
        "Reassinado com uma chave do operador", not own_ok,
        "inválida: não confere com a chave pública registrada da câmera. Sem a chave privada da câmera, "
        "não há como produzir uma assinatura aceita." if not own_ok else "válida",
    ))
    return forged, checks
