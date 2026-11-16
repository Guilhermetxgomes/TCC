"""
Append-only hash chain, used by the Servidor's audit log (services/audit_log.py) and by
the public bulletin of the Busca Total (services/bulletin.py).

    hash_i = SHA-256(context || hash_{i-1} || canonical(entry_i)),   hash_0 = 0...0

Editing an entry changes its hash; deleting one leaves a gap in `seq` and breaks the link
of the next entry. What the chain alone cannot catch is whoever holds the write key
rewriting the whole tail consistently, or dropping the last entries: that is what the
checkpoints are for -- (seq, hash) pairs that the Conselho de Governança copies out of the
Servidor from time to time. A rewrite of anything a checkpoint already covers no longer
matches it; changes after the last checkpoint stay invisible until the next one.
"""
import base64
import hashlib
from typing import Iterable, Optional

from crypto.canonical import encode, json_bytes
from crypto.tokens import SigningKey, verify_signature

GENESIS = "0" * 64
CHAIN_CONTEXT = b"nemesis-chain-v1"
LINK_FIELDS = ("prev_hash", "hash", "signature")


def content_of(entry: dict) -> dict:
    return {key: value for key, value in entry.items() if key not in LINK_FIELDS}


def entry_hash(prev_hash: str, content: dict) -> str:
    return hashlib.sha256(encode(CHAIN_CONTEXT, prev_hash.encode(), json_bytes(content))).hexdigest()


def link(head: Optional[dict], content: dict, signer: Optional[SigningKey] = None) -> dict:
    """The next entry after `head` (None for the first one): numbers, chains and signs it."""
    content = {**content, "seq": (head["seq"] + 1) if head else 1}
    prev_hash = head["hash"] if head else GENESIS
    digest = entry_hash(prev_hash, content)
    signature = base64.b64encode(signer.sign(digest.encode())).decode("ascii") if signer else None
    return {**content, "prev_hash": prev_hash, "hash": digest, "signature": signature}


def verify(entries: Iterable[dict], checkpoints: Iterable[dict] = (), public_key: Optional[bytes] = None) -> dict:
    """
    Walks the chain and reports every problem found: "seq" (entries missing), "link" (the
    entry does not point to the previous one), "edited" (its content does not match its
    hash), "signature" (not signed by `public_key`), "checkpoint" (does not match a
    checkpoint) and "truncated" (a checkpointed entry is gone).
    """
    entries = sorted(entries, key=lambda entry: entry["seq"])
    problems, broken = [], set()

    def flag(seq, kind, detail):
        problems.append({"seq": seq, "kind": kind, "detail": detail})
        broken.add(seq)

    expected, prev_hash = 1, GENESIS
    for entry in entries:
        seq = entry["seq"]
        if seq != expected:
            missing = f"{expected}" if seq == expected + 1 else f"{expected}–{seq - 1}"
            flag(seq, "seq", f"faltam as entradas {missing} antes desta")
        if entry["prev_hash"] != prev_hash:
            flag(seq, "link", "o hash anterior gravado não é o hash da entrada que a precede")
        if entry_hash(entry["prev_hash"], content_of(entry)) != entry["hash"]:
            flag(seq, "edited", "o conteúdo não confere com o hash gravado (entrada alterada)")
        if public_key is not None and not verify_signature(
                public_key, base64.b64decode(entry["signature"]) if entry.get("signature") else None,
                entry["hash"].encode()):
            flag(seq, "signature", "assinatura do Servidor inválida")
        expected, prev_hash = seq + 1, entry["hash"]

    by_seq = {entry["seq"]: entry for entry in entries}
    last_seq = entries[-1]["seq"] if entries else 0
    for checkpoint in checkpoints:
        entry = by_seq.get(checkpoint["seq"])
        if entry is None:
            flag(checkpoint["seq"], "truncated" if checkpoint["seq"] > last_seq else "seq",
                 f"a entrada {checkpoint['seq']}, coberta pelo checkpoint de {checkpoint.get('at', '?')}, sumiu")
        elif entry["hash"] != checkpoint["hash"]:
            flag(checkpoint["seq"], "checkpoint",
                 f"o hash não confere com o checkpoint de {checkpoint.get('at', '?')} guardado pelo Conselho")
    return {
        "ok": not problems, "length": len(entries), "head": entries[-1]["hash"] if entries else GENESIS,
        "problems": problems, "broken_seqs": sorted(broken),
    }
