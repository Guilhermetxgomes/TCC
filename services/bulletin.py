"""
Public bulletin of the Busca Total (RNF08) -- the "Diário Oficial" of the exceptional access.

Every activation of the Comitê de Emergência is published here BEFORE any partial
decryption, and closed afterwards with what it opened. The bulletin is a hash chain
(crypto/hashchain.py) that anyone can mirror; publishing returns a receipt (seq, hash),
and each committee member refuses to take part unless the receipt is in the bulletin and
names the same token (services/committee.py). An activation that did not leave a public
trace therefore cannot happen.
"""
from typing import Optional

from crypto import hashchain


class PublicBulletin:
    def __init__(self):
        self._entries: list[dict] = []

    def publish(self, kind: str, at: str, token_id: str, detail: dict) -> dict:
        head = self._entries[-1] if self._entries else None
        entry = hashchain.link(head, {"at": at, "kind": kind, "token_id": token_id, "detail": detail})
        self._entries.append(entry)
        return {"seq": entry["seq"], "hash": entry["hash"]}

    def entries(self) -> list[dict]:
        return list(self._entries)

    def contains(self, receipt: Optional[dict], token_id: str, kind: str = "activation") -> bool:
        """True when `receipt` points to an intact entry of this kind for this token."""
        if not receipt:
            return False
        entry = next((e for e in self._entries if e["seq"] == receipt.get("seq")), None)
        return (entry is not None and entry["hash"] == receipt.get("hash") and entry["token_id"] == token_id
                and entry["kind"] == kind and hashchain.verify(self._entries)["ok"])

    def verify(self) -> dict:
        return hashchain.verify(self._entries)
