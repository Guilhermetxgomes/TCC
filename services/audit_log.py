"""
The Servidor's decoding log (RF08, RNF03): every release of encrypted rows, every refusal
and every Busca Total release becomes one entry of a hash chain (crypto/hashchain.py),
signed with the Servidor's log key and stored in the database (table audit_log).

What the Servidor logs is a *release*, not a decryption: it is blind and cannot see what
the investigator decrypts. Each entry carries the token, the instant, the modality, the
operator, the camera and window released and the ids of the rows handed over.

The table lives in the same database the operator controls -- on purpose: the tampering
demo (simulation/governance_attacks.py) edits it, and the chain plus the checkpoints the
Conselho keeps (World.governance.checkpoints) show it.
"""
from typing import Optional

from crypto import hashchain
from crypto.tokens import SigningKey

ENTRY_FIELDS = ("seq", "at", "kind", "token_id", "mode", "operator_id", "camera_id", "window_start",
                "window_end", "records", "detail")


class AuditLog:
    def __init__(self, store, run_id: str, signer: SigningKey):
        self.store = store  # services.server.Server or simulation.memory_server.MemoryServer
        self.run_id = run_id
        self._signer = signer

    def append(self, kind: str, at: str, token_id: Optional[str] = None, mode: Optional[str] = None,
               operator_id: Optional[str] = None, camera_id: Optional[int] = None,
               window_start: Optional[str] = None, window_end: Optional[str] = None,
               records: int = 0, detail: Optional[dict] = None) -> dict:
        content = {
            "at": at, "kind": kind, "token_id": token_id, "mode": mode, "operator_id": operator_id,
            "camera_id": camera_id, "window_start": window_start, "window_end": window_end,
            "records": records, "detail": detail or {},
        }
        entry = hashchain.link(self.store.get_audit_head(self.run_id), content, self._signer)
        self.store.append_audit(self.run_id, entry)
        return entry

    def entries(self) -> list[dict]:
        return self.store.get_audit_log(self.run_id)

    def head(self) -> Optional[dict]:
        return self.store.get_audit_head(self.run_id)
