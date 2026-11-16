"""
The Governance layer of the simulation, in one place: the judge (tokens), the public
bulletin of the Busca Total, the Servidor's log key, the checkpoints of the log that the
Conselho de Governança keeps and the declarations of decryption the investigators send to
the Auditor.

Everything here lives OUTSIDE the Servidor's database (in World.governance), like the
cameras' public keys: these are the references the Servidor's log is checked against, so
the operator who controls the database must not be able to rewrite them.

Three independent sources feed the reconciliation (services/auditor.py): the tokens come
from the judge, the releases from the Servidor and the declarations from the Usuário.
"""
from dataclasses import dataclass, field
from typing import Optional

from crypto.tokens import SigningKey
from services.audit_log import AuditLog
from services.bulletin import PublicBulletin
from services.judge import LegalAuthorizer

DEFAULT_OPERATOR = "PC-0042"  # the police officer running the searches in the UI


@dataclass
class Governance:
    judge: LegalAuthorizer = field(default_factory=LegalAuthorizer)
    bulletin: PublicBulletin = field(default_factory=PublicBulletin)
    # The Servidor's own key for signing its log entries; only the public half is registered
    # with the Conselho. (It stays with the Servidor: a dishonest operator can use it, which is
    # why the checkpoints exist.)
    server_log_key: SigningKey = field(default_factory=SigningKey)
    checkpoints: list = field(default_factory=list)   # {seq, hash, at}
    declarations: list = field(default_factory=list)  # {token_id, operator_id, record_id, k, block_k, kind, at}

    @property
    def server_log_public_key(self) -> bytes:
        return self.server_log_key.public_key_bytes

    def audit_log(self, server, run_id: str) -> AuditLog:
        return AuditLog(server, run_id, self.server_log_key)

    def checkpoint(self, server, run_id: str, at: str) -> Optional[dict]:
        """The Conselho copies the head of the Servidor's log (seq, hash) out of the database."""
        head = server.get_audit_head(run_id)
        if head is None or (self.checkpoints and self.checkpoints[-1]["seq"] == head["seq"]):
            return None
        checkpoint = {"seq": head["seq"], "hash": head["hash"], "at": at}
        self.checkpoints.append(checkpoint)
        return checkpoint

    def declare(self, token_id: str, operator_id: str, record_id: int, k: int, at: str,
                block_k: Optional[int] = None, kind: str = "acerto", source: str = "busca") -> dict:
        """
        The investigator tells the Auditor which record it opened and with which solution.
        kind: "acerto" (the plate the token is for), "colateral" (a third party opened while
        looking for it) or "janela" (a record of a Busca Aberta window: all of them are in scope).
        """
        declaration = {"token_id": token_id, "operator_id": operator_id, "record_id": record_id, "k": k,
                       "block_k": block_k, "kind": kind, "at": at, "source": source}
        self.declarations.append(declaration)
        return declaration
