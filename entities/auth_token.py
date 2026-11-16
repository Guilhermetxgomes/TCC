from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AuthToken:
    """
    Authorization token issued and signed (ECDSA P-256) by the Autorizador Legal (the
    judge). The Servidor checks it before releasing any encrypted row (services/custody.py),
    and each Comitê de Emergência member checks it before releasing its Shamir share.

    `scope` depends on `mode`:
      - "aberta":  {"camera_id", "start", "end"}   -- one camera, one time window
      - "fechada": {"plate_hmac", "budget_records"} -- one plate (as an HMAC: the Servidor
                   never learns it) and a ceiling on how many rows may be released
      - "total":   {"period", "sessions", "camera_ids", "reason"} -- what one Busca Total
                   activation may open (camera_ids None = every camera)

    issued_at / expires_at are ISO-8601 instants of the simulated clock.
    """
    token_id: str
    mode: str
    operator_id: str
    issued_at: str
    expires_at: str
    scope: dict = field(default_factory=dict)
    signature: Optional[bytes] = None

    def summary(self) -> dict:
        """JSON-friendly view (no signature bytes) for the UI and the reconciliation."""
        return {
            "token_id": self.token_id, "mode": self.mode, "operator_id": self.operator_id,
            "issued_at": self.issued_at, "expires_at": self.expires_at, "scope": self.scope,
        }
